//! Building, canonically encoding, and signing a Sidewinder transaction — the `Slot.set` example.
//!
//! These tests need no external service. They drive the client's build/sign path with the
//! deterministic test key and check the result three ways, all offline:
//!
//! - the canonical MessagePack layout, by decoding the bytes with `rmpv` (keyed maps, sorted keys,
//!   `grp`/`note` omitted when absent, byte fields as `bin`);
//! - the signature, with `verify_strict` over the re-encoded body — exactly the check the node
//!   makes on submit;
//! - the transaction identifier, by recomputing the SHA-512/256 content address of the body.

use crate::support::mock_node::{MockNode, Route};
use crate::support::{TEST_SEED, TEST_TOKEN, client_for, signing_client_for};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512_256};
use sidewinder_ops::{AppArg, SidewinderErrorKind, TransactionRequest};

/// The transaction type the boot configuration binds `Slot.set` to (see sidewinder's e2e harness).
const SLOT_SET: u32 = 2;

/// A placeholder URL for the offline build/sign tests, which never open a connection.
const OFFLINE_URL: &str = "http://localhost:1";

/// A 32-byte instance identifier (any 32 bytes serve for an encoding test).
fn instance() -> Vec<u8> {
    (0u8..32).collect()
}

/// A `Slot.set(slot_addr, value)` request with a note, no atomic group.
fn slot_set_request() -> TransactionRequest {
    TransactionRequest {
        txn_type: SLOT_SET,
        args: vec![
            AppArg::Bytes(1234u64.to_be_bytes().to_vec()),
            AppArg::Bytes(b"hello".to_vec()),
        ],
        max_fee: 1000,
        first_valid: 0,
        last_valid: 5_000_000,
        instance: instance(),
        note: Some(7u64.to_le_bytes().to_vec()),
        group: None,
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn as_map(value: &rmpv::Value) -> &[(rmpv::Value, rmpv::Value)] {
    match value {
        rmpv::Value::Map(entries) => entries,
        other => panic!("expected a map, got {other:?}"),
    }
}

fn keys(map: &[(rmpv::Value, rmpv::Value)]) -> Vec<&str> {
    map.iter()
        .map(|(k, _)| k.as_str().expect("a string key"))
        .collect()
}

fn field<'a>(map: &'a [(rmpv::Value, rmpv::Value)], key: &str) -> &'a rmpv::Value {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("missing key `{key}`"))
}

fn bin(value: &rmpv::Value) -> &[u8] {
    match value {
        rmpv::Value::Binary(bytes) => bytes,
        other => panic!("expected binary, got {other:?}"),
    }
}

#[test]
fn slot_set_encodes_to_the_canonical_body_layout() {
    let client = signing_client_for(OFFLINE_URL);
    let request = slot_set_request();
    let signed = client
        .build_signed_transaction(&request)
        .expect("build and sign");

    // Outer envelope: the `txn` body then its `sig`.
    let envelope = rmpv::decode::read_value(&mut &signed.bytes[..]).expect("decode envelope");
    let envelope = as_map(&envelope);
    assert_eq!(keys(envelope), vec!["txn", "sig"]);

    // Body: keys in ascending order, `grp` omitted (no group), `note` present.
    let body = as_map(field(envelope, "txn"));
    assert_eq!(
        keys(body),
        vec!["args", "fee", "fv", "inst", "lv", "note", "snd", "typ"],
        "keys must be sorted and grp omitted when absent"
    );

    // args: the two raw byte-string arguments, in order.
    let args = match field(body, "args") {
        rmpv::Value::Array(items) => items,
        other => panic!("args should be an array, got {other:?}"),
    };
    assert_eq!(args.len(), 2);
    assert_eq!(bin(&args[0]), &1234u64.to_be_bytes());
    assert_eq!(bin(&args[1]), b"hello");

    // header integers and byte fields.
    assert_eq!(field(body, "fee").as_u64(), Some(1000));
    assert_eq!(field(body, "fv").as_u64(), Some(0));
    assert_eq!(field(body, "lv").as_u64(), Some(5_000_000));
    assert_eq!(field(body, "typ").as_u64(), Some(u64::from(SLOT_SET)));
    assert_eq!(bin(field(body, "inst")), instance().as_slice());
    assert_eq!(bin(field(body, "note")), &7u64.to_le_bytes());

    // snd is the signing account's public key.
    let sender = client
        .algo_ops()
        .public_key_bytes()
        .expect("the handle holds a key");
    assert_eq!(bin(field(body, "snd")), &sender);
}

#[test]
fn uint_and_utf8_args_pack_per_the_apparg_convention() {
    // A uint packs as 8 big-endian bytes (ARC-4 uint64); a utf8 arg packs as its raw bytes.
    let client = signing_client_for(OFFLINE_URL);
    let mut request = slot_set_request();
    request.args = vec![
        AppArg::Uint(0x0102_0304_0506_0708),
        AppArg::Utf8("v".into()),
    ];
    let signed = client.build_signed_transaction(&request).expect("build");

    let envelope = rmpv::decode::read_value(&mut &signed.bytes[..]).expect("decode");
    let body = as_map(field(as_map(&envelope), "txn"));
    let args = match field(body, "args") {
        rmpv::Value::Array(items) => items,
        other => panic!("args should be an array, got {other:?}"),
    };
    assert_eq!(bin(&args[0]), &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(bin(&args[1]), b"v");
}

#[test]
fn signature_verifies_over_the_canonical_body() {
    let client = signing_client_for(OFFLINE_URL);
    let signed = client
        .build_signed_transaction(&slot_set_request())
        .expect("build and sign");

    let envelope = rmpv::decode::read_value(&mut &signed.bytes[..]).expect("decode envelope");
    let envelope = as_map(&envelope);

    // Re-encode just the body — the bytes the signature and the identifier are taken over.
    let mut body_bytes = Vec::new();
    rmpv::encode::write_value(&mut body_bytes, field(envelope, "txn")).expect("re-encode body");

    let sig_bytes: [u8; 64] = bin(field(envelope, "sig"))
        .try_into()
        .expect("a 64-byte signature");
    let sender = client.algo_ops().public_key_bytes().expect("a key");

    // verify_strict is exactly the node's check (see sidewinder-core SignedTransaction::verify).
    let verifying_key = VerifyingKey::from_bytes(&sender).expect("a valid Ed25519 key");
    verifying_key
        .verify_strict(&body_bytes, &Signature::from_bytes(&sig_bytes))
        .expect("signature verifies over the canonical body");

    // The signature matches one made independently with the same seed — signing is deterministic.
    let expected = SigningKey::from_bytes(&TEST_SEED).sign(&body_bytes);
    assert_eq!(sig_bytes, expected.to_bytes());
}

#[test]
fn tx_id_is_the_content_address_of_the_body() {
    let client = signing_client_for(OFFLINE_URL);
    let signed = client
        .build_signed_transaction(&slot_set_request())
        .expect("build and sign");

    let envelope = rmpv::decode::read_value(&mut &signed.bytes[..]).expect("decode envelope");
    let mut body_bytes = Vec::new();
    rmpv::encode::write_value(&mut body_bytes, field(as_map(&envelope), "txn")).expect("re-encode");

    assert_eq!(signed.tx_id, hex(Sha512_256::digest(&body_bytes)));
    assert_eq!(
        signed.tx_id.len(),
        64,
        "a SHA-512/256 digest is 64 hex chars"
    );
}

#[test]
fn building_is_deterministic() {
    let client = signing_client_for(OFFLINE_URL);
    let request = slot_set_request();
    let a = client.build_signed_transaction(&request).expect("build");
    let b = client.build_signed_transaction(&request).expect("build");
    assert_eq!(a, b, "same request and key must give byte-identical output");
}

#[test]
fn group_is_included_in_sorted_position_when_present() {
    let client = signing_client_for(OFFLINE_URL);
    let mut request = slot_set_request();
    request.group = Some((100u8..132).collect());
    let signed = client.build_signed_transaction(&request).expect("build");

    let envelope = rmpv::decode::read_value(&mut &signed.bytes[..]).expect("decode");
    let body = as_map(field(as_map(&envelope), "txn"));
    assert_eq!(
        keys(body),
        vec![
            "args", "fee", "fv", "grp", "inst", "lv", "note", "snd", "typ"
        ],
        "grp sorts between fv and inst"
    );
    assert_eq!(
        bin(field(body, "grp")),
        (100u8..132).collect::<Vec<_>>().as_slice()
    );
}

#[test]
fn omitting_the_note_drops_the_field() {
    let client = signing_client_for(OFFLINE_URL);
    let mut request = slot_set_request();
    request.note = None;
    let signed = client.build_signed_transaction(&request).expect("build");

    let envelope = rmpv::decode::read_value(&mut &signed.bytes[..]).expect("decode");
    let body = as_map(field(as_map(&envelope), "txn"));
    assert_eq!(
        keys(body),
        vec!["args", "fee", "fv", "inst", "lv", "snd", "typ"],
        "an absent note is omitted entirely"
    );
}

#[test]
fn a_non_32_byte_instance_is_rejected() {
    let client = signing_client_for(OFFLINE_URL);
    let mut request = slot_set_request();
    request.instance = vec![0u8; 16];
    let err = client
        .build_signed_transaction(&request)
        .expect_err("a short instance must be rejected");
    let se = err
        .downcast_ref::<sidewinder_ops::SidewinderError>()
        .expect("a SidewinderError");
    assert_eq!(se.kind, SidewinderErrorKind::InvalidTransaction);
    assert!(se.message.contains("instance"));
}

#[test]
fn a_non_32_byte_group_is_rejected() {
    let client = signing_client_for(OFFLINE_URL);
    let mut request = slot_set_request();
    request.group = Some(vec![0u8; 8]);
    let err = client
        .build_signed_transaction(&request)
        .expect_err("a short group must be rejected");
    assert_eq!(
        err.downcast_ref::<sidewinder_ops::SidewinderError>()
            .expect("a SidewinderError")
            .kind,
        SidewinderErrorKind::InvalidTransaction
    );
}

#[test]
fn an_inverted_validity_window_is_rejected() {
    let client = signing_client_for(OFFLINE_URL);
    let mut request = slot_set_request();
    request.first_valid = 100;
    request.last_valid = 50;
    let err = client
        .build_signed_transaction(&request)
        .expect_err("last_valid before first_valid must be rejected");
    assert_eq!(
        err.downcast_ref::<sidewinder_ops::SidewinderError>()
            .expect("a SidewinderError")
            .kind,
        SidewinderErrorKind::InvalidTransaction
    );
}

#[test]
fn a_keyless_handle_cannot_build() {
    // client_for builds an indexer-only handle with no signing key.
    let client = client_for(OFFLINE_URL);
    let err = client
        .build_signed_transaction(&slot_set_request())
        .expect_err("a keyless handle cannot sign");
    assert_eq!(
        err.downcast_ref::<sidewinder_ops::SidewinderError>()
            .expect("a SidewinderError")
            .kind,
        SidewinderErrorKind::InvalidTransaction
    );
}

#[test]
fn submit_transaction_posts_the_signed_bytes_and_returns_the_node_txid() {
    let node = MockNode::start(vec![Route::ok_json(
        "POST",
        "/v2/transactions",
        r#"{"txId":"NODE-TXID"}"#,
    )]);
    let client = signing_client_for(&node.base_url());
    let request = slot_set_request();

    // The bytes the one-shot submit should post are exactly what build produces.
    let expected = client
        .build_signed_transaction(&request)
        .expect("build for comparison");

    let txid = client.submit_transaction(&request).expect("submit");
    assert_eq!(
        txid, "NODE-TXID",
        "returns the node's identifier, not the local one"
    );

    let req = node.last_request().expect("a request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/v2/transactions");
    assert_eq!(
        req.authorization(),
        Some(format!("Bearer {TEST_TOKEN}").as_str())
    );
    assert_eq!(req.header("content-type"), Some("application/msgpack"));
    assert_eq!(req.body, expected.bytes);
}
