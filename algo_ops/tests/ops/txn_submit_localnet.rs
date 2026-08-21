//! Localnet integration test for the transaction submit + confirmation-read
//! primitives (`submit_signed`, `confirmed_transaction`).
//!
//! Mirrors the consumer flow: build and sign a note-bearing payment with the SDK
//! directly (as `sw-chain` does), submit the raw bytes via `AlgoOps::submit_signed`,
//! then read the confirmed round and note back with `AlgoOps::confirmed_transaction`.
//! In the `integration` target; run with `cargo test --test integration`.

use crate::support::{setup_localnet, test_util};
use algonaut::core::{MicroAlgos, ToMsgPack};
use algonaut::transaction::Pay;
use algonaut::transaction::account::Account;

#[test]
#[cfg(not(target_os = "ios"))]
pub fn submit_signed_then_read_confirmed_note_and_round() {
    test_util::assert_localnet_available();
    let cfg = test_util::localnet_config();
    setup_localnet::ensure_localnet_accounts_funded(&cfg, &[test_util::ADDRESS_SPEND]).expect(
        "Failed to ensure localnet test accounts funded; install algokit and start localnet",
    );

    let ops = test_util::ops_from_mnemonic(
        test_util::ADDRESS_SPEND,
        test_util::PASSPHRASE_SPEND,
        cfg.clone(),
    );

    // Consumer side: build and sign a note-bearing self-payment with the SDK.
    let sk = ops.private_key_bytes().expect("account secret key");
    let seed: [u8; 32] = sk.as_slice().try_into().expect("32-byte seed");
    let account = Account::from_seed(seed);
    let addr = account.address();

    // Fetch params through the crate's own algod bridge (retry + blocking).
    let client = ops.algod_client().expect("algod client");
    let params = ops
        .algod_call(|| client.suggested_params())
        .expect("suggested params from localnet");

    let note = b"issue-33-submit-signed".to_vec();
    let tx = Pay::new(addr, addr, MicroAlgos(1_000))
        .note(note.clone())
        .build(&params)
        .expect("build payment");
    let signed = account
        .sign(tx)
        .expect("sign payment")
        .to_msg_pack()
        .expect("encode signed payment");

    // algo_ops side: submit the raw bytes and read the confirmation back.
    let txid = ops
        .submit_signed(&signed)
        .expect("submit_signed should broadcast");
    assert!(!txid.is_empty(), "submit_signed should return a txid");

    ops.wait_for_confirmation(&txid, 10)
        .expect("transaction should confirm on localnet");

    let confirmed = ops
        .confirmed_transaction(&txid)
        .expect("confirmed_transaction should succeed")
        .expect("a confirmed transaction should be known to the node");
    assert!(
        confirmed.confirmed_round > 0,
        "expected a non-zero confirmed round, got {}",
        confirmed.confirmed_round
    );
    assert_eq!(
        confirmed.note.as_deref(),
        Some(note.as_slice()),
        "the confirmed transaction should carry the submitted note"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn confirmed_transaction_unknown_txid_is_none() {
    test_util::assert_localnet_available();
    let ops = test_util::ops_from_mnemonic(
        test_util::ADDRESS_SPEND,
        test_util::PASSPHRASE_SPEND,
        test_util::localnet_config(),
    );

    // A well-formed but unknown txid: the node has no such pending transaction.
    let unknown = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let result = ops
        .confirmed_transaction(unknown)
        .expect("confirmed_transaction should not error for an unknown txid");
    assert!(
        result.is_none(),
        "expected None for a txid the node does not know"
    );
}
