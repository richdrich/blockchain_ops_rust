//! Building, canonical encoding, and signing of a Sidewinder transaction.
//!
//! A client fills in a [`TransactionRequest`] — the operation type, its arguments (as
//! [`algo_ops::AppArg`], the Algorand application-arguments convention), and the validity-window
//! header from [`params`](crate::SidewinderOps::params) — and the client turns it into a
//! [`SignedTransaction`]: the canonical MessagePack bytes to `POST /v2/transactions`, plus the
//! content-address transaction identifier.
//!
//! Operation arguments follow the Algorand application-arguments / Application Binary Interface
//! convention, reusing [`algo_ops::AppArg`]: each argument is packed on its own into one `args`
//! byte string — an [`AppArg::Uint`](algo_ops::AppArg::Uint) as 8 big-endian bytes (an Algorand
//! Request for Comments 4, ARC-4, `uint64`), and [`AppArg::Bytes`](algo_ops::AppArg::Bytes) /
//! [`AppArg::Utf8`](algo_ops::AppArg::Utf8) as their raw bytes. The 2-byte ARC-4 length prefix a
//! `byte[]` carries *inside* a tuple is not added at the top-level argument boundary, where the
//! length is implicit — matching how the node reads an argument back (`op::Args::bytes(i)`). v0
//! reaches neither the tuple layout nor the 16-argument overflow, so neither is modelled here.
//!
//! The wire form matches the `SignedTransaction` / `Transaction` schemas of the reconciled
//! `sidewinder_rest.yaml` contract and, byte for byte, the node's own `sidewinder-core` encoding:
//!
//! - Canonical MessagePack: `rmp_serde` with `.with_struct_map()` — each struct is a map keyed by
//!   its field name, integers in their most-compact form. The remaining canonical rules are carried
//!   by how the body is declared for serde: **fields in ascending key order** (`args`, `fee`, `fv`,
//!   `grp`, `inst`, `lv`, `note`, `snd`, `typ`) so the map encodes deterministically, the two
//!   optional fields (`grp`, `note`) **skipped when absent** so they do not perturb the identifier,
//!   and the 32-byte / byte-string fields tagged [`serde_bytes`] so they serialise as MessagePack
//!   `bin`.
//! - The transaction identifier is the SHA-512/256 hash of the canonical **body** (not the signed
//!   envelope), rendered as lowercase hex — the same string the node returns from `submit`.
//! - The signature is a plain `Ed25519(sender_key, canonical_body_bytes)` with no domain-separation
//!   tag (see [`algo_ops::AlgoOps::sign_bytes`]); the node re-encodes the body and verifies the
//!   signature over those exact bytes.
//!
//! The body carries no `did` (data-identifier) field. The `did` in the documentary `Transaction`
//! schema is obsolete — the node derives the item an operation acts on from its configured key
//! source (for `Slot`, the first argument), not from a caller-named field — and is slated for
//! removal from the schema, so it is not encoded here.

use crate::error::SidewinderError;
use algo_ops::AppArg;
use anyhow::Result;
use rmp_serde::Serializer;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha512_256};

/// The number of bytes an instance identifier, atomic-group identifier, or sender key occupies.
const HASH_BYTES: usize = 32;

/// A transaction to build, canonically encode, and sign.
///
/// The header fields (`instance`, `first_valid`, `last_valid`, `max_fee`) come from
/// [`SuggestedParams`](crate::SuggestedParams); the sender is supplied by the signing key, so it is
/// not part of the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRequest {
    /// The transaction type, which indexes the node's operation configuration and selects the
    /// operation (for example the type bound to `Slot.set`).
    pub txn_type: u32,
    /// The operation's arguments, in order. Each [`AppArg`] is packed into one `args` byte string
    /// (see the module docs); for `Slot.set` these are the slot address and the value.
    pub args: Vec<AppArg>,
    /// The maximum fee the sender authorises for parent-chain settlement
    /// ([`SuggestedParams::min_fee`](crate::SuggestedParams::min_fee) or above).
    pub max_fee: u64,
    /// First valid parent-chain round (typically
    /// [`SuggestedParams::last_round`](crate::SuggestedParams::last_round)).
    pub first_valid: u64,
    /// Last valid parent-chain round. `last_valid - first_valid` must not exceed the node's
    /// [`SuggestedParams::max_validity_window`](crate::SuggestedParams::max_validity_window).
    pub last_valid: u64,
    /// The Sidewinder instance identifier (32 bytes), from
    /// [`SuggestedParams::instance_id`](crate::SuggestedParams::instance_id); pins the transaction
    /// to one instance to prevent cross-instance replay.
    pub instance: Vec<u8>,
    /// Arbitrary sender bytes that also disambiguate otherwise-identical transactions (so a repeated
    /// operation gets a distinct identifier rather than being deduplicated by the mempool).
    pub note: Option<Vec<u8>>,
    /// The atomic-group identifier (32 bytes) for transactions that must commit together.
    pub group: Option<Vec<u8>>,
}

/// A built, signed transaction ready to submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    /// The content-address transaction identifier: lowercase hex of the SHA-512/256 hash of the
    /// canonical body. The same string [`submit`](crate::SidewinderOps::submit) returns, so a caller
    /// can begin polling [`status`](crate::SidewinderOps::status) with it immediately.
    pub tx_id: String,
    /// The canonical MessagePack encoding of the signed transaction, as posted to
    /// `POST /v2/transactions`.
    pub bytes: Vec<u8>,
}

// ── canonical wire structs ───────────────────────────────────────────────────
// Private serde mirrors of `sidewinder-core`'s `TransactionBody` / `PackedSignedTransaction`.
// Field order, `rename`s, and `skip_serializing_if` are load-bearing: they define the canonical
// byte layout (see the module docs). Byte-string fields use `ByteBuf` so they serialise as `bin`,
// matching how the node's `Address` and `Hash` newtypes serialise.

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct TransactionBodyWire {
    #[serde(rename = "args")]
    args: Vec<ByteBuf>,
    #[serde(rename = "fee")]
    fee: u64,
    #[serde(rename = "fv")]
    fv: u64,
    #[serde(rename = "grp", default, skip_serializing_if = "Option::is_none")]
    grp: Option<ByteBuf>,
    #[serde(rename = "inst")]
    inst: ByteBuf,
    #[serde(rename = "lv")]
    lv: u64,
    #[serde(rename = "note", default, skip_serializing_if = "Option::is_none")]
    note: Option<ByteBuf>,
    #[serde(rename = "snd")]
    snd: ByteBuf,
    #[serde(rename = "typ")]
    typ: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct SignedTransactionWire {
    #[serde(rename = "txn")]
    txn: TransactionBodyWire,
    #[serde(rename = "sig")]
    sig: ByteBuf,
}

/// Encode a serde value as canonical MessagePack: a keyed map with the most-compact integer
/// encoding (`with_struct_map`). Sorted keys and omitted empties are carried by the type's layout.
fn to_canonical<T: Serialize>(operation: &str, value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    value
        .serialize(&mut Serializer::new(&mut buf).with_struct_map())
        .map_err(|e| {
            SidewinderError::invalid_transaction(
                operation,
                &format!("canonical encode failed: {e}"),
            )
        })?;
    Ok(buf)
}

/// Lowercase hex of the SHA-512/256 digest of `bytes` — the Sidewinder content address.
fn content_address(bytes: &[u8]) -> String {
    let digest = Sha512_256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Validate that a byte field is exactly 32 bytes, tagging the field on failure.
fn require_hash(operation: &str, field: &str, bytes: &[u8]) -> Result<ByteBuf> {
    if bytes.len() != HASH_BYTES {
        return Err(SidewinderError::invalid_transaction(
            operation,
            &format!("`{field}` must be {HASH_BYTES} bytes, got {}", bytes.len()),
        )
        .into());
    }
    Ok(ByteBuf::from(bytes.to_vec()))
}

/// Build, canonically encode, and sign a transaction.
///
/// `sender` is the 32-byte Ed25519 public key placed in `snd`; `sign` signs the canonical body
/// bytes (the caller wires it to the enrolled key — see [`algo_ops::AlgoOps::sign_bytes`]). The
/// caller must ensure `sender` is the public key `sign` signs with, or the node will reject the
/// signature.
pub(crate) fn build_signed(
    operation: &str,
    request: &TransactionRequest,
    sender: [u8; 32],
    sign: impl FnOnce(&[u8]) -> Result<[u8; 64]>,
) -> Result<SignedTransaction> {
    if request.last_valid < request.first_valid {
        return Err(SidewinderError::invalid_transaction(
            operation,
            &format!(
                "validity window inverted: last_valid {} precedes first_valid {}",
                request.last_valid, request.first_valid
            ),
        )
        .into());
    }

    let grp = match &request.group {
        Some(bytes) => Some(require_hash(operation, "group", bytes)?),
        None => None,
    };

    let body = TransactionBodyWire {
        args: request
            .args
            .iter()
            .map(|arg| ByteBuf::from(arg.to_bytes()))
            .collect(),
        fee: request.max_fee,
        fv: request.first_valid,
        grp,
        inst: require_hash(operation, "instance", &request.instance)?,
        lv: request.last_valid,
        note: request.note.clone().map(ByteBuf::from),
        snd: ByteBuf::from(sender.to_vec()),
        typ: request.txn_type,
    };

    let body_bytes = to_canonical(operation, &body)?;
    let tx_id = content_address(&body_bytes);
    let signature = sign(&body_bytes)?;

    let signed = SignedTransactionWire {
        txn: body,
        sig: ByteBuf::from(signature.to_vec()),
    };
    let bytes = to_canonical(operation, &signed)?;

    Ok(SignedTransaction { tx_id, bytes })
}
