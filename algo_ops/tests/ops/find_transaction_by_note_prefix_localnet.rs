//! Localnet integration tests for the indexer byte-prefix note searches — both the single-match
//! `AlgoOps::find_transaction_by_note_prefix` and the list `AlgoOps::find_transactions_by_note_prefix`.
//!
//! Submits note-bearing self-payments (built and signed with the SDK, broadcast via
//! `AlgoOps::submit_signed`, as `txn_submit_localnet` does) and looks them up by note *prefix* through
//! the indexer. Covers, for the single-match method, a prefix match on a longer note, an absent
//! prefix, and equivalence with the exact method when the searched prefix is the complete note; and
//! for the list method, that two notes sharing a prefix are both returned (and an unrelated note is
//! not), and that an unmatched prefix yields an empty vec.
//! In the `integration` target; run with `cargo test --test integration`.

use crate::support::{setup_localnet, test_util};
use algo_ops::{AlgoOps, ConfirmedTxn};
use algonaut::core::{MicroAlgos, ToMsgPack};
use algonaut::transaction::Pay;
use algonaut::transaction::account::Account;
use std::time::Duration;

// Build, sign, and submit a note-bearing self-payment, then wait for algod to confirm it.
fn submit_note_txn(ops: &AlgoOps, note: &[u8]) {
    let sk = ops.private_key_bytes().expect("account secret key");
    let seed: [u8; 32] = sk.as_slice().try_into().expect("32-byte seed");
    let account = Account::from_seed(seed);
    let addr = account.address();

    let client = ops.algod_client().expect("algod client");
    let params = ops
        .algod_call(|| client.suggested_params())
        .expect("suggested params from localnet");

    let tx = Pay::new(addr, addr, MicroAlgos(1_000))
        .note(note.to_vec())
        .build(&params)
        .expect("build payment");
    let signed = account
        .sign(tx)
        .expect("sign payment")
        .to_msg_pack()
        .expect("encode signed payment");

    let txid = ops
        .submit_signed(&signed)
        .expect("submit_signed should broadcast");
    ops.wait_for_confirmation(&txid, 10)
        .expect("transaction should confirm on localnet");
}

// The indexer trails algod, so poll `find_transaction_by_note_prefix` until the just-confirmed
// transaction has been indexed (or give up after ~20 s).
fn find_indexed_prefix(ops: &AlgoOps, prefix: &[u8]) -> Option<ConfirmedTxn> {
    for _ in 0..40 {
        let hit = ops
            .find_transaction_by_note_prefix(prefix)
            .expect("find_transaction_by_note_prefix should not error");
        if hit.is_some() {
            return hit;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    None
}

fn spend_ops() -> AlgoOps {
    let cfg = test_util::localnet_config();
    setup_localnet::ensure_localnet_accounts_funded(&cfg, &[test_util::ADDRESS_SPEND]).expect(
        "Failed to ensure localnet test accounts funded; install algokit and start localnet",
    );
    test_util::ops_from_mnemonic(test_util::ADDRESS_SPEND, test_util::PASSPHRASE_SPEND, cfg)
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn find_transaction_by_note_prefix_matches_longer_note() {
    test_util::assert_localnet_available();
    let ops = spend_ops();

    // A note laid out as `prefix ‖ suffix`, so `prefix` is a strict byte prefix of an on-chain note
    // that equals no note exactly. A fresh prefix each run avoids colliding with accumulated history.
    let prefix = AlgoOps::unique_note();
    let mut full = prefix.clone();
    full.extend_from_slice(b"-suffix");
    submit_note_txn(&ops, &full);

    let found = find_indexed_prefix(&ops, &prefix)
        .expect("the note prefix should be findable once the indexer catches up");
    assert!(
        found.confirmed_round > 0,
        "expected a non-zero confirmed round, got {}",
        found.confirmed_round
    );
    assert_eq!(
        found.note.as_deref(),
        Some(full.as_slice()),
        "the located transaction should carry the full note whose leading bytes are the prefix"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn find_transaction_by_note_prefix_absent_prefix_is_none() {
    test_util::assert_localnet_available();
    let ops = spend_ops();

    // A fresh prefix that is never submitted: no transaction's note can start with it.
    let prefix = AlgoOps::unique_note();
    let result = ops
        .find_transaction_by_note_prefix(&prefix)
        .expect("find_transaction_by_note_prefix should not error for an absent prefix");
    assert!(
        result.is_none(),
        "expected None for a prefix no transaction's note starts with"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn find_transaction_by_note_prefix_full_note_equivalence() {
    test_util::assert_localnet_available();
    let ops = spend_ops();

    // When the searched prefix is the complete note, the prefix search must still find it — matching
    // what the exact-match `find_transaction_by_note` would return for a complete note.
    let note = AlgoOps::unique_note();
    submit_note_txn(&ops, &note);

    let found = find_indexed_prefix(&ops, &note)
        .expect("a full-note prefix search should find the confirmed transaction");
    assert_eq!(
        found.note.as_deref(),
        Some(note.as_slice()),
        "a full-note prefix search should locate exactly the submitted note"
    );

    let exact = ops
        .find_transaction_by_note(&note)
        .expect("find_transaction_by_note should not error");
    assert_eq!(
        exact.map(|c| c.note),
        Some(found.note),
        "prefix and exact searches must agree when the prefix is the whole note"
    );
}

// The indexer trails algod, so poll the list method until at least `want` matches for `prefix` have
// been indexed (or give up after ~20 s).
fn find_indexed_prefix_all(ops: &AlgoOps, prefix: &[u8], want: usize) -> Vec<ConfirmedTxn> {
    for _ in 0..40 {
        let hits = ops
            .find_transactions_by_note_prefix(prefix)
            .expect("find_transactions_by_note_prefix should not error");
        if hits.len() >= want {
            return hits;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("the indexer did not surface {want} matches for the prefix within the timeout");
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn find_transactions_by_note_prefix_returns_every_match() {
    test_util::assert_localnet_available();
    let ops = spend_ops();

    // Two notes that share a fresh prefix (`prefix ‖ a`, `prefix ‖ b`), plus one that does not. A
    // fresh prefix each run avoids colliding with accumulated history, so exactly these two match.
    let prefix = AlgoOps::unique_note();
    let mut note_a = prefix.clone();
    note_a.extend_from_slice(b"-a");
    let mut note_b = prefix.clone();
    note_b.extend_from_slice(b"-b");
    let unrelated = AlgoOps::unique_note();

    submit_note_txn(&ops, &note_a);
    submit_note_txn(&ops, &note_b);
    submit_note_txn(&ops, &unrelated);

    let hits = find_indexed_prefix_all(&ops, &prefix, 2);
    let notes: std::collections::HashSet<Vec<u8>> =
        hits.iter().filter_map(|c| c.note.clone()).collect();
    assert!(
        notes.contains(&note_a),
        "the prefix list should include the first matching note"
    );
    assert!(
        notes.contains(&note_b),
        "the prefix list should include the second matching note"
    );
    assert!(
        !notes.contains(&unrelated),
        "the prefix list must not include a note that does not share the prefix"
    );
    assert!(
        hits.iter().all(|c| c.confirmed_round > 0),
        "every returned transaction must be confirmed"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn find_transactions_by_note_prefix_absent_prefix_is_empty() {
    test_util::assert_localnet_available();
    let ops = spend_ops();

    // A fresh prefix that is never submitted: no transaction's note can start with it.
    let prefix = AlgoOps::unique_note();
    let hits = ops
        .find_transactions_by_note_prefix(&prefix)
        .expect("find_transactions_by_note_prefix should not error for an absent prefix");
    assert!(
        hits.is_empty(),
        "expected an empty vec for a prefix no transaction's note starts with"
    );
}
