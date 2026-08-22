//! Localnet integration test for `AlgoOps::find_transaction_by_note` (indexer note-prefix search).
//!
//! Submits note-bearing self-payments (built and signed with the SDK, broadcast via
//! `AlgoOps::submit_signed`, as `txn_submit_localnet` does) and then looks them up by note through
//! the indexer. Covers an exact match, an absent note, and the exact-match guard that rejects a
//! transaction whose note merely starts with the searched bytes.
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

// The indexer trails algod, so poll `find_transaction_by_note` until the just-confirmed
// transaction has been indexed (or give up after ~20 s).
fn find_indexed(ops: &AlgoOps, note: &[u8]) -> Option<ConfirmedTxn> {
    for _ in 0..40 {
        let hit = ops
            .find_transaction_by_note(note)
            .expect("find_transaction_by_note should not error");
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
pub fn find_transaction_by_note_matches_confirmed_note() {
    test_util::assert_localnet_available();
    let ops = spend_ops();

    // A fresh note each run, so a persistent localnet's accumulated history cannot collide.
    let note = AlgoOps::unique_note();
    submit_note_txn(&ops, &note);

    let found = find_indexed(&ops, &note)
        .expect("the submitted note should be findable once the indexer catches up");
    assert!(
        found.confirmed_round > 0,
        "expected a non-zero confirmed round, got {}",
        found.confirmed_round
    );
    assert_eq!(
        found.note.as_deref(),
        Some(note.as_slice()),
        "the located transaction should carry exactly the submitted note"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn find_transaction_by_note_absent_note_is_none() {
    test_util::assert_localnet_available();
    let ops = spend_ops();

    // A fresh note that is never submitted: no transaction can carry it.
    let note = AlgoOps::unique_note();
    let result = ops
        .find_transaction_by_note(&note)
        .expect("find_transaction_by_note should not error for an absent note");
    assert!(
        result.is_none(),
        "expected None for a note no transaction carries"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn find_transaction_by_note_rejects_prefix_only_match() {
    test_util::assert_localnet_available();
    let ops = spend_ops();

    // Submit a transaction whose note is `base` followed by extra bytes, so `base` is a strict
    // prefix of an on-chain note but equals no note exactly.
    let base = AlgoOps::unique_note();
    let mut full = base.clone();
    full.extend_from_slice(b"-suffix");
    submit_note_txn(&ops, &full);

    // Confirm the full note is indexed first, so a `None` for `base` cannot be indexer lag.
    find_indexed(&ops, &full)
        .expect("the full note should be findable once the indexer catches up");

    let prefix_hit = ops
        .find_transaction_by_note(&base)
        .expect("find_transaction_by_note should not error");
    assert!(
        prefix_hit.is_none(),
        "a transaction whose note only starts with the searched bytes must not match"
    );
}
