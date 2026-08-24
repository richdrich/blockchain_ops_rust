//! Localnet integration tests for the sender-authenticated note searches —
//! `AlgoOps::find_transaction_by_note_and_sender`, `find_transaction_by_note_prefix_and_sender`, and
//! `find_transactions_by_note_prefix_and_sender`.
//!
//! Two different funded accounts submit note-bearing self-payments that share a note prefix, so a
//! plain prefix search would return both; the sender-scoped searches must return only the transaction
//! signed by the requested account. This is the authentication a caller (e.g. sidewinder, counting
//! only anchors from its enrolled node accounts) relies on: a note a third party wrote with the same
//! bytes is not attributed to a known signer.
//! In the `integration` target; run with `cargo test --test integration`.

use crate::support::{setup_localnet, test_util};
use algo_ops::{AlgoOps, ConfirmedTxn};
use algonaut::core::{MicroAlgos, ToMsgPack};
use algonaut::transaction::Pay;
use algonaut::transaction::account::Account;
use std::collections::HashSet;
use std::time::Duration;

// Build, sign, and submit a note-bearing self-payment from `ops`'s own account, then wait for algod
// to confirm it.
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

// Two funded accounts, each with its own `AlgoOps` handle, to act as distinct signers.
fn two_senders() -> (AlgoOps, AlgoOps) {
    let cfg = test_util::localnet_config();
    setup_localnet::ensure_localnet_accounts_funded(
        &cfg,
        &[test_util::ADDRESS_SPEND, test_util::ADDRESS_RECEIVE],
    )
    .expect("Failed to ensure localnet test accounts funded; install algokit and start localnet");
    let alice = test_util::ops_from_mnemonic(
        test_util::ADDRESS_SPEND,
        test_util::PASSPHRASE_SPEND,
        test_util::localnet_config(),
    );
    let bob = test_util::ops_from_mnemonic(
        test_util::ADDRESS_RECEIVE,
        test_util::PASSPHRASE_RECEIVE,
        test_util::localnet_config(),
    );
    (alice, bob)
}

// The indexer trails algod: poll the sender-scoped list until at least `want` matches are indexed.
fn indexed_prefix_and_sender(
    ops: &AlgoOps,
    prefix: &[u8],
    sender: &str,
    want: usize,
) -> Vec<ConfirmedTxn> {
    for _ in 0..40 {
        let hits = ops
            .find_transactions_by_note_prefix_and_sender(prefix, sender)
            .expect("find_transactions_by_note_prefix_and_sender should not error");
        if hits.len() >= want {
            return hits;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("the indexer did not surface {want} matches for the prefix+sender within the timeout");
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn note_prefix_and_sender_restricts_to_the_signer() {
    test_util::assert_localnet_available();
    let (alice, bob) = two_senders();

    // Both accounts send a note sharing a fresh prefix (`prefix ‖ -alice`, `prefix ‖ -bob`), so a
    // plain prefix search would return both; only the sender filter tells them apart.
    let prefix = AlgoOps::unique_note();
    let mut note_a = prefix.clone();
    note_a.extend_from_slice(b"-alice");
    let mut note_b = prefix.clone();
    note_b.extend_from_slice(b"-bob");
    submit_note_txn(&alice, &note_a);
    submit_note_txn(&bob, &note_b);

    // scoped to Alice: her note only — Bob's shared-prefix note is excluded by the sender filter.
    let a_hits = indexed_prefix_and_sender(&alice, &prefix, test_util::ADDRESS_SPEND, 1);
    let a_notes: HashSet<Vec<u8>> = a_hits.iter().filter_map(|c| c.note.clone()).collect();
    assert!(a_notes.contains(&note_a), "Alice's own note is returned");
    assert!(
        !a_notes.contains(&note_b),
        "Bob's shared-prefix note is NOT returned under Alice's sender filter"
    );
    assert!(
        a_hits.iter().all(|c| c.confirmed_round > 0),
        "every returned transaction is confirmed"
    );

    // the single-hit sender-scoped prefix search finds Bob's note when scoped to Bob.
    let mut b_hit = None;
    for _ in 0..40 {
        b_hit = bob
            .find_transaction_by_note_prefix_and_sender(&prefix, test_util::ADDRESS_RECEIVE)
            .expect("find_transaction_by_note_prefix_and_sender should not error");
        if b_hit.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(
        b_hit.and_then(|c| c.note).as_deref(),
        Some(note_b.as_slice()),
        "scoped to Bob, the prefix search returns Bob's note"
    );

    // a sender that never anchored this prefix yields nothing.
    let empty = alice
        .find_transactions_by_note_prefix_and_sender(&prefix, test_util::ADDRESS_10MIL)
        .expect("find_transactions_by_note_prefix_and_sender should not error");
    assert!(
        empty.is_empty(),
        "a sender that did not submit a note with this prefix returns an empty vec"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn note_and_sender_authenticates_the_exact_note() {
    test_util::assert_localnet_available();
    let (alice, bob) = two_senders();

    // Alice submits a note; the exact note search must attribute it to Alice and NOT to Bob.
    let note = AlgoOps::unique_note();
    submit_note_txn(&alice, &note);

    let mut found = None;
    for _ in 0..40 {
        found = alice
            .find_transaction_by_note_and_sender(&note, test_util::ADDRESS_SPEND)
            .expect("find_transaction_by_note_and_sender should not error");
        if found.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(
        found.and_then(|c| c.note).as_deref(),
        Some(note.as_slice()),
        "the exact note is found when scoped to its actual signer"
    );

    // scoped to the wrong signer, the same exact note is not found — the authentication check.
    let wrong = bob
        .find_transaction_by_note_and_sender(&note, test_util::ADDRESS_RECEIVE)
        .expect("find_transaction_by_note_and_sender should not error");
    assert!(
        wrong.is_none(),
        "the note is not attributed to a signer that did not send it"
    );
}
