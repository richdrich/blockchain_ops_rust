//! Localnet integration test for the incremental cached transaction scanner
//! (`AlgoOps::fetch_transactions_cached`) against a real indexer.
//!
//! Submits two note-bearing self-payments sharing a fresh tag prefix but landing in different rounds
//! (built and signed with the SDK, broadcast via `AlgoOps::submit_signed`, as the other localnet
//! tests do). A single caller-owned `TxnScanCache` is refreshed repeatedly: after the first anchor is
//! captured the second refresh fetches only rounds past the watermark, so the first anchor is *not*
//! re-read — proven here by asserting it appears exactly once (an incremental scan cannot duplicate
//! it; a whole-history re-read would). The watermark advancing past the first anchor's round is the
//! observable signal that the min-round floor was applied.
//! In the `integration` target; run with `cargo test --test integration`.

use crate::support::{setup_localnet, test_util};
use algo_ops::{AlgoOps, QueryMode, ScannedTxn, TxnScanCache, TxnScanFilter};
use algonaut::core::{MicroAlgos, ToMsgPack};
use algonaut::transaction::Pay;
use algonaut::transaction::account::Account;
use std::sync::Mutex;
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

fn spend_ops() -> AlgoOps {
    let cfg = test_util::localnet_config();
    setup_localnet::ensure_localnet_accounts_funded(&cfg, &[test_util::ADDRESS_SPEND]).expect(
        "Failed to ensure localnet test accounts funded; install algokit and start localnet",
    );
    test_util::ops_from_mnemonic(test_util::ADDRESS_SPEND, test_util::PASSPHRASE_SPEND, cfg)
}

// Refresh the cache incrementally (lifetime `None`, so every call fetches past the watermark) until
// it holds at least `want` entries or ~20 s elapses. Returns the entry count actually reached.
fn poll_until(
    ops: &AlgoOps,
    cache: &Mutex<TxnScanCache<ScannedTxn>>,
    tag: &[u8],
    want: usize,
) -> usize {
    let tag = tag.to_vec();
    for _ in 0..40 {
        ops.fetch_transactions_cached(
            cache,
            TxnScanFilter {
                note_prefix: Some(tag.clone()),
                ..Default::default()
            },
            QueryMode::Refresh,
            None,
            // Defensive client-side re-check of the server-side prefix filter.
            |t| matches!(&t.note, Some(n) if n.starts_with(&tag)).then(|| t.clone()),
        )
        .expect("fetch_transactions_cached should not error");
        let len = cache.lock().unwrap().entries.len();
        if len >= want {
            return len;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    cache.lock().unwrap().entries.len()
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn second_refresh_fetches_only_new_rounds_without_re_reading() {
    test_util::assert_localnet_available();
    let ops = spend_ops();

    // A fresh tag each run so only this test's two anchors share the prefix.
    let tag = AlgoOps::unique_note();
    let mut note_a = tag.clone();
    note_a.extend_from_slice(b"-a");
    let mut note_b = tag.clone();
    note_b.extend_from_slice(b"-b");

    let cache = Mutex::new(TxnScanCache::<ScannedTxn>::new());

    // First anchor: bootstrap the cache (full scan) and poll until the indexer surfaces it.
    submit_note_txn(&ops, &note_a);
    let after_a = poll_until(&ops, &cache, &tag, 1);
    assert!(
        after_a >= 1,
        "the first anchor should be indexed and captured within the timeout"
    );
    let watermark_after_a = cache.lock().unwrap().last_round;
    assert!(
        watermark_after_a > 0,
        "the first scan must stamp a non-zero watermark"
    );

    // Second anchor lands in a later round; incremental refreshes should pick it up.
    submit_note_txn(&ops, &note_b);
    let after_b = poll_until(&ops, &cache, &tag, 2);
    assert!(
        after_b >= 2,
        "the second anchor should be captured by an incremental refresh"
    );

    let cache = cache.lock().unwrap();
    let notes: Vec<Vec<u8>> = cache
        .entries
        .iter()
        .filter_map(|t| t.note.clone())
        .collect();

    // Both anchors are present.
    assert!(notes.contains(&note_a), "the first anchor must be cached");
    assert!(notes.contains(&note_b), "the second anchor must be cached");

    // The decisive assertion: the first anchor appears exactly once. An incremental scan (min_round
    // past the watermark) cannot re-read its round; a whole-history re-read would have duplicated it.
    let a_count = notes.iter().filter(|n| **n == note_a).count();
    assert_eq!(
        a_count, 1,
        "the first anchor must not be re-read by the incremental refresh (found {a_count} copies)"
    );

    // The watermark advanced past the first anchor's round to cover the second — evidence the
    // min-round floor moved forward rather than rescanning from zero.
    assert!(
        cache.last_round >= watermark_after_a,
        "the watermark must advance (was {watermark_after_a}, now {})",
        cache.last_round
    );
    assert!(
        cache.entries.iter().all(|t| t.confirmed_round > 0),
        "every cached transaction must be confirmed"
    );
}
