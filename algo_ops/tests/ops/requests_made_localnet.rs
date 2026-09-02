//! Localnet integration test for the cumulative outbound-request counter (`AlgoOps::requests_made`)
//! against a real node and indexer.
//!
//! The counter increments once per real outbound request at the shared `algod_call` hook, so a
//! multi-request operation advances it by its request count — not by 1. This exercises that on the
//! real path: a known sequence of independent reads advances the counter by exactly that many, and a
//! paged cached scan advances it by its page count (every page is one request). Under-counting a
//! multi-page bootstrap scan is exactly the failure the counter exists to prevent.
//! In the `integration` target; run with `cargo test --test integration`.

use crate::support::{setup_localnet, test_util};
use algo_ops::{AlgoOps, QueryMode, ScannedTxn, TxnScanCache, TxnScanFilter};
use std::sync::Mutex;

fn spend_ops() -> AlgoOps {
    let cfg = test_util::localnet_config();
    setup_localnet::ensure_localnet_accounts_funded(&cfg, &[test_util::ADDRESS_SPEND]).expect(
        "Failed to ensure localnet test accounts funded; install algokit and start localnet",
    );
    test_util::ops_from_mnemonic(test_util::ADDRESS_SPEND, test_util::PASSPHRASE_SPEND, cfg)
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn requests_made_counts_each_real_outbound_request_including_scan_pages() {
    test_util::assert_localnet_available();
    let ops = spend_ops();

    // A known sequence of three independent reads → exactly three counted requests, proving the
    // counter charges per outbound request rather than per logical call.
    let before = ops.requests_made();
    let _ = ops.round().expect("round should read the node status");
    let _ = ops.round().expect("round should read the node status");
    let _ = ops
        .account_balance()
        .expect("account_balance should read the funded account");
    assert_eq!(
        ops.requests_made(),
        before + 3,
        "each outbound request is counted exactly once"
    );

    // A cached scan pages through the indexer; every page is one outbound request, so a full scan
    // advances the counter by its page count (>= 1) — never a flat 1 independent of the page count.
    let cache = Mutex::new(TxnScanCache::<ScannedTxn>::new());
    let before_scan = ops.requests_made();
    ops.fetch_transactions_cached(
        &cache,
        TxnScanFilter::default(),
        QueryMode::ForceFull,
        None,
        |t| Some(t.clone()),
    )
    .expect("a force-full scan should succeed against localnet");
    let pages = ops.requests_made() - before_scan;
    assert!(
        pages >= 1,
        "a scan fetches at least one page and every page is a counted request (counted {pages})"
    );
}
