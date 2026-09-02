//! Unit tests for the incremental cached transaction scanner engine
//! (`AlgoOps::fetch_transactions_cached_with`). The engine takes the page fetch as an injected
//! closure and the wall-clock as `now`, so these exercise the caching / freshness / watermark logic
//! deterministically with a stubbed, request-counting indexer — no node, no time, no network. The
//! matching behaviour against a real indexer lives in the `integration` bucket
//! (`fetch_transactions_cached_localnet.rs`). The engine is exposed only under the `test-support`
//! feature (enabled for this crate's own test build).

use algo_ops::{AlgoOps, QueryMode, ScannedTxn, TxnScanCache, TxnScanPage};
use anyhow::Result;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Mutex;

// A stubbed indexer: it hands back a scripted queue of pages (one per `fetch` call, in order — a
// paginated scan simply pops several) and records the `(min_round, next_token)` of every call so a
// test can assert the min-round watermark was honoured and count requests.
struct StubIndexer {
    pages: RefCell<VecDeque<TxnScanPage>>,
    calls: RefCell<Vec<(Option<u64>, Option<String>)>>,
}

impl StubIndexer {
    fn new(pages: Vec<TxnScanPage>) -> Self {
        StubIndexer {
            pages: RefCell::new(pages.into()),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn fetch(&self, min_round: Option<u64>, next: Option<&str>) -> Result<TxnScanPage> {
        self.calls
            .borrow_mut()
            .push((min_round, next.map(str::to_string)));
        Ok(self
            .pages
            .borrow_mut()
            .pop_front()
            .expect("stub indexer ran out of scripted pages — engine fetched more than expected"))
    }

    fn calls(&self) -> Vec<(Option<u64>, Option<String>)> {
        self.calls.borrow().clone()
    }
}

fn txn(round: u64, sender: &str, note: &[u8]) -> ScannedTxn {
    ScannedTxn {
        confirmed_round: round,
        sender: sender.to_string(),
        note: Some(note.to_vec()),
    }
}

fn page(txns: Vec<ScannedTxn>, next: Option<&str>, current_round: u64) -> TxnScanPage {
    TxnScanPage {
        txns,
        next_token: next.map(str::to_string),
        current_round,
    }
}

// `ingest` that keeps every transaction as-is — the default for tests that only care about the
// fetch/cache mechanics.
fn keep_all(t: &ScannedTxn) -> Option<ScannedTxn> {
    Some(t.clone())
}

#[test]
fn full_scan_bootstrap_populates_empty_cache() {
    let cache = Mutex::new(TxnScanCache::<ScannedTxn>::new());
    let stub = StubIndexer::new(vec![page(
        vec![txn(5, "A", b"n1"), txn(7, "B", b"n2")],
        None,
        8,
    )]);

    AlgoOps::fetch_transactions_cached_with(
        &cache,
        QueryMode::Refresh,
        Some(60),
        1_000,
        keep_all,
        |min_round, next| stub.fetch(min_round, next),
    )
    .expect("bootstrap scan should succeed");

    // A never-scanned cache does a full scan: exactly one page fetched with no min-round floor.
    assert_eq!(stub.calls(), vec![(None, None)]);
    let cache = cache.lock().unwrap();
    assert_eq!(cache.entries.len(), 2);
    // The watermark advances to the indexer's current-round, stamped fresh.
    assert_eq!(cache.last_round, 8);
    assert_eq!(cache.last_updated, 1_000);
}

#[test]
fn incremental_refresh_fetches_only_past_the_watermark() {
    // A cache already scanned through round 10 (holding one entry from an earlier scan).
    let cache = Mutex::new(TxnScanCache {
        last_round: 10,
        last_updated: 100,
        entries: vec![txn(3, "A", b"old")],
    });
    let stub = StubIndexer::new(vec![page(vec![txn(12, "B", b"new")], None, 13)]);

    // No freshness window → the refresh always fetches incrementally.
    AlgoOps::fetch_transactions_cached_with(
        &cache,
        QueryMode::Refresh,
        None,
        1_000,
        keep_all,
        |min_round, next| stub.fetch(min_round, next),
    )
    .expect("incremental refresh should succeed");

    // The incremental fetch starts strictly past the watermark (10 → min_round 11), never re-reading
    // history.
    assert_eq!(stub.calls(), vec![(Some(11), None)]);
    let cache = cache.lock().unwrap();
    // Append-only: the pre-existing entry is kept, the new one appended after it.
    assert_eq!(
        cache.entries,
        vec![txn(3, "A", b"old"), txn(12, "B", b"new")]
    );
    assert_eq!(cache.last_round, 13);
    assert_eq!(cache.last_updated, 1_000);
}

#[test]
fn fresh_refresh_degrades_to_cache_only_with_no_network() {
    // Scanned 5 seconds ago, and the lifetime is 60 s, so the cache is fresh.
    let cache = Mutex::new(TxnScanCache {
        last_round: 10,
        last_updated: 995,
        entries: vec![txn(3, "A", b"cached")],
    });
    // No scripted pages: the stub panics if the engine fetches at all.
    let stub = StubIndexer::new(vec![]);

    AlgoOps::fetch_transactions_cached_with(
        &cache,
        QueryMode::Refresh,
        Some(60),
        1_000,
        keep_all,
        |min_round, next| stub.fetch(min_round, next),
    )
    .expect("a fresh refresh should succeed without fetching");

    // Zero network, and the cache is left exactly as it was.
    assert!(stub.calls().is_empty(), "a fresh refresh must not fetch");
    let cache = cache.lock().unwrap();
    assert_eq!(cache.entries, vec![txn(3, "A", b"cached")]);
    assert_eq!(cache.last_round, 10);
    assert_eq!(cache.last_updated, 995);
}

#[test]
fn cache_only_never_fetches_even_when_stale() {
    // Old stamp and a tiny lifetime — the cache is stale, but CacheOnly still never fetches.
    let cache = Mutex::new(TxnScanCache {
        last_round: 10,
        last_updated: 100,
        entries: vec![txn(3, "A", b"cached")],
    });
    let stub = StubIndexer::new(vec![]);

    AlgoOps::fetch_transactions_cached_with(
        &cache,
        QueryMode::CacheOnly,
        Some(1),
        1_000,
        keep_all,
        |min_round, next| stub.fetch(min_round, next),
    )
    .expect("CacheOnly should succeed without fetching");

    assert!(stub.calls().is_empty(), "CacheOnly must never fetch");
    let cache = cache.lock().unwrap();
    assert_eq!(cache.entries, vec![txn(3, "A", b"cached")]);
    assert_eq!(cache.last_round, 10);
    assert_eq!(cache.last_updated, 100);
}

#[test]
fn force_full_discards_the_cache_and_rebuilds() {
    // A populated cache scanned through round 50.
    let cache = Mutex::new(TxnScanCache {
        last_round: 50,
        last_updated: 100,
        entries: vec![txn(1, "A", b"old1"), txn(2, "B", b"old2")],
    });
    let stub = StubIndexer::new(vec![page(
        vec![txn(2, "A", b"a"), txn(4, "B", b"b")],
        None,
        5,
    )]);

    AlgoOps::fetch_transactions_cached_with(
        &cache,
        QueryMode::ForceFull,
        Some(60),
        1_000,
        keep_all,
        |min_round, next| stub.fetch(min_round, next),
    )
    .expect("ForceFull should succeed");

    // Rebuilt from round 0 (no min-round floor), discarding the old entries.
    assert_eq!(stub.calls(), vec![(None, None)]);
    let cache = cache.lock().unwrap();
    assert_eq!(cache.entries, vec![txn(2, "A", b"a"), txn(4, "B", b"b")]);
    assert_eq!(cache.last_round, 5);
    assert_eq!(cache.last_updated, 1_000);
}

#[test]
fn paginated_scan_follows_next_token_and_watermarks_the_max_round() {
    let cache = Mutex::new(TxnScanCache::<ScannedTxn>::new());
    let stub = StubIndexer::new(vec![
        page(vec![txn(5, "A", b"n1")], Some("page2"), 20),
        page(vec![txn(9, "B", b"n2")], None, 22),
    ]);

    AlgoOps::fetch_transactions_cached_with(
        &cache,
        QueryMode::Refresh,
        Some(60),
        1_000,
        keep_all,
        |min_round, next| stub.fetch(min_round, next),
    )
    .expect("paginated scan should succeed");

    // Two pages: the second call carries the first page's next token; both are a full scan (no floor).
    assert_eq!(
        stub.calls(),
        vec![(None, None), (None, Some("page2".to_string()))]
    );
    let cache = cache.lock().unwrap();
    assert_eq!(cache.entries.len(), 2);
    // The watermark is the greatest current-round across the pages.
    assert_eq!(cache.last_round, 22);
}

#[test]
fn incremental_refresh_paginates_from_the_watermark_across_pages() {
    // A multi-page *incremental* refresh (the pagination coverage above is on a full scan). Pins down
    // that every page of an incremental scan carries the same min-round floor and the watermark ends
    // at the greatest current-round across the pages — the resume point for the following refresh.
    let cache = Mutex::new(TxnScanCache {
        last_round: 30,
        last_updated: 100,
        entries: vec![txn(7, "A", b"old")],
    });
    let stub = StubIndexer::new(vec![
        page(vec![txn(33, "B", b"n1")], Some("p2"), 40),
        page(vec![txn(38, "C", b"n2")], Some("p3"), 41),
        page(vec![txn(41, "D", b"n3")], None, 42),
    ]);

    // No freshness window → always incremental.
    AlgoOps::fetch_transactions_cached_with(
        &cache,
        QueryMode::Refresh,
        None,
        1_000,
        keep_all,
        |min_round, next| stub.fetch(min_round, next),
    )
    .expect("multi-page incremental refresh should succeed");

    // Every page fetches from the same floor (watermark 30 → min_round 31); the token threads through.
    assert_eq!(
        stub.calls(),
        vec![
            (Some(31), None),
            (Some(31), Some("p2".to_string())),
            (Some(31), Some("p3".to_string())),
        ]
    );
    let cache = cache.lock().unwrap();
    // Append-only: the pre-existing entry first, then the three new hits in page order.
    assert_eq!(
        cache.entries,
        vec![
            txn(7, "A", b"old"),
            txn(33, "B", b"n1"),
            txn(38, "C", b"n2"),
            txn(41, "D", b"n3"),
        ]
    );
    // The watermark advances to the final page's current-round (the max), so the next refresh resumes
    // at 43 — covering rounds the later pages surfaced while paging.
    assert_eq!(cache.last_round, 42);
}

#[test]
fn ingest_returning_none_skips_the_transaction() {
    let cache = Mutex::new(TxnScanCache::<ScannedTxn>::new());
    let stub = StubIndexer::new(vec![page(
        vec![txn(1, "A", b"keep"), txn(2, "B", b"drop")],
        None,
        3,
    )]);

    AlgoOps::fetch_transactions_cached_with(
        &cache,
        QueryMode::Refresh,
        Some(60),
        1_000,
        // Keep only the transaction whose note is exactly `keep`.
        |t| (t.note.as_deref() == Some(b"keep")).then(|| t.clone()),
        |min_round, next| stub.fetch(min_round, next),
    )
    .expect("scan with a selective ingest should succeed");

    let cache = cache.lock().unwrap();
    assert_eq!(cache.entries, vec![txn(1, "A", b"keep")]);
    // The watermark still advances over the skipped round.
    assert_eq!(cache.last_round, 3);
}

#[test]
fn the_cache_holds_the_refreshed_entries_after_a_fetch() {
    let cache = Mutex::new(TxnScanCache::<ScannedTxn>::new());
    let stub = StubIndexer::new(vec![page(
        vec![txn(5, "A", b"n1"), txn(7, "B", b"n2")],
        None,
        8,
    )]);

    AlgoOps::fetch_transactions_cached_with(
        &cache,
        QueryMode::Refresh,
        Some(60),
        1_000,
        keep_all,
        |min_round, next| stub.fetch(min_round, next),
    )
    .expect("fetch should succeed");

    // The caller reads the refreshed set straight from the cache after the fetch returns.
    assert_eq!(
        cache.lock().unwrap().entries.len(),
        2,
        "the refreshed cache holds the fetched entries"
    );
}

#[test]
fn empty_full_scan_still_stamps_the_watermark_so_next_refresh_is_incremental() {
    // A full scan that matches nothing must still record it scanned (last_updated > 0) and where the
    // chain was (last_round), so a later stale refresh fetches incrementally rather than re-bootstrapping.
    let cache = Mutex::new(TxnScanCache::<ScannedTxn>::new());
    let stub = StubIndexer::new(vec![
        page(vec![], None, 15),
        page(vec![txn(20, "A", b"n")], None, 21),
    ]);

    // First: full scan, matches nothing.
    AlgoOps::fetch_transactions_cached_with(
        &cache,
        QueryMode::Refresh,
        None,
        1_000,
        keep_all,
        |min_round, next| stub.fetch(min_round, next),
    )
    .expect("first scan should succeed");

    // Second: stale refresh should be incremental from the stamped watermark (15 → min_round 16).
    AlgoOps::fetch_transactions_cached_with(
        &cache,
        QueryMode::Refresh,
        None,
        2_000,
        keep_all,
        |min_round, next| stub.fetch(min_round, next),
    )
    .expect("second scan should succeed");

    assert_eq!(stub.calls(), vec![(None, None), (Some(16), None)]);
    let cache = cache.lock().unwrap();
    assert_eq!(cache.entries, vec![txn(20, "A", b"n")]);
    assert_eq!(cache.last_round, 21);
}
