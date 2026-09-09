//! Unit tests for the incremental cached opted-in-account scanner engine
//! (`AlgoOps::fetch_opted_in_accounts_cached_with`). The engine takes its three network operations as
//! injected closures and the wall-clock as `now`, so these exercise the caching / freshness /
//! watermark / revisit logic deterministically with a stubbed, request-counting indexer — no node, no
//! time, no network. Behaviour against a real indexer lives in the `integration` bucket
//! (`fetch_opted_in_accounts_cached_localnet.rs`). The engine is exposed only under the `test-support`
//! feature (enabled for this crate's own test build).

use algo_ops::{
    AccountScanCache, AccountScanPage, AlgoOps, ChangedAddressesPage, QueryMode, ScannedAccount,
};
use anyhow::Result;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

// A stubbed indexer for the three injected operations: it hands back scripted queues of full-scan and
// change-discovery pages (one per call, in order) and a scripted map of per-account re-reads, and
// records every call so a test can assert the min-round watermark was honoured and count requests.
struct StubIndexer {
    full_pages: RefCell<VecDeque<AccountScanPage>>,
    changed_pages: RefCell<VecDeque<ChangedAddressesPage>>,
    lookups: RefCell<HashMap<String, Option<ScannedAccount>>>,
    full_calls: RefCell<Vec<Option<String>>>,
    changed_calls: RefCell<Vec<(u64, Option<String>)>>,
    lookup_calls: RefCell<Vec<String>>,
}

impl StubIndexer {
    fn new(
        full_pages: Vec<AccountScanPage>,
        changed_pages: Vec<ChangedAddressesPage>,
        lookups: Vec<(&str, Option<ScannedAccount>)>,
    ) -> Self {
        StubIndexer {
            full_pages: RefCell::new(full_pages.into()),
            changed_pages: RefCell::new(changed_pages.into()),
            lookups: RefCell::new(
                lookups
                    .into_iter()
                    .map(|(a, r)| (a.to_string(), r))
                    .collect(),
            ),
            full_calls: RefCell::new(Vec::new()),
            changed_calls: RefCell::new(Vec::new()),
            lookup_calls: RefCell::new(Vec::new()),
        }
    }

    fn full_page(&self, next: Option<&str>) -> Result<AccountScanPage> {
        self.full_calls.borrow_mut().push(next.map(str::to_string));
        Ok(self
            .full_pages
            .borrow_mut()
            .pop_front()
            .expect("stub ran out of scripted full-scan pages"))
    }

    fn changed_page(&self, min_round: u64, next: Option<&str>) -> Result<ChangedAddressesPage> {
        self.changed_calls
            .borrow_mut()
            .push((min_round, next.map(str::to_string)));
        Ok(self
            .changed_pages
            .borrow_mut()
            .pop_front()
            .expect("stub ran out of scripted change-discovery pages"))
    }

    fn lookup(&self, address: &str) -> Result<Option<ScannedAccount>> {
        self.lookup_calls.borrow_mut().push(address.to_string());
        Ok(self.lookups.borrow().get(address).cloned().unwrap_or(None))
    }
}

fn acct(address: &str, key: &str, value: &str) -> ScannedAccount {
    ScannedAccount {
        address: address.to_string(),
        local_state: vec![(key.to_string(), value.to_string())],
    }
}

fn full_page(
    accounts: Vec<ScannedAccount>,
    next: Option<&str>,
    current_round: u64,
) -> AccountScanPage {
    AccountScanPage {
        accounts,
        next_token: next.map(str::to_string),
        current_round,
    }
}

fn changed_page(
    addresses: &[&str],
    next: Option<&str>,
    current_round: u64,
) -> ChangedAddressesPage {
    ChangedAddressesPage {
        addresses: addresses.iter().map(|a| a.to_string()).collect(),
        next_token: next.map(str::to_string),
        current_round,
    }
}

// `ingest` that keeps every account as-is — the default for tests that only care about the
// fetch/cache mechanics.
fn keep_all(a: &ScannedAccount) -> Option<ScannedAccount> {
    Some(a.clone())
}

// Drive the engine over a stub, wiring its three operations to the injected closures.
fn run(
    cache: &Mutex<AccountScanCache<ScannedAccount>>,
    mode: QueryMode,
    lifetime: Option<u64>,
    now: u64,
    stub: &StubIndexer,
    ingest: impl Fn(&ScannedAccount) -> Option<ScannedAccount>,
) {
    AlgoOps::fetch_opted_in_accounts_cached_with(
        cache,
        mode,
        lifetime,
        now,
        ingest,
        |next| stub.full_page(next),
        |min_round, next| stub.changed_page(min_round, next),
        |address| stub.lookup(address),
    )
    .expect("account scan should succeed");
}

#[test]
fn full_scan_bootstrap_populates_empty_cache() {
    let cache = Mutex::new(AccountScanCache::<ScannedAccount>::new());
    let stub = StubIndexer::new(
        vec![full_page(
            vec![acct("A", "bit", "1"), acct("B", "bit", "0")],
            None,
            8,
        )],
        vec![],
        vec![],
    );

    run(&cache, QueryMode::Refresh, Some(60), 1_000, &stub, keep_all);

    // A never-scanned cache does a full scan: one full page, no change-discovery, no re-reads.
    assert_eq!(stub.full_calls.borrow().clone(), vec![None]);
    assert!(stub.changed_calls.borrow().is_empty());
    assert!(stub.lookup_calls.borrow().is_empty());

    let cache = cache.lock().unwrap();
    assert_eq!(
        cache.entries,
        vec![
            ("A".to_string(), acct("A", "bit", "1")),
            ("B".to_string(), acct("B", "bit", "0")),
        ]
    );
    // The watermark advances to the indexer's current-round, stamped fresh.
    assert_eq!(cache.last_round, 8);
    assert_eq!(cache.last_updated, 1_000);
}

#[test]
fn incremental_refresh_rereads_only_changed_accounts() {
    // A cache already scanned through round 10, holding two accounts.
    let cache = Mutex::new(AccountScanCache {
        last_round: 10,
        last_updated: 100,
        entries: vec![
            ("A".to_string(), acct("A", "bit", "0")),
            ("B".to_string(), acct("B", "bit", "0")),
        ],
    });
    // Only B was touched past the watermark; its bit flipped to 1.
    let stub = StubIndexer::new(
        vec![],
        vec![changed_page(&["B"], None, 13)],
        vec![("B", Some(acct("B", "bit", "1")))],
    );

    // No freshness window → the refresh always runs incrementally.
    run(&cache, QueryMode::Refresh, None, 1_000, &stub, keep_all);

    // No full scan; change discovery starts strictly past the watermark (10 → min_round 11); only the
    // one changed account is re-read.
    assert!(stub.full_calls.borrow().is_empty());
    assert_eq!(stub.changed_calls.borrow().clone(), vec![(11, None)]);
    assert_eq!(stub.lookup_calls.borrow().clone(), vec!["B".to_string()]);

    let cache = cache.lock().unwrap();
    // A is left untouched; B is replaced in place (no duplicate entry).
    assert_eq!(
        cache.entries,
        vec![
            ("A".to_string(), acct("A", "bit", "0")),
            ("B".to_string(), acct("B", "bit", "1")),
        ]
    );
    assert_eq!(cache.last_round, 13);
    assert_eq!(cache.last_updated, 1_000);
}

#[test]
fn fresh_refresh_degrades_to_cache_only_with_no_network() {
    // Scanned 5 seconds ago with a 60 s lifetime, so the cache is fresh.
    let cache = Mutex::new(AccountScanCache {
        last_round: 10,
        last_updated: 995,
        entries: vec![("A".to_string(), acct("A", "bit", "1"))],
    });
    let stub = StubIndexer::new(vec![], vec![], vec![]);

    run(&cache, QueryMode::Refresh, Some(60), 1_000, &stub, keep_all);

    // Zero network of any kind, and the cache is left exactly as it was.
    assert!(stub.full_calls.borrow().is_empty());
    assert!(stub.changed_calls.borrow().is_empty());
    assert!(stub.lookup_calls.borrow().is_empty());
    let cache = cache.lock().unwrap();
    assert_eq!(
        cache.entries,
        vec![("A".to_string(), acct("A", "bit", "1"))]
    );
    assert_eq!(cache.last_round, 10);
    assert_eq!(cache.last_updated, 995);
}

#[test]
fn cache_only_never_fetches_even_when_stale() {
    // Old stamp and a tiny lifetime — stale, but CacheOnly still never fetches.
    let cache = Mutex::new(AccountScanCache {
        last_round: 10,
        last_updated: 100,
        entries: vec![("A".to_string(), acct("A", "bit", "1"))],
    });
    let stub = StubIndexer::new(vec![], vec![], vec![]);

    run(
        &cache,
        QueryMode::CacheOnly,
        Some(1),
        1_000,
        &stub,
        keep_all,
    );

    assert!(stub.full_calls.borrow().is_empty());
    assert!(stub.changed_calls.borrow().is_empty());
    assert!(stub.lookup_calls.borrow().is_empty());
    let cache = cache.lock().unwrap();
    assert_eq!(
        cache.entries,
        vec![("A".to_string(), acct("A", "bit", "1"))]
    );
    assert_eq!(cache.last_round, 10);
    assert_eq!(cache.last_updated, 100);
}

#[test]
fn force_full_discards_the_cache_and_rebuilds() {
    // A populated cache scanned through round 50.
    let cache = Mutex::new(AccountScanCache {
        last_round: 50,
        last_updated: 100,
        entries: vec![
            ("OLD1".to_string(), acct("OLD1", "bit", "1")),
            ("OLD2".to_string(), acct("OLD2", "bit", "1")),
        ],
    });
    let stub = StubIndexer::new(
        vec![full_page(vec![acct("A", "bit", "1")], None, 55)],
        vec![],
        vec![],
    );

    run(
        &cache,
        QueryMode::ForceFull,
        Some(60),
        1_000,
        &stub,
        keep_all,
    );

    // Rebuilt with a full scan (no next token), discarding the old entries — even though the cache was
    // fresh (ForceFull ignores freshness).
    assert_eq!(stub.full_calls.borrow().clone(), vec![None]);
    let cache = cache.lock().unwrap();
    assert_eq!(
        cache.entries,
        vec![("A".to_string(), acct("A", "bit", "1"))]
    );
    assert_eq!(cache.last_round, 55);
    assert_eq!(cache.last_updated, 1_000);
}

#[test]
fn incremental_opt_out_removes_the_account() {
    // A was cached; it opts out past the watermark, so its re-read returns None.
    let cache = Mutex::new(AccountScanCache {
        last_round: 10,
        last_updated: 100,
        entries: vec![
            ("A".to_string(), acct("A", "bit", "1")),
            ("B".to_string(), acct("B", "bit", "1")),
        ],
    });
    let stub = StubIndexer::new(
        vec![],
        vec![changed_page(&["A"], None, 12)],
        vec![("A", None)],
    );

    run(&cache, QueryMode::Refresh, None, 1_000, &stub, keep_all);

    assert_eq!(stub.lookup_calls.borrow().clone(), vec!["A".to_string()]);
    let cache = cache.lock().unwrap();
    // A is dropped; B (untouched) remains.
    assert_eq!(
        cache.entries,
        vec![("B".to_string(), acct("B", "bit", "1"))]
    );
    assert_eq!(cache.last_round, 12);
}

#[test]
fn incremental_ingest_returning_none_removes_the_account() {
    // A's re-read succeeds, but the caller's ingest now rejects it (e.g. its membership bit cleared),
    // so it is removed from the set just like an opt-out.
    let cache = Mutex::new(AccountScanCache {
        last_round: 10,
        last_updated: 100,
        entries: vec![("A".to_string(), acct("A", "bit", "1"))],
    });
    let stub = StubIndexer::new(
        vec![],
        vec![changed_page(&["A"], None, 12)],
        vec![("A", Some(acct("A", "bit", "0")))],
    );

    // Keep only accounts whose `bit` is "1".
    run(&cache, QueryMode::Refresh, None, 1_000, &stub, |a| {
        (a.local_state.iter().any(|(k, v)| k == "bit" && v == "1")).then(|| a.clone())
    });

    let cache = cache.lock().unwrap();
    assert!(cache.entries.is_empty(), "a rejected re-read is removed");
    assert_eq!(cache.last_round, 12);
}

#[test]
fn paginated_full_scan_follows_next_token_and_watermarks_the_max_round() {
    let cache = Mutex::new(AccountScanCache::<ScannedAccount>::new());
    let stub = StubIndexer::new(
        vec![
            full_page(vec![acct("A", "bit", "1")], Some("page2"), 20),
            full_page(vec![acct("B", "bit", "1")], None, 22),
        ],
        vec![],
        vec![],
    );

    run(&cache, QueryMode::Refresh, Some(60), 1_000, &stub, keep_all);

    // Two pages: the second call carries the first page's next token.
    assert_eq!(
        stub.full_calls.borrow().clone(),
        vec![None, Some("page2".to_string())]
    );
    let cache = cache.lock().unwrap();
    assert_eq!(cache.entries.len(), 2);
    // The watermark is the greatest current-round across the pages.
    assert_eq!(cache.last_round, 22);
}

#[test]
fn incremental_change_discovery_paginates_from_watermark_and_dedups_addresses() {
    // A multi-page change-discovery scan: every page carries the same min-round floor, an address
    // repeated across pages is re-read once, and the watermark ends at the greatest current-round.
    let cache = Mutex::new(AccountScanCache {
        last_round: 30,
        last_updated: 100,
        entries: vec![("A".to_string(), acct("A", "bit", "0"))],
    });
    let stub = StubIndexer::new(
        vec![],
        vec![
            changed_page(&["A", "B"], Some("p2"), 40),
            // "A" appears again on the next page — it must not be re-read twice.
            changed_page(&["A"], None, 41),
        ],
        vec![
            ("A", Some(acct("A", "bit", "1"))),
            ("B", Some(acct("B", "bit", "1"))),
        ],
    );

    run(&cache, QueryMode::Refresh, None, 1_000, &stub, keep_all);

    // Both change-discovery pages fetch from the same floor (watermark 30 → min_round 31).
    assert_eq!(
        stub.changed_calls.borrow().clone(),
        vec![(31, None), (31, Some("p2".to_string()))]
    );
    // Each distinct changed address is re-read exactly once (A deduped across the two pages).
    assert_eq!(
        stub.lookup_calls.borrow().clone(),
        vec!["A".to_string(), "B".to_string()]
    );
    let cache = cache.lock().unwrap();
    assert_eq!(
        cache.entries,
        vec![
            ("A".to_string(), acct("A", "bit", "1")),
            ("B".to_string(), acct("B", "bit", "1")),
        ]
    );
    assert_eq!(cache.last_round, 41);
}

#[test]
fn empty_scan_still_stamps_watermark_so_next_refresh_is_incremental() {
    // A full scan that matches nothing must still record it scanned (last_updated > 0) and where the
    // chain was (last_round), so a later stale refresh runs incrementally rather than re-bootstrapping.
    let cache = Mutex::new(AccountScanCache::<ScannedAccount>::new());
    let stub = StubIndexer::new(
        vec![full_page(vec![], None, 15)],
        vec![changed_page(&["A"], None, 21)],
        vec![("A", Some(acct("A", "bit", "1")))],
    );

    // First: full scan, matches nothing, but stamps the watermark.
    run(&cache, QueryMode::Refresh, None, 1_000, &stub, keep_all);
    {
        let cache = cache.lock().unwrap();
        assert!(cache.entries.is_empty());
        assert_eq!(cache.last_round, 15);
        assert_eq!(cache.last_updated, 1_000);
    }

    // Second: a stale refresh discovers changes from the stamped watermark (15 → min_round 16),
    // never re-running the full scan.
    run(&cache, QueryMode::Refresh, None, 2_000, &stub, keep_all);

    assert_eq!(stub.full_calls.borrow().clone(), vec![None]);
    assert_eq!(stub.changed_calls.borrow().clone(), vec![(16, None)]);
    let cache = cache.lock().unwrap();
    assert_eq!(
        cache.entries,
        vec![("A".to_string(), acct("A", "bit", "1"))]
    );
    assert_eq!(cache.last_round, 21);
}

#[test]
fn each_page_and_re_read_is_one_request() {
    // The per-request counter increments once per outbound request; in the engine that means one call
    // per full-scan page, per change-discovery page, and per account re-read. Count them via the stub:
    // a bootstrap here is one full page, then an incremental refresh is one change page + two re-reads.
    let cache = Mutex::new(AccountScanCache::<ScannedAccount>::new());
    let stub = StubIndexer::new(
        vec![full_page(vec![acct("A", "bit", "1")], None, 10)],
        vec![changed_page(&["A", "B"], None, 20)],
        vec![
            ("A", Some(acct("A", "bit", "1"))),
            ("B", Some(acct("B", "bit", "1"))),
        ],
    );

    // Bootstrap (full scan): one request.
    run(&cache, QueryMode::Refresh, None, 1_000, &stub, keep_all);
    // Incremental refresh: one change-discovery page + one re-read per changed account.
    run(&cache, QueryMode::Refresh, None, 2_000, &stub, keep_all);

    let total = stub.full_calls.borrow().len()
        + stub.changed_calls.borrow().len()
        + stub.lookup_calls.borrow().len();
    // 1 full page + 1 change page + 2 re-reads = 4 outbound requests.
    assert_eq!(total, 4);
}
