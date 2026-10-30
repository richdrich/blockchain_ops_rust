//! Unit tests for an incremental opted-in-account refresh that meets a closed account (#136). Each
//! test drives `AlgoOps::fetch_opted_in_accounts_cached` through real algonaut requests against a
//! local stub indexer, which answers by request path, so the indexer's 404 for a closed account
//! reaches the production lookup.

use algo_ops::error::{AlgoError, AlgoErrorKind};
use algo_ops::{AccountScanCache, AlgoChainConfig, AlgoOps, QueryMode, ScannedAccount};
use algonaut::model::indexer::transaction::TxType;
use algonaut::model::indexer::{OnCompletion, Transaction, TransactionApplication};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Mutex;

const APP_ID: u64 = 771_828_003;
const CACHED_ROUND: u64 = 100;
const CURRENT_ROUND: u64 = 200;
/// The account from the TestNet incident, closed by a handle clash recovery group.
const CLOSED: &str = "I6VFWBRODJVPD6FFOKGGLNFS5B7CG6VBMTJVMJMUOCIGHHGK3FQGR6HLHU";
const LIVE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";

/// The body the indexer sends for a closed account.
fn not_found_body(address: &str) -> String {
    format!(r#"{{"message":"no accounts found for address: {address}"}}"#)
}

/// A page of the app's transactions since the watermark: `CLOSED` sends a call naming `LIVE`.
fn changed_page_body() -> String {
    let mut app = TransactionApplication::new(APP_ID, OnCompletion::Noop);
    app.accounts = Some(vec![LIVE.to_string()]);
    let mut txn = Transaction::new(1_000, 1, 1_000, CLOSED.to_string(), TxType::Appl);
    txn.application_transaction = Some(Box::new(app));
    serde_json::json!({ "current-round": CURRENT_ROUND, "transactions": [txn] }).to_string()
}

/// A `LIVE` account lookup body, opted in to `APP_ID`.
fn live_account_body() -> String {
    serde_json::json!({
        "current-round": CURRENT_ROUND,
        "account": {
            "address": LIVE,
            "amount": 1,
            "amount-without-pending-rewards": 1,
            "pending-rewards": 0,
            "rewards": 0,
            "round": CURRENT_ROUND,
            "status": "Offline",
            "apps-local-state": [{
                "id": APP_ID,
                "schema": { "num-byte-slice": 0, "num-uint": 0 },
            }],
        },
    })
    .to_string()
}

/// Bind a stub indexer that answers each request with `route(path)`, a status and a JSON body, and
/// closes each connection.
fn stub_indexer(route: impl Fn(&str) -> (u16, String) + Send + 'static) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            // read the request head; the requests under test carry no body
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            let head = String::from_utf8_lossy(&head);
            let path = head.split_whitespace().nth(1).unwrap_or_default();
            let (status, body) = route(path);
            let response = format!(
                "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    addr
}

/// The stub's answers when the transaction search succeeds and `CLOSED` looks up as `closed`.
fn route_closed_lookup_as(closed: (u16, String)) -> impl Fn(&str) -> (u16, String) {
    move |path| {
        if path.starts_with(&format!("/v2/accounts/{CLOSED}")) {
            closed.clone()
        } else if path.starts_with(&format!("/v2/accounts/{LIVE}")) {
            (200, live_account_body())
        } else if path.starts_with("/v2/transactions") {
            (200, changed_page_body())
        } else {
            (500, format!(r#"{{"message":"unexpected path {path}"}}"#))
        }
    }
}

/// A stale cache holding both accounts, tagged `old`, so a refresh takes the incremental path.
fn stale_cache() -> Mutex<AccountScanCache<String>> {
    Mutex::new(AccountScanCache {
        last_round: CACHED_ROUND,
        last_updated: 1,
        entries: vec![
            (CLOSED.to_string(), "old".to_string()),
            (LIVE.to_string(), "old".to_string()),
        ],
    })
}

/// Run an incremental refresh against `addr`, tagging each entry it re-reads `new`.
fn refresh(addr: SocketAddr, cache: &Mutex<AccountScanCache<String>>) -> anyhow::Result<()> {
    let mut config = AlgoChainConfig::default();
    config.indexer_api_url = format!("http://{}", addr.ip());
    config.indexer_api_port = addr.port();
    let ops = AlgoOps::new_for_algorand(None, None, Some(config));
    ops.fetch_opted_in_accounts_cached(
        APP_ID,
        cache,
        QueryMode::Refresh,
        None,
        |_: &ScannedAccount| Some("new".to_string()),
    )
}

/// Assert a failed refresh left the cache as it was, so the next one retries the same rounds.
fn assert_cache_untouched(cache: &Mutex<AccountScanCache<String>>) {
    let cache = cache.lock().expect("cache");
    assert_eq!(cache.last_round, CACHED_ROUND, "the watermark holds");
    assert_eq!(cache.entries, stale_cache().lock().expect("cache").entries);
}

#[test]
#[cfg(not(target_os = "ios"))]
fn closed_account_leaves_the_cache_and_the_watermark_advances() {
    let addr = stub_indexer(route_closed_lookup_as((404, not_found_body(CLOSED))));
    let cache = stale_cache();

    refresh(addr, &cache).expect("a closed account doesn't fail the refresh");

    let cache = cache.lock().expect("cache");
    assert_eq!(
        cache.entries,
        vec![(LIVE.to_string(), "new".to_string())],
        "the closed account is gone and the live one is re-read"
    );
    assert_eq!(cache.last_round, CURRENT_ROUND);
}

#[test]
#[cfg(not(target_os = "ios"))]
fn other_http_lookup_error_fails_the_refresh() {
    // a 403 isn't retried, so this doesn't wait out the backoff a 5xx would
    let addr = stub_indexer(route_closed_lookup_as((
        403,
        r#"{"message":"forbidden"}"#.to_string(),
    )));
    let cache = stale_cache();

    let err = refresh(addr, &cache).expect_err("a 403 fails the refresh");

    let e = err
        .downcast_ref::<AlgoError>()
        .unwrap_or_else(|| panic!("expected an AlgoError, got: {err}"));
    assert_eq!(e.kind, AlgoErrorKind::HttpError);
    assert_eq!(e.status, Some(403));
    assert_cache_untouched(&cache);
}

#[test]
#[cfg(not(target_os = "ios"))]
fn undecodable_lookup_fails_the_refresh() {
    let addr = stub_indexer(route_closed_lookup_as((200, "not json".to_string())));
    let cache = stale_cache();

    refresh(addr, &cache).expect_err("a decode failure fails the refresh");

    assert_cache_untouched(&cache);
}

#[test]
#[cfg(not(target_os = "ios"))]
fn change_discovery_404_fails_the_refresh() {
    // only the per-account lookup reads a 404 as a closed account
    let addr = stub_indexer(|_| (404, r#"{"message":"not found"}"#.to_string()));
    let cache = stale_cache();

    let err = refresh(addr, &cache).expect_err("a 404 from the search fails the refresh");

    assert!(err.to_string().contains("404"), "got: {err}");
    assert_cache_untouched(&cache);
}
