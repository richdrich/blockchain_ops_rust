//! Localnet integration test for the incremental cached opted-in-account scanner
//! (`AlgoOps::fetch_opted_in_accounts_cached`) against a real indexer.
//!
//! Deploys a tiny opt-in TEAL app that writes a local `m = 1` on opt-in, then drives a single
//! caller-owned `AccountScanCache` through the lifecycle: bootstrap (full scan) captures the first
//! opted-in account; an incremental refresh picks up a second opt-in *without* re-reading the first
//! (proven by the first account appearing exactly once and the watermark advancing); a further
//! incremental refresh drops an account that has closed out. The `ingest` closure decodes the app's
//! own membership field (`m`) from the account's local state, exercising the "caller decodes its own
//! field" contract. Requires algokit localnet; in the `integration` target (run with
//! `cargo test --test integration`).

use crate::support::{blockchain_users, setup_localnet, test_util};
use algo_ops::{AccountScanCache, AlgoOps, QueryMode, ScannedAccount};
use std::sync::Mutex;
use std::time::Duration;

// A minimal TEAL v8 app: bare create; opt-in writes local `m = 1`; close-out and no-op approve;
// update/delete are creator-only. Clear state always approves. Enough to enumerate opt-ins and to
// exercise an opt-out (close-out) removing an account from the scan.
const OPTIN_APPROVAL: &str = r#"#pragma version 8
txn ApplicationID
int 0
==
bnz handle_approve
txn OnCompletion
int OptIn
==
bnz handle_optin
txn OnCompletion
int CloseOut
==
bnz handle_approve
txn OnCompletion
int NoOp
==
bnz handle_approve
txn OnCompletion
int UpdateApplication
==
bnz handle_creator
txn OnCompletion
int DeleteApplication
==
bnz handle_creator
err
handle_optin:
txn Sender
byte "m"
int 1
app_local_put
int 1
return
handle_creator:
txn Sender
global CreatorAddress
==
assert
int 1
return
handle_approve:
int 1
return
"#;

const OPTIN_CLEAR: &str = r#"#pragma version 8
int 1
return
"#;

// One uint of local state (the `m` membership flag), no global state.
const OPTIN_ARC56: &str =
    r#"{"state":{"schema":{"global":{"ints":0,"bytes":0},"local":{"ints":1,"bytes":0}}}}"#;

fn ops_for(addr: &str, mnem: &str) -> AlgoOps {
    let cfg = test_util::localnet_config();
    setup_localnet::ensure_localnet_accounts_funded(&cfg, &[addr]).expect(
        "Failed to ensure localnet test accounts funded; install algokit and start localnet",
    );
    test_util::ops_from_mnemonic(addr, mnem, cfg)
}

// The caller's membership decode: read the app's own `m` flag out of the account's local state.
fn membership(acct: &ScannedAccount) -> Option<u64> {
    acct.local_state
        .iter()
        .find(|(k, _)| k == "m")
        .and_then(|(_, v)| v.parse::<u64>().ok())
}

// Refresh the cache incrementally until it holds exactly `want` entries or ~20 s elapses. Returns the
// entry count actually reached.
fn poll_until(
    reader: &AlgoOps,
    app_id: u64,
    cache: &Mutex<AccountScanCache<u64>>,
    want: usize,
) -> usize {
    for _ in 0..40 {
        reader
            .fetch_opted_in_accounts_cached(app_id, cache, QueryMode::Refresh, None, membership)
            .expect("fetch_opted_in_accounts_cached should not error");
        let len = cache.lock().unwrap().entries.len();
        if len == want {
            return len;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    cache.lock().unwrap().entries.len()
}

fn entry_for<'a>(cache: &'a AccountScanCache<u64>, addr: &str) -> Option<&'a (String, u64)> {
    cache.entries.iter().find(|(a, _)| a == addr)
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn incremental_scan_tracks_opt_in_and_opt_out() {
    test_util::assert_localnet_available();

    // Creator deploys the opt-in app; two users will opt in and out of it.
    let creator = ops_for(
        blockchain_users::ADDRESS_APP_CREATOR,
        blockchain_users::PASSPHRASE_APP_CREATOR,
    );
    let user1 = ops_for(
        blockchain_users::ADDRESS_USER,
        blockchain_users::PASSPHRASE_USER,
    );
    let user2 = ops_for(
        blockchain_users::ADDRESS_USER_STATIC,
        blockchain_users::PASSPHRASE_USER_STATIC,
    );

    let approval = creator
        .compile_teal(OPTIN_APPROVAL)
        .expect("compile opt-in approval teal");
    let clear = creator
        .compile_teal(OPTIN_CLEAR)
        .expect("compile opt-in clear teal");
    let app_id = creator
        .deploy_app(&approval, &clear, None, None, &[], "noop", OPTIN_ARC56)
        .expect("deploy opt-in app")
        .expect("created app id");

    let cache = Mutex::new(AccountScanCache::<u64>::new());

    // First opt-in: bootstrap the cache (full scan) and poll until the indexer surfaces user1.
    user1.opt_in_app(app_id).expect("user1 opt-in");
    let after_1 = poll_until(&creator, app_id, &cache, 1);
    assert_eq!(
        after_1, 1,
        "the first opt-in should be captured within the timeout"
    );
    let watermark_after_1 = {
        let c = cache.lock().unwrap();
        // The caller's decoded membership flag came through the ingest closure.
        assert_eq!(
            entry_for(&c, blockchain_users::ADDRESS_USER).map(|(_, m)| *m),
            Some(1),
            "user1's decoded membership flag should be 1"
        );
        assert!(
            c.last_round > 0,
            "the first scan must stamp a non-zero watermark"
        );
        c.last_round
    };

    // Second opt-in: an incremental refresh should pick up user2.
    user2.opt_in_app(app_id).expect("user2 opt-in");
    let after_2 = poll_until(&creator, app_id, &cache, 2);
    assert_eq!(
        after_2, 2,
        "the second opt-in should be captured incrementally"
    );
    {
        let c = cache.lock().unwrap();
        assert!(
            entry_for(&c, blockchain_users::ADDRESS_USER_STATIC).is_some(),
            "user2 must be in the set after opting in"
        );
        // The decisive assertion: user1 appears exactly once. An incremental refresh re-reads only the
        // changed account (user2); it must neither drop nor duplicate the untouched user1.
        let user1_count = c
            .entries
            .iter()
            .filter(|(a, _)| a == blockchain_users::ADDRESS_USER)
            .count();
        assert_eq!(
            user1_count, 1,
            "user1 must appear exactly once, not re-read or duplicated"
        );
        assert!(
            c.last_round >= watermark_after_1,
            "the watermark must advance (was {watermark_after_1}, now {})",
            c.last_round
        );
    }

    // user1 closes out: an incremental refresh should drop it, leaving only user2.
    user1.close_out_app(app_id).expect("user1 close-out");
    let after_close = poll_until(&creator, app_id, &cache, 1);
    assert_eq!(after_close, 1, "closing out should drop user1 from the set");
    {
        let c = cache.lock().unwrap();
        assert!(
            entry_for(&c, blockchain_users::ADDRESS_USER).is_none(),
            "user1 must be removed after closing out"
        );
        assert!(
            entry_for(&c, blockchain_users::ADDRESS_USER_STATIC).is_some(),
            "user2 must remain after user1 closes out"
        );
    }

    // CacheOnly serves the last-refreshed set without touching the network.
    let before = creator.requests_made();
    creator
        .fetch_opted_in_accounts_cached(app_id, &cache, QueryMode::CacheOnly, None, membership)
        .expect("CacheOnly refresh should succeed");
    assert_eq!(
        creator.requests_made(),
        before,
        "CacheOnly must not issue any request"
    );

    // Tidy up so re-runs start clean: user2 closes out and the creator deletes the app.
    user2.close_out_app(app_id).expect("user2 close-out");
    creator.delete_app(app_id).expect("delete opt-in app");
}
