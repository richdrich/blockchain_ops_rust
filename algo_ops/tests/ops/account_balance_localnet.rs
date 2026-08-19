//! Localnet integration tests for AlgoOps read paths (formerly bingle_core's
//! `algo_ops_integration_localnet.rs`). In the `integration` target, which a bare
//! `cargo test` skips; run with `cargo test --test integration`.

use crate::support::setup_localnet;
use crate::support::test_util::{self, ADDRESS_10MIL, localnet_config};
use algo_ops::AlgoOps;

fn fund_test_accounts_or_panic() {
    let cfg = test_util::localnet_config();
    setup_localnet::ensure_localnet_accounts_funded(
        &cfg,
        &[
            test_util::ADDRESS_10MIL,
            test_util::ADDRESS_SPEND,
            test_util::ADDRESS_RECEIVE,
        ],
    )
    .expect("Failed to ensure localnet test accounts funded; install algokit and start localnet");
}

// How to run these integration tests:
// - Ensure algokit localnet (or another local Algorand node) is running at http://localhost:4001
//   with token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.
// - Run `cargo test --test integration`. The tests fail if localnet is not available.

#[test]
#[cfg(not(target_os = "ios"))]
pub fn account_balance_for_address10mil_returns_some() {
    test_util::assert_localnet_available();
    fund_test_accounts_or_panic();
    let cfg = localnet_config();
    let ops = AlgoOps::new(None, Some(ADDRESS_10MIL.to_string()), Some(cfg));
    let bal = ops
        .account_balance()
        .expect("network query should not error on localnet");
    assert!(
        bal.is_some(),
        "Expected Some(balance) for funded localnet account"
    );
    assert!(bal.unwrap() >= 0.0);
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn global_state_for_address10mil_returns_some_vec() {
    test_util::assert_localnet_available();
    fund_test_accounts_or_panic();
    let cfg = localnet_config();
    let ops = AlgoOps::new(None, Some(ADDRESS_10MIL.to_string()), Some(cfg));
    let gs = ops
        .global_state(None)
        .expect("global_state call should succeed on localnet");
    assert!(
        gs.is_some(),
        "Should return Some (possibly empty) global state vector"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn algo_ops_integration_localnet_placeholder() {
    test_util::assert_localnet_available();
    // Keep placeholder light to avoid duplicating other tests.
}
