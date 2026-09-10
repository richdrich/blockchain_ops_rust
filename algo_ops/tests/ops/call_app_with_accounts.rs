//! Unit tests for `AlgoOps::call_app_with_accounts` guard paths that fail *before* any network I/O,
//! so they need no running node. The foreign-accounts array assembly (extra accounts ahead of the
//! app creator) is exercised end-to-end by consumer localnet tests that write a target account's
//! local state through an admin method.

use algo_ops::{AlgoChainConfig, AlgoOps, AppArg};

// An AlgoOps with account access but pointed at an unreachable node. The guard checks below all bail
// before the first network call, so the node is never contacted.
fn offline_ops() -> AlgoOps {
    let config = AlgoChainConfig {
        client_api_url: "http://localhost".to_string(),
        client_api_port: 1234,
        indexer_api_url: "http://localhost".to_string(),
        indexer_api_port: 1234,
        token: None,
        token_key: None,
        app_id: None,
        asset_id: None,
        rate_limit: None,
        daily_budget: None,
    };
    let (_id, passphrase) = AlgoOps::generate_keypair();
    AlgoOps::new_for_algorand(Some(passphrase), None, Some(config))
}

#[test]
fn zero_app_id_is_rejected_before_network() {
    let ops = offline_ops();
    let err = ops
        .call_app_with_accounts(0, None, Some("m(address,uint64)void"), &[], &[])
        .expect_err("app_id 0 must be rejected");
    assert!(
        err.to_string().contains("app_id must be > 0"),
        "unexpected error message: {err}"
    );
}

#[test]
fn invalid_extra_account_is_rejected_before_network() {
    // A malformed extra account is parsed (and rejected) before any node call, so the unreachable
    // node above is never contacted.
    let ops = offline_ops();
    let err = ops
        .call_app_with_accounts(
            123,
            None,
            Some("m(address,uint64)void"),
            &[AppArg::Uint(1)],
            &["not-a-valid-address"],
        )
        .expect_err("a malformed extra account must be rejected");
    assert!(
        err.to_string().contains("invalid address"),
        "unexpected error message: {err}"
    );
}
