//! Unit tests for the atomic transaction-group builder (`AlgoOps::transaction_group`).
//!
//! These cover the builder-misuse paths that fail *before* any network I/O, so they
//! need no running node. End-to-end grouping (build + sign + atomic broadcast + confirm)
//! is exercised by the localnet test `transaction_group_localnet.rs` in the
//! `integration` target.

use algo_ops::{AlgoChainConfig, AlgoOps, AppArg};

// An AlgoOps with account access but pointed at an unreachable node. The builder-misuse
// checks below all bail before the first network call, so the node is never contacted.
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
fn empty_group_is_rejected_before_network() {
    let ops = offline_ops();
    let err = ops
        .transaction_group()
        .sign_and_send()
        .expect_err("an empty transaction group must be rejected");
    assert!(
        err.to_string().contains("at least one"),
        "unexpected error message: {err}"
    );
}

#[test]
fn foreign_asset_without_app_call_is_rejected() {
    let ops = offline_ops();
    let err = ops
        .transaction_group()
        .payment("AAAA", 1000)
        .foreign_asset(42)
        .sign_and_send()
        .expect_err("foreign_asset() with no preceding call_app() must be rejected");
    assert!(
        err.to_string().contains("foreign_asset"),
        "unexpected error message: {err}"
    );
}

#[test]
fn foreign_app_without_app_call_is_rejected() {
    let ops = offline_ops();
    let err = ops
        .transaction_group()
        .foreign_app(7)
        .sign_and_send()
        .expect_err("foreign_app() with no preceding call_app() must be rejected");
    assert!(
        err.to_string().contains("foreign_app"),
        "unexpected error message: {err}"
    );
}

#[test]
fn call_app_with_zero_app_id_is_rejected() {
    let ops = offline_ops();
    let err = ops
        .transaction_group()
        .call_app(0, Some("buy_bingle()void"), &[])
        .sign_and_send()
        .expect_err("call_app() with app_id 0 must be rejected");
    assert!(
        err.to_string().contains("app_id"),
        "unexpected error message: {err}"
    );
}

#[test]
fn first_builder_error_is_reported() {
    // Two misuses in one chain: the first recorded error should be the one surfaced.
    let ops = offline_ops();
    let err = ops
        .transaction_group()
        .foreign_asset(1) // first misuse: no preceding call_app
        .foreign_app(2) // second misuse
        .sign_and_send()
        .expect_err("a misused builder must be rejected");
    assert!(
        err.to_string().contains("foreign_asset"),
        "expected the first misuse to be reported, got: {err}"
    );
}

#[test]
fn builder_accepts_the_buy_bingle_shape() {
    // Assemble the buy_bingle group shape (payment + app-call-with-foreign-asset). This must
    // pass all pre-network validation and only fail when it reaches the unreachable node,
    // proving the builder accepts the shape the acceptance criteria require.
    let ops = offline_ops();
    let result = ops
        .transaction_group()
        .payment("AAAA", 1000)
        .call_app(123, Some("buy_bingle()void"), &[AppArg::Uint(1)])
        .foreign_asset(456)
        .sign_and_send();
    let err = result.expect_err("the offline node must make the broadcast fail");
    let msg = err.to_string();
    assert!(
        !msg.contains("at least one")
            && !msg.contains("foreign_asset")
            && !msg.contains("foreign_app"),
        "the group shape itself must be valid; got a validation error: {msg}"
    );
}
