//! Localnet integration test for the atomic transaction-group builder.
//!
//! Deploys the mini dapp, then broadcasts a `[payment, app-call]` atomic group with
//! `AlgoOps::transaction_group().payment(..).call_app(..).sign_and_send()` — the exact
//! shape (minus the ASA setup) that `bingle_rust`'s `buy_bingle` needs, proving the group
//! is assigned a shared id, signed by the ops account, broadcast atomically, and confirmed.
//! Requires algokit localnet; in the `integration` target (run with
//! `cargo test --test integration`).

use crate::support::setup_localnet;
use crate::support::test_util;
use algo_ops::AppArg;
use std::fs;

const MINI_APPROVAL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/dapp/mini_approval.teal");
const MINI_CLEAR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/dapp/mini_clear_state.teal"
);

#[test]
#[cfg(not(target_os = "ios"))]
pub fn payment_and_app_call_group_is_atomic() {
    test_util::assert_localnet_available();
    let cfg = test_util::localnet_config();
    setup_localnet::ensure_localnet_accounts_funded(&cfg, &[test_util::ADDRESS_SPEND]).expect(
        "Failed to ensure localnet test accounts funded; install algokit and start localnet",
    );

    let ops = test_util::ops_from_mnemonic(
        test_util::ADDRESS_SPEND,
        test_util::PASSPHRASE_SPEND,
        cfg.clone(),
    );

    let approval_src = fs::read_to_string(MINI_APPROVAL).expect("read approval teal");
    let clear_src = fs::read_to_string(MINI_CLEAR).expect("read clear teal");
    let approval_prog = ops
        .compile_teal(&approval_src)
        .expect("compile approval teal");
    let clear_prog = ops.compile_teal(&clear_src).expect("compile clear teal");

    // The mini contract holds no application state; supply a minimal ARC-56 spec to match.
    let arc56_json =
        r#"{"state":{"schema":{"global":{"ints":0,"bytes":0},"local":{"ints":0,"bytes":0}}}}"#;

    let app_id = ops
        .deploy_app(
            &approval_prog,
            &clear_prog,
            None,
            None,
            &[],
            "opt_in_to_bingle(uint64)void",
            arc56_json,
        )
        .expect("deploy app call")
        .expect("created app id");

    // Send the app address a small self-payment leg atomically grouped with an app-call leg.
    // The single ops account signs both legs; the group must confirm as one unit.
    let sender = ops.address_str().expect("ops address");
    let x: u64 = 15;
    let tx_id = ops
        .transaction_group()
        .payment(&sender, 1_000)
        .call_app(app_id, Some("fn(uint64)uint64"), &[AppArg::Uint(x)])
        .sign_and_send()
        .expect("atomic payment + app-call group should confirm");

    assert!(
        !tx_id.is_empty(),
        "sign_and_send should return the group's representative transaction id"
    );

    // Clean up.
    ops.delete_app(app_id).expect("delete app");
}
