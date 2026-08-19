//! Localnet integration test exercising the AlgoOps TEAL application lifecycle
//! (`compile_teal` → `deploy_app` → `call_app` → `update_app` → `delete_app`)
//! against the mini/mini2 dapp fixtures under `tests/dapp/`.
//!
//! This is the AlgoOps-via-dapp test: it drives AlgoOps' app methods directly
//! against a small TEAL contract, with no higher-level orchestration. Requires
//! algokit localnet; `#[ignore]`d by default (run with `-- --ignored`).

use crate::support::setup_localnet;
use crate::support::test_util;
use algo_ops::AppArg;
use std::fs;

// Fixtures are resolved relative to the crate manifest so the test is independent
// of the process working directory.
const MINI_APPROVAL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/dapp/mini_approval.teal");
const MINI_CLEAR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/dapp/mini_clear_state.teal"
);
const MINI2_APPROVAL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/dapp/mini2_approval.teal"
);
const MINI2_CLEAR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/dapp/mini2_clear_state.teal"
);

#[test]
#[cfg(not(target_os = "ios"))]
#[ignore = "requires algokit localnet"]
pub fn deploy_call_validate_and_delete_teal_app() {
    test_util::assert_localnet_available();
    let cfg = test_util::localnet_config();
    // Ensure creator account funded
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

    // Compile via algod developer API
    let approval_prog = ops
        .compile_teal(&approval_src)
        .expect("compile approval teal");
    let clear_prog = ops.compile_teal(&clear_src).expect("compile clear teal");

    // The mini contract holds no application state; supply a minimal ARC-56 spec to match.
    let arc56_json =
        r#"{"state":{"schema":{"global":{"ints":0,"bytes":0},"local":{"ints":0,"bytes":0}}}}"#;

    // Deploy
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

    // Call app via AlgoOps and validate initial behavior x*2+1
    let x: u64 = 15;
    let (_tx_id, logs) = ops
        .call_app(app_id, None, Some("fn(uint64)uint64"), &[AppArg::Uint(x)])
        .expect("call app");
    assert!(!logs.is_empty(), "app call should emit at least one log");
    let log_bytes = &logs[0];
    assert!(log_bytes.len() >= 12, "expected selector(4)+u64(8) in log");
    let ret_bytes = &log_bytes[4..12];
    let mut eight = [0u8; 8];
    eight.copy_from_slice(ret_bytes);
    let ret = u64::from_be_bytes(eight);
    let expected = 2u64 * x + 1u64;
    assert_eq!(ret, expected, "unexpected return value from fn");

    // Update the app to the mini2 implementation (x*3 - 20)
    let approval2_src = fs::read_to_string(MINI2_APPROVAL).expect("read mini2 approval teal");
    let clear2_src = fs::read_to_string(MINI2_CLEAR).expect("read mini2 clear teal");
    let approval2_prog = ops
        .compile_teal(&approval2_src)
        .expect("compile mini2 approval");
    let clear2_prog = ops.compile_teal(&clear2_src).expect("compile mini2 clear");

    ops.update_app(app_id, &approval2_prog, &clear2_prog, None)
        .expect("update app");

    // Call again and validate the new behavior using AlgoOps::call_app
    let (_tx2, logs2) = ops
        .call_app(app_id, None, Some("fn(uint64)uint64"), &[AppArg::Uint(x)])
        .expect("call app after update");
    assert!(
        !logs2.is_empty(),
        "app call after update should emit at least one log"
    );
    let log_bytes2 = &logs2[0];
    assert!(
        log_bytes2.len() >= 12,
        "expected selector(4)+u64(8) in log after update"
    );
    let ret_bytes2 = &log_bytes2[4..12];
    let mut eight2 = [0u8; 8];
    eight2.copy_from_slice(ret_bytes2);
    let ret2 = u64::from_be_bytes(eight2);
    let expected2 = 3u64 * x - 20u64;
    assert_eq!(
        ret2, expected2,
        "unexpected return value from fn after update"
    );

    // Delete app: approval allows creator to delete; require success
    ops.delete_app(app_id).expect("delete app");
}
