//! LocalNet test for ARC-4 argument framing in the transaction-group builder (#131).
//!
//! Deploys `dapp/bytesarg_approval.teal`, which rejects a NoOp method call whose argument is not a
//! well-formed ARC-4 dynamic `byte[]` (on-wire length must equal 2 + the declared length — the check
//! puya generates). It then sends the `register(string)` group shape — an asset transfer atomically
//! grouped with an app call carrying a dynamic argument, with the asset as a foreign asset — and
//! asserts: the raw builder `call_app` leg is rejected, so the whole group fails, while the
//! `call_app_arc4_args` leg is framed and the group confirms.
//! In the `integration` target; run with `cargo test --test integration`.

use crate::support::setup_localnet;
use crate::support::test_util;
use algo_ops::AppArg;
use std::fs;

const APPROVAL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/dapp/bytesarg_approval.teal"
);
const CLEAR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/dapp/bytesarg_clear.teal"
);

#[test]
#[cfg(not(target_os = "ios"))]
pub fn a_grouped_app_call_frames_its_dynamic_argument() {
    test_util::assert_localnet_available();
    let cfg = test_util::localnet_config();
    setup_localnet::ensure_localnet_accounts_funded(&cfg, &[test_util::ADDRESS_SPEND]).expect(
        "Failed to ensure localnet test accounts funded; install algokit and start localnet",
    );
    let ops =
        test_util::ops_from_mnemonic(test_util::ADDRESS_SPEND, test_util::PASSPHRASE_SPEND, cfg);

    let approval = ops
        .compile_teal(&fs::read_to_string(APPROVAL).expect("read approval teal"))
        .expect("compile approval teal");
    let clear = ops
        .compile_teal(&fs::read_to_string(CLEAR).expect("read clear teal"))
        .expect("compile clear teal");
    let arc56_json =
        r#"{"state":{"schema":{"global":{"ints":0,"bytes":0},"local":{"ints":0,"bytes":0}}}}"#;
    let app_id = ops
        .deploy_app(
            &approval,
            &clear,
            None,
            None,
            &[],
            "noop(uint64)void",
            arc56_json,
        )
        .expect("deploy app call")
        .expect("created app id");

    // the creator holds the whole issue, so a self-transfer is a valid asset-transfer leg.
    let asset_id = ops
        .create_asset("ARC4GRP", 1_000)
        .expect("create asset")
        .expect("created asset id");
    let sender = ops.address_str().expect("ops address");
    // three bytes whose first two (0x6162) are not a valid length prefix for a 3-byte arg, so the
    // fixture's length assert fails unless the argument is framed.
    let handle = "abc";

    let raw_group = ops
        .transaction_group()
        .asset_transfer(asset_id, 1, &sender)
        .call_app(
            app_id,
            Some("store_bytes(string)void"),
            &[AppArg::Utf8(handle.to_string())],
        )
        .foreign_asset(asset_id)
        .sign_and_send();
    assert!(
        raw_group.is_err(),
        "a raw call_app leg sends the string unframed, so the contract rejects it and the whole group fails"
    );

    let framed_group = ops
        .transaction_group()
        .asset_transfer(asset_id, 1, &sender)
        .call_app_arc4_args(
            app_id,
            Some("store_bytes(string)void"),
            &[AppArg::Utf8(handle.to_string())],
        )
        .foreign_asset(asset_id)
        .sign_and_send();
    assert!(
        framed_group.is_ok(),
        "call_app_arc4_args frames the string ([00 03]abc), so the group confirms: {:?}",
        framed_group.err()
    );

    let _ = ops.delete_app(app_id);
}
