//! Regression test for the dynamic `byte[]` ABI-argument encoding bug in `AlgoOps::call_app`.
//!
//! `call_app` assembles an ABI method call's application args as `[selector] + args.map(AppArg::to_bytes)`,
//! and `AppArg::to_bytes()` returns the raw bytes with **no ARC-4 framing** (`ops.rs`). That is correct
//! for *fixed-size* ARC-4 types (`address` = 32 bytes, `uint64` = 8 bytes), which is why every existing
//! caller works. But a **dynamic** ARC-4 type — `byte[]` — must be encoded `[uint16 length_be][data]`.
//! Passing the raw bytes makes the contract's ABI decode read the first two data bytes as the length
//! prefix and fail its length-consistency assert (`len; ==; assert`).
//!
//! This surfaced in production: sw-node's `register_sidewinder_endpoint(byte[])` endpoint publish is the
//! first caller to pass a dynamic `byte[]` arg, and it is rejected on-chain (assert failed pc=… on the
//! Bingle DApp). See the bug for the full write-up.
//!
//! The fixture `dapp/bytesarg_approval.teal` reproduces the exact puya-generated check: on a NoOp method
//! call it asserts `on_wire_len(arg) == 2 + declared_uint16_len(arg)`. This test deploys it and calls
//! `store_bytes(byte[])` with a 3-byte record; it is **RED until `call_app` ARC-4-encodes dynamic byte[]
//! args** (algo_ops bug: dynamic-byte[]-abi-encoding). It turns GREEN once the arg is length-prefixed.

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
pub fn call_app_arc4_encodes_a_dynamic_byte_slice_arg() {
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

    // A 3-byte record whose first two bytes (0xAABB) are NOT a valid length prefix for a 3-byte arg,
    // so the fixture's ARC-4 length assert fails unless call_app prepends the real [uint16 len] prefix.
    let record = vec![0xAAu8, 0xBB, 0xCC];

    // RED until AlgoOps::call_app ARC-4-encodes dynamic `byte[]` args. When it does, the wire arg becomes
    // [00 03][AA BB CC] and the contract's length assert (len == 2 + declared) passes.
    let result = ops.call_app(
        app_id,
        None,
        Some("store_bytes(byte[])void"),
        &[AppArg::Bytes(record)],
    );

    ops.delete_app(app_id).ok();

    result.expect(
        "call_app(store_bytes(byte[])) must succeed — a dynamic byte[] arg must be ARC-4 length-prefixed \
         [uint16 len][data]; AlgoOps::call_app currently passes the raw bytes, so the contract's byte[] \
         decode rejects it (assert len == 2 + declared). RED until the dynamic-byte[] ABI encoding is fixed.",
    );
}
