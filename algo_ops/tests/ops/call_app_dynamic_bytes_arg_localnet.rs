//! Tests the dynamic `byte[]` ABI-argument encoding split in `AlgoOps` (#109).
//!
//! `AppArg` is **raw bytes by contract** — `call_app` / `call_app_raw_args` send each arg verbatim and the
//! caller frames dynamic ARC-4 types (e.g. `register(string)` pre-prefixes its handle). That is why a raw
//! `byte[]` arg is rejected by a contract's ABI decode: it reads the first two data bytes as the length
//! prefix and fails its length-consistency assert (`len; ==; assert`). This bit production — sw-node's
//! `register_sidewinder_endpoint(byte[])` publish sent an unframed `byte[]` and was rejected on-chain.
//!
//! `call_app_arc4_args` is the framing variant: it length-prefixes dynamic (`byte[]`/`string`) args from the
//! method signature. This test deploys `dapp/bytesarg_approval.teal` (which reproduces puya's
//! `on_wire_len(arg) == 2 + declared_uint16_len(arg)` check on a NoOp `store_bytes(byte[])` call) and asserts:
//! raw `call_app` is **rejected** (caller-frames contract preserved), and `call_app_arc4_args` is **accepted**.

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
    // so the fixture's ARC-4 length assert (len == 2 + declared) fails unless the arg is length-prefixed.
    let record = vec![0xAAu8, 0xBB, 0xCC];

    // Raw call_app: AppArg is raw-bytes-by-contract, so the byte[] goes on the wire unframed and the
    // contract's ARC-4 decode rejects it. This is the documented raw contract, NOT a bug — callers that
    // pre-frame (e.g. register(string)) rely on it, so call_app must NOT auto-frame.
    let raw = ops.call_app(
        app_id,
        None,
        Some("store_bytes(byte[])void"),
        &[AppArg::Bytes(record.clone())],
    );
    assert!(
        raw.is_err(),
        "raw call_app must pass a dynamic byte[] arg UNframed (caller-frames contract); the contract rejects it"
    );

    // call_app_arc4_args frames the dynamic arg from the signature: the wire arg becomes [00 03][AA BB CC],
    // so the contract's length assert (len == 2 + declared) passes.
    let framed = ops.call_app_arc4_args(
        app_id,
        None,
        Some("store_bytes(byte[])void"),
        &[AppArg::Bytes(record)],
    );

    ops.delete_app(app_id).ok();

    framed.expect(
        "call_app_arc4_args(store_bytes(byte[])) must succeed — it ARC-4-frames the dynamic byte[] arg \
         as [uint16 len][data] so the contract's byte[] decode accepts it",
    );
}
