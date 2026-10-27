//! LocalNet test for the per-client app-creator cache (#132): a real app call looks up the app's
//! creator (to list it as a foreign account) and caches it, so a later lookup for that app makes no
//! request, and a repeat call still succeeds using the cached creator.
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
pub fn an_app_call_caches_the_creator_for_later_calls() {
    test_util::assert_localnet_available();
    let cfg = test_util::localnet_config();
    setup_localnet::ensure_localnet_accounts_funded(&cfg, &[test_util::ADDRESS_SPEND]).expect(
        "Failed to ensure localnet test accounts funded; install algokit and start localnet",
    );
    let deployer = test_util::ops_from_mnemonic(
        test_util::ADDRESS_SPEND,
        test_util::PASSPHRASE_SPEND,
        cfg.clone(),
    );
    let approval = deployer
        .compile_teal(&fs::read_to_string(APPROVAL).expect("read approval teal"))
        .expect("compile approval teal");
    let clear = deployer
        .compile_teal(&fs::read_to_string(CLEAR).expect("read clear teal"))
        .expect("compile clear teal");
    let arc56_json =
        r#"{"state":{"schema":{"global":{"ints":0,"bytes":0},"local":{"ints":0,"bytes":0}}}}"#;
    let app_id = deployer
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

    // a fresh client (not a clone of the deployer), so its cache starts empty.
    let caller =
        test_util::ops_from_mnemonic(test_util::ADDRESS_SPEND, test_util::PASSPHRASE_SPEND, cfg);
    caller
        .call_app_arc4_args(
            app_id,
            None,
            Some("store_bytes(byte[])void"),
            &[AppArg::Bytes(vec![0xAA, 0xBB, 0xCC])],
        )
        .expect("first call looks up and caches the creator");

    // the call cached the creator: looking it up again makes no request and returns the deployer.
    let before_lookup = caller.requests_made();
    let creator = caller.app_creator(app_id).expect("cached creator");
    assert_eq!(
        caller.requests_made(),
        before_lookup,
        "the creator was cached by the app call, so this lookup makes no request"
    );
    assert_eq!(
        creator,
        test_util::ADDRESS_SPEND,
        "the cached creator is the app's real creator"
    );

    // a repeat call builds its foreign-accounts array from the cached creator and is still accepted.
    caller
        .call_app_arc4_args(
            app_id,
            None,
            Some("store_bytes(byte[])void"),
            &[AppArg::Bytes(vec![0xDD])],
        )
        .expect("repeat call with the cached creator");

    let _ = deployer.delete_app(app_id);
}
