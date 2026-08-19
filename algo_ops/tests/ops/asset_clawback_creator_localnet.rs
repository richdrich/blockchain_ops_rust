//! Localnet integration test: a plain `create_asset` sets clawback to the creator.
//! Requires algokit localnet; in the `integration` target (run with
//! `cargo test --test integration`).

use crate::support::setup_localnet;
use crate::support::test_util::{
    self, ADDRESS_SPEND, PASSPHRASE_SPEND, localnet_config, ops_from_mnemonic,
};
use algo_ops::AlgoChainConfig;

#[test]
#[cfg(not(target_os = "ios"))]
pub fn asset_creation_sets_clawback_to_creator() {
    test_util::assert_localnet_available();

    // Ensure funding for the creator test account
    let cfg: AlgoChainConfig = localnet_config();
    setup_localnet::ensure_localnet_accounts_funded(&cfg, &[ADDRESS_SPEND]).expect(
        "Failed to ensure localnet test account funded; install algokit and start localnet",
    );

    // Ops for creator
    let creator = ops_from_mnemonic(ADDRESS_SPEND, PASSPHRASE_SPEND, cfg.clone());

    // Create a tiny ASA
    let asset_id = creator
        .create_asset("CLAWCHK", 10)
        .expect("create_asset call")
        .expect("asset id");

    // Query on-chain asset info and assert params.clawback equals creator address
    let algod = {
        let url = format!("{}:{}", cfg.client_api_url, cfg.client_api_port);
        let token = cfg.token.clone().unwrap_or_default();
        algonaut::Algod::new(&url, &token).expect("algod client")
    };

    let info = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async { algod.asset(algonaut::core::AssetId(asset_id)).await })
            .expect("asset info ok")
    };

    let v = serde_json::to_value(&info).expect("json");
    // clawback can appear under params.clawback or params.clawback-address
    let cb = v
        .get("params")
        .and_then(|p| {
            p.get("clawback").and_then(|x| x.as_str()).or_else(|| {
                p.get("clawback-address")
                    .or_else(|| p.get("clawback_address"))
                    .and_then(|x| x.as_str())
            })
        })
        .expect("clawback field present");

    assert_eq!(
        cb, ADDRESS_SPEND,
        "asset clawback should be the creator address"
    );
}
