//! Localnet integration test: `create_asset_configured` sets distinct manager,
//! reserve, clawback and freeze roles. Requires algokit localnet; in the
//! `integration` target (run with `cargo test --test integration`).

use crate::support::blockchain_users::{
    ADDRESS_ASSET_CLAWBACK, ADDRESS_ASSET_CREATOR, ADDRESS_ASSET_FREEZE, ADDRESS_ASSET_MANAGER,
    ADDRESS_ASSET_RESERVE, PASSPHRASE_ASSET_CREATOR,
};
use crate::support::setup_localnet;
use crate::support::test_util;

#[test]
#[cfg(not(target_os = "ios"))]
pub fn create_asset_configured_sets_manager_reserve_clawback() {
    test_util::assert_localnet_available();

    let cfg = test_util::localnet_config();
    setup_localnet::ensure_localnet_accounts_funded(
        &cfg,
        &[
            ADDRESS_ASSET_CREATOR,
            ADDRESS_ASSET_MANAGER,
            ADDRESS_ASSET_RESERVE,
            ADDRESS_ASSET_CLAWBACK,
            ADDRESS_ASSET_FREEZE,
        ],
    )
    .expect("fund blockchain user accounts; ensure algokit localnet is running");

    let creator =
        test_util::ops_from_mnemonic(ADDRESS_ASSET_CREATOR, PASSPHRASE_ASSET_CREATOR, cfg.clone());

    let asset_id = creator
        .create_asset_configured(
            "CFGCHK",
            1_000,
            ADDRESS_ASSET_MANAGER,
            ADDRESS_ASSET_RESERVE,
            ADDRESS_ASSET_CLAWBACK,
            ADDRESS_ASSET_FREEZE,
        )
        .expect("create_asset_configured call")
        .expect("asset id returned");

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
            .expect("asset info from algod")
    };

    let v = serde_json::to_value(&info).expect("json");
    let params = v.get("params").expect("params field");

    let field = |key: &str, alt: &str| -> String {
        params
            .get(key)
            .and_then(|x| x.as_str())
            .or_else(|| params.get(alt).and_then(|x| x.as_str()))
            .unwrap_or_else(|| panic!("expected field {} or {} in asset params", key, alt))
            .to_string()
    };

    assert_eq!(
        field("manager", "manager-address"),
        ADDRESS_ASSET_MANAGER,
        "manager should be asset manager"
    );
    assert_eq!(
        field("reserve", "reserve-address"),
        ADDRESS_ASSET_RESERVE,
        "reserve should be ASSET_RESERVE"
    );
    assert_eq!(
        field("clawback", "clawback-address"),
        ADDRESS_ASSET_CLAWBACK,
        "clawback should be ASSET_CLAWBACK"
    );
    assert_eq!(
        field("freeze", "freeze-address"),
        ADDRESS_ASSET_FREEZE,
        "freeze should be ASSET_FREEZE"
    );
}
