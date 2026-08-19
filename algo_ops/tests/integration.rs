//! `integration` test target: AlgoOps tests that require algokit localnet.
//!
//! Every test in this bucket is `#[ignore]`d so the default `cargo test` stays
//! green without a node. Run them with:
//!   `cargo test --test integration -- --ignored`
//! (Wiring CI to run this bucket is tracked separately.)

#[path = "support/mod.rs"]
mod support;

#[path = "ops/account_balance_localnet.rs"]
mod account_balance_localnet;
#[path = "ops/asset_clawback_creator_localnet.rs"]
mod asset_clawback_creator_localnet;
#[path = "ops/asset_configured_creator_localnet.rs"]
mod asset_configured_creator_localnet;
#[path = "ops/asset_manager_creator_localnet.rs"]
mod asset_manager_creator_localnet;
#[path = "ops/dapp_app_integration_localnet.rs"]
mod dapp_app_integration_localnet;
