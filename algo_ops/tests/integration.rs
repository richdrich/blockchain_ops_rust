//! `integration` test target: AlgoOps tests that require algokit localnet.
//!
//! This target is marked `test = false` in Cargo.toml, so a bare `cargo test`
//! skips it and stays green without a node. Run this bucket explicitly with:
//!   `cargo test --test integration`
//! The tests fail (rather than skip) if localnet is not running.
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
