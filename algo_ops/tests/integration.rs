//! `integration` test target: AlgoOps tests that require algokit localnet.
//!
//! This target is marked `test = false` in Cargo.toml, so a bare `cargo test`
//! skips it and stays green without a node. Run this bucket explicitly with:
//!   `cargo test --test integration`
//! The tests fail (rather than skip) if localnet is not running.
//! CI runs this bucket against localnet via `.github/workflows/integration.yml`.

#[path = "support/mod.rs"]
mod support;

#[path = "ops/account_balance_localnet.rs"]
mod account_balance_localnet;
#[path = "ops/algod_reads_localnet.rs"]
mod algod_reads_localnet;
#[path = "ops/asset_clawback_creator_localnet.rs"]
mod asset_clawback_creator_localnet;
#[path = "ops/asset_configured_creator_localnet.rs"]
mod asset_configured_creator_localnet;
#[path = "ops/asset_manager_creator_localnet.rs"]
mod asset_manager_creator_localnet;
#[path = "ops/dapp_app_integration_localnet.rs"]
mod dapp_app_integration_localnet;
#[path = "ops/fetch_transactions_cached_localnet.rs"]
mod fetch_transactions_cached_localnet;
#[path = "ops/find_transaction_by_note_and_sender_localnet.rs"]
mod find_transaction_by_note_and_sender_localnet;
#[path = "ops/find_transaction_by_note_localnet.rs"]
mod find_transaction_by_note_localnet;
#[path = "ops/find_transaction_by_note_prefix_localnet.rs"]
mod find_transaction_by_note_prefix_localnet;
#[path = "ops/requests_made_localnet.rs"]
mod requests_made_localnet;
#[path = "ops/transaction_group_localnet.rs"]
mod transaction_group_localnet;
#[path = "ops/txn_submit_localnet.rs"]
mod txn_submit_localnet;
