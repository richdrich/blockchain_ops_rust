//! `unit` test target: AlgoOps tests that need no running node.
//!
//! Each `tests/ops/*.rs` file is included as a submodule so the whole bucket
//! builds as one test binary (after the bingle_rust pattern). The localnet/dapp
//! tests live in the sibling `integration` target instead.

#[path = "support/mod.rs"]
mod support;

#[path = "ops/account_balance.rs"]
mod account_balance;
#[path = "ops/address_derivation.rs"]
mod address_derivation;
#[path = "ops/asset_holding.rs"]
mod asset_holding;
#[path = "ops/change_reserve.rs"]
mod change_reserve;
#[path = "ops/generate_keypair.rs"]
mod generate_keypair;
#[path = "ops/node_errors.rs"]
mod node_errors;
#[path = "ops/reserve_helpers.rs"]
mod reserve_helpers;
#[path = "ops/retry_logic.rs"]
mod retry_logic;
#[path = "ops/set_asset_clawback.rs"]
mod set_asset_clawback;
#[path = "ops/sign_notify_envelope.rs"]
mod sign_notify_envelope;
