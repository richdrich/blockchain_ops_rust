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
#[path = "ops/algod_reads.rs"]
mod algod_reads;
#[path = "ops/asset_holding.rs"]
mod asset_holding;
#[path = "ops/block_header_seed.rs"]
mod block_header_seed;
#[path = "ops/change_reserve.rs"]
mod change_reserve;
#[path = "ops/daily_budget.rs"]
mod daily_budget;
#[path = "ops/error_classification.rs"]
mod error_classification;
#[path = "ops/fetch_transactions_cached.rs"]
mod fetch_transactions_cached;
#[path = "ops/find_transaction_by_note_and_sender.rs"]
mod find_transaction_by_note_and_sender;
#[path = "ops/find_transactions_by_note_prefix.rs"]
mod find_transactions_by_note_prefix;
#[path = "ops/generate_keypair.rs"]
mod generate_keypair;
#[path = "ops/node_errors.rs"]
mod node_errors;
#[path = "ops/rate_limit.rs"]
mod rate_limit;
#[path = "ops/reserve_helpers.rs"]
mod reserve_helpers;
#[path = "ops/retry_logic.rs"]
mod retry_logic;
#[path = "ops/set_asset_clawback.rs"]
mod set_asset_clawback;
#[path = "ops/sign_bytes.rs"]
mod sign_bytes;
#[path = "ops/sign_notify_envelope.rs"]
mod sign_notify_envelope;
#[path = "ops/transaction_group.rs"]
mod transaction_group;
#[path = "ops/txn_submit.rs"]
mod txn_submit;
