//! Print an Algorand account balance.
//!
//! Reads a balance against a running node — algokit localnet by default (algod on
//! `localhost:4001`), which `AlgoChainConfig::default()` targets. Start localnet with
//! `algokit localnet start`, then run:
//!
//!   cargo run -p algo_ops --example print_balance -- <ALGORAND_ADDRESS>
//!
//! With no argument it reads the `ALGO_ADDRESS` environment variable, falling back to a
//! localnet address. Only the address is needed to read a balance (no passphrase).

use algo_ops::{AlgoChainConfig, AlgoOps};

/// A localnet address to fall back on when none is supplied. Replace with your own.
const DEFAULT_ADDRESS: &str = "P577PSTDICQ6PQFBR5YMDMJ2YVK7LT5V4GOPNVDLCEDJIL7XGRWC5BRFWA";

fn main() -> anyhow::Result<()> {
    // Address from the first command-line argument, else `ALGO_ADDRESS`, else the default.
    let address = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ALGO_ADDRESS").ok())
        .unwrap_or_else(|| DEFAULT_ADDRESS.to_string());

    // `AlgoChainConfig::default()` targets algokit localnet (algod on localhost:4001).
    let ops = AlgoOps::new_for_algorand(
        None,
        Some(address.clone()),
        Some(AlgoChainConfig::default()),
    );

    // `account_balance` returns whole ALGO, or `None` if the account does not exist yet.
    match ops.account_balance()? {
        Some(algos) => println!("{address}: {algos} ALGO"),
        None => println!("{address}: account not found"),
    }
    Ok(())
}
