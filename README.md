# blockchain_ops_rust

In producing distributed blockchain applications, we found a need for a shared high level interface to
a blockchain (initially Algorand).

This is that interface - it provides chain-agnostic operation traits (`BlockChainOps`, `AssetOps`).

It's implemented through the following two crates:

- **`blockchain_ops`** — chain-agnostic operation traits (`BlockChainOps`, `AssetOps`). Depends only on `anyhow`; no chain software development kit (SDK).
- **`algo_ops`** — the Algorand implementation over [`algonaut`]: `AlgoOps` (accounts, payments, Algorand Standard Assets, and the Transaction Execution Approval Language (TEAL) application lifecycle), implementing the `blockchain_ops` traits, plus the `AlgoOps::new_for_algorand` constructor.

The consumer is expected to be blockchain-aware: the traits cover what reads naturally on any chain, while chain-specific power is reached directly on `AlgoOps` or via its native escape hatch (the `algonaut` client accessors).

## Usage

Consume as a git dependency, pinned to a tag:

```toml
blockchain_ops = { git = "https://github.com/richdrich/blockchain_ops_rust", tag = "v0.1.0" }
algo_ops = { git = "https://github.com/richdrich/blockchain_ops_rust", tag = "v0.1.0" }
```

## Example: print an Algorand balance

`AlgoChainConfig::default()` targets [algokit] localnet (algod on `localhost:4001`). Start it with `algokit localnet start`, then read an account balance:

```rust
use algo_ops::{AlgoChainConfig, AlgoOps};

fn main() -> anyhow::Result<()> {
    let address = "P577PSTDICQ6PQFBR5YMDMJ2YVK7LT5V4GOPNVDLCEDJIL7XGRWC5BRFWA".to_string();

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
```

The same program ships as a runnable example:

```
cargo run -p algo_ops --example print_balance -- P577PSTDICQ6PQFBR5YMDMJ2YVK7LT5V4GOPNVDLCEDJIL7XGRWC5BRFWA
```

## Documentation

Per-crate documentation: [`blockchain_ops`](blockchain_ops/README.md) and [`algo_ops`](algo_ops/README.md). Application programming interface (API) docs are published on [docs.rs] once the crates are released to crates.io.

## Development

See [DEVELOPER.md](DEVELOPER.md) for build, test, and continuous-integration (CI) instructions.

[`algonaut`]: https://crates.io/crates/algonaut
[algokit]: https://github.com/algorandfoundation/algokit-cli
[docs.rs]: https://docs.rs
