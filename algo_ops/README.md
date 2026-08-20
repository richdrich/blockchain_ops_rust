# algo_ops

The Algorand implementation of the [`blockchain_ops`] traits, over [`algonaut`].
`AlgoOps` covers accounts, payments, Algorand Standard Assets, and the
Transaction Execution Approval Language (TEAL) application lifecycle, and
implements `BlockChainOps` and `AssetOps`. Construct it with
`AlgoOps::new_for_algorand`.

The consumer is expected to be blockchain-aware: the traits cover what reads
naturally on any chain, while Algorand-specific power is reached directly on
`AlgoOps` or via its native escape hatch (the `algonaut` client accessors).

## Example: print an account balance

`AlgoChainConfig::default()` targets [algokit] localnet (algod on
`localhost:4001`). Start it with `algokit localnet start`, then:

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

The same program is a runnable example — `cargo run -p algo_ops --example print_balance -- <ADDRESS>`.

Part of the [`blockchain_ops_rust`] workspace — see the root README for the full
picture.

[`blockchain_ops`]: https://crates.io/crates/blockchain_ops
[`algonaut`]: https://crates.io/crates/algonaut
[algokit]: https://github.com/algorandfoundation/algokit-cli
[`blockchain_ops_rust`]: https://github.com/richdrich/blockchain_ops_rust
