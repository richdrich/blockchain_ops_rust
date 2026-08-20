# blockchain_ops

In producing distributed blockchain applications, we found a need for a shared high level interface to
a blockchain (initially Algorand).

This crate is part of that interface, it provides chain-agnostic blockchain-operation traits. 
`BlockChainOps` covers accounts, keys, signing, payments, and confirmation; `AssetOps` covers fungible-asset
transfers and holdings. The traits are what reads naturally on any chain —
chain-specific power lives in the implementation crate.

Depends only on [`anyhow`]; no chain software development kit (SDK) is pulled in.

The Algorand implementation is [`algo_ops`]. Part of the
[`blockchain_ops_rust`] workspace — see the root README for usage and a runnable
example.

[`anyhow`]: https://crates.io/crates/anyhow
[`algo_ops`]: https://crates.io/crates/algo_ops
[`blockchain_ops_rust`]: https://github.com/richdrich/blockchain_ops_rust
