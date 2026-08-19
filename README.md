# blockchain_ops_rust

Reusable blockchain-operations crates, extracted from `bingle_rust` (see that repo's issue #161).

- **`blockchain_ops`** — chain-agnostic operation traits (`BlockChainOps`, `AssetOps`). Depends only on `anyhow`; no chain SDK.
- **`algo_ops`** — the Algorand implementation over [`algonaut`]: `AlgoOps` (accounts, payments, Algorand Standard Assets, and the TEAL application lifecycle), implementing the `blockchain_ops` traits, plus the `AlgoOps::new_for_algorand` constructor.

The consumer is expected to be blockchain-aware: the traits cover what reads naturally on any chain, while chain-specific power is reached directly on `AlgoOps` or via its native escape hatch (the `algonaut` client accessors).

## Usage

Consume as a git dependency, pinned to a tag:

```toml
blockchain_ops = { git = "https://github.com/richdrich/blockchain_ops_rust", tag = "v0.1.0" }
algo_ops = { git = "https://github.com/richdrich/blockchain_ops_rust", tag = "v0.1.0" }
```

## Development

```
cargo build
cargo test
cargo clippy --workspace --all-targets
cargo fmt --check
```

### Tests

`algo_ops` splits its tests into two buckets (declared in `algo_ops/Cargo.toml`):

- **`unit`** — no external services; run by a bare `cargo test`.
- **`integration`** — localnet/dapp tests that need [algokit] localnet running
  (algod on `localhost:4001`). Marked `test = false`, so a bare `cargo test`
  skips them; run them explicitly with `cargo test -p algo_ops --test integration`
  after `algokit localnet start`.

### Continuous integration

The `integration` bucket runs in GitHub Actions
(`.github/workflows/integration.yml`) against algokit localnet. It is kept off
the fast per-push path because it needs Docker and is slow; it is triggered:

- nightly on a schedule,
- on a pull request that carries the `localnet` label, and
- manually via `workflow_dispatch` from the Actions tab.

[`algonaut`]: https://crates.io/crates/algonaut
[algokit]: https://github.com/algorandfoundation/algokit-cli
