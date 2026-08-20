# blockchain_ops_rust

In producing distributed blockchain applications, we found a need for a shared high level interface to
a blockchain (initially Algorand).

This is that interface - it provides chain-agnostic operation traits (`BlockChainOps`, `AssetOps`).

It's implemented through the following two crates:

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

The fast path runs on every pull request and on pushes to `master`, needs no
external services, and is what you require in branch protection:

- **`quality-checks.yml`** (job `quality`) — `cargo fmt --check` and
  `cargo clippy --workspace --all-targets -- -D warnings`.
- **`unit-tests.yml`** (job `unit`) — builds and runs the workspace unit tests
  with [`cargo-nextest`]. A bare test run covers the `unit` bucket and the crate
  lib tests and skips the `test = false` integration target, so no localnet is
  needed.

The slower **`integration.yml`** runs the `algo_ops` `integration` bucket
against algokit localnet (Docker). It is kept off the fast per-push path and is
triggered:

- on every push to `master` (mainline guard),
- nightly on a schedule,
- on a pull request that carries the `localnet` label, and
- manually via `workflow_dispatch` from the Actions tab.

All three cancel a superseded run for the same ref (`concurrency`) so stale
runs do not pile up.

[`algonaut`]: https://crates.io/crates/algonaut
[algokit]: https://github.com/algorandfoundation/algokit-cli
[`cargo-nextest`]: https://nexte.st
