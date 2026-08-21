# Developing blockchain_ops_rust

Development and continuous-integration (CI) instructions for the workspace. For
what the crates are and how to depend on them, see the [README](README.md).

## Build and check

```
cargo build
cargo test
cargo clippy --workspace --all-targets
cargo fmt --check
```

## Tests

`algo_ops` splits its tests into two buckets (declared in `algo_ops/Cargo.toml`):

- **`unit`** — no external services; run by a bare `cargo test`.
- **`integration`** — localnet/dapp tests that need [algokit] localnet running
  (algod on `localhost:4001`). Marked `test = false`, so a bare `cargo test`
  skips them; run them explicitly with `cargo test -p algo_ops --test integration`
  after `algokit localnet start`.

### `test-support` feature

`AlgoOps::new` is `pub(crate)` — construct via the `AlgoOps::new_for_algorand`
factory. A handful of genuinely test-only helpers
(the JSON parsers, the retry predicate, and the `build_call_app_tx*` escape
hatches) are `pub(crate)` too, re-exported as `pub` only under the opt-in
`test-support` cargo feature. This crate's own tests enable it automatically (a
self dev-dependency in `algo_ops/Cargo.toml`), so a bare `cargo test` just works;
external consumers add `features = ["test-support"]` to their dev-dependency.

## Continuous integration

The fast path runs on every pull request and on pushes to `master`, needs no
external services, and is what you require in branch protection:

- **`quality-checks.yml`** (job `quality`) — `cargo fmt --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`, and a warning-free
  `cargo doc --no-deps --workspace`.
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

[algokit]: https://github.com/algorandfoundation/algokit-cli
[`cargo-nextest`]: https://nexte.st
