# sidewinder_ops

A synchronous client for a [Sidewinder](https://github.com/richdrich/sidewinder) sidechain node.

> **Note:** Sidewinder is not released yet. This client targets the pinned `sidewinder_rest.yaml`
> v0.1.1 REST contract and is built and tested against it; it does not depend on any published
> Sidewinder crate.

`SidewinderClient` wraps the node's REST surface — the reconciled `sidewinder_rest.yaml` v0.1.1
contract — behind the `SidewinderOps` trait, one method per endpoint. It is built on an
`algo_ops::AlgoOps` handle (the enrolled parent-chain account) plus a `SidewinderConfig` naming the
node URL and bearer token.

```rust
use algo_ops::AlgoOps;
use sidewinder_ops::{SidewinderClient, SidewinderConfig, SidewinderOps};

let algo = AlgoOps::new_for_algorand(Some(passphrase), None, Some(chain_config));
let client = SidewinderClient::from_algo_ops(
    algo,
    SidewinderConfig::new("http://localhost:12122", "node-token"),
);

let alive = client.health()?;
let params = client.params()?;
let txid = client.submit(&signed_txn_bytes)?;
let pending = client.status(&txid, false)?;
```

## Design notes

- Speaks only the HTTP contract — no code dependency on the `sidewinder` crates. Neutral types on the
  boundary keep consumers decoupled from the node's internal versions.
- Synchronous API over the async `reqwest` stack, driven on a per-call Tokio runtime — the same shape
  `algo_ops` uses over algod.
- Certificate and proof bytes are surfaced opaque and are **not** verified (a v0.0.2 non-goal).
- Transaction building and signing is issue #45; until then `submit` takes pre-encoded signed bytes.

## Tests

`cargo test -p sidewinder_ops` runs the `unit` bucket against an in-process mock HTTP node — no
external services required.
