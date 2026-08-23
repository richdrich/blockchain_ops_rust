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
use sidewinder_ops::{AppArg, SidewinderClient, SidewinderConfig, SidewinderOps, TransactionRequest};

let algo = AlgoOps::new_for_algorand(Some(passphrase), None, Some(chain_config));
let client = SidewinderClient::from_algo_ops(
    algo,
    SidewinderConfig::new("http://localhost:12122", "node-token"),
);

let alive = client.health()?;
let params = client.params()?;

// Build, canonically encode, and sign a `Slot.set(slot_id, value)` with the enrolled key,
// then submit it — `submit_transaction` does all three in one call.
let request = TransactionRequest {
    txn_type: 2, // the type the node binds `Slot.set` to
    args: vec![AppArg::Bytes(slot_id), AppArg::Bytes(value)],
    max_fee: params.min_fee,
    first_valid: params.last_round,
    last_valid: params.last_round + params.max_validity_window,
    instance: params.instance_id,
    note: None,
    group: None,
};
let txid = client.submit_transaction(&request)?;
let pending = client.status(&txid, false)?;
```

## Design notes

- Speaks only the HTTP contract — no code dependency on the `sidewinder` crates. Neutral types on the
  boundary keep consumers decoupled from the node's internal versions.
- Synchronous API over the async `reqwest` stack, driven on a per-call Tokio runtime — the same shape
  `algo_ops` uses over algod.
- Certificate and proof bytes are surfaced opaque and are **not** verified (a v0.0.2 non-goal).
- The client owns the Sidewinder canonical MessagePack encoding, packs operation arguments with the
  shared `algo_ops::AppArg` (the Algorand application-arguments / Algorand Request for Comments 4,
  ARC-4, convention), and signs the canonical body with the enrolled `algo_ops` Ed25519 key
  (`AlgoOps::sign_bytes`). `build_signed_transaction` returns the bytes and transaction identifier;
  `submit_transaction` builds, signs, and submits. `submit` still accepts pre-encoded bytes directly.

## Tests

`cargo test -p sidewinder_ops` runs the `unit` bucket against an in-process mock HTTP node — no
external services required.
