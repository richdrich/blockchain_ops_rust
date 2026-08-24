# sidewinder_ops external integration test

The `integration` bucket drives `sidewinder_ops` end to end against a running **nest** of Sidewinder
nodes: it builds and signs a `Slot.set` with an enrolled `algo_ops` key, submits it to one node,
polls to the `final` stage on another, and asserts the returned previous value (a read-after-write
across the nest).

The test carries no infrastructure. It is configured from the environment and **skips cleanly**
(passes without running) when the nest is not configured or not reachable, so a bare
`cargo test --test integration` stays green with no nest available.

## Running

```
SIDEWINDER_NODES=http://localhost:9101,http://localhost:9102 SIDEWINDER_TOKEN=dev-token SIDEWINDER_ACCOUNT_MNEMONIC="word1 word2 ... word25" cargo test -p sidewinder_ops --test integration -- --nocapture
```

| Variable | Required | Meaning |
|---|---|---|
| `SIDEWINDER_NODES` | yes | Comma-separated node base URLs. The test submits on the first and reads on the last, so listing two or more exercises cross-node visibility. |
| `SIDEWINDER_ACCOUNT_MNEMONIC` | yes | 25-word Algorand mnemonic for an **enrolled** caller; its key signs the transaction and must be in the nest's allowlist. |
| `SIDEWINDER_TOKEN` | no | Bearer token every node accepts. Defaults to empty (a nest with auth disabled). |
| `SIDEWINDER_SLOT_SET_TYPE` | no | Transaction type bound to `Slot.set` in the nest's `application.yaml`. Defaults to `2`. |

With none of these set the test prints a skip message and passes.

## Bringing up a nest

Sidewinder is private and unreleased, so there is no published image yet — the nest is built from the
sidewinder repository. This is the documented shape; the concrete compose file and its shared config
land with the sidewinder-side deploy work (a `sw-node` image plus a wired `application.yaml` that
binds `Slot`).

1. **Build the node image** from a sidewinder checkout (build context is the whole workspace):

   ```
   docker build -f deploy/Dockerfile -t sw-node:latest .
   ```

2. **Provision the shared, network-wide config** (identical on every node — see sidewinder
   `deploy/README.md`): `application.yaml` binding `Slot.get`/`Slot.set` to their transaction types,
   `allowlist.yaml` with each node's minted Boneh-Lynn-Shacham (BLS) consensus key, and
   `parent-chain.json` naming the algod endpoint. Mint each node's key with:

   ```
   sw-node keygen --out etc/node-0/consensus.key --account <THIS_NODE_ALGORAND_ADDRESS>
   ```

3. **Enrol the signing account** used by the test (`SIDEWINDER_ACCOUNT_MNEMONIC`) as a caller in
   `allowlist.yaml`, so its submissions are authorised.

4. **Run the nodes**, each with its own per-host `node.yaml` (index, `listen`, `peers`) and data
   volume, publishing its API port. A `docker compose` file over `sw-node:latest` is the convenient
   local form; nodes need no start ordering (the transport retries peers). Point `SIDEWINDER_NODES`
   at the published API ports.

## Continuous integration

CI wiring is gated on the sidewinder-side deploy artifacts above (a published/buildable `sw-node`
image and the shared config). Until those exist, the bucket is safe to invoke in CI as-is: with the
`SIDEWINDER_*` variables unset it skips and passes. When the image is available, a CI job stands up
the compose nest, exports the `SIDEWINDER_*` variables, and runs
`cargo test -p sidewinder_ops --test integration`.
