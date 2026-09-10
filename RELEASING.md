# Releasing

How the crates are published to [crates.io]. For day-to-day development see
[DEVELOPER.md](DEVELOPER.md).

## Flow

`master` always sits one patch ahead of the published release (e.g. crates.io at
`0.7.7`, `master` at `0.7.8`). Releasing that version is one command, run by the
repo owner from a clean checkout with `gh` authenticated:

```
scripts/deploy 0.7.8
```

The argument is the version to publish and must equal the version already on
`master` — it is a safety assertion of exactly what ships (pass `--yes` to skip
the pre-publish confirmation prompt). [`scripts/deploy`](scripts/deploy) then, in
order:

1. **Raises the deployment pull request (PR)** `master` -> `deployed` and labels
   it `localnet` so the `integration` check runs on it. The `deploy-guard` check
   enforces that the PR head is a commit already on `master`.
2. **Waits for the required checks** (`quality`, `unit`, `integration`) to pass.
3. **Merges it** with `--admin` (the owner cannot self-approve a review gate, and
   the checks are already green). The push to `deployed` triggers
   [`deploy.yml`](.github/workflows/deploy.yml), which re-runs every gate, then
   publishes `blockchain_ops`, `algo_ops`, `sw_identity_tls`, then `sidewinder_ops`
   to crates.io via Trusted Publishing (OpenID Connect / OIDC — no stored registry
   token; each is published before the crates that depend on it), and tags the
   commit `vX.Y.Z`.
4. **Waits for that deploy run to succeed**, then **bumps `master` to the next
   patch** (`cargo set-version`, all crates in lockstep) and pushes it **directly,
   with no PR**, so `master` is ready for the following deploy.

To deploy manually instead (e.g. `gh`/script unavailable), do steps 1–3 by hand —
open the `master` -> `deployed` PR, add the `localnet` label, get it green, merge
— then bump `master` yourself (`cargo set-version --bump patch`, commit, push);
`deploy.yml` no longer opens a bump PR.

## One-time setup (required before the first deploy)

The crates are brand-new on crates.io, and a Trusted Publisher cannot be
configured on a crate that does not exist yet — so the very first publish is
manual, after which continuous integration (CI) is token-free.

1. **First publish (manual, once).** With a crates.io API token exported as
   `CARGO_REGISTRY_TOKEN` (`export CARGO_REGISTRY_TOKEN=<token>`, or run
   `cargo login` once instead), from a clean `master` checkout, publish the
   dependency first:

   ```
   cargo publish -p blockchain_ops
   ```

   then, once each is visible on crates.io, publish the crates that depend on it,
   in order:

   ```
   cargo publish -p algo_ops
   ```

   ```
   cargo publish -p sidewinder_ops
   ```

   A crate must be bootstrapped this way **once, when it is first added** — a
   Trusted Publisher cannot be configured on a crate that does not exist yet.
   `sidewinder_ops` was added after `blockchain_ops`/`algo_ops` were already
   published, so it needs its own one-time manual publish (of the current
   `master` version) before the deploy job can publish it via OIDC.

   **`sw_identity_tls`** was added the same way and also needs this one-time
   bootstrap. It depends on `algo_ops`, so that dependency must be on crates.io at
   a version its requirement accepts before the manual publish resolves — publish
   `algo_ops` first (as above), then:

   ```
   cargo publish -p sw_identity_tls
   ```

   Then configure Trusted Publishing for it (below). After that the deploy job
   publishes it via OIDC, in order after `algo_ops` and before `sidewinder_ops`.

2. **Configure Trusted Publishing** for each crate on crates.io — `blockchain_ops`,
   `algo_ops`, `sw_identity_tls`, and `sidewinder_ops` (crate → Settings → Trusted Publishing):
   GitHub repository `richdrich/blockchain_ops_rust`, workflow `deploy.yml`. After
   this the deploy job authenticates via OIDC and no registry token is ever stored.

3. **Protect `deployed`** with branch protection / a ruleset requiring the
   `quality`, `unit`, and `integration` status checks, so a deployment PR cannot
   merge unless all gates are green. `scripts/deploy` waits for those checks and
   then merges with `--admin`, so the release actor must have **admin** on the
   repo (the owner does) and be allowed to bypass the check/review requirement on
   merge.

4. **Allow the release actor to push directly to `master`.** The script's final
   step bumps `master` to the next patch with a PR-less push. If `master` is
   protected, add the owner (or the release actor) to that rule's **bypass list**
   so the direct push is accepted; otherwise the bump must be done by hand.

The former version-bump GitHub App (and its `VERSION_BUMP_APP_ID` /
`VERSION_BUMP_APP_PRIVATE_KEY` secrets) is **no longer used** — the bump is a
direct push from `scripts/deploy` — and those secrets can be removed.

After these steps, every subsequent release is just `scripts/deploy <version>`.

[crates.io]: https://crates.io
