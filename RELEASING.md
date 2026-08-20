# Releasing

How the crates are published to [crates.io]. For day-to-day development see
[DEVELOPER.md](DEVELOPER.md).

## Flow

All promotion goes through `master`, which is gated by the required `quality`
and `unit` checks (the `integration` localnet bucket also runs on every push to
`master`).

1. **Deployment pull request (PR):** open a PR from `master` into the long-lived
   `deployed` branch. The `deploy-guard` check enforces that the PR head is a
   commit already on `master`; branch protection on `deployed` requires the
   `quality`, `unit`, and `integration` checks to be green. (Add the `localnet`
   label to the deployment PR so `integration` runs on it pre-merge.)
2. **Deploy on merge:** merging the PR pushes to `deployed` and triggers
   [`deploy.yml`](.github/workflows/deploy.yml), which:
   - re-runs the fast checks, unit tests, and the localnet integration bucket;
   - publishes `blockchain_ops`, then `algo_ops`, to crates.io via Trusted
     Publishing (OpenID Connect / OIDC) — no stored registry token;
   - tags the released commit `vX.Y.Z`;
   - opens the next version-bump PR on `master` via release-plz.
3. **Version bump:** review and merge the release-plz PR on `master`; it raises
   both crates (kept in lockstep by the `version_group` in
   [`release-plz.toml`](release-plz.toml)) to the next version, ready for the
   following deploy.

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

   then, once it is visible on crates.io:

   ```
   cargo publish -p algo_ops
   ```

2. **Configure Trusted Publishing** for each crate on crates.io
   (crate → Settings → Trusted Publishing): GitHub repository
   `richdrich/blockchain_ops_rust`, workflow `deploy.yml`. After this the deploy
   job authenticates via OIDC and no registry token is ever stored.

3. **Set up the release-plz GitHub App** so the version-bump PR is authored by
   the App rather than the default `GITHUB_TOKEN` — the App's pull requests (PRs)
   trigger the required `quality`/`unit` checks, so the bump PR is mergeable.

   a. **Create the App.** GitHub → Settings → Developer settings → GitHub Apps →
      New GitHub App. Set a name (e.g. `blockchain-ops-release-plz`) and a
      homepage (your GitHub profile is fine). Under **Webhook**, uncheck
      `Active` (no webhook URL needed).

   b. **Repository permissions** (Read & write): **Contents** and
      **Pull requests**. (Add **Administration** only if you later protect the
      release tags.) No account/organization permissions are needed.

   c. **Installation scope.** Choose "Only on this account", then **Create**.

   d. **Generate a private key.** On the App's page, under
      "Private keys", click **Generate a private key** — a `.pem` file
      downloads. Note the numeric **App ID** shown near the top of the same page.

   e. **Install the App** on `richdrich/blockchain_ops_rust`
      (App page → Install App → pick the repo).

   f. **Store two repository secrets** (repo → Settings → Secrets and variables →
      Actions), with exactly these names — they are what `deploy.yml` reads:
      - `RELEASE_PLZ_APP_ID` — the numeric App ID from step (d).
      - `RELEASE_PLZ_APP_PRIVATE_KEY` — the full contents of the `.pem` file.

   The deploy job's `bump` step exchanges these for a short-lived token via
   `actions/create-github-app-token` and passes it to release-plz.

4. **Create branch protection / a ruleset on `deployed`** requiring the
   `quality`, `unit`, and `integration` status checks, so a deployment PR cannot
   merge unless all gates are green.

After these four steps, every subsequent release is just: open a deployment PR,
get it green, merge.

[crates.io]: https://crates.io
