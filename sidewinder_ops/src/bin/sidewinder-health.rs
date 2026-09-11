//! `sidewinder-health` — an authenticated, identity-pinned mutual-TLS probe of a Sidewinder node's
//! client API, so a cluster running in `on-chain-identity` (mutual-TLS) auth mode stays observable
//! (blockchain_ops_rust#104; consumed by the Sidewinder deploy's `check-health.sh`).
//!
//! A plain `curl` cannot reach the API under mutual TLS: every connection needs an ephemeral
//! identity-bound client certificate at the handshake (minted from an enrolled Algorand account key, not
//! a static PEM), and the node's own identity-bound certificate must be verified. This tool mints the
//! certificate from the given account, connects pinning the node's identity, and does a raw `GET` of a
//! path (default `/health`) — printing the response body so a script can parse it (e.g. `loopStalled`
//! and `lastRound` from `/v2/status`).
//!
//! The node is addressed either **directly** by `--url`, or **resolved from the chain**: with
//! `--app-id` and `--parent-chain` (an algod/indexer config) and no `--url`, the node's published
//! endpoint is discovered on-chain for the given `--node-identity` — so an operator need not track each
//! node's address.
//!
//! Usage:
//! ```text
//! sidewinder-health --node-identity ADDRESS --url URL [--path PATH] [--mnemonic-file FILE]
//! sidewinder-health --node-identity ADDRESS --app-id ID --parent-chain FILE [--path PATH] [--mnemonic-file FILE]
//! ```
//! The enrolled **client** account (its `allow_sw_client` bit must be set so the node admits it) is
//! taken from `--mnemonic-file`, or the `SIDEWINDER_ACCOUNT_MNEMONIC` environment variable.
//!
//! Exit codes: `0` a served 2xx response, `3` a served non-2xx (e.g. `/health` 503 "not ready"), `2` the
//! node was unreachable or the handshake failed, `1` a usage or configuration error (including a node
//! whose endpoint could not be resolved). The response body is written to stdout; the HTTP status and
//! diagnostics to stderr.

use std::process::ExitCode;

use algo_ops::{AlgoChainConfig, AlgoOps};
use anyhow::{Context, Result, anyhow, bail};
use sidewinder_ops::{DiscoveryConfig, SidewinderClient, resolve_nodes};

const USAGE: &str = "sidewinder-health --node-identity <algo-address> \
(--url <https-base> | --app-id <id> --parent-chain <file>) [--path <path>] [--mnemonic-file <path>]\n  \
account mnemonic: --mnemonic-file or SIDEWINDER_ACCOUNT_MNEMONIC";

struct Args {
    node_identity: String,
    // direct addressing: the node's `https://` base URL. When absent, the endpoint is resolved on-chain
    // from `app_id` + `parent_chain`.
    url: Option<String>,
    app_id: Option<u64>,
    parent_chain: Option<String>,
    path: String,
    mnemonic_file: Option<String>,
}

fn parse_args() -> Result<Args> {
    let mut node_identity = None;
    let mut url = None;
    let mut app_id = None;
    let mut parent_chain = None;
    let mut path = String::from("/health");
    let mut mnemonic_file = None;

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--node-identity" => node_identity = Some(next_value(&mut it, "--node-identity")?),
            "--url" => url = Some(next_value(&mut it, "--url")?),
            "--app-id" => {
                let raw = next_value(&mut it, "--app-id")?;
                app_id = Some(
                    raw.parse()
                        .with_context(|| format!("--app-id `{raw}` not a u64"))?,
                );
            }
            "--parent-chain" => parent_chain = Some(next_value(&mut it, "--parent-chain")?),
            "--path" => path = next_value(&mut it, "--path")?,
            "--mnemonic-file" => mnemonic_file = Some(next_value(&mut it, "--mnemonic-file")?),
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown argument `{other}`\n{USAGE}"),
        }
    }

    let node_identity = node_identity.ok_or_else(|| anyhow!("missing --node-identity\n{USAGE}"))?;
    // exactly one addressing mode: a direct URL, or on-chain resolution.
    if url.is_none() && (app_id.is_none() || parent_chain.is_none()) {
        bail!("address the node with either --url, or --app-id and --parent-chain\n{USAGE}");
    }

    Ok(Args {
        node_identity,
        url,
        app_id,
        parent_chain,
        path,
        mnemonic_file,
    })
}

fn next_value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    it.next().ok_or_else(|| anyhow!("`{flag}` needs a value"))
}

/// The enrolled client account mnemonic, from `--mnemonic-file` or `SIDEWINDER_ACCOUNT_MNEMONIC`.
fn load_mnemonic(mnemonic_file: &Option<String>) -> Result<String> {
    if let Some(file) = mnemonic_file {
        let text = std::fs::read_to_string(file)
            .with_context(|| format!("reading mnemonic file `{file}`"))?;
        let mnemonic = text.trim().to_string();
        if mnemonic.is_empty() {
            bail!("mnemonic file `{file}` is empty");
        }
        return Ok(mnemonic);
    }
    match std::env::var("SIDEWINDER_ACCOUNT_MNEMONIC") {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        _ => bail!("no account: pass --mnemonic-file or set SIDEWINDER_ACCOUNT_MNEMONIC\n{USAGE}"),
    }
}

/// Parse an algod/indexer connection config (the deploy parent-chain file) for on-chain resolution.
fn load_chain_config(file: &str) -> Result<AlgoChainConfig> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("reading parent-chain file `{file}`"))?;
    serde_json::from_str(&text).with_context(|| format!("parsing parent-chain file `{file}`"))
}

/// Build the mutual-TLS client for the target node: directly from `--url`, or by resolving the node's
/// published endpoint on-chain for its identity. Errors (exit 1) are configuration/resolution problems,
/// distinct from the node being unreachable (handled at the `get` call).
fn build_client(args: &Args, mnemonic: String) -> Result<SidewinderClient> {
    if let Some(url) = &args.url {
        // direct: no parent-chain call needed.
        let algo = AlgoOps::new_for_algorand(Some(mnemonic), None, None);
        return SidewinderClient::connect_pinned(algo, url, &args.node_identity)
            .context("building the mutual-TLS client");
    }

    // resolve the endpoint on-chain for `node_identity`.
    let app_id = args.app_id.expect("validated present without --url");
    let chain = load_chain_config(args.parent_chain.as_ref().expect("validated present"))?;
    let algo = AlgoOps::new_for_algorand(Some(mnemonic), None, Some(chain));
    let nodes = resolve_nodes(&algo, &DiscoveryConfig::bingle(app_id))
        .context("resolving node endpoints from the chain")?;
    let node = nodes
        .into_iter()
        .find(|node| node.identity == args.node_identity)
        .ok_or_else(|| {
            anyhow!(
                "node {} has no published endpoint in app {app_id} (not enrolled, or endpoint not advertised)",
                args.node_identity
            )
        })?;
    SidewinderClient::connect(algo, &node).context("building the mutual-TLS client")
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("sidewinder-health: {error:#}");
            // usage / configuration / resolution errors are exit 1; reachability is exit 2 inside run().
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let args = parse_args()?;
    let mnemonic = load_mnemonic(&args.mnemonic_file)?;
    let client = build_client(&args, mnemonic)?;

    match client.get(&args.path) {
        Ok((status, body)) => {
            // stdout is the raw body (so a script can `jq` /v2/status); stderr carries the status.
            use std::io::Write;
            std::io::stdout().write_all(&body).ok();
            eprintln!("{} {} -> HTTP {status}", args.node_identity, args.path);
            if (200..300).contains(&status) {
                Ok(ExitCode::from(0))
            } else {
                Ok(ExitCode::from(3))
            }
        }
        Err(error) => {
            // an unreachable node or a failed handshake — distinct from a served non-2xx.
            eprintln!(
                "unreachable/handshake failed for {}: {error:#}",
                args.node_identity
            );
            Ok(ExitCode::from(2))
        }
    }
}
