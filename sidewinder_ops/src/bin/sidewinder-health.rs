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
//! Usage:
//! ```text
//! sidewinder-health --url URL --node-identity ADDRESS [--path PATH] [--mnemonic-file FILE]
//! ```
//! The enrolled **client** account (its `allow_sw_client` bit must be set so the node admits it) is
//! taken from `--mnemonic-file`, or the `SIDEWINDER_ACCOUNT_MNEMONIC` environment variable.
//!
//! Exit codes: `0` a served 2xx response, `3` a served non-2xx (e.g. `/health` 503 "not ready"), `2` the
//! node was unreachable or the handshake failed, `1` a usage or configuration error. The response body
//! is written to stdout; the HTTP status and diagnostics to stderr.

use std::process::ExitCode;

use algo_ops::AlgoOps;
use anyhow::{Context, Result, anyhow, bail};
use sidewinder_ops::SidewinderClient;

const USAGE: &str = "sidewinder-health --url <https-base> --node-identity <algo-address> \
[--path <path>] [--mnemonic-file <path>]\n  account mnemonic: --mnemonic-file or \
SIDEWINDER_ACCOUNT_MNEMONIC";

struct Args {
    url: String,
    node_identity: String,
    path: String,
    mnemonic_file: Option<String>,
}

fn parse_args() -> Result<Args> {
    let mut url = None;
    let mut node_identity = None;
    let mut path = String::from("/health");
    let mut mnemonic_file = None;

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--url" => url = Some(next_value(&mut it, "--url")?),
            "--node-identity" => node_identity = Some(next_value(&mut it, "--node-identity")?),
            "--path" => path = next_value(&mut it, "--path")?,
            "--mnemonic-file" => mnemonic_file = Some(next_value(&mut it, "--mnemonic-file")?),
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown argument `{other}`\n{USAGE}"),
        }
    }

    Ok(Args {
        url: url.ok_or_else(|| anyhow!("missing --url\n{USAGE}"))?,
        node_identity: node_identity.ok_or_else(|| anyhow!("missing --node-identity\n{USAGE}"))?,
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

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("sidewinder-health: {error:#}");
            // a build/usage error is exit 1; reachability failures are handled inside run() as exit 2.
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let args = parse_args()?;
    let mnemonic = load_mnemonic(&args.mnemonic_file)?;

    // the account key mints this client's identity certificate; no parent-chain call is made (the node
    // URL and identity are supplied), so the chain config is irrelevant here.
    let algo = AlgoOps::new_for_algorand(Some(mnemonic), None, None);
    let client = SidewinderClient::connect_pinned(algo, &args.url, &args.node_identity)
        .context("building the mutual-TLS client")?;

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
            eprintln!("unreachable/handshake failed for {}: {error:#}", args.url);
            Ok(ExitCode::from(2))
        }
    }
}
