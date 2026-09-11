//! End-to-end discovery + identity-pinned mutual TLS against a running membership application (#375).
//!
//! Given a membership app id, resolve the live cluster-node endpoints on-chain and connect to one over
//! identity-bound mutual TLS, pinning its Algorand identity. Configured from the environment and **skips
//! cleanly** (returns without failing) when the app / parent chain is not configured or not reachable, so
//! a bare `cargo test --test integration` stays green without infrastructure.
//!
//! Environment:
//! - `SIDEWINDER_DISCOVERY_APP_ID` — the membership application id to resolve nodes from (required).
//! - `SIDEWINDER_ACCOUNT_MNEMONIC` — an enrolled caller mnemonic; its key is this client's TLS identity.
//! - parent chain: localnet by default ([`AlgoChainConfig::default`]); a real deployment sets its own.

use algo_ops::{AlgoChainConfig, AlgoOps};
use sidewinder_ops::{DiscoveryConfig, SidewinderClient, SidewinderOps, resolve_nodes};

fn app_id_from_env() -> Option<u64> {
    std::env::var("SIDEWINDER_DISCOVERY_APP_ID")
        .ok()
        .and_then(|value| value.trim().parse().ok())
}

/// The client `AlgoOps` (its account key is the mutual-TLS identity), or `None` to skip.
fn discovery_algo() -> Option<AlgoOps> {
    let mnemonic = std::env::var("SIDEWINDER_ACCOUNT_MNEMONIC").ok()?;
    Some(AlgoOps::new_for_algorand(
        Some(mnemonic),
        None,
        Some(AlgoChainConfig::default()),
    ))
}

#[test]
fn resolves_and_connects_to_a_permitted_node_over_mtls() {
    let (Some(app_id), Some(algo)) = (app_id_from_env(), discovery_algo()) else {
        eprintln!(
            "skipping resolves_and_connects_to_a_permitted_node_over_mtls: set \
             SIDEWINDER_DISCOVERY_APP_ID and SIDEWINDER_ACCOUNT_MNEMONIC to run — see \
             tests/integration/README.md"
        );
        return;
    };

    let cfg = DiscoveryConfig::bingle(app_id);

    // Reachability gate: skip (do not fail) when the parent chain is not up or the app is empty.
    let nodes = match resolve_nodes(&algo, &cfg) {
        Ok(nodes) if !nodes.is_empty() => nodes,
        Ok(_) => {
            eprintln!("skipping: app {app_id} has no permitted node with a published endpoint");
            return;
        }
        Err(error) => {
            eprintln!("skipping: could not reach the parent chain to resolve nodes: {error}");
            return;
        }
    };

    // every resolved node carries a reachable endpoint bound to its identity.
    for node in &nodes {
        assert!(
            node.base_url().is_some(),
            "resolved node {} must advertise a reachable endpoint",
            node.identity
        );
    }

    // resolve-then-connect to the first node over identity-pinned mutual TLS, then reach it.
    let (client, node) =
        SidewinderClient::resolve_and_connect(algo, &cfg).expect("resolve and connect over mTLS");
    assert!(
        client
            .health()
            .expect("health over discovered mutual-TLS connection"),
        "the client reaches node {} it discovered and pinned",
        node.identity
    );
}
