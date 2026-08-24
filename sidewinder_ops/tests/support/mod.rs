//! Shared test-support scaffolding for the sidewinder_ops unit suite.
//!
//! Included into the test binary via `#[path = "support/mod.rs"] mod support;`.
#![allow(dead_code)]

pub mod mock_node;

use algo_ops::AlgoOps;
use sidewinder_ops::{SidewinderClient, SidewinderConfig};

/// The bearer token the mock node and client agree on in tests.
pub const TEST_TOKEN: &str = "test-token";

/// A fixed 32-byte seed as a "b64:" secret, so the derived signing key — and therefore every
/// signature — is deterministic and needs no running node. It is the little-endian bytes `0..=31`.
pub const TEST_SEED_B64: &str = "b64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// The raw 32-byte seed behind [`TEST_SEED_B64`], for building the matching key in a test.
pub const TEST_SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// Build a client pointed at `base_url` with [`TEST_TOKEN`]. The `AlgoOps` handle carries no key —
/// #44's endpoints do not sign — so it is an indexer-only construction.
pub fn client_for(base_url: &str) -> SidewinderClient {
    let algo = AlgoOps::new_for_algorand(None, None, None);
    SidewinderClient::from_algo_ops(algo, SidewinderConfig::new(base_url, TEST_TOKEN))
}

/// Build a client whose `AlgoOps` handle holds the deterministic [`TEST_SEED_B64`] key, so it can
/// build and sign transactions. Building and signing make no network calls, so `base_url` need only
/// point at a running mock node for the tests that go on to `submit`.
pub fn signing_client_for(base_url: &str) -> SidewinderClient {
    let algo = AlgoOps::new_for_algorand(Some(TEST_SEED_B64.to_string()), None, None);
    SidewinderClient::from_algo_ops(algo, SidewinderConfig::new(base_url, TEST_TOKEN))
}

// ── external node-nest configuration (integration target) ────────────────────
// The `integration` bucket drives a real nest of Sidewinder nodes, configured entirely from the
// environment so the test carries no infrastructure. It skips cleanly (returns early, does not fail)
// when the nest is not configured or not reachable — see `tests/integration/README.md`.

/// Connection details for a running Sidewinder node nest, read from the environment.
pub struct NestConfig {
    /// One or more node base URLs (`SIDEWINDER_NODES`, comma-separated). Submitting on the first and
    /// reading on the last exercises cross-node visibility when more than one is given.
    pub node_urls: Vec<String>,
    /// The bearer token every node accepts (`SIDEWINDER_TOKEN`).
    pub token: String,
    /// A 25-word Algorand mnemonic for an enrolled caller (`SIDEWINDER_ACCOUNT_MNEMONIC`); its key
    /// signs the transactions and must be allowlisted in the nest.
    pub mnemonic: String,
}

/// Read a [`NestConfig`] from the environment, or `None` when the nest is not configured — the
/// signal for a test to skip. `SIDEWINDER_TOKEN` defaults to empty (a nest with auth disabled);
/// the node list and the signing mnemonic are required.
pub fn nest_from_env() -> Option<NestConfig> {
    let node_urls: Vec<String> = std::env::var("SIDEWINDER_NODES")
        .ok()?
        .split(',')
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect();
    if node_urls.is_empty() {
        return None;
    }
    let mnemonic = std::env::var("SIDEWINDER_ACCOUNT_MNEMONIC").ok()?;
    let token = std::env::var("SIDEWINDER_TOKEN").unwrap_or_default();
    Some(NestConfig {
        node_urls,
        token,
        mnemonic,
    })
}

/// A signing client pointed at one node `url` of the nest, using the configured caller key and token.
pub fn nest_client(url: &str, config: &NestConfig) -> SidewinderClient {
    let algo = AlgoOps::new_for_algorand(Some(config.mnemonic.clone()), None, None);
    SidewinderClient::from_algo_ops(algo, SidewinderConfig::new(url, &config.token))
}
