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
