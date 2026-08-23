//! Shared test-support scaffolding for the sidewinder_ops unit suite.
//!
//! Included into the test binary via `#[path = "support/mod.rs"] mod support;`.
#![allow(dead_code)]

pub mod mock_node;

use algo_ops::AlgoOps;
use sidewinder_ops::{SidewinderClient, SidewinderConfig};

/// The bearer token the mock node and client agree on in tests.
pub const TEST_TOKEN: &str = "test-token";

/// Build a client pointed at `base_url` with [`TEST_TOKEN`]. The `AlgoOps` handle carries no key —
/// #44's endpoints do not sign — so it is an indexer-only construction.
pub fn client_for(base_url: &str) -> SidewinderClient {
    let algo = AlgoOps::new_for_algorand(None, None, None);
    SidewinderClient::from_algo_ops(algo, SidewinderConfig::new(base_url, TEST_TOKEN))
}
