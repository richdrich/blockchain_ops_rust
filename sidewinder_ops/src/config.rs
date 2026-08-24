//! Endpoint configuration for a Sidewinder node.

use serde::{Deserialize, Serialize};

/// How to reach a Sidewinder node: its base Uniform Resource Locator (URL) and the bearer token
/// required on every endpoint but `/health`.
///
/// Mirrors the role [`algo_ops::AlgoChainConfig`] plays for algod. Unlike that type there is no
/// `Default`: a node URL and token are deployment-specific, and per the project guidelines traits and
/// production types do not fabricate defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidewinderConfig {
    /// Base URL of the node, for example `http://localhost:12122`. A trailing slash is tolerated.
    pub base_url: String,
    /// Bearer token sent as `Authorization: Bearer <token>` on authenticated endpoints.
    pub token: String,
}

impl SidewinderConfig {
    /// Construct a config from a base URL and bearer token.
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            token: token.into(),
        }
    }

    /// The base URL without a trailing slash, so path joining does not double up separators.
    pub(crate) fn trimmed_base(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }
}
