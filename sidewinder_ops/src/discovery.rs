//! Discovery + identity-pinned mutual TLS for reaching a Sidewinder node (Sidewinder #240/#375).
//!
//! The reusable client half of authenticated access: given an application id, resolve a network's live
//! cluster-node endpoints on-chain, then connect to one over TLS **pinning that node's Algorand
//! identity** — so a fake endpoint, or a node presenting an identity other than the one resolved, is
//! rejected at the handshake. It uses only the `sw_identity_tls` client subset (`generate` for this
//! client's own credential + `IdentityServerVerifier` to authenticate the node); it never authenticates
//! inbound peers or maintains a membership cache (those are the node/server side).
//!
//! Discovery reads the endpoint each permitted cluster node published into the application's per-account
//! local state ([`sw_identity_tls::EndpointResolver`]), so a client finds where the network is from the
//! app id alone and reconnects to a rotated endpoint on the next resolve.

use std::sync::Arc;

use algo_ops::AlgoOps;
use anyhow::{Result, anyhow};
use ed25519_dalek::SigningKey;
use rustls::ClientConfig;
use sw_identity_tls::client::{IdentityServerVerifier, client_config};
use sw_identity_tls::{
    EndpointRecord, EndpointResolver, MembershipAuthority, Role, StaticMembership, bit_decoder,
    default_provider, generate,
};

/// How to discover the permitted cluster nodes of an application: the local-state key/bit that marks a
/// permitted cluster node (`allow_sw_node`) and the key its endpoint record lives under. These are the
/// deploying application's schema (for the Bingle contract: `allow_static` bit 2, endpoint `rsvd_l_b1`),
/// so they are given explicitly rather than assumed.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// the membership application's id whose opted-in cluster-node accounts publish endpoints.
    pub app_id: u64,
    /// local-state key holding the packed allow bitfield that gates cluster-node membership.
    pub allow_key: String,
    /// bit in the allow bitfield marking a permitted Sidewinder cluster node (`allow_sw_node`).
    pub node_bit: u8,
    /// local-state key each node publishes its endpoint record under.
    pub endpoint_key: String,
    /// the resolver scan's freshness window (seconds); `None` refreshes incrementally each call.
    pub cache_lifetime_secs: Option<u64>,
}

impl DiscoveryConfig {
    /// A config for the Bingle DApp contract: `allow_static` bitfield with `allow_sw_node` at bit 2, and
    /// the endpoint record in the reserved `rsvd_l_b1` byte-slice (bingle_rust#234/#237).
    pub fn bingle(app_id: u64) -> Self {
        Self {
            app_id,
            allow_key: "allow_static".to_string(),
            node_bit: 2,
            endpoint_key: "rsvd_l_b1".to_string(),
            cache_lifetime_secs: None,
        }
    }
}

/// A resolved cluster node: its Algorand identity address and the endpoint record it published. The
/// identity is what a connecting client pins in the TLS handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredNode {
    /// the node's Algorand identity address (the value the TLS verifier authenticates the node against).
    pub identity: String,
    /// the node's published reachable endpoint(s).
    pub endpoint: EndpointRecord,
}

impl DiscoveredNode {
    /// The `https` base URL for this node's first advertised address (IPv4 preferred), or `None` if the
    /// record carries no address. IPv6 is bracketed by [`std::net::SocketAddr`]'s formatting.
    pub fn base_url(&self) -> Option<String> {
        self.endpoint
            .socket_addrs()
            .first()
            .map(|addr| format!("https://{addr}"))
    }
}

/// Resolve the live, permitted cluster nodes of `cfg.app_id` and their published endpoints, using `algo`
/// for parent-chain access. Only nodes holding the `allow_sw_node` bit are returned, so an endpoint
/// published by an unpermitted account cannot poison discovery. A redeploy that rewrites an endpoint is
/// observed on the next call within the freshness window.
pub fn resolve_nodes(algo: &AlgoOps, cfg: &DiscoveryConfig) -> Result<Vec<DiscoveredNode>> {
    let resolver = EndpointResolver::new(
        algo.clone(),
        cfg.app_id,
        cfg.cache_lifetime_secs,
        cfg.endpoint_key.clone(),
        bit_decoder(cfg.allow_key.clone(), cfg.node_bit),
    );
    Ok(resolver
        .resolve()?
        .into_iter()
        .map(|(identity, endpoint)| DiscoveredNode { identity, endpoint })
        .collect())
}

/// Build the mutual-TLS [`ClientConfig`] for reaching a node: it presents `own`'s identity certificate
/// and **pins the server to exactly `node_identity`** — the node must present a certificate bound to
/// that Algorand identity (any other authentic node, or a forged certificate, is rejected). The pin is a
/// single-entry [`StaticMembership`]; no membership cache or node call is involved.
pub fn pinned_client_config(own: &SigningKey, node_identity: &str) -> Result<ClientConfig> {
    let provider = default_provider();
    let authority: Arc<dyn MembershipAuthority> =
        Arc::new(StaticMembership::new().with(node_identity, Role::ClusterNode));
    let verifier = Arc::new(IdentityServerVerifier::new_for_role(
        authority,
        provider,
        Role::ClusterNode,
    ));
    let cert = generate(own).map_err(|e| anyhow!("mint client identity certificate: {e}"))?;
    client_config(cert, verifier).map_err(|e| anyhow!("build client mutual-TLS config: {e}"))
}

/// This account's Ed25519 identity key, from its parent-chain seed — the identity the client's
/// certificate is bound to (so a node running inbound-client mutual TLS authorizes it as a client).
pub(crate) fn identity_key(algo: &AlgoOps) -> Result<SigningKey> {
    let seed = algo.private_key_bytes()?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow!("account seed must be 32 bytes for a TLS identity"))?;
    Ok(SigningKey::from_bytes(&seed))
}
