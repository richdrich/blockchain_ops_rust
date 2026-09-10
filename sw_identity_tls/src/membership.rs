//! The authorization seam the identity verifiers query.
//!
//! [`verify_identity_cert`](crate::verify_identity_cert) authenticates a peer by its Algorand identity;
//! *authorization* — is that identity permitted, and in what capacity — is a separate decision made
//! against a [`MembershipAuthority`]. The verifier holds an `Arc<dyn MembershipAuthority>` and consults
//! it **live** on each handshake, so a membership change (e.g. a polled on-chain cache picking up a new
//! registration) takes effect without rebuilding the verifier.
//!
//! The query is defined to be **pure CPU work with no node/indexer call** — a miss is as cheap as a hit,
//! and the gate fails **closed** (an unknown identity is [`None`], i.e. not authorized). That property is
//! what makes the authenticated entry point safe against a flood of unregistered identities; it is the
//! contract every implementor must uphold.
//!
//! [`StaticMembership`] is the fixed-set implementation: it backs the static `allowlist` auth mode on the
//! node side, is how a client pins the single node identity it resolved, and is the test double for the
//! verifier suite. The polled, on-chain-backed implementation lives in the sidewinder `sw-membership`
//! crate and implements this same trait.

use std::collections::{HashMap, HashSet};
use std::fmt;

/// The capacity in which an identity is permitted on a Sidewinder network.
///
/// Mirrors the two membership sets that the static gate (`cluster/allowlist.yaml`) already distinguishes:
/// cluster nodes (`nodes:`) and API clients (`callers:`). Authentication is identical for both (the same
/// identity-bound mutual TLS); the role decides *which* surface an authenticated peer may use, gated by
/// the server-side verifier (node-to-cluster #373, inbound client #374).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// A cluster node — permitted to join consensus and connect node-to-node.
    ClusterNode,
    /// An API client — permitted to reach a node's client REST surface.
    Client,
}

/// Answers *is this Algorand identity permitted, and as what* for the TLS verifiers.
///
/// **Contract:** [`role_of`](MembershipAuthority::role_of) must be pure CPU work — **no** algod/indexer
/// call on the query path, on a hit *or* a miss — and must fail **closed** (return [`None`] for any
/// identity it has not positively admitted). Implementors that maintain their set from the chain do so
/// out-of-band (e.g. a background poll), never on demand from a query.
pub trait MembershipAuthority: Send + Sync + fmt::Debug {
    /// The role `address` is permitted, or [`None`] if it is not a member (fail closed).
    fn role_of(&self, address: &str) -> Option<Role>;

    /// Whether `address` is a member in any role. Convenience over [`role_of`](Self::role_of); it must
    /// stay I/O-free for the same reason.
    fn is_member(&self, address: &str) -> bool {
        self.role_of(address).is_some()
    }
}

/// A fixed, in-memory [`MembershipAuthority`] — the authority for the static `allowlist` auth mode, the
/// single-identity pin a resolved-then-connected client uses, and the test double for the verifier
/// suite. Built once from a known set of addresses; it never scans.
#[derive(Debug, Clone, Default)]
pub struct StaticMembership {
    roles: HashMap<String, Role>,
}

impl StaticMembership {
    /// An empty authority — admits nobody (the fail-closed baseline).
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from an explicit address-to-role mapping.
    pub fn from_roles(roles: HashMap<String, Role>) -> Self {
        Self { roles }
    }

    /// Build from the two allowlist sets — cluster `nodes` and API `callers` — mirroring
    /// `cluster/allowlist.yaml`. An address present in both is recorded as a [`Role::ClusterNode`].
    pub fn from_sets(
        nodes: impl IntoIterator<Item = String>,
        callers: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut roles = HashMap::new();
        for caller in callers {
            roles.insert(caller, Role::Client);
        }
        // nodes win over callers on overlap: the cluster role is the more privileged.
        for node in nodes {
            roles.insert(node, Role::ClusterNode);
        }
        Self { roles }
    }

    /// Add or overwrite a single member's role, returning `self` for chaining in tests and setup.
    pub fn with(mut self, address: impl Into<String>, role: Role) -> Self {
        self.roles.insert(address.into(), role);
        self
    }
}

impl MembershipAuthority for StaticMembership {
    fn role_of(&self, address: &str) -> Option<Role> {
        self.roles.get(address).copied()
    }
}

/// A bare set of addresses, all treated as [`Role::Client`]. Lets call sites and tests that only have an
/// allow-set authorize without constructing a role map.
impl MembershipAuthority for HashSet<String> {
    fn role_of(&self, address: &str) -> Option<Role> {
        self.contains(address).then_some(Role::Client)
    }
}
