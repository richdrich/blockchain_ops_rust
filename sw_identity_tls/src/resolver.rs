//! Resolving node endpoints from only the app id — the discovery read path (#372).
//!
//! [`EndpointResolver`] enumerates the accounts opted into the membership application and decodes each
//! **permitted cluster node's** published endpoint record ([`EndpointRecord`], from the caller-named
//! endpoint local-state key) off the same incremental opted-in-accounts scan the membership cache uses
//! (#371 / algo_ops#91). It
//! yields `(node identity, endpoint)` pairs, so a client resolves a network's live endpoints from the app
//! id alone and then connects to each pinning that identity in the `sw-tls` `IdentityServerVerifier`.
//!
//! Only permitted-node records are returned (the caller supplies the "is a permitted node" decoder — the
//! `allow_sw_node` bit), so a fake endpoint from an unpermitted account is never surfaced; endpoints
//! **rotate** as a redeploy rewrites the record, observed on the next resolve within the freshness window.

use std::sync::Mutex;

use algo_ops::{AccountScanCache, AlgoOps, QueryMode, ScannedAccount};
use anyhow::{Result, anyhow};

use crate::decoder::MembershipDecoder;
use crate::endpoint::EndpointRecord;

/// Resolves the published endpoints of the permitted cluster nodes of an application, backed by the
/// incremental cached opted-in-accounts scan.
pub struct EndpointResolver {
    ops: AlgoOps,
    app_id: u64,
    cache_lifetime_secs: Option<u64>,
    // the local-state key the endpoint record is published under — named by the deploying app's schema,
    // so the resolver works against an arbitrary application exposing an endpoint field (nothing is baked
    // in).
    endpoint_key: String,
    // decides whether an account is a permitted cluster node (the `allow_sw_node` bit); only such nodes'
    // endpoints are surfaced, so an unpermitted account cannot poison discovery.
    is_node: MembershipDecoder,
    // the scan's own incremental cache (watermark + the resolved `(address, endpoint)` set), held across
    // resolves so each one only re-reads accounts changed past the watermark.
    scan: Mutex<AccountScanCache<EndpointRecord>>,
}

impl std::fmt::Debug for EndpointResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointResolver")
            .field("app_id", &self.app_id)
            .field("cache_lifetime_secs", &self.cache_lifetime_secs)
            .finish_non_exhaustive()
    }
}

impl EndpointResolver {
    /// A resolver over `app_id`, reading each node's endpoint from the local-state key `endpoint_key` and
    /// treating an account as a node when `is_node` accepts its local state, using `ops` for parent-chain
    /// access. `cache_lifetime_secs` is the scan's freshness window. The caller supplies `endpoint_key`
    /// from the deploying app's schema — the resolver bakes in no specific key.
    pub fn new(
        ops: AlgoOps,
        app_id: u64,
        cache_lifetime_secs: Option<u64>,
        endpoint_key: impl Into<String>,
        is_node: MembershipDecoder,
    ) -> Self {
        Self {
            ops,
            app_id,
            cache_lifetime_secs,
            endpoint_key: endpoint_key.into(),
            is_node,
            scan: Mutex::new(AccountScanCache::new()),
        }
    }

    /// Resolve the current `(node address, endpoint)` set of permitted cluster nodes that have published
    /// a valid endpoint. Runs an incremental scan (bootstrap once, then only rounds past the watermark);
    /// a node without the permission bit, without a record, or with a malformed one is skipped.
    pub fn resolve(&self) -> Result<Vec<(String, EndpointRecord)>> {
        let is_node = self.is_node.clone();
        let endpoint_key = self.endpoint_key.clone();
        self.ops.fetch_opted_in_accounts_cached(
            self.app_id,
            &self.scan,
            QueryMode::Refresh,
            self.cache_lifetime_secs,
            move |account: &ScannedAccount| decode_node_endpoint(&is_node, &endpoint_key, account),
        )?;
        let scan = self
            .scan
            .lock()
            .map_err(|_| anyhow!("endpoint scan cache mutex poisoned"))?;
        Ok(scan
            .entries
            .iter()
            .map(|(address, record)| (address.clone(), *record))
            .collect())
    }
}

/// the ingest for the scan: a permitted cluster node's decoded endpoint record (from `endpoint_key`), or
/// `None` to skip.
fn decode_node_endpoint(
    is_node: &MembershipDecoder,
    endpoint_key: &str,
    account: &ScannedAccount,
) -> Option<EndpointRecord> {
    if !is_node(&account.local_state) {
        return None;
    }
    let value = account
        .local_state
        .iter()
        .find(|(key, _)| key == endpoint_key)
        .map(|(_, value)| value.as_str())?;
    EndpointRecord::decode(value)
}
