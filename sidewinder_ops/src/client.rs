//! The synchronous Sidewinder node client.
//!
//! [`SidewinderClient`] presents a blocking API over the async `reqwest` stack by driving each request
//! on a fresh current-thread Tokio runtime ([`SidewinderClient::rt_block_on`]) — the same shape
//! [`algo_ops::AlgoOps`] uses over algod. It implements [`SidewinderOps`], one method per endpoint of
//! the reconciled `sidewinder_rest.yaml` v0.1.1 contract.

use crate::config::SidewinderConfig;
use crate::error::SidewinderError;
use crate::transaction::{SignedTransaction, TransactionRequest, build_signed};
use crate::types::{
    NodeStatus, NodeStatusWire, OperationSchema, OperationSchemaWire, PendingTransaction,
    PendingWire, PostTransactionResponseWire, SuggestedParams, SuggestedParamsWire,
};
use algo_ops::AlgoOps;
use anyhow::{Result, anyhow};
use reqwest::Method;
use rustls::ClientConfig;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;

use crate::discovery::{DiscoveredNode, DiscoveryConfig, identity_key, pinned_client_config};

/// The client-facing surface of a Sidewinder node.
///
/// One method per REST endpoint. All return [`anyhow::Result`]; the error downcasts to
/// [`SidewinderError`] for a plain-typed classification (unreachable, unauthorized, not-found, …).
/// Every method but [`SidewinderOps::health`] sends the configured bearer token.
pub trait SidewinderOps {
    /// Submit one canonically-encoded, signed transaction; returns the content-address identifier.
    ///
    /// `signed_txn` is the raw MessagePack-encoded `SignedTransaction` bytes. Build them with
    /// [`SidewinderClient::build_signed_transaction`], or use
    /// [`SidewinderClient::submit_transaction`] to build, sign, and submit in one call.
    fn submit(&self, signed_txn: &[u8]) -> Result<String>;

    /// Fetch the current response for a transaction. Set `proof` to also return the (opaque, v0)
    /// certificate and Merkle proof bytes.
    fn status(&self, txid: &str, proof: bool) -> Result<PendingTransaction>;

    /// Long-poll form of [`SidewinderOps::status`]: the node holds the request open until the stage
    /// advances or `wait_secs` elapses.
    ///
    /// A terminal unsuccessful outcome (`Failed`, `Rejected`, `Expired`) is returned as `Ok` with the
    /// node's reason in [`PendingTransaction::error`](crate::PendingTransaction::error), not as an
    /// error: the request worked, and re-submitting will not change the outcome. Check
    /// [`Stage::is_terminal`](crate::Stage::is_terminal) to stop polling and
    /// [`Stage::is_unsuccessful`](crate::Stage::is_unsuccessful) to stop retrying.
    fn watch(&self, txid: &str, proof: bool, wait_secs: u64) -> Result<PendingTransaction>;

    /// Suggested parameters for building a transaction header.
    fn params(&self) -> Result<SuggestedParams>;

    /// The node's view of the parent chain and node set.
    fn node_status(&self) -> Result<NodeStatus>;

    /// Operation configuration for a transaction type, or `None` if none is configured (HTTP 404).
    fn operations(&self, typ: u32) -> Result<Option<OperationSchema>>;

    /// Liveness probe. `true` when the node is serving (HTTP 200), `false` when not ready (HTTP 503).
    fn health(&self) -> Result<bool>;
}

/// A client for one Sidewinder node, built on an [`AlgoOps`] parent-chain handle plus endpoint config.
///
/// Two transports: the default plaintext-plus-bearer surface ([`from_algo_ops`](Self::from_algo_ops)),
/// and identity-bound **mutual TLS** ([`connect`](Self::connect) / [`mtls`](Self::mtls)) where the node
/// is authenticated by its on-chain identity and the bearer token is not used.
pub struct SidewinderClient {
    algo: AlgoOps,
    config: SidewinderConfig,
    // `Some` selects the mutual-TLS transport: reqwest is built with this preconfigured client config
    // (which pins the node's identity and presents ours) and no bearer token is sent. `None` is the
    // default plaintext + bearer surface, byte-for-byte as before.
    tls: Option<Arc<ClientConfig>>,
}

// Number of retries and backoff base for unreachable-host errors — mirrors the algo_ops policy.
const MAX_RETRIES: u32 = 3;
const RETRY_BASE_MS: u64 = 1_000;

// Why one send failed, classified while the error is still typed (before it is flattened to text).
enum SendFailure {
    // the node completed the mutual-TLS handshake far enough to refuse this client's identity with the
    // `access_denied` alert. Carries the full cause chain.
    IdentityRefused(String),
    // the request could not be sent, or its response could not be read. Carries the full cause chain —
    // `reqwest`'s own message is only "error sending request for url (…)", which names no cause.
    Transport(String),
    // a local failure before anything was sent (the HTTP client could not be built).
    Local(anyhow::Error),
}

impl SendFailure {
    // Classify a failed `reqwest` call. `mutual_tls` is whether this client presented an identity
    // certificate — only then can an `access_denied` alert mean "the node refused this identity".
    fn from_reqwest(error: reqwest::Error, mutual_tls: bool) -> Self {
        let chain = cause_chain(&error);
        if mutual_tls && refused_with_access_denied(&error, &chain) {
            SendFailure::IdentityRefused(chain)
        } else {
            SendFailure::Transport(chain)
        }
    }
}

// The error and every cause beneath it, outermost first, joined with ": " — the whole story rather
// than the top-level summary. A cause whose text an outer message already includes is not repeated.
fn cause_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut chain = error.to_string();
    let mut cause = error.source();
    while let Some(inner) = cause {
        let text = inner.to_string();
        if !chain.contains(&text) {
            chain.push_str(": ");
            chain.push_str(&text);
        }
        cause = inner.source();
    }
    chain
}

// Whether `error` was caused by the peer sending the TLS `access_denied` alert — how a Sidewinder node
// refuses an authentic identity it does not permit. Checked on the typed `rustls` error where the
// chain exposes it; an I/O error hides its payload from `source()`, so that is looked inside too. The
// text check is the fallback for a chain that carries the alert only as a message.
fn refused_with_access_denied(error: &(dyn std::error::Error + 'static), chain: &str) -> bool {
    fn is_access_denied(error: &(dyn std::error::Error + 'static)) -> bool {
        matches!(
            error.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::AlertReceived(
                rustls::AlertDescription::AccessDenied
            ))
        )
    }
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = cause {
        if is_access_denied(current) {
            return true;
        }
        if let Some(io) = current.downcast_ref::<std::io::Error>()
            && let Some(payload) = io.get_ref()
            && is_access_denied(payload)
        {
            return true;
        }
        cause = current.source();
    }
    chain.contains("received fatal alert: AccessDenied")
}

impl SidewinderClient {
    /// Build a client from an Algorand operations handle (which signs transactions) and endpoint config.
    /// The default plaintext transport: requests carry the config's bearer token.
    pub fn from_algo_ops(algo: AlgoOps, config: SidewinderConfig) -> Self {
        Self {
            algo,
            config,
            tls: None,
        }
    }

    /// Build a mutual-TLS client for a node at `base_url` (an `https://` URL), using `tls` to
    /// authenticate the node by its Algorand identity and present this client's own identity
    /// certificate. No bearer token is sent — mutual TLS is the authentication. Prefer
    /// [`connect`](Self::connect), which discovers the endpoint and pins the identity for you.
    pub fn mtls(algo: AlgoOps, base_url: impl Into<String>, tls: Arc<ClientConfig>) -> Self {
        Self {
            algo,
            // the bearer token is unused on the mutual-TLS transport; keep an empty one.
            config: SidewinderConfig::new(base_url, String::new()),
            tls: Some(tls),
        }
    }

    /// Discover `node`'s endpoint (already resolved from the app id) and connect to it over identity-bound
    /// mutual TLS, pinning `node.identity`: the node must present a certificate bound to that Algorand
    /// identity or the handshake fails. This client presents its own identity (this account's key), so a
    /// node running inbound-client mutual TLS authorizes it as a client. Errors if `node` published no
    /// reachable address, or the client identity/TLS config cannot be built.
    pub fn connect(algo: AlgoOps, node: &DiscoveredNode) -> Result<Self> {
        let base_url = node.base_url().ok_or_else(|| {
            anyhow!(
                "resolved node {} published no reachable endpoint",
                node.identity
            )
        })?;
        let own = identity_key(&algo)?;
        let tls = pinned_client_config(&own, &node.identity)?;
        Ok(Self::mtls(algo, base_url, Arc::new(tls)))
    }

    /// Connect to a node at a **known** `base_url` (an `https://` URL) over identity-bound mutual TLS,
    /// pinning `node_identity` (an Algorand address): the node must present a certificate bound to that
    /// identity or the handshake fails. Unlike [`connect`](Self::connect) this needs no discovery scan —
    /// the caller already knows where the node is and who it is (e.g. a health probe reading the cluster
    /// allowlist), so it makes **no** parent-chain call. This client presents its own identity (this
    /// account's key). Errors if the client identity or TLS config cannot be built.
    pub fn connect_pinned(
        algo: AlgoOps,
        base_url: impl Into<String>,
        node_identity: &str,
    ) -> Result<Self> {
        let own = identity_key(&algo)?;
        let tls = pinned_client_config(&own, node_identity)?;
        Ok(Self::mtls(algo, base_url, Arc::new(tls)))
    }

    /// Discover the permitted cluster nodes of `cfg.app_id` and connect to the first one that published a
    /// reachable endpoint, over identity-pinned mutual TLS ([`connect`](Self::connect)). Returns the
    /// connected client and the [`DiscoveredNode`] it bound to (so a caller can re-resolve later and
    /// reconnect if the node rotates its endpoint). Errors if no permitted node has published an endpoint.
    pub fn resolve_and_connect(
        algo: AlgoOps,
        cfg: &DiscoveryConfig,
    ) -> Result<(Self, DiscoveredNode)> {
        let nodes = crate::discovery::resolve_nodes(&algo, cfg)?;
        let node = nodes
            .into_iter()
            .find(|node| node.base_url().is_some())
            .ok_or_else(|| {
                anyhow!(
                    "no permitted cluster node of app {} has published a reachable endpoint",
                    cfg.app_id
                )
            })?;
        let client = Self::connect(algo, &node)?;
        Ok((client, node))
    }

    /// Perform a raw authenticated `GET` of `path`, returning the served `(HTTP status, body bytes)`.
    /// Over the mutual-TLS transport the node authenticates this client at the handshake; over the
    /// default transport the bearer token is sent. Only a network-level failure (an unreachable node or
    /// a failed handshake) is an `Err` — any served HTTP status (including 4xx/5xx) returns `Ok`, so a
    /// caller can inspect the code. Useful for an endpoint without a typed method, such as the raw
    /// `/v2/status` JSON a cluster health check parses.
    pub fn get(&self, path: &str) -> Result<(u16, Vec<u8>)> {
        self.send("get", Method::GET, path, None, true, None)
    }

    /// The underlying Algorand operations handle (the enrolled parent-chain account).
    pub fn algo_ops(&self) -> &AlgoOps {
        &self.algo
    }

    /// The endpoint configuration.
    pub fn config(&self) -> &SidewinderConfig {
        &self.config
    }

    /// Build, canonically encode, and sign a transaction with the enrolled parent-chain key.
    ///
    /// The sender (`snd`) is this client's [`AlgoOps`] account public key, and the signature is a
    /// plain Ed25519 over the canonical body ([`AlgoOps::sign_bytes`]). The returned
    /// [`SignedTransaction`] carries both the bytes to submit and the transaction identifier. Errors
    /// (as [`SidewinderErrorKind::InvalidTransaction`](crate::SidewinderErrorKind::InvalidTransaction))
    /// if the handle holds no signing key or a field is not the required 32 bytes.
    pub fn build_signed_transaction(
        &self,
        request: &TransactionRequest,
    ) -> Result<SignedTransaction> {
        let op = "build_signed_transaction";
        let sender = self.algo.public_key_bytes().map_err(|e| {
            SidewinderError::invalid_transaction(op, &format!("no signing key available: {e}"))
        })?;
        build_signed(op, request, sender, |bytes| self.algo.sign_bytes(bytes))
    }

    /// Build, sign, and [`submit`](SidewinderOps::submit) a transaction in one call; returns the
    /// node's transaction identifier.
    pub fn submit_transaction(&self, request: &TransactionRequest) -> Result<String> {
        let signed = self.build_signed_transaction(request)?;
        self.submit(&signed.bytes)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.config.trimmed_base(), path)
    }

    // Run an async future on a fresh current-thread Tokio runtime, handling the nested-runtime case
    // (a caller already inside a runtime) by spawning a scoped thread. Mirrors `AlgoOps::rt_block_on`.
    fn rt_block_on<T: Send>(&self, fut: impl std::future::Future<Output = T> + Send) -> Result<T> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return std::thread::scope(|s| {
                let handle = s.spawn(|| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("failed to build temporary tokio runtime");
                    rt.block_on(fut)
                });
                handle
                    .join()
                    .map_err(|_| anyhow!("rt_block_on thread panicked"))
            });
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
        Ok(rt.block_on(fut))
    }

    // Send one request, returning `(status, body)` for any served HTTP response. Only network-level
    // failures (an unreachable host, a refused handshake) surface as `Err`, classified as a
    // [`SendFailure`]; HTTP status handling is left to the callers.
    fn send_once(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        authenticated: bool,
        timeout: Option<Duration>,
    ) -> std::result::Result<(u16, Vec<u8>), SendFailure> {
        let url = self.url(path);
        let token = self.config.token.clone();
        let tls = self.tls.clone();
        let fut = async move {
            let mut builder = reqwest::Client::builder();
            if let Some(tls) = &tls {
                // mutual-TLS transport: hand reqwest the preconfigured config (node-identity pinning +
                // our client certificate); the node authenticates us at the handshake, not via a token.
                builder = builder.tls_backend_preconfigured((**tls).clone());
            }
            let mutual_tls = tls.is_some();
            let client = builder.build().map_err(|e| {
                SendFailure::Local(anyhow!("failed to build HTTP client: {}", cause_chain(&e)))
            })?;
            let mut req = client.request(method, &url);
            // bearer auth applies only to the plaintext transport; mutual TLS is the authentication.
            if authenticated && tls.is_none() {
                req = req.bearer_auth(&token);
            }
            if let Some(bytes) = body {
                req = req
                    .header(reqwest::header::CONTENT_TYPE, "application/msgpack")
                    .body(bytes);
            }
            if let Some(t) = timeout {
                req = req.timeout(t);
            }
            // in TLS 1.3 the client's handshake finishes before the node has judged its certificate,
            // so a refusal can arrive on either the send or the first read of the response.
            let resp = req
                .send()
                .await
                .map_err(|e| SendFailure::from_reqwest(e, mutual_tls))?;
            let status = resp.status().as_u16();
            let bytes = resp
                .bytes()
                .await
                .map_err(|e| SendFailure::from_reqwest(e, mutual_tls))?
                .to_vec();
            Ok::<(u16, Vec<u8>), SendFailure>((status, bytes))
        };
        self.rt_block_on(fut).map_err(SendFailure::Local)?
    }

    // The error for a node that refused this client's identity: says the node was reached, names the
    // identity it refused, and what to check — the cause chain alone only says `access_denied`.
    fn identity_refused(&self, operation: &str, chain: &str) -> SidewinderError {
        let identity = self
            .algo
            .address_str()
            .unwrap_or_else(|_| "(unknown address)".to_string());
        SidewinderError::identity_refused(
            operation,
            &format!(
                "the node at {} refused this client's identity {identity}: it is not a permitted \
                 client there. Check that the account is opted in to the node's membership \
                 application and has the client permission bit set (a newly set bit is only seen at \
                 the node's next membership poll). Cause: {chain}",
                self.config.trimmed_base()
            ),
        )
    }

    // Send with retry-and-backoff on unreachable-host errors. A served HTTP error is not retried, and
    // neither is a refused identity: the node answered, and asking again cannot change the answer.
    fn send(
        &self,
        operation: &str,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        authenticated: bool,
        timeout: Option<Duration>,
    ) -> Result<(u16, Vec<u8>)> {
        let mut attempt = 0u32;
        loop {
            match self.send_once(method.clone(), path, body.clone(), authenticated, timeout) {
                Ok(pair) => return Ok(pair),
                Err(SendFailure::IdentityRefused(chain)) => {
                    return Err(self.identity_refused(operation, &chain).into());
                }
                Err(SendFailure::Local(e)) => return Err(e),
                Err(SendFailure::Transport(msg)) => {
                    if attempt < MAX_RETRIES && SidewinderError::looks_unreachable(&msg) {
                        let delay = Duration::from_millis(RETRY_BASE_MS * (1u64 << attempt));
                        tracing::warn!(
                            "sidewinder transient error on {} (attempt {}/{}), retrying in {:?}: {}",
                            operation,
                            attempt + 1,
                            MAX_RETRIES,
                            delay,
                            msg
                        );
                        std::thread::sleep(delay);
                        attempt += 1;
                        continue;
                    }
                    if SidewinderError::looks_unreachable(&msg) {
                        return Err(SidewinderError::unreachable(operation, &msg).into());
                    }
                    return Err(anyhow!("{msg}"));
                }
            }
        }
    }
}

// Parse a JSON body into a wire type, tagging the operation on failure.
fn parse_json<T: DeserializeOwned>(operation: &str, bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|e| {
        SidewinderError::malformed_response(operation, &format!("bad JSON: {e}")).into()
    })
}

// Best-effort human message from an error body: the `message` field if present, else the raw text.
fn error_message(bytes: &[u8]) -> String {
    match serde_json::from_slice::<crate::types::ErrorWire>(bytes) {
        Ok(err) => err.message,
        Err(_) => String::from_utf8_lossy(bytes).trim().to_string(),
    }
}

impl SidewinderOps for SidewinderClient {
    fn submit(&self, signed_txn: &[u8]) -> Result<String> {
        let op = "submit";
        let (status, body) = self.send(
            op,
            Method::POST,
            "/v2/transactions",
            Some(signed_txn.to_vec()),
            true,
            None,
        )?;
        match status {
            200 => Ok(parse_json::<PostTransactionResponseWire>(op, &body)?.tx_id),
            400 => Err(SidewinderError::bad_request(op, &error_message(&body)).into()),
            401 => Err(SidewinderError::unauthorized(op, &error_message(&body)).into()),
            other => {
                Err(SidewinderError::unexpected_status(op, other, &error_message(&body)).into())
            }
        }
    }

    fn status(&self, txid: &str, proof: bool) -> Result<PendingTransaction> {
        let op = "status";
        let path = format!("/v2/transactions/pending/{txid}?proof={proof}");
        let (status, body) = self.send(op, Method::GET, &path, None, true, None)?;
        pending_from(op, status, &body)
    }

    fn watch(&self, txid: &str, proof: bool, wait_secs: u64) -> Result<PendingTransaction> {
        let op = "watch";
        let path = format!("/v2/transactions/pending/{txid}?proof={proof}&wait={wait_secs}");
        // Give the request longer than the node's long-poll window before the client gives up.
        let timeout = Duration::from_secs(wait_secs.saturating_add(30));
        let (status, body) = self.send(op, Method::GET, &path, None, true, Some(timeout))?;
        pending_from(op, status, &body)
    }

    fn params(&self) -> Result<SuggestedParams> {
        let op = "params";
        let (status, body) =
            self.send(op, Method::GET, "/v2/transactions/params", None, true, None)?;
        match status {
            200 => parse_json::<SuggestedParamsWire>(op, &body)?
                .into_params(op)
                .map_err(Into::into),
            401 => Err(SidewinderError::unauthorized(op, &error_message(&body)).into()),
            other => {
                Err(SidewinderError::unexpected_status(op, other, &error_message(&body)).into())
            }
        }
    }

    fn node_status(&self) -> Result<NodeStatus> {
        let op = "node_status";
        let (status, body) = self.send(op, Method::GET, "/v2/status", None, true, None)?;
        match status {
            200 => parse_json::<NodeStatusWire>(op, &body)?
                .into_status(op)
                .map_err(Into::into),
            401 => Err(SidewinderError::unauthorized(op, &error_message(&body)).into()),
            other => {
                Err(SidewinderError::unexpected_status(op, other, &error_message(&body)).into())
            }
        }
    }

    fn operations(&self, typ: u32) -> Result<Option<OperationSchema>> {
        let op = "operations";
        let path = format!("/v2/operations/{typ}");
        let (status, body) = self.send(op, Method::GET, &path, None, true, None)?;
        match status {
            200 => Ok(Some(
                parse_json::<OperationSchemaWire>(op, &body)?.into_schema(op)?,
            )),
            404 => Ok(None),
            401 => Err(SidewinderError::unauthorized(op, &error_message(&body)).into()),
            other => {
                Err(SidewinderError::unexpected_status(op, other, &error_message(&body)).into())
            }
        }
    }

    fn health(&self) -> Result<bool> {
        let op = "health";
        // `/health` is the one unauthenticated endpoint; 503 is a valid "not ready" answer, not an error.
        let (status, body) = self.send(op, Method::GET, "/health", None, false, None)?;
        match status {
            200 => Ok(true),
            503 => Ok(false),
            other => {
                Err(SidewinderError::unexpected_status(op, other, &error_message(&body)).into())
            }
        }
    }
}

// Map a pending-endpoint `(status, body)` to a `PendingTransaction`, shared by `status` and `watch`.
fn pending_from(op: &str, status: u16, body: &[u8]) -> Result<PendingTransaction> {
    match status {
        200 => parse_json::<PendingWire>(op, body)?
            .into_pending(op)
            .map_err(Into::into),
        401 => Err(SidewinderError::unauthorized(op, &error_message(body)).into()),
        404 => Err(SidewinderError::not_found(op, &error_message(body)).into()),
        other => Err(SidewinderError::unexpected_status(op, other, &error_message(body)).into()),
    }
}
