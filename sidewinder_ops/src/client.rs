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
use serde::de::DeserializeOwned;
use std::time::Duration;

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
pub struct SidewinderClient {
    algo: AlgoOps,
    config: SidewinderConfig,
}

// Number of retries and backoff base for unreachable-host errors — mirrors the algo_ops policy.
const MAX_RETRIES: u32 = 3;
const RETRY_BASE_MS: u64 = 1_000;

impl SidewinderClient {
    /// Build a client from an Algorand operations handle (which signs transactions) and endpoint config.
    pub fn from_algo_ops(algo: AlgoOps, config: SidewinderConfig) -> Self {
        Self { algo, config }
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
    // failures (unreachable host) surface as `Err`; HTTP status handling is left to the callers.
    fn send_once(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        authenticated: bool,
        timeout: Option<Duration>,
    ) -> Result<(u16, Vec<u8>)> {
        let url = self.url(path);
        let token = self.config.token.clone();
        let fut = async move {
            let client = reqwest::Client::builder()
                .build()
                .map_err(|e| anyhow!("failed to build HTTP client: {e}"))?;
            let mut req = client.request(method, &url);
            if authenticated {
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
            let resp = req.send().await.map_err(|e| anyhow!("{e}"))?;
            let status = resp.status().as_u16();
            let bytes = resp.bytes().await.map_err(|e| anyhow!("{e}"))?.to_vec();
            Ok::<(u16, Vec<u8>), anyhow::Error>((status, bytes))
        };
        self.rt_block_on(fut)?
    }

    // Send with retry-and-backoff on unreachable-host errors (a served HTTP error is not retried).
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
                Err(e) => {
                    let msg = e.to_string();
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
                    return Err(e);
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
