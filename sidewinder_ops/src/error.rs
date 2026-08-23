//! The client's error type.
//!
//! Mirrors [`algo_ops::AlgoError`] in shape: a `kind` plus the operation and a message, carrying a
//! plain-typed classification across the boundary (no `reqwest` types) so a consumer built against a
//! different HTTP-stack version can match on the failure without a version bump.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SidewinderErrorKind {
    /// The node could not be reached (connection refused, DNS failure, timeout).
    HostUnreachable,
    /// A transient error that exhausted all retries.
    TransientFailure,
    /// The request was rejected for a missing or invalid bearer token (HTTP 401).
    Unauthorized,
    /// The node has no record of the requested resource (HTTP 404).
    NotFound,
    /// The request was malformed and the node rejected it (HTTP 400).
    BadRequest,
    /// The node returned an unexpected HTTP status.
    UnexpectedStatus,
    /// The node's response body could not be decoded (bad JSON, bad base64, unknown enum).
    MalformedResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidewinderError {
    pub kind: SidewinderErrorKind,
    pub operation: String,
    /// The HTTP status, when the failure carried one.
    pub status: Option<u16>,
    pub message: String,
}

impl std::fmt::Display for SidewinderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(status) => write!(
                f,
                "SidewinderError ({:?}): operation '{}' failed (HTTP {}): {}",
                self.kind, self.operation, status, self.message
            ),
            None => write!(
                f,
                "SidewinderError ({:?}): operation '{}' failed: {}",
                self.kind, self.operation, self.message
            ),
        }
    }
}

impl std::error::Error for SidewinderError {}

impl SidewinderError {
    pub fn unreachable(operation: &str, message: &str) -> Self {
        Self {
            kind: SidewinderErrorKind::HostUnreachable,
            operation: operation.to_string(),
            status: None,
            message: message.to_string(),
        }
    }

    pub fn transient(operation: &str, message: &str) -> Self {
        Self {
            kind: SidewinderErrorKind::TransientFailure,
            operation: operation.to_string(),
            status: None,
            message: message.to_string(),
        }
    }

    pub fn unauthorized(operation: &str, message: &str) -> Self {
        Self {
            kind: SidewinderErrorKind::Unauthorized,
            operation: operation.to_string(),
            status: Some(401),
            message: message.to_string(),
        }
    }

    pub fn not_found(operation: &str, message: &str) -> Self {
        Self {
            kind: SidewinderErrorKind::NotFound,
            operation: operation.to_string(),
            status: Some(404),
            message: message.to_string(),
        }
    }

    pub fn bad_request(operation: &str, message: &str) -> Self {
        Self {
            kind: SidewinderErrorKind::BadRequest,
            operation: operation.to_string(),
            status: Some(400),
            message: message.to_string(),
        }
    }

    pub fn unexpected_status(operation: &str, status: u16, message: &str) -> Self {
        Self {
            kind: SidewinderErrorKind::UnexpectedStatus,
            operation: operation.to_string(),
            status: Some(status),
            message: message.to_string(),
        }
    }

    pub fn malformed_response(operation: &str, message: &str) -> Self {
        Self {
            kind: SidewinderErrorKind::MalformedResponse,
            operation: operation.to_string(),
            status: None,
            message: message.to_string(),
        }
    }

    /// True when a `reqwest` error string looks like an unreachable host rather than a served
    /// HTTP response, so [`crate::SidewinderClient`] can retry it. Mirrors the algo_ops heuristic.
    pub fn looks_unreachable(message: &str) -> bool {
        let s = message.to_lowercase();
        s.contains("tcp connect error")
            || s.contains("connection refused")
            || s.contains("connection reset")
            || s.contains("timed out")
            || s.contains("timeout")
            || s.contains("dns error")
            || s.contains("host unreachable")
            || s.contains("error sending request")
    }
}
