use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgoErrorKind {
    HostUnreachable,
    /// Transient HTTP error (e.g. 408, 429, 503) that exhausted all retries
    TransientFailure,
    /// A non-retryable HTTP error from the node or indexer, carrying its status code (for
    /// example 400 bad request, 401 unauthorized, or 403 daily-quota exceeded). See
    /// [`AlgoError::status`] for the code and [`AlgoError::is_quota`] / [`AlgoError::is_forbidden`].
    HttpError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgoError {
    pub kind: AlgoErrorKind,
    pub operation: String,
    pub message: String,
    /// The HTTP status code, when the failure carried an HTTP response. `None` for
    /// transport-level failures (host unreachable, timeout) that never received one.
    pub status: Option<u16>,
}

impl std::fmt::Display for AlgoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(status) => write!(
                f,
                "AlgoError ({:?}, http {}): operation '{}' failed: {}",
                self.kind, status, self.operation, self.message
            ),
            None => write!(
                f,
                "AlgoError ({:?}): operation '{}' failed: {}",
                self.kind, self.operation, self.message
            ),
        }
    }
}

impl std::error::Error for AlgoError {}

impl AlgoError {
    pub fn transient(operation: &str, message: &str) -> Self {
        Self {
            kind: AlgoErrorKind::TransientFailure,
            operation: operation.to_string(),
            message: message.to_string(),
            status: None,
        }
    }

    pub fn unreachable(operation: &str, message: &str) -> Self {
        Self {
            kind: AlgoErrorKind::HostUnreachable,
            operation: operation.to_string(),
            message: message.to_string(),
            status: None,
        }
    }

    /// Build a non-retryable HTTP error carrying its `status` code. Used by the call path to
    /// surface a hard rejection (for example a 403 daily-quota stop) as a typed error a caller
    /// can classify with [`is_quota`](Self::is_quota) / [`is_forbidden`](Self::is_forbidden)
    /// instead of string-matching the message.
    pub fn http(operation: &str, status: u16, message: &str) -> Self {
        Self {
            kind: AlgoErrorKind::HttpError,
            operation: operation.to_string(),
            message: message.to_string(),
            status: Some(status),
        }
    }

    /// The HTTP status code this error carried, or `None` for a transport-level failure that
    /// never received an HTTP response.
    pub fn status(&self) -> Option<u16> {
        self.status
    }

    /// True when the node or indexer rejected the request with HTTP 403 Forbidden.
    ///
    /// On the metered free tier a 403 is the daily byte/request-quota stop (authentication
    /// failures come back as 401), so a caller should treat this as hard and not retry.
    pub fn is_forbidden(&self) -> bool {
        self.status == Some(403)
    }

    /// True when the failure is a quota/allowance rejection the caller must not retry: a 403
    /// (the documented daily-quota stop) or any error whose message mentions "quota" (covering
    /// providers that phrase it differently). A per-second rate limit comes back as a retryable
    /// [`TransientFailure`](AlgoErrorKind::TransientFailure) (HTTP 429) instead.
    pub fn is_quota(&self) -> bool {
        self.is_forbidden() || self.message.to_lowercase().contains("quota")
    }

    /// Add operation context to `e` while keeping a typed [`AlgoError`] intact so callers can
    /// still `downcast_ref::<AlgoError>()` (and reach [`is_quota`](Self::is_quota) /
    /// [`is_forbidden`](Self::is_forbidden)). A non-typed error is given the `operation` prefix;
    /// a typed one is passed through unchanged (it already names its operation).
    pub fn contextualize(operation: &str, e: anyhow::Error) -> anyhow::Error {
        if e.downcast_ref::<AlgoError>().is_some() {
            e
        } else {
            anyhow::anyhow!("{operation}: {e}")
        }
    }

    pub fn is_host_unreachable(e: &anyhow::Error) -> bool {
        let s = e.to_string().to_lowercase();
        s.contains("tcp connect error")
            || s.contains("connection refused")
            || s.contains("connection reset")
            || s.contains("timeout")
            || s.contains("dns error")
            || s.contains("host unreachable")
            || s.contains("error sending request")
    }

    pub fn map_node_err<T, E: std::fmt::Display>(
        operation: &str,
        res: anyhow::Result<anyhow::Result<T, E>>,
    ) -> anyhow::Result<T> {
        match res {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => {
                let ae = anyhow::anyhow!(e.to_string());
                if Self::is_host_unreachable(&ae) {
                    Err(Self::unreachable(operation, &ae.to_string()).into())
                } else {
                    Err(anyhow::anyhow!("{} failed: {}", operation, ae))
                }
            }
            Err(e) => {
                if Self::is_host_unreachable(&e) {
                    Err(Self::unreachable(operation, &e.to_string()).into())
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn map_node_err_opt<T, E: std::fmt::Display>(
        operation: &str,
        res: anyhow::Result<anyhow::Result<T, E>>,
    ) -> anyhow::Result<Option<T>> {
        match res {
            Ok(Ok(v)) => Ok(Some(v)),
            Ok(Err(e)) => {
                let ae = anyhow::anyhow!(e.to_string());
                if Self::is_host_unreachable(&ae) {
                    Err(Self::unreachable(operation, &ae.to_string()).into())
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                if Self::is_host_unreachable(&e) {
                    Err(Self::unreachable(operation, &e.to_string()).into())
                } else {
                    Err(e)
                }
            }
        }
    }
}
