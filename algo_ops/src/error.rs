use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgoErrorKind {
    HostUnreachable,
    /// Transient HTTP error (e.g. 408, 429, 503) that exhausted all retries
    TransientFailure,
    /// A non-retryable HTTP error from the node or indexer, carrying its status code (for
    /// example 400 bad request, 401 unauthorized, or 403 daily-quota exceeded). See
    /// [`AlgoError::status`] for the code and [`AlgoError::is_quota`] / [`AlgoError::is_forbidden`].
    HttpError,
    /// The client's own outbound token-bucket rate limit rejected the request in `Reject` mode —
    /// no network request was made. Carries the wait until the next token in
    /// [`AlgoError::retry_after`]. Distinct from a server-side 429 (a retryable
    /// [`TransientFailure`](AlgoErrorKind::TransientFailure)) and from a 403/quota stop
    /// ([`HttpError`](AlgoErrorKind::HttpError)); the caller may retry after the wait.
    RateLimited,
    /// The client's own self-imposed wall-clock daily request budget is spent — no network request
    /// was made. Carries the wait until the next day-start boundary (when the count resets) in
    /// [`AlgoError::retry_after`]. Distinct from [`RateLimited`](AlgoErrorKind::RateLimited) (a
    /// transient per-window burst clip): this is a quota-class event a caller logs/alarms once and
    /// self-heals from at the boundary, not a request-by-request back-off.
    DailyBudgetExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgoError {
    pub kind: AlgoErrorKind,
    pub operation: String,
    pub message: String,
    /// The HTTP status code, when the failure carried an HTTP response. `None` for
    /// transport-level failures (host unreachable, timeout) that never received one.
    pub status: Option<u16>,
    /// For a [`RateLimited`](AlgoErrorKind::RateLimited) rejection, the wait until the client's
    /// token bucket next grants a token, so the caller can schedule a precise back-off. `None` for
    /// every other kind. Defaulted on deserialization so older serialized errors still load.
    #[serde(default)]
    pub retry_after: Option<Duration>,
}

impl std::fmt::Display for AlgoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.status, self.retry_after) {
            (Some(status), _) => write!(
                f,
                "AlgoError ({:?}, http {}): operation '{}' failed: {}",
                self.kind, status, self.operation, self.message
            ),
            (None, Some(retry_after)) => write!(
                f,
                "AlgoError ({:?}, retry after {} ms): operation '{}' failed: {}",
                self.kind,
                retry_after.as_millis(),
                self.operation,
                self.message
            ),
            (None, None) => write!(
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
            retry_after: None,
        }
    }

    pub fn unreachable(operation: &str, message: &str) -> Self {
        Self {
            kind: AlgoErrorKind::HostUnreachable,
            operation: operation.to_string(),
            message: message.to_string(),
            status: None,
            retry_after: None,
        }
    }

    /// Build a [`RateLimited`](AlgoErrorKind::RateLimited) rejection: the client's own outbound
    /// token bucket had no token in `Reject` mode, so no request was made. `retry_after` is the
    /// bucket's computed wait until the next token, surfaced on [`retry_after`](Self::retry_after)
    /// so the caller can back off precisely rather than block the thread.
    pub fn rate_limited(operation: &str, retry_after: Duration) -> Self {
        Self {
            kind: AlgoErrorKind::RateLimited,
            operation: operation.to_string(),
            message: format!(
                "outbound rate limit reached; retry after {} ms",
                retry_after.as_millis()
            ),
            status: None,
            retry_after: Some(retry_after),
        }
    }

    /// Build a [`DailyBudgetExceeded`](AlgoErrorKind::DailyBudgetExceeded) rejection: the client's
    /// own self-imposed daily request budget is spent, so no request was made. `retry_after` is the
    /// time to the next day-start boundary (when the count resets), surfaced on
    /// [`retry_after`](Self::retry_after) so the caller can self-heal precisely at the boundary.
    ///
    /// Distinct from [`rate_limited`](Self::rate_limited) (a transient per-window burst clip) so a
    /// consumer can treat it as a quota-class event — log/alarm once rather than back off per
    /// request. See [`is_daily_budget_exceeded`](Self::is_daily_budget_exceeded).
    pub fn daily_budget_exceeded(retry_after: Duration) -> Self {
        Self {
            kind: AlgoErrorKind::DailyBudgetExceeded,
            operation: "algod call".to_string(),
            message: format!(
                "daily request budget exhausted; resets in {} s",
                retry_after.as_secs()
            ),
            status: None,
            retry_after: Some(retry_after),
        }
    }

    /// True when this is the client's own daily-budget rejection — the self-imposed wall-clock
    /// daily request cap is spent and no request reached the network. Distinct from
    /// [`is_rate_limited`](Self::is_rate_limited) (a transient burst clip) and from a server-side
    /// 403/quota stop ([`is_quota`](Self::is_quota)); [`retry_after`](Self::retry_after) carries the
    /// wait to the next day-start boundary.
    pub fn is_daily_budget_exceeded(&self) -> bool {
        self.kind == AlgoErrorKind::DailyBudgetExceeded
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
            retry_after: None,
        }
    }

    /// The HTTP status code this error carried, or `None` for a transport-level failure that
    /// never received an HTTP response.
    pub fn status(&self) -> Option<u16> {
        self.status
    }

    /// True when this is the client's own outbound rate-limit rejection ([`Reject` mode][rl]) — no
    /// request reached the network. Distinct from a server-side 429 (which surfaces as a retryable
    /// [`TransientFailure`](AlgoErrorKind::TransientFailure)) and from a 403/quota stop, so
    /// [`is_quota`](Self::is_quota) and [`is_forbidden`](Self::is_forbidden) are both `false` here.
    ///
    /// [rl]: crate::RateLimitMode::Reject
    pub fn is_rate_limited(&self) -> bool {
        self.kind == AlgoErrorKind::RateLimited
    }

    /// The wait until the client's token bucket next grants a token, set only on a
    /// [`RateLimited`](AlgoErrorKind::RateLimited) rejection (`None` otherwise). Lets a caller
    /// schedule a precise back-off instead of guessing.
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
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
