use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgoErrorKind {
    HostUnreachable,
    /// Transient HTTP error (e.g. 408, 429, 503) that exhausted all retries
    TransientFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgoError {
    pub kind: AlgoErrorKind,
    pub operation: String,
    pub message: String,
}

impl std::fmt::Display for AlgoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AlgoError ({:?}): operation '{}' failed: {}",
            self.kind, self.operation, self.message
        )
    }
}

impl std::error::Error for AlgoError {}

impl AlgoError {
    pub fn transient(operation: &str, message: &str) -> Self {
        Self {
            kind: AlgoErrorKind::TransientFailure,
            operation: operation.to_string(),
            message: message.to_string(),
        }
    }

    pub fn unreachable(operation: &str, message: &str) -> Self {
        Self {
            kind: AlgoErrorKind::HostUnreachable,
            operation: operation.to_string(),
            message: message.to_string(),
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
