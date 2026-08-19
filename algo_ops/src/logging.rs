//! Minimal debug-logging shim for the `algo_ops` crate.
//!
//! `algo_log!` routes to `tracing::info!` when a Bingle debug env var is set, otherwise to
//! `tracing::trace!`. A crate-local copy so `algo_ops` stays independent of `bingle_core`.

use std::sync::OnceLock;

static ALGO_DEBUG: OnceLock<bool> = OnceLock::new();

pub fn is_algo_debug_enabled() -> bool {
    *ALGO_DEBUG.get_or_init(|| {
        std::env::var("BINGLE_ALGO_DEBUG")
            .or_else(|_| std::env::var("RUST_COMMS_DEBUG"))
            .or_else(|_| std::env::var("BINGLE_DEBUG"))
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
    })
}

macro_rules! algo_log {
    ($($arg:tt)*) => {
        if $crate::logging::is_algo_debug_enabled() {
            tracing::info!($($arg)*);
        } else {
            tracing::trace!($($arg)*);
        }
    };
}
