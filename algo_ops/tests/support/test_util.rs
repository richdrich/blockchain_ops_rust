//! Algorand-only slice of the former bingle_core `tests/test_util.rs`.
//!
//! Only the helpers the moved AlgoOps tests actually use are carried over here:
//! localnet config, availability probe, mnemonic-based construction, and a simple
//! test-logging initializer. The granular per-role accounts live in
//! [`super::blockchain_users`]; the base spend/receive accounts stay here.

use algo_ops::{AlgoChainConfig, AlgoOps};
use std::net::TcpStream;
use std::sync::Once;

// Localnet token from the Algorand docs / algokit localnet.
pub const LOCALNET_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// Provided accounts and mnemonics (mnemonics derive the seed via algonaut).
pub const PASSPHRASE_10MIL: &str = "provide protect forest couch shaft buyer tenant language almost response chief roast spider scorpion injury they good ecology super east domain thunder shrimp absent output";
pub const ADDRESS_10MIL: &str = "P577PSTDICQ6PQFBR5YMDMJ2YVK7LT5V4GOPNVDLCEDJIL7XGRWC5BRFWA";

pub const ADDRESS_SPEND: &str = "4TKGNGRAUHMQI4EOQ34L2AIDX2VGS4OZNZIOE6BLEQFZUDRSB6RJRBPVRE";
pub const PASSPHRASE_SPEND: &str = "theme term glow reflect essence artefact tired bicycle february demand vacuum tent faculty arch elevator rent already anchor rough cry sketch nurse mom able inquiry";

pub const ADDRESS_RECEIVE: &str = "OO3BIFZDJPGMNXZ74NOVH5KZ5WBL3KCPLPELAF32P7HDCQGQIBID7PJC7A";
pub const PASSPHRASE_RECEIVE: &str = "earth idle country misery matrix wolf tired cabin craft roof quantum comfort answer praise second scout title napkin crop trial industry glue kid absorb midnight";

pub fn localnet_config() -> AlgoChainConfig {
    AlgoChainConfig {
        client_api_url: "http://localhost".to_string(),
        client_api_port: 4001,
        indexer_api_url: "http://localhost".to_string(),
        indexer_api_port: 8980,
        token: Some(LOCALNET_TOKEN.to_string()),
        token_key: Some("X-Algo-API-Token".to_string()),
        app_id: None,
        asset_id: None,
    }
}

/// Panic unless algokit localnet is reachable on the configured algod port. The
/// localnet tests live in the `integration` target (`test = false`), so this only
/// fires when they are run explicitly with `cargo test --test integration`.
pub fn assert_localnet_available() {
    let cfg = localnet_config();
    let addr = format!(
        "{}:{}",
        cfg.client_api_url
            .trim_start_matches("http://")
            .trim_start_matches("https://"),
        cfg.client_api_port
    );
    TcpStream::connect(&addr).unwrap_or_else(|e| {
        panic!(
            "localnet is not available at {} - ensure algokit localnet is running: {}",
            addr, e
        )
    });
}

/// Construct an `AlgoOps` from a 25-word mnemonic passphrase and address.
pub fn ops_from_mnemonic(addr: &str, mnem: &str, cfg: AlgoChainConfig) -> AlgoOps {
    AlgoOps::new(Some(mnem.to_string()), Some(addr.to_string()), Some(cfg))
}

pub fn init_test_logging() {
    init_test_logging_with_filter("debug");
}

/// Install a simple test-writer tracing subscriber once per process. Unlike the
/// bingle_core original this uses the plain `tracing_subscriber` formatter (no
/// bingle-specific layers), which is all the moved tests need.
pub fn init_test_logging_with_filter(filter_str: &str) {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::EnvFilter;
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter_str));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_test_writer()
            .try_init();
    });
}
