use algo_ops::{AlgoChainConfig, AlgoOps};

fn default_cfg() -> AlgoChainConfig {
    AlgoChainConfig::default()
}

const DUMMY_ADDR: &str = "P577PSTDICQ6PQFBR5YMDMJ2YVK7LT5V4GOPNVDLCEDJIL7XGRWC5BRFWA";

#[test]
#[cfg(not(target_os = "ios"))]
pub fn asset_holding_returns_error_with_invalid_address() {
    // AlgoOps with an invalid address parameter should fail
    let ops = AlgoOps::new(None, Some(DUMMY_ADDR.to_string()), Some(default_cfg()));
    let result = ops.asset_holding("INVALID_ADDRESS", 123);
    assert!(result.is_err(), "expected error for invalid address");
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn asset_holding_fails_with_unreachable_node() {
    // Valid address but unreachable node should return an error
    let (addr, _) = AlgoOps::generate_keypair();
    let mut cfg = default_cfg();
    cfg.client_api_url = "http://127.0.0.1".to_string();
    cfg.client_api_port = 19999;
    cfg.token = Some("".to_string());

    let ops = AlgoOps::new(None, Some(DUMMY_ADDR.to_string()), Some(cfg));
    let result = ops.asset_holding(&addr, 123);
    assert!(result.is_err(), "expected error for unreachable node");
}
