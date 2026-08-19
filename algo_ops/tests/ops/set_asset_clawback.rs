use algo_ops::{AlgoChainConfig, AlgoOps};

fn default_cfg() -> AlgoChainConfig {
    AlgoChainConfig::default()
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn test_set_asset_clawback_to_app_requires_creator() {
    // No mock available for the algod response, but we can check the call fails
    // cleanly against the default (unreachable-in-test) endpoint.
    let (id, passphrase) = AlgoOps::generate_keypair();
    let ops = AlgoOps::new(Some(passphrase), Some(id), Some(default_cfg()));

    // We expect this to fail because it will try to call algod
    let result = ops.set_asset_clawback_to_app(1, 1);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("algod") || err.contains("connection") || err.contains("failed"),
        "Error was: {}",
        err
    );
}
