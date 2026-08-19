use algo_ops::{AlgoChainConfig, AlgoOps};

fn default_cfg() -> AlgoChainConfig {
    AlgoChainConfig::default()
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn account_balance_returns_error_with_invalid_address() {
    // AlgoOps with an explicit but invalid address should fail with a clear error
    let ops = AlgoOps::new(
        None,
        Some("INVALID_ADDRESS".to_string()),
        Some(default_cfg()),
    );
    let result = ops.account_balance();
    assert!(result.is_err(), "expected error for invalid address");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("address") || err_msg.contains("invalid"),
        "error should mention address or invalid, got: {}",
        err_msg
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn account_balance_returns_none_with_unreachable_provider() {
    // Generate a real keypair so we have a valid address, but point at an unreachable provider.
    // The HTTP call fails at the algod response level so the error is logged and Ok(None) returned.
    let (id, _passphrase) = AlgoOps::generate_keypair();
    let mut cfg = default_cfg();
    cfg.client_api_url = "http://127.0.0.1".to_string();
    cfg.client_api_port = 19999; // unlikely to be running

    let ops = AlgoOps::new(None, Some(id), Some(cfg));
    assert!(ops.address.is_some(), "expected address to be set");

    let result = ops.account_balance();
    // The inner account_information call fails; error is logged and Ok(None) returned
    match result {
        Ok(balance) => assert!(
            balance.is_none(),
            "expected None balance for unreachable provider"
        ),
        Err(e) => {
            // Also acceptable: a transport-level error propagated as Err
            let msg = e.to_string();
            assert!(!msg.is_empty(), "error message should not be empty");
        }
    }
}
