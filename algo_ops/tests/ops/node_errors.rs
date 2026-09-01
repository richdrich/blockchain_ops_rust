use crate::support::test_util::init_test_logging;
use algo_ops::{AlgoChainConfig, AlgoOps};

#[test]
#[cfg(not(target_os = "ios"))]
pub fn test_node_unreachable() {
    init_test_logging();

    let config = AlgoChainConfig {
        client_api_url: "http://localhost".to_string(),
        client_api_port: 1234,
        indexer_api_url: "http://localhost".to_string(),
        indexer_api_port: 1234,
        token: None,
        token_key: None,
        app_id: None,
        asset_id: None,
        rate_limit: None,
    };

    let (id, _passphrase) = AlgoOps::generate_keypair();
    let ops = AlgoOps::new_for_algorand(None, Some(id), Some(config));

    // account_balance makes a network call - with an unreachable address it should fail or return None
    let result = ops.account_balance();

    // Either an error or Ok(None) is acceptable for an unreachable node
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(!msg.is_empty(), "error message should not be empty");
        }
        Ok(balance) => {
            assert!(
                balance.is_none(),
                "expected None balance for unreachable node"
            );
        }
    }
}
