//! Unit tests for the generic algod read primitives (`round`, `block_seed`,
//! `suggested_params`) that need no running node: they assert the plain return
//! shape and the `HostUnreachable` behaviour when the node is down.

use algo_ops::error::{AlgoError, AlgoErrorKind};
use algo_ops::{AlgoChainConfig, AlgoOps, AlgoSuggestedParams};

// Config pointing at a port nothing is listening on, so every algod call fails
// at the transport layer (connection refused) rather than reaching a node.
fn unreachable_cfg() -> AlgoChainConfig {
    let mut cfg = AlgoChainConfig::default();
    cfg.client_api_url = "http://127.0.0.1".to_string();
    cfg.client_api_port = 19999; // unlikely to be running
    cfg
}

fn assert_host_unreachable(err: &anyhow::Error, context: &str) {
    match err.downcast_ref::<AlgoError>() {
        Some(ae) => assert_eq!(
            ae.kind,
            AlgoErrorKind::HostUnreachable,
            "{context}: expected HostUnreachable, got {:?}",
            ae.kind
        ),
        None => panic!("{context}: expected an AlgoError, got: {err}"),
    }
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn round_reports_host_unreachable_when_node_down() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(unreachable_cfg()));
    let err = ops
        .round()
        .expect_err("round should fail against an unreachable node");
    assert_host_unreachable(&err, "round");
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn block_seed_reports_host_unreachable_when_node_down() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(unreachable_cfg()));
    let err = ops
        .block_seed(1)
        .expect_err("block_seed should fail against an unreachable node");
    assert_host_unreachable(&err, "block_seed");
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn suggested_params_reports_host_unreachable_when_node_down() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(unreachable_cfg()));
    let err = ops
        .suggested_params()
        .expect_err("suggested_params should fail against an unreachable node");
    assert_host_unreachable(&err, "suggested_params");
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn suggested_params_is_plain_and_serde_round_trips() {
    // The return type carries only plain types, so a consumer on a different
    // algonaut version can move it across the boundary unchanged.
    let params = AlgoSuggestedParams {
        last_round: 42,
        min_fee: 1_000,
        genesis_hash: [7u8; 32],
        genesis_id: "testnet-v1.0".to_string(),
    };
    let json = serde_json::to_string(&params).expect("serialize AlgoSuggestedParams");
    let back: AlgoSuggestedParams = serde_json::from_str(&json).expect("deserialize round trip");
    assert_eq!(params, back);
}
