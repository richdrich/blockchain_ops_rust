//! Unit tests for the transaction submit + confirmation-read primitives
//! (`submit_signed`, `confirmed_transaction`) that need no running node: they
//! assert input validation, the plain return shape, and the `HostUnreachable`
//! behaviour when the node is down.

use algo_ops::error::{AlgoError, AlgoErrorKind};
use algo_ops::{AlgoChainConfig, AlgoOps, ConfirmedTxn};

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
pub fn submit_signed_rejects_empty_bytes() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(unreachable_cfg()));
    let err = ops
        .submit_signed(&[])
        .expect_err("empty signed bytes should be rejected");
    assert!(
        err.to_string().contains("must not be empty"),
        "unexpected error: {err}"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn submit_signed_reports_host_unreachable_when_node_down() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(unreachable_cfg()));
    // Non-empty bytes get past validation and reach the (unreachable) node.
    let err = ops
        .submit_signed(&[1, 2, 3])
        .expect_err("submit_signed should fail against an unreachable node");
    assert_host_unreachable(&err, "submit_signed");
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn confirmed_transaction_rejects_empty_txid() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(unreachable_cfg()));
    let err = ops
        .confirmed_transaction("   ")
        .expect_err("blank txid should be rejected");
    assert!(
        err.to_string().contains("must not be empty"),
        "unexpected error: {err}"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn confirmed_transaction_reports_host_unreachable_when_node_down() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(unreachable_cfg()));
    let err = ops
        .confirmed_transaction("SOMETXID")
        .expect_err("confirmed_transaction should fail against an unreachable node");
    assert_host_unreachable(&err, "confirmed_transaction");
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn confirmed_txn_is_plain_and_serde_round_trips() {
    // The return type carries only plain types, so a consumer on a different
    // algonaut version can move it across the boundary unchanged.
    let txn = ConfirmedTxn {
        confirmed_round: 100,
        note: Some(vec![1, 2, 3, 4]),
    };
    let json = serde_json::to_string(&txn).expect("serialize ConfirmedTxn");
    let back: ConfirmedTxn = serde_json::from_str(&json).expect("deserialize round trip");
    assert_eq!(txn, back);
}
