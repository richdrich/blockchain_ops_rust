//! Unit tests for the transaction submit + query primitives (`submit_signed`,
//! `confirmed_transaction`, `find_transaction_by_note`) that need no running
//! node: they assert input validation, the plain return shape, and the
//! `HostUnreachable` behaviour when the node/indexer is down.

use algo_ops::error::{AlgoError, AlgoErrorKind};
use algo_ops::{AlgoChainConfig, AlgoOps, ConfirmedTxn};

// Config pointing at ports nothing is listening on, so every algod and indexer
// call fails at the transport layer (connection refused) rather than reaching a
// node.
fn unreachable_cfg() -> AlgoChainConfig {
    let mut cfg = AlgoChainConfig::default();
    cfg.client_api_url = "http://127.0.0.1".to_string();
    cfg.client_api_port = 19999; // unlikely to be running
    cfg.indexer_api_url = "http://127.0.0.1".to_string();
    cfg.indexer_api_port = 19998; // unlikely to be running
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
pub fn find_transaction_by_note_rejects_empty_note() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(unreachable_cfg()));
    let err = ops
        .find_transaction_by_note(&[])
        .expect_err("empty note should be rejected");
    assert!(
        err.to_string().contains("must not be empty"),
        "unexpected error: {err}"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn find_transaction_by_note_reports_host_unreachable_when_indexer_down() {
    let ops = AlgoOps::new_for_algorand(None, None, Some(unreachable_cfg()));
    // A non-empty note gets past validation and reaches the (unreachable) indexer.
    let err = ops
        .find_transaction_by_note(b"anchor")
        .expect_err("find_transaction_by_note should fail against an unreachable indexer");
    assert_host_unreachable(&err, "find_transaction_by_note");
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
