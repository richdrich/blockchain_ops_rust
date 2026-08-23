//! `GET /v2/transactions/pending/{txid}` — status and its long-poll `watch` form.

use crate::support::client_for;
use crate::support::mock_node::{MockNode, Route};
use sidewinder_ops::{Disposition, SidewinderErrorKind, SidewinderOps, Stage};

#[test]
fn status_final_decodes_all_byte_fields() {
    let body = r#"{
        "txId":"TX1",
        "stage":"final",
        "result":"cmVzdWx0",
        "logs":["bG9nMQ=="],
        "events":[{"selector":"AAECAw==","name":"Swapped"}],
        "certificate":"Y2VydA==",
        "proof":"cHJvb2Y=",
        "error":null
    }"#;
    let node = MockNode::start(vec![Route::ok_json(
        "GET",
        "/v2/transactions/pending/TX1",
        body,
    )]);
    let client = client_for(&node.base_url());

    let pending = client.status("TX1", true).expect("status");
    assert_eq!(pending.tx_id, "TX1");
    assert_eq!(pending.stage, Stage::Final);
    assert_eq!(pending.result.as_deref(), Some(&b"result"[..]));
    assert_eq!(pending.logs, vec![b"log1".to_vec()]);
    assert_eq!(pending.events.len(), 1);
    assert_eq!(pending.events[0].selector, vec![0, 1, 2, 3]);
    assert_eq!(pending.events[0].name, "Swapped");
    assert_eq!(pending.certificate.as_deref(), Some(&b"cert"[..]));
    assert_eq!(pending.proof.as_deref(), Some(&b"proof"[..]));
    assert!(pending.error.is_none());

    // proof=true is carried on the query string, and the call is authenticated.
    let req = node.last_request().expect("a request");
    assert!(req.path.contains("proof=true"), "path was {}", req.path);
    assert_eq!(req.authorization(), Some("Bearer test-token"));
}

#[test]
fn status_pending_has_no_result_or_proof() {
    let node = MockNode::start(vec![Route::ok_json(
        "GET",
        "/v2/transactions/pending/TX2",
        r#"{"txId":"TX2","stage":"pending"}"#,
    )]);
    let client = client_for(&node.base_url());

    let pending = client.status("TX2", false).expect("status");
    assert_eq!(pending.stage, Stage::Pending);
    assert!(pending.result.is_none());
    assert!(pending.logs.is_empty());
    assert!(pending.events.is_empty());
    assert!(pending.certificate.is_none());
    assert!(pending.proof.is_none());

    let req = node.last_request().expect("a request");
    assert!(req.path.contains("proof=false"), "path was {}", req.path);
}

#[test]
fn status_failed_carries_error_and_disposition() {
    let node = MockNode::start(vec![Route::ok_json(
        "GET",
        "/v2/transactions/pending/TX3",
        r#"{"txId":"TX3","stage":"failed","error":{"message":"boom","disposition":"escalated"}}"#,
    )]);
    let client = client_for(&node.base_url());

    let pending = client.status("TX3", false).expect("status");
    assert_eq!(pending.stage, Stage::Failed);
    let err = pending.error.expect("an error body");
    assert_eq!(err.message, "boom");
    assert_eq!(err.disposition, Some(Disposition::Escalated));
}

#[test]
fn status_404_is_not_found() {
    let node = MockNode::start(vec![Route::json(
        "GET",
        "/v2/transactions/pending/NOPE",
        404,
        r#"{"message":"no transaction with that identifier"}"#,
    )]);
    let client = client_for(&node.base_url());

    let err = client.status("NOPE", false).expect_err("404 should error");
    let se = err
        .downcast_ref::<sidewinder_ops::SidewinderError>()
        .expect("a SidewinderError");
    assert_eq!(se.kind, SidewinderErrorKind::NotFound);
}

#[test]
fn watch_sets_wait_query() {
    let node = MockNode::start(vec![Route::ok_json(
        "GET",
        "/v2/transactions/pending/TX1",
        r#"{"txId":"TX1","stage":"provisional"}"#,
    )]);
    let client = client_for(&node.base_url());

    let pending = client.watch("TX1", false, 5).expect("watch");
    assert_eq!(pending.stage, Stage::Provisional);

    let req = node.last_request().expect("a request");
    assert!(req.path.contains("wait=5"), "path was {}", req.path);
    assert!(req.path.contains("proof=false"), "path was {}", req.path);
}
