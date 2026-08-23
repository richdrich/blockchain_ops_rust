//! `POST /v2/transactions` — submit signed bytes, returns the txId.

use crate::support::client_for;
use crate::support::mock_node::{MockNode, Route};
use sidewinder_ops::{SidewinderErrorKind, SidewinderOps};

#[test]
fn submit_returns_txid_and_sends_token_body_and_content_type() {
    let node = MockNode::start(vec![Route::ok_json(
        "POST",
        "/v2/transactions",
        r#"{"txId":"ABC123"}"#,
    )]);
    let client = client_for(&node.base_url());

    let raw = b"raw-signed-transaction-bytes";
    let txid = client.submit(raw).expect("submit");
    assert_eq!(txid, "ABC123");

    let req = node.last_request().expect("a request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/v2/transactions");
    assert_eq!(req.authorization(), Some("Bearer test-token"));
    assert_eq!(req.header("content-type"), Some("application/msgpack"));
    assert_eq!(req.body, raw);
}

#[test]
fn submit_400_is_bad_request() {
    let node = MockNode::start(vec![Route::json(
        "POST",
        "/v2/transactions",
        400,
        r#"{"message":"malformed encoding"}"#,
    )]);
    let client = client_for(&node.base_url());

    let err = client.submit(b"bad").expect_err("400 should error");
    let se = err
        .downcast_ref::<sidewinder_ops::SidewinderError>()
        .expect("a SidewinderError");
    assert_eq!(se.kind, SidewinderErrorKind::BadRequest);
    assert_eq!(se.status, Some(400));
    assert!(se.message.contains("malformed encoding"));
}

#[test]
fn submit_401_is_unauthorized() {
    let node = MockNode::start(vec![Route::json(
        "POST",
        "/v2/transactions",
        401,
        r#"{"message":"missing or invalid authorization token"}"#,
    )]);
    let client = client_for(&node.base_url());

    let err = client.submit(b"x").expect_err("401 should error");
    let se = err
        .downcast_ref::<sidewinder_ops::SidewinderError>()
        .expect("a SidewinderError");
    assert_eq!(se.kind, SidewinderErrorKind::Unauthorized);
}
