//! `GET /health` — the one unauthenticated endpoint; 200 → true, 503 → false.

use crate::support::client_for;
use crate::support::mock_node::{MockNode, Route};
use sidewinder_ops::{SidewinderErrorKind, SidewinderOps};

#[test]
fn health_ok_is_true() {
    let node = MockNode::start(vec![Route::empty("GET", "/health", 200)]);
    let client = client_for(&node.base_url());

    assert!(client.health().expect("health call"));

    // `/health` is unauthenticated: the client must not send the bearer token.
    let req = node.last_request().expect("a request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/health");
    assert!(
        req.authorization().is_none(),
        "health must not be authenticated"
    );
}

#[test]
fn health_503_is_false() {
    let node = MockNode::start(vec![Route::empty("GET", "/health", 503)]);
    let client = client_for(&node.base_url());

    assert!(!client.health().expect("health call"));
}

#[test]
fn health_unexpected_status_errors() {
    let node = MockNode::start(vec![Route::empty("GET", "/health", 500)]);
    let client = client_for(&node.base_url());

    let err = client.health().expect_err("500 should error");
    let se = err
        .downcast_ref::<sidewinder_ops::SidewinderError>()
        .expect("a SidewinderError");
    assert_eq!(se.kind, SidewinderErrorKind::UnexpectedStatus);
    assert_eq!(se.status, Some(500));
}
