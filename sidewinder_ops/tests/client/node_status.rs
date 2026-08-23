//! `GET /v2/status` — the node's view of the parent chain and node set.

use crate::support::client_for;
use crate::support::mock_node::{MockNode, Route};
use sidewinder_ops::SidewinderOps;

#[test]
fn node_status_decodes_fields() {
    let node = MockNode::start(vec![Route::ok_json(
        "GET",
        "/v2/status",
        r#"{"instanceId":"aW5zdA==","lastRound":42,"nodeSetEpoch":0,"synced":true,"version":"0.1.1"}"#,
    )]);
    let client = client_for(&node.base_url());

    let status = client.node_status().expect("node_status");
    assert_eq!(status.instance_id, b"inst");
    assert_eq!(status.last_round, 42);
    assert_eq!(status.node_set_epoch, 0);
    assert!(status.synced);
    assert_eq!(status.version.as_deref(), Some("0.1.1"));
}

#[test]
fn node_status_version_is_optional() {
    let node = MockNode::start(vec![Route::ok_json(
        "GET",
        "/v2/status",
        r#"{"instanceId":"aW5zdA==","lastRound":7,"nodeSetEpoch":0,"synced":false}"#,
    )]);
    let client = client_for(&node.base_url());

    let status = client.node_status().expect("node_status");
    assert!(status.version.is_none());
    assert!(!status.synced);
}
