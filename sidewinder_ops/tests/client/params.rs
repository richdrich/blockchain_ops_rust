//! `GET /v2/transactions/params` — suggested transaction parameters.

use crate::support::client_for;
use crate::support::mock_node::{MockNode, Route};
use sidewinder_ops::SidewinderOps;

#[test]
fn params_decodes_fields() {
    let node = MockNode::start(vec![Route::ok_json(
        "GET",
        "/v2/transactions/params",
        r#"{"instanceId":"aW5zdA==","lastRound":42,"minFee":1000,"maxValidityWindow":1000}"#,
    )]);
    let client = client_for(&node.base_url());

    let params = client.params().expect("params");
    assert_eq!(params.instance_id, b"inst");
    assert_eq!(params.last_round, 42);
    assert_eq!(params.min_fee, 1000);
    assert_eq!(params.max_validity_window, 1000);

    let req = node.last_request().expect("a request");
    assert_eq!(req.authorization(), Some("Bearer test-token"));
}
