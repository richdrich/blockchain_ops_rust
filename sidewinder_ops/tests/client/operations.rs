//! `GET /v2/operations/{typ}` — operation configuration for a transaction type.

use crate::support::client_for;
use crate::support::mock_node::{MockNode, Route};
use sidewinder_ops::SidewinderOps;

#[test]
fn operations_present_decodes_schema() {
    let node = MockNode::start(vec![Route::ok_json(
        "GET",
        "/v2/operations/2",
        r#"{"typ":2,"name":"Slot","returnType":"byte[]","events":[{"name":"Set","signature":"Set(byte[])","selector":"AAECAw=="}]}"#,
    )]);
    let client = client_for(&node.base_url());

    let schema = client
        .operations(2)
        .expect("operations")
        .expect("a configured operation");
    assert_eq!(schema.typ, 2);
    assert_eq!(schema.name.as_deref(), Some("Slot"));
    assert_eq!(schema.return_type, "byte[]");
    assert_eq!(schema.events.len(), 1);
    assert_eq!(schema.events[0].name, "Set");
    assert_eq!(schema.events[0].signature, "Set(byte[])");
    assert_eq!(schema.events[0].selector, vec![0, 1, 2, 3]);
}

#[test]
fn operations_404_is_none() {
    let node = MockNode::start(vec![Route::json(
        "GET",
        "/v2/operations/7",
        404,
        r#"{"message":"no operation configured for that type"}"#,
    )]);
    let client = client_for(&node.base_url());

    assert!(client.operations(7).expect("operations").is_none());
}
