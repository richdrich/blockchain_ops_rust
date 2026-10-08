//! Cross-cutting behaviour: URL joining and the unreachable-host heuristic.

use crate::support::mock_node::{MockNode, Route};
use crate::support::{TEST_TOKEN, client_for};
use algo_ops::AlgoOps;
use sidewinder_ops::{
    SidewinderClient, SidewinderConfig, SidewinderError, SidewinderErrorKind, SidewinderOps,
};

#[test]
fn trailing_slash_in_base_url_does_not_double_the_separator() {
    let node = MockNode::start(vec![Route::empty("GET", "/health", 200)]);
    let algo = AlgoOps::new_for_algorand(None, None, None);
    // Base URL with a trailing slash — the client must still request "/health", not "//health".
    let base = format!("{}/", node.base_url());
    let client = SidewinderClient::from_algo_ops(algo, SidewinderConfig::new(base, TEST_TOKEN));

    assert!(client.health().expect("health"));
    let req = node.last_request().expect("a request");
    assert_eq!(req.path, "/health");
}

#[test]
fn looks_unreachable_classifies_connection_errors() {
    assert!(SidewinderError::looks_unreachable(
        "error sending request for url (http://x)"
    ));
    assert!(SidewinderError::looks_unreachable(
        "tcp connect error: Connection refused"
    ));
    assert!(SidewinderError::looks_unreachable("operation timed out"));
    // A served HTTP error is not an unreachable host.
    assert!(!SidewinderError::looks_unreachable("400 Bad Request"));
}

#[test]
fn an_unreachable_node_is_retried_and_reports_its_underlying_cause() {
    // nothing listens on the port: a real network fault, still retried and still `HostUnreachable` —
    // but the message must carry why the send failed, not only that it did (#114).
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("local addr")
    };
    let client = client_for(&format!("http://{closed}"));

    let error = client.health().expect_err("nothing is listening");
    let unreachable = error
        .downcast_ref::<SidewinderError>()
        .unwrap_or_else(|| panic!("a typed SidewinderError, got: {error:#}"));
    assert_eq!(unreachable.kind, SidewinderErrorKind::HostUnreachable);
    assert!(
        unreachable.message.to_lowercase().contains("refused"),
        "the cause beneath \"error sending request\" is reported: {}",
        unreachable.message
    );
}
