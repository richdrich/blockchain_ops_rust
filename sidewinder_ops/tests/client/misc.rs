//! Cross-cutting behaviour: URL joining and the unreachable-host heuristic.

use crate::support::TEST_TOKEN;
use crate::support::mock_node::{MockNode, Route};
use algo_ops::AlgoOps;
use sidewinder_ops::{SidewinderClient, SidewinderConfig, SidewinderError, SidewinderOps};

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
