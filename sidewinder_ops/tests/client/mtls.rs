//! Offline tests for the identity-pinned mutual-TLS client transport (#375): a client reaches a node
//! whose identity it pins, and is rejected when the node's identity does not match the resolved one or
//! when the node does not authorize the client. Drives the real `SidewinderClient` mutual-TLS transport
//! against a loopback TLS node — no chain, no discovery scan (that is the integration bucket).

use std::net::SocketAddr;

use algo_ops::AlgoOps;
use ed25519_dalek::SigningKey;
use sidewinder_ops::{DiscoveredNode, EndpointRecord, SidewinderClient, SidewinderOps};

use crate::support::TEST_SEED_B64;
use crate::support::tls_mock_node::{TlsMockNode, identity_address};

/// The client's own identity key — the same account `AlgoOps::new_for_algorand(TEST_SEED_B64)` derives,
/// so `SidewinderClient::connect` presents a certificate the node can authorize.
fn client_key() -> SigningKey {
    let seed = AlgoOps::new_for_algorand(Some(TEST_SEED_B64.to_string()), None, None)
        .private_key_bytes()
        .expect("client seed");
    SigningKey::from_bytes(&seed.try_into().expect("32-byte seed"))
}

/// A `DiscoveredNode` pointing at `addr`, bound to `identity` — as the resolver would yield.
fn discovered(addr: SocketAddr, identity: String) -> DiscoveredNode {
    let SocketAddr::V4(v4) = addr else {
        panic!("loopback is IPv4");
    };
    DiscoveredNode {
        identity,
        endpoint: EndpointRecord::new(Some(v4), None).expect("endpoint record"),
    }
}

fn client_algo() -> AlgoOps {
    AlgoOps::new_for_algorand(Some(TEST_SEED_B64.to_string()), None, None)
}

#[test]
fn a_client_reaches_a_node_whose_identity_it_pins() {
    let client_addr = identity_address(&client_key());
    let node_key = SigningKey::from_bytes(&[200u8; 32]);
    let node_addr = identity_address(&node_key);

    // the node authorizes this client and presents its own identity certificate.
    let node = TlsMockNode::start(&node_key, vec![client_addr]);
    let target = discovered(node.addr(), node_addr);

    let client =
        SidewinderClient::connect(client_algo(), &target).expect("connect over mutual TLS");
    assert!(
        client.health().expect("health over mutual TLS"),
        "the client reaches a node whose on-chain identity it pinned"
    );
}

#[test]
fn a_node_presenting_a_different_identity_is_rejected() {
    let client_addr = identity_address(&client_key());
    let node_key = SigningKey::from_bytes(&[200u8; 32]);
    // the resolver-supplied identity is a DIFFERENT key than the node actually presents (a fake
    // endpoint, or a node impersonating another).
    let resolved_but_wrong = identity_address(&SigningKey::from_bytes(&[201u8; 32]));

    let node = TlsMockNode::start(&node_key, vec![client_addr]);
    let target = discovered(node.addr(), resolved_but_wrong);

    let client = SidewinderClient::connect(client_algo(), &target).expect("client builds");
    assert!(
        client.health().is_err(),
        "a node whose identity does not match the pinned one must be rejected at the handshake"
    );
}

#[test]
fn a_node_that_does_not_authorize_the_client_rejects_it() {
    let node_key = SigningKey::from_bytes(&[200u8; 32]);
    let node_addr = identity_address(&node_key);

    // the node pins the correct identity but authorizes no client — mutual TLS, so the handshake fails.
    let node = TlsMockNode::start(&node_key, Vec::new());
    let target = discovered(node.addr(), node_addr);

    let client = SidewinderClient::connect(client_algo(), &target).expect("client builds");
    assert!(
        client.health().is_err(),
        "a node that does not authorize the client's identity must reject the connection"
    );
}
