//! In-memory mutual-TLS handshake proof: both ends present identity-bound certificates and each
//! authenticates the other by Algorand address. Drives `rustls` connections over an in-memory buffer,
//! so there is no socket and no external service.

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection};
use sw_identity_tls::client::{IdentityServerVerifier, client_config};
use sw_identity_tls::server::{IdentityClientVerifier, server_config};
use sw_identity_tls::{Role, StaticMembership, default_provider};

use crate::support::{allow, cert};

/// Shuttle handshake records between the two connections until both finish or it fails to converge.
/// A verifier rejection surfaces as an `Err` from `process_new_packets`.
fn drive(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), rustls::Error> {
    for _ in 0..30 {
        let mut flight = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut flight).expect("client write_tls");
        }
        let mut unread = flight.as_slice();
        while !unread.is_empty() {
            if server.read_tls(&mut unread).expect("server read_tls") == 0 {
                break;
            }
        }
        server.process_new_packets()?;

        let mut flight = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut flight).expect("server write_tls");
        }
        let mut unread = flight.as_slice();
        while !unread.is_empty() {
            if client.read_tls(&mut unread).expect("client read_tls") == 0 {
                break;
            }
        }
        client.process_new_packets()?;

        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err(rustls::Error::General("handshake did not converge".into()))
}

fn server_name() -> ServerName<'static> {
    ServerName::try_from("node.sidewinder.invalid".to_owned()).expect("valid server name")
}

#[test]
fn mutual_tls_authenticates_both_identities() {
    let provider = default_provider();
    let server_cert = cert(21);
    let client_cert = cert(22);
    let server_addr = server_cert.address.clone();
    let client_addr = client_cert.address.clone();

    // each side trusts exactly the other's on-chain identity.
    let server_verifier = Arc::new(IdentityClientVerifier::new(
        allow([client_addr.clone()]),
        provider.clone(),
    ));
    let client_verifier = Arc::new(IdentityServerVerifier::new(
        allow([server_addr.clone()]),
        provider.clone(),
    ));

    let server_cfg = server_config(server_cert, server_verifier.clone()).unwrap();
    let client_cfg = client_config(client_cert, client_verifier.clone()).unwrap();

    let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
    let mut client = ClientConnection::new(Arc::new(client_cfg), server_name()).unwrap();

    drive(&mut client, &mut server).expect("handshake completes");
    assert!(!client.is_handshaking() && !server.is_handshaking());

    assert_eq!(
        server_verifier.authenticated_peer().as_deref(),
        Some(client_addr.as_str()),
        "server authenticated the client's identity"
    );
    assert_eq!(
        client_verifier.authenticated_peer().as_deref(),
        Some(server_addr.as_str()),
        "client authenticated the server's identity"
    );
}

#[test]
fn unauthorized_client_identity_is_rejected() {
    let provider = default_provider();
    let server_cert = cert(31);
    let client_cert = cert(32);
    let server_addr = server_cert.address.clone();
    let some_other_authorized = cert(99).address; // the client's identity is NOT this one.

    let server_verifier = Arc::new(IdentityClientVerifier::new(
        allow([some_other_authorized]),
        provider.clone(),
    ));
    let client_verifier = Arc::new(IdentityServerVerifier::new(
        allow([server_addr.clone()]),
        provider.clone(),
    ));

    let server_cfg = server_config(server_cert, server_verifier.clone()).unwrap();
    let client_cfg = client_config(client_cert, client_verifier).unwrap();

    let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
    let mut client = ClientConnection::new(Arc::new(client_cfg), server_name()).unwrap();

    assert!(
        drive(&mut client, &mut server).is_err(),
        "handshake must fail for an unauthorized client identity"
    );
    assert!(server_verifier.authenticated_peer().is_none());
}

#[test]
fn mutual_tls_role_gated_to_cluster_nodes_succeeds() {
    let provider = default_provider();
    let server_cert = cert(51);
    let client_cert = cert(52);
    let server_addr = server_cert.address.clone();
    let client_addr = client_cert.address.clone();

    // both peers are cluster nodes; both links require Role::ClusterNode.
    let nodes: Arc<StaticMembership> = Arc::new(
        StaticMembership::new()
            .with(server_addr.clone(), Role::ClusterNode)
            .with(client_addr.clone(), Role::ClusterNode),
    );
    let server_verifier = Arc::new(IdentityClientVerifier::new_for_role(
        nodes.clone(),
        provider.clone(),
        Role::ClusterNode,
    ));
    let client_verifier = Arc::new(IdentityServerVerifier::new_for_role(
        nodes.clone(),
        provider.clone(),
        Role::ClusterNode,
    ));

    let server_cfg = server_config(server_cert, server_verifier.clone()).unwrap();
    let client_cfg = client_config(client_cert, client_verifier.clone()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
    let mut client = ClientConnection::new(Arc::new(client_cfg), server_name()).unwrap();

    drive(&mut client, &mut server).expect("handshake completes for two cluster nodes");
    assert_eq!(
        server_verifier.authenticated_peer().as_deref(),
        Some(client_addr.as_str())
    );
    assert_eq!(
        client_verifier.authenticated_peer().as_deref(),
        Some(server_addr.as_str())
    );
}

#[test]
fn mutual_tls_rejects_a_client_role_peer_on_a_node_link() {
    let provider = default_provider();
    let server_cert = cert(61);
    let client_cert = cert(62);
    let server_addr = server_cert.address.clone();
    let client_addr = client_cert.address.clone();

    // the connecting peer is an authentic member — but only a Client, not a ClusterNode. A node-to-node
    // link (server verifier gated to ClusterNode) must reject it.
    let authority: Arc<StaticMembership> = Arc::new(
        StaticMembership::new()
            .with(server_addr.clone(), Role::ClusterNode)
            .with(client_addr.clone(), Role::Client),
    );
    let server_verifier = Arc::new(IdentityClientVerifier::new_for_role(
        authority.clone(),
        provider.clone(),
        Role::ClusterNode,
    ));
    let client_verifier = Arc::new(IdentityServerVerifier::new_for_role(
        authority.clone(),
        provider.clone(),
        Role::ClusterNode,
    ));

    let server_cfg = server_config(server_cert, server_verifier.clone()).unwrap();
    let client_cfg = client_config(client_cert, client_verifier).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
    let mut client = ClientConnection::new(Arc::new(client_cfg), server_name()).unwrap();

    assert!(
        drive(&mut client, &mut server).is_err(),
        "a Client-role peer must be rejected on a ClusterNode-gated node link"
    );
    assert!(server_verifier.authenticated_peer().is_none());
}
