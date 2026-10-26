//! In-memory mutual-TLS handshake proof: both ends present identity-bound certificates and each
//! authenticates the other by Algorand address. Drives `rustls` connections over an in-memory buffer,
//! so there is no socket and no external service.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{AlertDescription, CertificateError, ClientConnection, ServerConnection};
use sw_identity_tls::client::{IdentityServerVerifier, client_config};
use sw_identity_tls::server::{IdentityClientVerifier, server_config};
use sw_identity_tls::{IdentityCert, Role, StaticMembership, default_provider};

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

/// Drive a handshake the **server** is expected to refuse, returning `(the server's own error, what the
/// client then receives)`. The server's verifier error becomes a fatal alert; this delivers that alert
/// to the client so a test can assert on the reason the client is actually told.
fn drive_to_refusal(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> (rustls::Error, rustls::Error) {
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
        let refused = server.process_new_packets().err();

        // whatever the server has to say next — its handshake flight, or the alert for the refusal.
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
        let received = client.process_new_packets().err();

        if let Some(server_error) = refused {
            let client_error = received.expect("the client is told the handshake was refused");
            return (server_error, client_error);
        }
        assert!(
            received.is_none(),
            "the client failed before the server refused: {received:?}"
        );
    }
    panic!("the server never refused the handshake");
}

/// A self-signed certificate with **no** Sidewinder identity extension, packaged so a client can
/// present it: authentic TLS, but it binds no Algorand identity at all.
fn plain_cert() -> IdentityCert {
    let params = rcgen::CertificateParams::new(vec!["plain.invalid".to_string()]).unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let plain = params.self_signed(&key_pair).unwrap();
    IdentityCert {
        cert: CertificateDer::from(plain.der().to_vec()),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
        address: String::new(),
    }
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

#[test]
fn an_unpermitted_client_identity_is_refused_with_access_denied() {
    // #114: a client that proves an identity the server does not permit must be told *that* — the
    // `access_denied` alert — so it can report "this node does not admit my identity" instead of
    // retrying what looks like a network fault.
    let provider = default_provider();
    let server_cert = cert(41);
    let client_cert = cert(42);
    let server_addr = server_cert.address.clone();
    let some_other_authorized = cert(99).address; // the client's identity is NOT this one.

    let server_verifier = Arc::new(IdentityClientVerifier::new(
        allow([some_other_authorized]),
        provider.clone(),
    ));
    let client_verifier = Arc::new(IdentityServerVerifier::new(allow([server_addr]), provider));
    let server_cfg = server_config(server_cert, server_verifier).unwrap();
    let client_cfg = client_config(client_cert, client_verifier).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
    let mut client = ClientConnection::new(Arc::new(client_cfg), server_name()).unwrap();

    let (server_error, client_error) = drive_to_refusal(&mut client, &mut server);
    assert_eq!(
        server_error,
        rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
        "the server refuses on its access-control decision, not a certificate defect"
    );
    assert_eq!(
        client_error,
        rustls::Error::AlertReceived(AlertDescription::AccessDenied),
        "the client is told access was denied"
    );
}

#[test]
fn a_client_role_peer_on_a_node_link_is_refused_with_access_denied() {
    // the role gate is the same access-control decision: an authentic member of the wrong role.
    let provider = default_provider();
    let server_cert = cert(43);
    let client_cert = cert(44);
    let membership = Arc::new(
        StaticMembership::new()
            .with(server_cert.address.clone(), Role::ClusterNode)
            .with(client_cert.address.clone(), Role::Client),
    );

    let server_verifier = Arc::new(IdentityClientVerifier::new_for_role(
        membership.clone(),
        provider.clone(),
        Role::ClusterNode,
    ));
    let client_verifier = Arc::new(IdentityServerVerifier::new(membership, provider));
    let server_cfg = server_config(server_cert, server_verifier).unwrap();
    let client_cfg = client_config(client_cert, client_verifier).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
    let mut client = ClientConnection::new(Arc::new(client_cfg), server_name()).unwrap();

    let (_server_error, client_error) = drive_to_refusal(&mut client, &mut server);
    assert_eq!(
        client_error,
        rustls::Error::AlertReceived(AlertDescription::AccessDenied)
    );
}

#[test]
fn a_certificate_binding_no_identity_is_not_reported_as_a_membership_refusal() {
    // a certificate with no identity extension proves nothing, so it is a broken handshake — never
    // `access_denied`, which a client reads as "your identity is known but not permitted".
    let provider = default_provider();
    let server_cert = cert(45);
    let server_addr = server_cert.address.clone();

    let server_verifier = Arc::new(IdentityClientVerifier::new(
        allow([cert(46).address]),
        provider.clone(),
    ));
    let client_verifier = Arc::new(IdentityServerVerifier::new(allow([server_addr]), provider));
    let server_cfg = server_config(server_cert, server_verifier).unwrap();
    let client_cfg = client_config(plain_cert(), client_verifier).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
    let mut client = ClientConnection::new(Arc::new(client_cfg), server_name()).unwrap();

    let (server_error, client_error) = drive_to_refusal(&mut client, &mut server);
    assert!(
        matches!(&server_error, rustls::Error::General(reason) if reason.contains("identity extension")),
        "the server keeps the descriptive reason: {server_error:?}"
    );
    assert_ne!(
        client_error,
        rustls::Error::AlertReceived(AlertDescription::AccessDenied),
        "a certificate with no identity is not an access-control refusal"
    );
    assert!(
        matches!(client_error, rustls::Error::AlertReceived(_)),
        "the client is still told the handshake failed: {client_error:?}"
    );
}
