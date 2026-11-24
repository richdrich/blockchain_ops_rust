//! A client tries every address a node advertises (#146): native IPv6 first, then NAT64-synthesised
//! forms of the IPv4 address, then native IPv4 — and the node's pinned identity is checked whichever
//! address answers. Drives the real mutual-TLS transport against loopback TLS nodes on `[::1]` and
//! `127.0.0.1`; the NAT64 resolver is injected, so no test touches the network's DNS.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use algo_ops::AlgoOps;
use ed25519_dalek::SigningKey;
use sidewinder_ops::nat64::{Nat64Prefix, Nat64Resolver};
use sidewinder_ops::{
    DiscoveredNode, EndpointRecord, SidewinderClient, SidewinderError, SidewinderErrorKind,
    SidewinderOps,
};

use crate::support::TEST_SEED_B64;
use crate::support::tls_mock_node::{TlsMockNode, identity_address};

/// A NAT64 resolver with canned `ipv4only.arpa` answers that counts how often it is asked.
struct CountingResolver {
    answers: Vec<IpAddr>,
    lookups: AtomicUsize,
}

impl CountingResolver {
    fn new(answers: Vec<IpAddr>) -> Arc<Self> {
        Arc::new(Self {
            answers,
            lookups: AtomicUsize::new(0),
        })
    }

    fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl Nat64Resolver for CountingResolver {
    fn lookup_ipv4only(&self) -> std::io::Result<Vec<IpAddr>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Ok(self.answers.clone())
    }
}

fn client_algo() -> AlgoOps {
    AlgoOps::new_for_algorand(Some(TEST_SEED_B64.to_string()), None, None)
}

fn client_identity() -> String {
    let seed = client_algo().private_key_bytes().expect("client seed");
    identity_address(&SigningKey::from_bytes(
        &seed.try_into().expect("32-byte seed"),
    ))
}

/// A loopback address on `ip` with nothing listening — a connection to it is refused at once.
fn dead_addr(ip: &str) -> SocketAddr {
    let listener = TcpListener::bind((ip, 0)).expect("bind a throwaway port");
    let addr = listener.local_addr().expect("throwaway local addr");
    drop(listener);
    addr
}

fn v4(addr: SocketAddr) -> SocketAddrV4 {
    match addr {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => panic!("expected an IPv4 address, got {addr}"),
    }
}

fn v6(addr: SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V6(v6) => v6,
        SocketAddr::V4(_) => panic!("expected an IPv6 address, got {addr}"),
    }
}

/// A discovered node bound to `identity` advertising both an IPv4 and an IPv6 endpoint.
fn dual_stack(identity: String, ipv4: SocketAddr, ipv6: SocketAddr) -> DiscoveredNode {
    DiscoveredNode {
        identity,
        endpoint: EndpointRecord::new(Some(v4(ipv4)), Some(v6(ipv6))).expect("endpoint record"),
    }
}

/// A resolver reporting no NAT64 (and counting lookups), so the tests never query real DNS.
fn no_nat64() -> Arc<CountingResolver> {
    CountingResolver::new(Vec::new())
}

#[test]
fn a_dead_ipv4_and_live_ipv6_endpoint_connects_with_the_pin_holding() {
    let node_key = SigningKey::from_bytes(&[200u8; 32]);
    let node = TlsMockNode::start_v6(&node_key, vec![client_identity()]);
    let target = dual_stack(
        identity_address(&node_key),
        dead_addr("127.0.0.1"),
        node.addr(),
    );

    let client = SidewinderClient::connect(client_algo(), &target)
        .expect("connect")
        .with_nat64_resolver(no_nat64());
    let (status, _body) = client
        .get("/health")
        .expect("the live IPv6 address answers although the IPv4 one is dead");
    assert_eq!(status, 200);
    assert_eq!(node.connections(), 1, "IPv6 is tried first and answers");
}

#[test]
fn a_dead_ipv6_falls_back_to_a_live_ipv4() {
    let node_key = SigningKey::from_bytes(&[200u8; 32]);
    let node = TlsMockNode::start(&node_key, vec![client_identity()]);
    let target = dual_stack(identity_address(&node_key), node.addr(), dead_addr("::1"));

    let client = SidewinderClient::connect(client_algo(), &target)
        .expect("connect")
        .with_nat64_resolver(no_nat64());
    assert!(
        client.health().expect("the IPv4 fallback answers"),
        "every advertised address is tried, not just the first"
    );
}

#[test]
fn the_pin_still_rejects_a_wrong_identity_on_the_ipv6_address() {
    let node_key = SigningKey::from_bytes(&[200u8; 32]);
    let node = TlsMockNode::start_v6(&node_key, vec![client_identity()]);
    // the resolved identity is not the one the node at [::1] presents.
    let wrong = identity_address(&SigningKey::from_bytes(&[201u8; 32]));
    let target = dual_stack(wrong, dead_addr("127.0.0.1"), node.addr());

    let client = SidewinderClient::connect(client_algo(), &target)
        .expect("client builds")
        .with_nat64_resolver(no_nat64());
    let error = client
        .health()
        .expect_err("a node presenting another identity is rejected on any address");
    let typed = error
        .downcast_ref::<SidewinderError>()
        .unwrap_or_else(|| panic!("a typed SidewinderError, got: {error:#}"));
    assert_eq!(typed.kind, SidewinderErrorKind::HostUnreachable);
    assert!(
        typed.message.contains("not authorized"),
        "the verifier's reason is reported: {}",
        typed.message
    );
}

#[test]
fn candidates_put_synthesised_nat64_between_native_ipv6_and_ipv4() {
    let prefix = Nat64Prefix::well_known();
    let resolver = CountingResolver::new(vec![
        IpAddr::V6(prefix.embed(Ipv4Addr::new(192, 0, 0, 170))),
        IpAddr::V6(prefix.embed(Ipv4Addr::new(192, 0, 0, 171))),
    ]);
    let ipv4 = SocketAddr::from_str("203.0.113.5:4443").expect("ipv4");
    let ipv6 = SocketAddr::from_str("[2001:db8::5]:443").expect("ipv6");
    let target = dual_stack(
        identity_address(&SigningKey::from_bytes(&[200u8; 32])),
        ipv4,
        ipv6,
    );

    let client = SidewinderClient::connect(client_algo(), &target)
        .expect("connect")
        .with_nat64_resolver(resolver.clone());
    let expected = vec![
        ipv6,
        SocketAddr::from_str("[64:ff9b::cb00:7105]:4443").expect("synthesised"),
        ipv4,
    ];
    assert_eq!(client.candidate_addrs().expect("candidates"), expected);
    assert_eq!(
        client.candidate_addrs().expect("candidates again"),
        expected
    );
    assert_eq!(
        resolver.lookups(),
        1,
        "the NAT64 prefix is discovered once per client"
    );
}

#[test]
fn no_nat64_lookup_is_made_when_there_is_no_global_ipv4_to_synthesise() {
    let resolver = no_nat64();
    let target = dual_stack(
        identity_address(&SigningKey::from_bytes(&[200u8; 32])),
        SocketAddr::from_str("127.0.0.1:4443").expect("ipv4"),
        SocketAddr::from_str("[::1]:443").expect("ipv6"),
    );
    let client = SidewinderClient::connect(client_algo(), &target)
        .expect("connect")
        .with_nat64_resolver(resolver.clone());
    assert_eq!(
        client.candidate_addrs().expect("candidates"),
        vec![
            SocketAddr::from_str("[::1]:443").expect("ipv6"),
            SocketAddr::from_str("127.0.0.1:4443").expect("ipv4"),
        ]
    );
    assert_eq!(resolver.lookups(), 0);
}

#[test]
fn connect_addrs_rejects_an_empty_address_list() {
    let identity = identity_address(&SigningKey::from_bytes(&[200u8; 32]));
    assert!(SidewinderClient::connect_addrs(client_algo(), &[], &identity).is_err());
}

#[test]
fn one_client_serves_repeated_requests() {
    // the transport (and its runtime) is built once and reused; the mock closes each connection, so
    // every request dials again through the same client.
    let node_key = SigningKey::from_bytes(&[200u8; 32]);
    let node = TlsMockNode::start_v6(&node_key, vec![client_identity()]);
    let client = SidewinderClient::connect_addrs(
        client_algo(),
        &[node.addr()],
        &identity_address(&node_key),
    )
    .expect("connect")
    .with_nat64_resolver(no_nat64());
    for _ in 0..3 {
        assert!(client.health().expect("health"));
    }
    assert_eq!(node.connections(), 3);
}

#[test]
fn a_client_works_from_inside_a_tokio_runtime() {
    let node_key = SigningKey::from_bytes(&[200u8; 32]);
    let node = TlsMockNode::start_v6(&node_key, vec![client_identity()]);
    let client = SidewinderClient::connect_addrs(
        client_algo(),
        &[node.addr()],
        &identity_address(&node_key),
    )
    .expect("connect")
    .with_nat64_resolver(no_nat64());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("caller runtime");
    // the blocking call and the client's drop both happen inside the caller's runtime.
    runtime.block_on(async move {
        assert!(client.health().expect("health from inside a runtime"));
        drop(client);
    });
}
