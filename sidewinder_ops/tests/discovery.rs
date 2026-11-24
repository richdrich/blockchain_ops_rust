//! `DiscoveredNode` address accessors (#146): every advertised address, IPv6 first.

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use sidewinder_ops::{DiscoveredNode, EndpointRecord};

fn node(v4: Option<&str>, v6: Option<&str>) -> DiscoveredNode {
    let v4 = v4.map(|text| SocketAddrV4::from_str(text).expect("ipv4"));
    let v6 = v6.map(|text| SocketAddrV6::from_str(text).expect("ipv6"));
    DiscoveredNode {
        identity: "IDENTITY".to_string(),
        endpoint: EndpointRecord::new(v4, v6).expect("endpoint record"),
    }
}

fn sock(text: &str) -> SocketAddr {
    SocketAddr::from_str(text).expect("socket address")
}

#[test]
fn addrs_lists_ipv6_before_ipv4() {
    let dual = node(Some("203.0.113.5:4443"), Some("[2001:db8::5]:443"));
    assert_eq!(
        dual.addrs(),
        vec![sock("[2001:db8::5]:443"), sock("203.0.113.5:4443")]
    );
}

#[test]
fn base_url_is_the_first_ipv6_address() {
    let dual = node(Some("203.0.113.5:4443"), Some("[2001:db8::5]:443"));
    assert_eq!(
        dual.base_url().as_deref(),
        Some("https://[2001:db8::5]:443")
    );
}

#[test]
fn a_single_stack_node_lists_its_one_address() {
    let ipv4_only = node(Some("203.0.113.5:4443"), None);
    assert_eq!(ipv4_only.addrs(), vec![sock("203.0.113.5:4443")]);
    assert_eq!(
        ipv4_only.base_url().as_deref(),
        Some("https://203.0.113.5:4443")
    );

    let ipv6_only = node(None, Some("[2001:db8::5]:443"));
    assert_eq!(ipv6_only.addrs(), vec![sock("[2001:db8::5]:443")]);
}
