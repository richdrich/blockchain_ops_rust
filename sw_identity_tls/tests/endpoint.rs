//! Unit tests for the endpoint record codec (#372) — round-trips, layout, and rejection of malformed
//! records. Pure, offline.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use sw_identity_tls::EndpointRecord;

fn v4(a: [u8; 4], port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::from(a), port)
}

fn v6(port: u16) -> SocketAddrV6 {
    SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), port, 0, 0)
}

#[test]
fn round_trips_both_stacks_through_the_base64_form() {
    let record = EndpointRecord::new(Some(v4([203, 0, 113, 7], 4000)), Some(v6(4001))).unwrap();
    let decoded = EndpointRecord::decode(&record.encode()).expect("decode");
    assert_eq!(decoded, record);
    // the ordered socket addresses a client would try: IPv4 first, then IPv6.
    assert_eq!(
        decoded.socket_addrs(),
        vec![
            SocketAddr::V4(v4([203, 0, 113, 7], 4000)),
            SocketAddr::V6(v6(4001)),
        ]
    );
}

#[test]
fn round_trips_a_single_stack_each_way() {
    // the ambiguous case the base64 wrapping guards: 127.0.0.1's bytes are valid ASCII.
    let only_v4 = EndpointRecord::new(Some(v4([127, 0, 0, 1], 1080)), None).unwrap();
    assert_eq!(EndpointRecord::decode(&only_v4.encode()), Some(only_v4));

    let only_v6 = EndpointRecord::new(None, Some(v6(1080))).unwrap();
    assert_eq!(EndpointRecord::decode(&only_v6.encode()), Some(only_v6));
}

#[test]
fn the_binary_layout_is_the_documented_compact_form() {
    let record = EndpointRecord::new(Some(v4([10, 0, 0, 1], 0x0102)), None).unwrap();
    // flags = 0b01 (IPv4 only), then 4 address bytes, then the big-endian port.
    assert_eq!(record.to_bytes(), vec![0b01, 10, 0, 0, 1, 0x01, 0x02]);

    let both = EndpointRecord::new(Some(v4([1, 2, 3, 4], 5)), Some(v6(6))).unwrap();
    assert_eq!(both.to_bytes().len(), 1 + 6 + 18); // flags + v4 block + v6 block
    assert_eq!(both.to_bytes()[0], 0b11);
}

#[test]
fn an_empty_record_has_no_endpoint_and_is_rejected() {
    assert_eq!(EndpointRecord::new(None, None), None);
    // a flags-only blob (no stacks) decodes to nothing.
    assert_eq!(EndpointRecord::from_bytes(&[0b00]), None);
}

#[test]
fn malformed_records_are_rejected() {
    assert_eq!(EndpointRecord::from_bytes(&[]), None); // empty
    assert_eq!(EndpointRecord::from_bytes(&[0b01, 10, 0, 0]), None); // truncated v4 block
    assert_eq!(
        EndpointRecord::from_bytes(&[0b01, 10, 0, 0, 1, 0, 0, 99]),
        None
    ); // trailing byte
    assert_eq!(EndpointRecord::from_bytes(&[0b100, 1, 2, 3]), None); // unknown flag bit
    assert_eq!(EndpointRecord::decode("not base64!!"), None);
}
