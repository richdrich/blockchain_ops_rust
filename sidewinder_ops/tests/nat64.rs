//! NAT64 prefix discovery (RFC 7050) and IPv4-embedded address synthesis (RFC 6052) — #146. The
//! resolver is a fake, so no test touches the network's DNS.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use sidewinder_ops::nat64::{
    Nat64Prefix, Nat64Resolver, PREFIX_LENGTHS, discover_prefixes, ordered_candidates,
    prefixes_from_answers, synthesisable,
};

/// A resolver that returns canned `ipv4only.arpa` answers, or an error.
struct FakeResolver(std::io::Result<Vec<IpAddr>>);

impl Nat64Resolver for FakeResolver {
    fn lookup_ipv4only(&self) -> std::io::Result<Vec<IpAddr>> {
        match &self.0 {
            Ok(answers) => Ok(answers.clone()),
            Err(error) => Err(std::io::Error::new(error.kind(), error.to_string())),
        }
    }
}

fn v6(text: &str) -> Ipv6Addr {
    Ipv6Addr::from_str(text).expect("valid IPv6 literal")
}

fn sock(text: &str) -> SocketAddr {
    SocketAddr::from_str(text).expect("valid socket address")
}

// RFC 6052 section 2.4 table: 192.0.2.33 embedded under 2001:db8:122:344::/n for every length.
const RFC6052_EXAMPLES: [(u8, &str, &str); 6] = [
    (32, "2001:db8::", "2001:db8:c000:221::"),
    (40, "2001:db8:100::", "2001:db8:1c0:2:21::"),
    (48, "2001:db8:122::", "2001:db8:122:c000:2:2100::"),
    (56, "2001:db8:122:300::", "2001:db8:122:3c0:0:221::"),
    (64, "2001:db8:122:344::", "2001:db8:122:344:c0:2:2100:0"),
    (96, "2001:db8:122:344::", "2001:db8:122:344::192.0.2.33"),
];

#[test]
fn embedding_matches_the_rfc_6052_examples_for_every_prefix_length() {
    let v4 = Ipv4Addr::new(192, 0, 2, 33);
    for (len, prefix, expected) in RFC6052_EXAMPLES {
        let prefix = Nat64Prefix::new(v6(prefix), len).expect("permitted length");
        assert_eq!(prefix.embed(v4), v6(expected), "/{len}");
        assert_eq!(prefix.extract(v6(expected)), Some(v4), "/{len} round-trips");
    }
}

#[test]
fn the_well_known_prefix_embeds_in_the_last_four_octets() {
    let prefix = Nat64Prefix::well_known();
    assert_eq!(prefix.prefix_len(), 96);
    assert_eq!(
        prefix.embed(Ipv4Addr::new(203, 0, 113, 5)),
        v6("64:ff9b::cb00:7105")
    );
    assert_eq!(prefix.to_string(), "64:ff9b::/96");
}

#[test]
fn only_rfc_6052_prefix_lengths_are_accepted_and_host_bits_are_dropped() {
    for len in 0..=128u8 {
        assert_eq!(
            Nat64Prefix::new(v6("2001:db8::"), len).is_some(),
            PREFIX_LENGTHS.contains(&len),
            "/{len}"
        );
    }
    let prefix = Nat64Prefix::new(v6("2001:db8:ffff:ffff::1"), 32).expect("/32");
    assert_eq!(prefix.prefix(), v6("2001:db8::"));
}

#[test]
fn extract_rejects_an_address_outside_the_prefix_or_with_the_u_octet_set() {
    let prefix = Nat64Prefix::new(v6("2001:db8:122:344::"), 64).expect("/64");
    assert_eq!(prefix.extract(v6("2001:db8:999:344:c0:2:2100:0")), None);
    assert_eq!(prefix.extract(v6("2001:db8:122:344:ffc0:2:2100:0")), None);
}

#[test]
fn discovery_finds_the_prefix_at_every_length_from_the_well_known_answers() {
    for (len, prefix, _) in RFC6052_EXAMPLES {
        let prefix = Nat64Prefix::new(v6(prefix), len).expect("permitted length");
        // a DNS64 resolver answers ipv4only.arpa with both well-known addresses synthesised.
        let answers = vec![
            IpAddr::V6(prefix.embed(Ipv4Addr::new(192, 0, 0, 170))),
            IpAddr::V6(prefix.embed(Ipv4Addr::new(192, 0, 0, 171))),
        ];
        assert_eq!(
            discover_prefixes(&FakeResolver(Ok(answers))),
            vec![prefix],
            "/{len}: one prefix, de-duplicated across the two answers"
        );
    }
}

#[test]
fn discovery_reports_every_distinct_prefix() {
    let a = Nat64Prefix::well_known();
    let b = Nat64Prefix::new(v6("2001:db8:64::"), 96).expect("/96");
    let answers = vec![
        IpAddr::V6(a.embed(Ipv4Addr::new(192, 0, 0, 170))),
        IpAddr::V6(b.embed(Ipv4Addr::new(192, 0, 0, 171))),
    ];
    assert_eq!(prefixes_from_answers(&answers), vec![a, b]);
}

#[test]
fn a_network_without_dns64_yields_no_prefix() {
    // no NAT64: ipv4only.arpa resolves to its plain IPv4 addresses only.
    let ipv4_only = FakeResolver(Ok(vec![
        IpAddr::V4(Ipv4Addr::new(192, 0, 0, 170)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 0, 171)),
    ]));
    assert!(discover_prefixes(&ipv4_only).is_empty());

    // an IPv6 answer with no well-known address embedded is not a NAT64 prefix.
    let unrelated = FakeResolver(Ok(vec![IpAddr::V6(v6("2001:db8::1"))]));
    assert!(discover_prefixes(&unrelated).is_empty());

    // a failed lookup (offline, no resolver) is "no prefix", not an error.
    let failed = FakeResolver(Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "lookup failed",
    )));
    assert!(discover_prefixes(&failed).is_empty());
}

#[test]
fn only_global_ipv4_is_synthesised() {
    assert!(synthesisable(Ipv4Addr::new(203, 0, 113, 5)));
    assert!(!synthesisable(Ipv4Addr::LOCALHOST));
    assert!(!synthesisable(Ipv4Addr::UNSPECIFIED));
    assert!(!synthesisable(Ipv4Addr::BROADCAST));
    assert!(!synthesisable(Ipv4Addr::new(169, 254, 1, 1)));
    assert!(!synthesisable(Ipv4Addr::new(224, 0, 0, 1)));
}

#[test]
fn candidates_are_native_ipv6_then_synthesised_then_native_ipv4() {
    let prefix = Nat64Prefix::well_known();
    let addrs = [sock("203.0.113.5:4443"), sock("[2001:db8::5]:443")];
    assert_eq!(
        ordered_candidates(&addrs, &[prefix]),
        vec![
            sock("[2001:db8::5]:443"),
            // the synthesised address keeps the IPv4 endpoint's own port.
            sock("[64:ff9b::cb00:7105]:4443"),
            sock("203.0.113.5:4443"),
        ]
    );
}

#[test]
fn candidates_without_a_prefix_are_ipv6_then_ipv4() {
    let addrs = [sock("203.0.113.5:4443"), sock("[2001:db8::5]:443")];
    assert_eq!(
        ordered_candidates(&addrs, &[]),
        vec![sock("[2001:db8::5]:443"), sock("203.0.113.5:4443")]
    );
}

#[test]
fn loopback_ipv4_is_not_synthesised_and_duplicates_are_dropped() {
    let prefix = Nat64Prefix::well_known();
    let addrs = [sock("127.0.0.1:1"), sock("[::1]:2"), sock("[::1]:2")];
    assert_eq!(
        ordered_candidates(&addrs, &[prefix]),
        vec![sock("[::1]:2"), sock("127.0.0.1:1")]
    );
}
