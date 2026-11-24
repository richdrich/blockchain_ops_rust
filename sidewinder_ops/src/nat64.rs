//! NAT64 prefix discovery and address synthesis, so an IPv6-only client can reach a node that also
//! advertises an IPv4 literal (blockchain_ops_rust#146).
//!
//! On an IPv6-only network with NAT64 (Network Address Translation from IPv6 to IPv4) and DNS64, the
//! resolver synthesises IPv6 addresses for IPv4-only names, but nothing synthesises an IPv4 *literal*:
//! the HTTP connector never resolves an IP-literal host. So the client discovers the network's NAT64
//! prefix itself, per RFC 7050 (look up the well-known IPv4-only name `ipv4only.arpa` and find where its
//! well-known addresses `192.0.0.170` / `192.0.0.171` are embedded in the IPv6 answers), then embeds a
//! node's IPv4 address in that prefix per RFC 6052.
//!
//! The lookup goes through a [`Nat64Resolver`] so tests can inject the answers;
//! [`SystemNat64Resolver`] uses the platform resolver (`getaddrinfo`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs};

/// The well-known IPv4-only name RFC 7050 resolves to discover a NAT64 prefix.
pub const IPV4ONLY_ARPA: &str = "ipv4only.arpa";

/// The two well-known IPv4 addresses `ipv4only.arpa` resolves to (RFC 7050 section 2.2).
pub const WELL_KNOWN_IPV4: [Ipv4Addr; 2] =
    [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

/// The prefix lengths RFC 6052 section 2.2 permits, longest first.
pub const PREFIX_LENGTHS: [u8; 6] = [96, 64, 56, 48, 40, 32];

/// Looks up the addresses of [`IPV4ONLY_ARPA`] — the only query RFC 7050 discovery needs.
pub trait Nat64Resolver: Send + Sync {
    /// Every address the network's resolver returns for `ipv4only.arpa` (IPv4 and IPv6 alike). An
    /// error, or no IPv6 answer, means no NAT64 prefix is discoverable.
    fn lookup_ipv4only(&self) -> std::io::Result<Vec<IpAddr>>;
}

/// The platform resolver: `("ipv4only.arpa", 0).to_socket_addrs()`, which calls `getaddrinfo` for a
/// hostname, so on a DNS64 network the IPv6 answers are the synthesised ones.
#[derive(Debug, Clone, Copy)]
pub struct SystemNat64Resolver;

impl Nat64Resolver for SystemNat64Resolver {
    fn lookup_ipv4only(&self) -> std::io::Result<Vec<IpAddr>> {
        Ok((IPV4ONLY_ARPA, 0)
            .to_socket_addrs()?
            .map(|addr| addr.ip())
            .collect())
    }
}

/// A NAT64 prefix: the network bits and their length (one of [`PREFIX_LENGTHS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nat64Prefix {
    // the prefix octets with every bit past `len` zeroed.
    octets: [u8; 16],
    len: u8,
}

impl Nat64Prefix {
    /// The RFC 6052 well-known prefix `64:ff9b::/96`.
    pub fn well_known() -> Self {
        Self::new(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96)
            .expect("64:ff9b::/96 is a valid prefix")
    }

    /// A prefix of `len` bits taken from `prefix`, or `None` if `len` is not one of [`PREFIX_LENGTHS`].
    /// Bits past `len` are ignored.
    pub fn new(prefix: Ipv6Addr, len: u8) -> Option<Self> {
        if !PREFIX_LENGTHS.contains(&len) {
            return None;
        }
        let mut octets = prefix.octets();
        for octet in octets.iter_mut().skip(usize::from(len / 8)) {
            *octet = 0;
        }
        Some(Self { octets, len })
    }

    /// The prefix as an address, bits past [`prefix_len`](Self::prefix_len) zero.
    pub fn prefix(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.octets)
    }

    /// The prefix length in bits.
    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    /// The IPv4-embedded IPv6 address for `v4` under this prefix (RFC 6052 section 2.2): the IPv4 octets
    /// go at the positions for the prefix length, skipping bits 64–71 (the `u` octet, always zero), and
    /// the suffix is zero.
    pub fn embed(&self, v4: Ipv4Addr) -> Ipv6Addr {
        let mut octets = self.octets;
        for (position, byte) in embed_positions(self.len).iter().zip(v4.octets()) {
            octets[*position] = byte;
        }
        Ipv6Addr::from(octets)
    }

    /// The IPv4 address embedded in `v6` at this prefix length's positions, if `v6` lies under this
    /// prefix and its `u` octet is zero.
    pub fn extract(&self, v6: Ipv6Addr) -> Option<Ipv4Addr> {
        let candidate = Self::new(v6, self.len)?;
        if candidate.octets != self.octets {
            return None;
        }
        embedded_ipv4(v6, self.len)
    }
}

impl std::fmt::Display for Nat64Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.prefix(), self.len)
    }
}

// The octet positions the four IPv4 octets occupy for a prefix of `len` bits (RFC 6052 figure 1). Octet
// 8 (bits 64–71) is the reserved `u` octet and is never used.
fn embed_positions(len: u8) -> [usize; 4] {
    match len {
        32 => [4, 5, 6, 7],
        40 => [5, 6, 7, 9],
        48 => [6, 7, 9, 10],
        56 => [7, 9, 10, 11],
        64 => [9, 10, 11, 12],
        96 => [12, 13, 14, 15],
        other => unreachable!("prefix length {other} was validated by Nat64Prefix::new"),
    }
}

// The IPv4 address at the `len`-bit embedding positions of `v6`, or `None` when the `u` octet is set
// (only a /96 has no `u` octet to check).
fn embedded_ipv4(v6: Ipv6Addr, len: u8) -> Option<Ipv4Addr> {
    let octets = v6.octets();
    if len != 96 && octets[8] != 0 {
        return None;
    }
    let [a, b, c, d] = embed_positions(len).map(|position| octets[position]);
    Some(Ipv4Addr::new(a, b, c, d))
}

/// The NAT64 prefixes evident in `answers` (the addresses `ipv4only.arpa` resolved to): for each IPv6
/// answer, the longest RFC 6052 prefix length at whose position a well-known IPv4 address is embedded.
/// IPv4 answers (a network without DNS64) are ignored. De-duplicated, in answer order.
pub fn prefixes_from_answers(answers: &[IpAddr]) -> Vec<Nat64Prefix> {
    let mut prefixes = Vec::new();
    for answer in answers {
        let IpAddr::V6(v6) = answer else {
            continue;
        };
        let found = PREFIX_LENGTHS.iter().find_map(|&len| {
            let embedded = embedded_ipv4(*v6, len)?;
            if WELL_KNOWN_IPV4.contains(&embedded) {
                Nat64Prefix::new(*v6, len)
            } else {
                None
            }
        });
        if let Some(prefix) = found
            && !prefixes.contains(&prefix)
        {
            prefixes.push(prefix);
        }
    }
    prefixes
}

/// Discover the network's NAT64 prefixes through `resolver` (RFC 7050). Empty when the lookup fails or
/// returns no synthesised IPv6 address — the network has no NAT64, and nothing should be synthesised.
pub fn discover_prefixes(resolver: &dyn Nat64Resolver) -> Vec<Nat64Prefix> {
    match resolver.lookup_ipv4only() {
        Ok(answers) => prefixes_from_answers(&answers),
        Err(error) => {
            tracing::debug!("NAT64 prefix discovery ({IPV4ONLY_ARPA}) found nothing: {error}");
            Vec::new()
        }
    }
}

/// Whether an IPv4 address is worth reaching through NAT64: a NAT64 gateway only translates to global
/// destinations, so loopback, link-local, unspecified, broadcast and multicast addresses are skipped.
pub fn synthesisable(v4: Ipv4Addr) -> bool {
    !(v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast())
}

/// The order a client tries a node's advertised `addrs` in: every native IPv6 address, then the
/// NAT64-synthesised form of each synthesisable IPv4 address under each of `prefixes` (keeping its
/// port), then every native IPv4 address. Duplicates are dropped. The HTTP connector races the first
/// family against the second (Happy Eyeballs), so IPv6 — native or synthesised — is preferred and IPv4
/// is the fallback.
pub fn ordered_candidates(addrs: &[SocketAddr], prefixes: &[Nat64Prefix]) -> Vec<SocketAddr> {
    let mut ordered: Vec<SocketAddr> = Vec::new();
    let mut push = |addr: SocketAddr| {
        if !ordered.contains(&addr) {
            ordered.push(addr);
        }
    };
    for addr in addrs.iter().filter(|addr| addr.is_ipv6()) {
        push(*addr);
    }
    for addr in addrs {
        if let SocketAddr::V4(v4) = addr
            && synthesisable(*v4.ip())
        {
            for prefix in prefixes {
                push(SocketAddr::V6(SocketAddrV6::new(
                    prefix.embed(*v4.ip()),
                    v4.port(),
                    0,
                    0,
                )));
            }
        }
    }
    for addr in addrs.iter().filter(|addr| addr.is_ipv4()) {
        push(*addr);
    }
    ordered
}
