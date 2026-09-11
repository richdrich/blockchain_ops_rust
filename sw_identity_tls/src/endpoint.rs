//! The on-chain node-endpoint record — the discovery half of epic #240 (#372).
//!
//! A permitted cluster node publishes its reachable Sidewinder endpoint(s) into a byte-slice in one of
//! its own per-account local-state keys (which key, and the setter method that writes it, are the
//! deploying DApp's concern — the node config names them); a client resolves a network's live endpoints
//! from only the app id by enumerating the opted-in node accounts and decoding this record. This module
//! is the **shared codec**: the node encodes its endpoints to publish, and the resolver decodes them on
//! read — both sides agree on the layout here and with the DApp write side. It is DApp-agnostic: no
//! specific local-state key or method name is baked in.
//!
//! **Layout.** The record is a compact binary blob, **base64-encoded** for storage (so the opted-in scan's
//! string decode of the byte-slice is unambiguous UTF-8 — a raw record like `127.0.0.1` is otherwise
//! valid ASCII and indistinguishable from the hex fallback). The binary is:
//! `[flags:1]` (bit 0 = IPv4 present, bit 1 = IPv6 present) then, if present, `[v4 addr:4][port:2]` then
//! `[v6 addr:16][port:2]`. The two stacks are independent — each carries its own address and port. ≤ 25
//! bytes (base64 ≤ 36).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

const FLAG_V4: u8 = 0b01;
const FLAG_V6: u8 = 0b10;

/// a node's published reachable endpoint(s): an optional IPv4 socket address and an optional IPv6 one,
/// each independent (they need not share an address or a port). At least one is present in a valid record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointRecord {
    /// the node's IPv4 endpoint, if it publishes one.
    pub v4: Option<SocketAddrV4>,
    /// the node's IPv6 endpoint, if it publishes one.
    pub v6: Option<SocketAddrV6>,
}

impl EndpointRecord {
    /// A record with the given IPv4 and/or IPv6 endpoints. Returns `None` if both are absent (an empty
    /// record carries no endpoint and is never published).
    pub fn new(v4: Option<SocketAddrV4>, v6: Option<SocketAddrV6>) -> Option<Self> {
        (v4.is_some() || v6.is_some()).then_some(Self { v4, v6 })
    }

    /// A record from optionally-advertised IPv4 and IPv6 socket addresses (e.g. a node's `advertise`
    /// config). Only the matching family of each argument is used — a `SocketAddr::V6` given as the IPv4
    /// argument is dropped, not published under the wrong stack. `None` if neither yields an endpoint.
    pub fn from_socket_addrs(ipv4: Option<SocketAddr>, ipv6: Option<SocketAddr>) -> Option<Self> {
        let v4 = ipv4.and_then(|addr| match addr {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        });
        let v6 = ipv6.and_then(|addr| match addr {
            SocketAddr::V6(v6) => Some(v6),
            SocketAddr::V4(_) => None,
        });
        Self::new(v4, v6)
    }

    /// The reachable socket addresses this record advertises, IPv4 first then IPv6 — the order a client
    /// tries them in.
    pub fn socket_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs = Vec::with_capacity(2);
        if let Some(v4) = self.v4 {
            addrs.push(SocketAddr::V4(v4));
        }
        if let Some(v6) = self.v6 {
            addrs.push(SocketAddr::V6(v6));
        }
        addrs
    }

    /// The compact binary encoding (see the module layout). Prefer [`encode`](Self::encode) for the
    /// on-chain (base64) form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(25);
        let mut flags = 0u8;
        if self.v4.is_some() {
            flags |= FLAG_V4;
        }
        if self.v6.is_some() {
            flags |= FLAG_V6;
        }
        out.push(flags);
        if let Some(v4) = self.v4 {
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        if let Some(v6) = self.v6 {
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
        out
    }

    /// Decode the compact binary form. `None` on a malformed record (unknown flag bits, a truncated or
    /// over-long blob, or an empty record with no endpoint). Strict: trailing bytes are rejected.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&flags, mut rest) = bytes.split_first()?;
        if flags & !(FLAG_V4 | FLAG_V6) != 0 {
            return None; // unknown flag bits — a record from a newer/other format.
        }
        let mut v4 = None;
        let mut v6 = None;
        if flags & FLAG_V4 != 0 {
            let (block, tail) = rest.split_at_checked(6)?;
            let ip = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
            let port = u16::from_be_bytes([block[4], block[5]]);
            v4 = Some(SocketAddrV4::new(ip, port));
            rest = tail;
        }
        if flags & FLAG_V6 != 0 {
            let (block, tail) = rest.split_at_checked(18)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&block[..16]);
            let port = u16::from_be_bytes([block[16], block[17]]);
            v6 = Some(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0));
            rest = tail;
        }
        if !rest.is_empty() {
            return None; // trailing bytes.
        }
        Self::new(v4, v6)
    }

    /// The on-chain form: base64 of the compact binary record. This is the value stored in the DApp's
    /// endpoint local-state byte-slice (whichever key the deployment names).
    pub fn encode(&self) -> String {
        STANDARD.encode(self.to_bytes())
    }

    /// Decode the on-chain (base64) form as read from local state. `None` if it is not valid base64 or
    /// not a valid record.
    pub fn decode(value: &str) -> Option<Self> {
        Self::from_bytes(&STANDARD.decode(value).ok()?)
    }
}
