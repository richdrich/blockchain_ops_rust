//! Identity-bound TLS for Sidewinder access — the libp2p TLS handshake pattern rooted in an Algorand
//! identity, plus the endpoint-discovery codec. The single, publishable source of this logic, shared by
//! the Sidewinder node/server side (the `sw-tls`/`sw-membership` crates in the sidewinder repo re-export
//! from here) and the client side ([`sidewinder_ops`](https://docs.rs/sidewinder_ops)).
//!
//! A node or client presents a **self-signed certificate with an ephemeral key** (deliberately
//! unrelated to its long-lived Algorand key). The certificate carries a custom X.509 extension in which
//! the **Algorand identity key (Ed25519) signs the ephemeral certificate's `SubjectPublicKeyInfo`**. A
//! peer verifies that signature, derives the Algorand address from the identity key, and checks it
//! against a [`MembershipAuthority`] — never validating a certificate chain against a Certificate
//! Authority (CA), and never calling a node/indexer.
//!
//! [`generate`] mints an identity-bound certificate and [`verify_identity_cert`] runs the offline check.
//! The two ends of a mutual-TLS connection are assembled from separate modules so a build can take just
//! the half it needs:
//!
//! - [`client`] — authenticate the **server** by identity ([`client::IdentityServerVerifier`]) and build
//!   a [`rustls::ClientConfig`] ([`client::client_config`]). Always available.
//! - [`server`] — authenticate the **client** by identity ([`server::IdentityClientVerifier`]) and build
//!   a [`rustls::ServerConfig`] ([`server::server_config`]). Gated behind the `server` cargo feature, so
//!   a **pure API client** (`default-features = false`) never compiles the server-side verifier.
//!
//! Discovery: [`EndpointRecord`] is the shared codec for a node's reachable endpoint(s), and
//! [`EndpointResolver`] resolves the live `(identity, endpoint)` set of an application's permitted nodes
//! off the incremental opted-in-accounts scan. The local-state decoders ([`MembershipDecoder`],
//! [`bit_decoder`], [`key_set_decoder`]) are the generic seam both discovery and the on-chain membership
//! sources (in the sidewinder `sw-membership` crate) build on.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

mod certificate;
mod decoder;
mod endpoint;
mod membership;
mod resolver;
mod verify;

pub mod client;
#[cfg(feature = "server")]
pub mod server;

pub use certificate::{IdentityCert, generate};
pub use decoder::{MembershipDecoder, bit_decoder, key_set_decoder};
pub use endpoint::EndpointRecord;
pub use membership::{MembershipAuthority, Role, StaticMembership};
pub use resolver::EndpointResolver;
pub use verify::{VerifyError, verify_identity_cert, verify_identity_cert_for_role};

/// The crate's crypto provider: `rustls`'s **ring** provider, selected explicitly (not aws-lc-rs) to
/// avoid a C toolchain build dependency. Both the config builders and the verifiers must share one
/// provider; construct it here so consumers do not reach into `rustls::crypto` themselves.
pub fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The object identifier (OID) of the Sidewinder identity-binding certificate extension.
///
/// Placeholder value pending an Internet Assigned Numbers Authority (IANA) Private Enterprise Number
/// (PEN) assignment for Sidewinder — do **not** reuse libp2p's registered arc (`…53594.1.1`). Both ends
/// only need to agree on this value, so a placeholder is sufficient for the spike; final assignment is
/// an open question tracked in the design note.
pub const SIDEWINDER_IDENTITY_EXT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 66778, 1, 1];

/// The dotted-string form of [`SIDEWINDER_IDENTITY_EXT_OID`], for matching a parsed certificate's
/// extension without reconstructing an OID value.
pub const SIDEWINDER_IDENTITY_EXT_OID_STR: &str = "1.3.6.1.4.1.66778.1.1";

/// The domain-separation prefix the identity key signs, ahead of the leaf `SubjectPublicKeyInfo`.
///
/// Sidewinder-scoped and versioned so a signature can never be replayed as a libp2p handshake signature
/// (which uses `libp2p-tls-handshake:`) or across a future Sidewinder scheme revision.
pub const IDENTITY_SIG_PREFIX: &[u8] = b"sidewinder-tls-identity:v1:";

/// DER-encode the `SignedKey` extension payload: `SEQUENCE { identityPublicKey OCTET STRING, signature
/// OCTET STRING }` (raw 32-byte Ed25519 public key, raw 64-byte signature).
pub(crate) fn encode_signed_key(identity_public_key: &[u8], signature: &[u8]) -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|seq| {
            seq.next().write_bytes(identity_public_key);
            seq.next().write_bytes(signature);
        });
    })
}

/// Decode the `SignedKey` payload produced by [`encode_signed_key`].
pub(crate) fn decode_signed_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), yasna::ASN1Error> {
    yasna::parse_der(der, |reader| {
        reader.read_sequence(|seq| {
            let public_key = seq.next().read_bytes()?;
            let signature = seq.next().read_bytes()?;
            Ok((public_key, signature))
        })
    })
}

/// The message the identity key signs: [`IDENTITY_SIG_PREFIX`] concatenated with the leaf certificate's
/// `SubjectPublicKeyInfo` DER. Shared by the generator and the verifier so the two cannot drift.
pub(crate) fn identity_signing_message(leaf_spki_der: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(IDENTITY_SIG_PREFIX.len() + leaf_spki_der.len());
    message.extend_from_slice(IDENTITY_SIG_PREFIX);
    message.extend_from_slice(leaf_spki_der);
    message
}
