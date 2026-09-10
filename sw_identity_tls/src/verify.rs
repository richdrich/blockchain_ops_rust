//! The offline identity check, shared by the client-side and server-side `rustls` verifiers.
//!
//! [`verify_identity_cert`] is the whole trust decision: parse the presented certificate, verify the
//! Algorand identity's signature over the leaf key, derive the identity's address, and check it against
//! a [`MembershipAuthority`]. It makes **no** node/indexer call. The verifier adapters that plug this
//! into `rustls` live in [`crate::client`] (server-cert direction) and [`crate::server`] (client-cert
//! direction); the [`tls12`] / [`tls13`] helpers below back both of them.

use std::fmt;

use algo_ops::byte_key_to_address;
use ed25519_dalek::{Signature, VerifyingKey};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::{DigitallySignedStruct, Error as RustlsError};
use x509_parser::prelude::*;

use crate::membership::{MembershipAuthority, Role};
use crate::{SIDEWINDER_IDENTITY_EXT_OID_STR, decode_signed_key, identity_signing_message};

/// Why an identity certificate failed verification.
#[derive(Debug)]
pub enum VerifyError {
    /// The certificate could not be parsed as X.509.
    Parse(String),
    /// The certificate carries no Sidewinder identity extension.
    MissingExtension,
    /// The identity extension payload is malformed.
    BadSignedKey(String),
    /// The embedded identity public key is not a valid 32-byte Ed25519 key.
    BadPublicKey,
    /// The identity signature over the leaf key is invalid (wrong signer, or a tampered certificate).
    SignatureInvalid,
    /// The identity address could not be derived from the public key.
    Address(String),
    /// The identity is authentic but not in the authorized allow-set.
    NotAuthorized(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Parse(e) => write!(f, "certificate parse error: {e}"),
            VerifyError::MissingExtension => write!(f, "no Sidewinder identity extension"),
            VerifyError::BadSignedKey(e) => write!(f, "malformed identity extension: {e}"),
            VerifyError::BadPublicKey => write!(f, "invalid Ed25519 identity public key"),
            VerifyError::SignatureInvalid => write!(f, "identity signature invalid"),
            VerifyError::Address(e) => write!(f, "address derivation failed: {e}"),
            VerifyError::NotAuthorized(a) => write!(f, "identity {a} not authorized"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify that `end_entity` is bound to an authorized Algorand identity, authorized as a **member in any
/// role**, returning that identity's address. This is the role-agnostic wrapper over the shared inner
/// check (`required = None` admits a member in any role).
pub fn verify_identity_cert(
    end_entity: &CertificateDer<'_>,
    authority: &dyn MembershipAuthority,
) -> Result<String, VerifyError> {
    verify_identity_cert_inner(end_entity, authority, None)
}

/// Verify that `end_entity` is bound to an authorized Algorand identity that holds **exactly** `role`,
/// returning that identity's address. Rejects an authentic member of a *different* role (e.g. a
/// [`Role::Client`] presenting on a node-to-node link that requires [`Role::ClusterNode`]) with
/// [`VerifyError::NotAuthorized`], the same as an unknown identity. This is the role-gating the
/// node-to-node (#373) and inbound-client (#374) surfaces apply.
pub fn verify_identity_cert_for_role(
    end_entity: &CertificateDer<'_>,
    authority: &dyn MembershipAuthority,
    role: Role,
) -> Result<String, VerifyError> {
    verify_identity_cert_inner(end_entity, authority, Some(role))
}

/// Verify that `end_entity` is bound to an authorized Algorand identity, returning that identity's
/// address. Pure CPU work — parse, one Ed25519 verification, an address derivation, and a membership
/// lookup. No algod/indexer call is made: authentication is offline, and `authority` is contractually
/// I/O-free too (see [`MembershipAuthority`]), so the whole decision is cheap on a hit *and* a miss.
///
/// `required` gates authorization: `None` admits a member in **any** role; `Some(role)` admits only an
/// identity whose role is exactly `role`. Either way an identity the authority does not admit fails
/// **closed** ([`VerifyError::NotAuthorized`]).
pub(crate) fn verify_identity_cert_inner(
    end_entity: &CertificateDer<'_>,
    authority: &dyn MembershipAuthority,
    required: Option<Role>,
) -> Result<String, VerifyError> {
    let (_, cert) = parse_x509_certificate(end_entity.as_ref())
        .map_err(|e| VerifyError::Parse(e.to_string()))?;

    // the exact SubjectPublicKeyInfo DER the identity key signed at generation.
    let leaf_spki = cert.public_key().raw;

    let extension = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_string() == SIDEWINDER_IDENTITY_EXT_OID_STR)
        .ok_or(VerifyError::MissingExtension)?;

    let (public_key, signature) =
        decode_signed_key(extension.value).map_err(|e| VerifyError::BadSignedKey(e.to_string()))?;

    let public_key_bytes: [u8; 32] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::BadPublicKey)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| VerifyError::BadPublicKey)?;

    let signature_bytes: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::SignatureInvalid)?;
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify_strict(&identity_signing_message(leaf_spki), &signature)
        .map_err(|_| VerifyError::SignatureInvalid)?;

    let address =
        byte_key_to_address(&public_key_bytes).map_err(|e| VerifyError::Address(e.to_string()))?;
    let authorized = match required {
        Some(role) => authority.role_of(&address) == Some(role),
        None => authority.is_member(&address),
    };
    if !authorized {
        return Err(VerifyError::NotAuthorized(address));
    }
    Ok(address)
}

/// Verify a TLS 1.2 handshake signature with `provider`'s algorithms — the identity verifiers delegate
/// the ordinary handshake-signature check here while owning only the peer-identity decision.
pub(crate) fn tls12(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, RustlsError> {
    rustls::crypto::verify_tls12_signature(
        message,
        cert,
        dss,
        &provider.signature_verification_algorithms,
    )
}

/// Verify a TLS 1.3 handshake signature with `provider`'s algorithms (see [`tls12`]).
pub(crate) fn tls13(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, RustlsError> {
    rustls::crypto::verify_tls13_signature(
        message,
        cert,
        dss,
        &provider.signature_verification_algorithms,
    )
}
