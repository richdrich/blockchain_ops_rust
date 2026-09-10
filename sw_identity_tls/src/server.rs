//! Server-side identity-bound TLS.
//!
//! A listening node authenticates the **client** by its Algorand identity ([`IdentityClientVerifier`],
//! client authentication is mandatory) and presents its own identity certificate. This module is gated
//! behind the `server` cargo feature so a client-only consumer does not compile it — nor an on-chain
//! membership cache plugged into the authorization seam here.

use std::sync::{Arc, Mutex};

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error as RustlsError, ServerConfig, SignatureScheme,
};

use crate::verify::{tls12, tls13, verify_identity_cert_inner};
use crate::{IdentityCert, MembershipAuthority, Role};

/// A `rustls` client-certificate verifier that authenticates the **client** by its Algorand identity.
/// Client authentication is mandatory; trust is pinned to the on-chain identity, never a CA chain.
#[derive(Debug)]
pub struct IdentityClientVerifier {
    authority: Arc<dyn MembershipAuthority>,
    required_role: Option<Role>,
    provider: Arc<CryptoProvider>,
    authenticated: Arc<Mutex<Option<String>>>,
}

impl IdentityClientVerifier {
    /// Build a verifier that accepts any client identity `authority` deems a member (any role), using
    /// `provider` for handshake-signature verification. `authority` is consulted **live** on each
    /// handshake, so a membership change (e.g. a polled on-chain cache) takes effect without rebuilding
    /// this.
    pub fn new(authority: Arc<dyn MembershipAuthority>, provider: Arc<CryptoProvider>) -> Self {
        Self {
            authority,
            required_role: None,
            provider,
            authenticated: Arc::new(Mutex::new(None)),
        }
    }

    /// Build a verifier that accepts only a client identity `authority` admits in **exactly** `role`.
    /// For node-to-node links this pins the accepted peer to [`Role::ClusterNode`] (#373); for the
    /// inbound client surface it pins to [`Role::Client`] (#374).
    pub fn new_for_role(
        authority: Arc<dyn MembershipAuthority>,
        provider: Arc<CryptoProvider>,
        role: Role,
    ) -> Self {
        Self {
            authority,
            required_role: Some(role),
            provider,
            authenticated: Arc::new(Mutex::new(None)),
        }
    }

    /// The Algorand address authenticated on the last successful handshake, if any.
    pub fn authenticated_peer(&self) -> Option<String> {
        self.authenticated
            .lock()
            .expect("identity verifier mutex poisoned")
            .clone()
    }
}

impl ClientCertVerifier for IdentityClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        let address =
            verify_identity_cert_inner(end_entity, self.authority.as_ref(), self.required_role)
                .map_err(|e| RustlsError::General(e.to_string()))?;
        *self
            .authenticated
            .lock()
            .expect("identity verifier mutex poisoned") = Some(address);
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        tls12(&self.provider, message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        tls13(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Assemble a ready-to-use [`ServerConfig`] that requires and authenticates a client identity
/// (`verifier`) and presents `own` as this node's identity certificate.
///
/// The verifier's crypto provider is reused so config and verifier agree on the selected provider
/// (ring). Keep a clone of `verifier` to read [`IdentityClientVerifier::authenticated_peer`] after the
/// handshake.
pub fn server_config(
    own: IdentityCert,
    verifier: Arc<IdentityClientVerifier>,
) -> Result<ServerConfig, RustlsError> {
    let provider = verifier.provider.clone();
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![own.cert], own.key)
}
