//! Client-side identity-bound TLS.
//!
//! A connecting endpoint authenticates the **server** by its Algorand identity ([`IdentityServerVerifier`])
//! and presents its own identity certificate for mutual TLS. This module is compiled in a client-only
//! build (without the `server` feature), so a pure API client pulls in neither [`crate::server`]'s
//! client-cert verifier nor an on-chain membership cache.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};

use crate::verify::{tls12, tls13, verify_identity_cert_inner};
use crate::{IdentityCert, MembershipAuthority, Role};

/// A `rustls` server-certificate verifier that authenticates the **server** by its Algorand identity.
///
/// It ignores the requested server name (SAN) entirely — trust is pinned to the on-chain identity, not a
/// hostname — and never validates a certificate chain against a Certificate Authority.
#[derive(Debug)]
pub struct IdentityServerVerifier {
    authority: Arc<dyn MembershipAuthority>,
    required_role: Option<Role>,
    provider: Arc<CryptoProvider>,
    authenticated: Arc<Mutex<Option<String>>>,
}

impl IdentityServerVerifier {
    /// Build a verifier that accepts any server identity `authority` deems a member (any role), using
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

    /// Build a verifier that accepts only a server identity `authority` admits in **exactly** `role`.
    /// For node-to-node links this pins the accepted peer to [`Role::ClusterNode`] (#373).
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

impl ServerCertVerifier for IdentityServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let address =
            verify_identity_cert_inner(end_entity, self.authority.as_ref(), self.required_role)
                .map_err(|e| RustlsError::General(e.to_string()))?;
        *self
            .authenticated
            .lock()
            .expect("identity verifier mutex poisoned") = Some(address);
        Ok(ServerCertVerified::assertion())
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

/// Assemble a ready-to-use [`ClientConfig`] that authenticates the server by identity (`verifier`) and
/// presents `own` as this client's identity certificate for mutual TLS.
///
/// The verifier's crypto provider is reused so config and verifier can never disagree on the selected
/// provider (ring). Keep a clone of `verifier` to read [`IdentityServerVerifier::authenticated_peer`]
/// after the handshake.
pub fn client_config(
    own: IdentityCert,
    verifier: Arc<IdentityServerVerifier>,
) -> Result<ClientConfig, RustlsError> {
    let provider = verifier.provider.clone();
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![own.cert], own.key)
}
