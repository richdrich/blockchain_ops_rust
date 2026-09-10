//! Mint an identity-bound certificate: an ephemeral self-signed leaf whose `SubjectPublicKeyInfo` is
//! signed by the Algorand identity key and carried in the [`crate::SIDEWINDER_IDENTITY_EXT_OID`]
//! extension.

use algo_ops::byte_key_to_address;
use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::{SIDEWINDER_IDENTITY_EXT_OID, encode_signed_key, identity_signing_message};

/// A self-signed certificate bound to an Algorand identity, plus its ephemeral private key, ready to
/// hand to `rustls` as this endpoint's own credential.
#[derive(Debug)]
pub struct IdentityCert {
    /// The DER-encoded self-signed leaf certificate (carries the identity-binding extension).
    pub cert: CertificateDer<'static>,
    /// The ephemeral leaf private key (PKCS#8 DER). Unrelated to the Algorand identity key; safe to
    /// rotate per connection.
    pub key: PrivateKeyDer<'static>,
    /// The Algorand address of the bound identity — the value a peer's verifier derives and authorizes.
    pub address: String,
}

/// Generate an [`IdentityCert`] bound to `identity`.
///
/// The leaf key is a fresh Elliptic Curve Digital Signature Algorithm (ECDSA) P-256 key (rcgen's
/// default) for broad cipher-suite support; it is independent of the Ed25519 identity key, which signs
/// only the leaf's `SubjectPublicKeyInfo`. Nothing here touches the network.
pub fn generate(identity: &SigningKey) -> Result<IdentityCert> {
    // ephemeral leaf key — deliberately unrelated to the identity key (libp2p TLS spec).
    let leaf = KeyPair::generate().context("generate ephemeral leaf key")?;
    let leaf_spki = leaf.public_key_der();

    // the identity key signs the leaf's SubjectPublicKeyInfo, binding this certificate to the identity.
    let signature = identity.sign(&identity_signing_message(&leaf_spki));
    let identity_public_key = identity.verifying_key();
    let extension_payload =
        encode_signed_key(identity_public_key.as_bytes(), &signature.to_bytes());

    let mut params = CertificateParams::new(vec!["node.sidewinder.invalid".to_string()])
        .context("build certificate parameters")?;
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            SIDEWINDER_IDENTITY_EXT_OID,
            extension_payload,
        ));

    let cert = params
        .self_signed(&leaf)
        .context("self-sign identity certificate")?;

    let address = byte_key_to_address(identity_public_key.as_bytes())
        .context("derive Algorand address from identity key")?;

    Ok(IdentityCert {
        cert: cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.serialize_der())),
        address,
    })
}
