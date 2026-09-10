//! Offline unit tests for the identity check — no sockets, no node calls.

use std::collections::HashSet;

use rustls::pki_types::CertificateDer;
use sw_identity_tls::{
    Role, StaticMembership, VerifyError, generate, verify_identity_cert,
    verify_identity_cert_for_role,
};

use crate::support::{allow, cert, find_subslice, identity};

#[test]
fn authorized_identity_verifies_to_its_address() {
    let c = cert(11);
    let allowed = allow([c.address.clone()]);
    let got = verify_identity_cert(&c.cert, &*allowed).expect("authorized identity verifies");
    assert_eq!(got, c.address);
}

#[test]
fn authentic_but_unlisted_identity_is_rejected() {
    let c = cert(12);
    let empty: HashSet<String> = HashSet::new();
    let err = verify_identity_cert(&c.cert, &empty).unwrap_err();
    assert!(matches!(err, VerifyError::NotAuthorized(a) if a == c.address));
}

#[test]
fn tampered_signature_is_rejected() {
    let id = identity(13);
    let c = generate(&id).expect("generate");
    let mut der = c.cert.as_ref().to_vec();

    // extension payload is SEQUENCE { OCTET STRING(32 = identity key), OCTET STRING(64 = signature) };
    // locate the identity key, then corrupt a byte inside the signature that follows it.
    let key = id.verifying_key();
    let key_pos = find_subslice(&der, key.as_bytes()).expect("identity key present in certificate");
    let signature_content = key_pos + 32 + 2; // skip the 32 key bytes and the signature's tag+length.
    der[signature_content] ^= 0xff;

    let tampered = CertificateDer::from(der);
    let allowed = allow([c.address.clone()]);
    let err = verify_identity_cert(&tampered, &*allowed).unwrap_err();
    assert!(matches!(err, VerifyError::SignatureInvalid));
}

#[test]
fn certificate_without_identity_extension_is_rejected() {
    let params = rcgen::CertificateParams::new(vec!["plain.invalid".to_string()]).unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let plain = params.self_signed(&key_pair).unwrap();
    let der = CertificateDer::from(plain.der().to_vec());

    let empty: HashSet<String> = HashSet::new();
    let err = verify_identity_cert(&der, &empty).unwrap_err();
    assert!(matches!(err, VerifyError::MissingExtension));
}

#[test]
fn role_gated_verify_accepts_the_required_role() {
    let c = cert(41);
    let authority = StaticMembership::new().with(c.address.clone(), Role::ClusterNode);
    let got = verify_identity_cert_for_role(&c.cert, &authority, Role::ClusterNode)
        .expect("a cluster node is authorized on a cluster-node link");
    assert_eq!(got, c.address);
}

#[test]
fn role_gated_verify_rejects_an_authentic_member_of_a_different_role() {
    let c = cert(42);
    // authentic and a member — but as a Client, not permitted on a ClusterNode-gated link.
    let authority = StaticMembership::new().with(c.address.clone(), Role::Client);
    let err = verify_identity_cert_for_role(&c.cert, &authority, Role::ClusterNode).unwrap_err();
    assert!(matches!(err, VerifyError::NotAuthorized(a) if a == c.address));
}

#[test]
fn role_gated_verify_rejects_a_non_member() {
    let c = cert(43);
    let authority = StaticMembership::new(); // admits nobody
    let err = verify_identity_cert_for_role(&c.cert, &authority, Role::ClusterNode).unwrap_err();
    assert!(matches!(err, VerifyError::NotAuthorized(a) if a == c.address));
}
