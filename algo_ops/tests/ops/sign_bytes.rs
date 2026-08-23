//! `AlgoOps::sign_bytes` — a plain `Ed25519(sk, message)` over raw bytes, no domain tag.

use algo_ops::{AlgoChainConfig, AlgoOps};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

// A "b64:" secret is a fixed 32-byte seed, so the derived key — and therefore the signature — is
// deterministic without needing a running node.
const TEST_SEED_B64: &str = "b64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn test_ops() -> AlgoOps {
    // No network calls are made in these tests, but AlgoOps requires a config.
    AlgoOps::new_for_algorand(
        Some(TEST_SEED_B64.to_string()),
        None,
        Some(AlgoChainConfig::default()),
    )
}

#[test]
fn sign_bytes_verifies_against_the_public_key() {
    let ops = test_ops();
    let message = b"canonical transaction body bytes";

    let sig = ops.sign_bytes(message).expect("sign the bytes");

    // The verifier re-checks a plain Ed25519 signature over the exact bytes — the same shape a
    // Sidewinder node uses to verify a transaction body.
    let vk = VerifyingKey::from_bytes(&ops.public_key_bytes().expect("public key"))
        .expect("a valid Ed25519 key");
    vk.verify(message, &Signature::from_bytes(&sig))
        .expect("signature verifies over the signed bytes");
}

#[test]
fn sign_bytes_is_deterministic() {
    let ops = test_ops();
    let message = b"repeatable";
    let a = ops.sign_bytes(message).expect("sign");
    let b = ops.sign_bytes(message).expect("sign");
    assert_eq!(a, b, "Ed25519 signing must be deterministic");
}

#[test]
fn sign_bytes_rejects_a_tampered_message() {
    let ops = test_ops();
    let sig = ops.sign_bytes(b"original").expect("sign");
    let vk = VerifyingKey::from_bytes(&ops.public_key_bytes().expect("public key"))
        .expect("a valid Ed25519 key");
    assert!(
        vk.verify(b"tampered", &Signature::from_bytes(&sig))
            .is_err(),
        "a signature must not verify over different bytes"
    );
}

#[test]
fn sign_bytes_requires_account_access() {
    // No passphrase → no key → cannot sign.
    let ops = AlgoOps::new_for_algorand(None, None, Some(AlgoChainConfig::default()));
    assert!(
        ops.sign_bytes(b"anything").is_err(),
        "signing without account access must fail rather than produce a bogus signature"
    );
}
