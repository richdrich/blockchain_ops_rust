//! Unit tests for the password-based key-file encryption in `blockchain_account_vault::envelope`.

use std::sync::Once;

use anyhow::anyhow;
use blockchain_account_vault::envelope::{
    ENVELOPE_MARKER, FAST_KDF_ENV, decrypt_bytes, decrypt_secret, derive_key, encrypt_bytes,
    encrypt_secret, is_encrypted_envelope, reencrypt_envelope,
};
use serde_json::Value;

const SAMPLE: &[u8] = br#"{"address":"ABC","passphrase":"twenty five word mnemonic here"}"#;

static FAST_KDF: Once = Once::new();

// Select the reduced KDF cost so these tests, which derive keys many times, stay
// fast. Serialised through Once so the env var is written exactly once, before
// any key derivation on this thread reads it. Every test calls this first.
fn fast_kdf() {
    FAST_KDF.call_once(|| unsafe { std::env::set_var(FAST_KDF_ENV, "1") });
}

#[test]
fn encrypt_then_decrypt_roundtrips() {
    fast_kdf();
    let envelope = encrypt_bytes(SAMPLE, "correct horse battery staple").unwrap();
    let recovered = decrypt_bytes(&envelope, "correct horse battery staple").unwrap();
    assert_eq!(recovered, SAMPLE);
}

#[test]
fn wrong_password_fails_to_decrypt() {
    fast_kdf();
    let envelope = encrypt_bytes(SAMPLE, "the-real-password").unwrap();
    // A wrong password must produce an authentication error, not garbage plaintext.
    let result = decrypt_bytes(&envelope, "not-the-password");
    assert!(
        result.is_err(),
        "decryption should fail with the wrong password"
    );
}

#[test]
fn envelope_is_recognisable_json_with_expected_fields() {
    fast_kdf();
    let envelope = encrypt_bytes(SAMPLE, "pw").unwrap();

    assert!(is_encrypted_envelope(&envelope));
    assert!(!is_encrypted_envelope(SAMPLE));

    let json: Value = serde_json::from_slice(&envelope).unwrap();
    assert_eq!(
        json["bingle_encrypted"].as_u64(),
        Some(ENVELOPE_MARKER as u64)
    );
    assert_eq!(json["kdf"].as_str(), Some("argon2id"));
    for field in ["salt", "nonce", "ciphertext"] {
        assert!(
            json[field].as_str().map(|s| !s.is_empty()).unwrap_or(false),
            "field {field} should be a non-empty base64 string"
        );
    }
}

#[test]
fn repeated_encryption_uses_fresh_salt_and_nonce() {
    fast_kdf();
    let a = encrypt_bytes(SAMPLE, "pw").unwrap();
    let b = encrypt_bytes(SAMPLE, "pw").unwrap();

    let ja: Value = serde_json::from_slice(&a).unwrap();
    let jb: Value = serde_json::from_slice(&b).unwrap();

    assert_ne!(ja["salt"], jb["salt"], "salt must be random per encryption");
    assert_ne!(
        ja["nonce"], jb["nonce"],
        "nonce must be random per encryption"
    );
    assert_ne!(
        ja["ciphertext"], jb["ciphertext"],
        "ciphertext must differ for identical plaintext"
    );

    // Both envelopes must still decrypt to the original plaintext.
    assert_eq!(decrypt_bytes(&a, "pw").unwrap(), SAMPLE);
    assert_eq!(decrypt_bytes(&b, "pw").unwrap(), SAMPLE);
}

#[test]
fn derive_key_is_deterministic_and_salt_sensitive() {
    fast_kdf();
    let salt_a = [7u8; 16];
    let salt_b = [9u8; 16];

    let k1 = derive_key("password", &salt_a).unwrap();
    let k2 = derive_key("password", &salt_a).unwrap();
    let k3 = derive_key("password", &salt_b).unwrap();

    assert_eq!(k1, k2, "same password and salt must derive the same key");
    assert_ne!(k1, k3, "different salt must derive a different key");
    assert_eq!(k1.len(), 32, "AES-256 requires a 32-byte key");
}

#[test]
fn reencrypt_changes_password() {
    fast_kdf();
    let old = encrypt_bytes(SAMPLE, "old-pw").unwrap();

    let mut cached_old: Option<String> = None;
    let new = reencrypt_envelope(&old, "new-pw", &mut cached_old, || Ok("old-pw".to_string()))
        .unwrap()
        .expect("password differs, so a new envelope should be produced");

    // New envelope opens with the new password, and its plaintext is preserved.
    assert_eq!(decrypt_bytes(&new, "new-pw").unwrap(), SAMPLE);
    // The old password no longer opens the re-encrypted file.
    assert!(decrypt_bytes(&new, "old-pw").is_err());
    // The old password was cached for reuse.
    assert_eq!(cached_old.as_deref(), Some("old-pw"));
}

#[test]
fn reencrypt_noop_when_already_new_password() {
    fast_kdf();
    let envelope = encrypt_bytes(SAMPLE, "pw").unwrap();

    let mut cached_old: Option<String> = None;
    let result = reencrypt_envelope(&envelope, "pw", &mut cached_old, || {
        panic!("prompt must not be called when the new password already decrypts")
    })
    .unwrap();

    assert!(
        result.is_none(),
        "already keyed to the new password → no change"
    );
    assert!(cached_old.is_none());
}

#[test]
fn reencrypt_reuses_cached_old_password_across_files() {
    fast_kdf();
    // Two files encrypted with the same old password.
    let a = encrypt_bytes(b"file-a", "old-pw").unwrap();
    let b = encrypt_bytes(b"file-b", "old-pw").unwrap();

    let mut cached_old: Option<String> = None;
    let mut prompt_calls = 0usize;
    let mut prompt = || {
        prompt_calls += 1;
        Ok("old-pw".to_string())
    };

    let a2 = reencrypt_envelope(&a, "new-pw", &mut cached_old, &mut prompt)
        .unwrap()
        .unwrap();
    let b2 = reencrypt_envelope(&b, "new-pw", &mut cached_old, &mut prompt)
        .unwrap()
        .unwrap();

    assert_eq!(
        prompt_calls, 1,
        "old password should be requested only once"
    );
    assert_eq!(decrypt_bytes(&a2, "new-pw").unwrap(), b"file-a");
    assert_eq!(decrypt_bytes(&b2, "new-pw").unwrap(), b"file-b");
}

#[test]
fn reencrypt_fails_on_wrong_old_password() {
    fast_kdf();
    let envelope = encrypt_bytes(SAMPLE, "old-pw").unwrap();
    let mut cached_old: Option<String> = None;
    let result = reencrypt_envelope(&envelope, "new-pw", &mut cached_old, || {
        Ok("wrong".to_string())
    });
    assert!(result.is_err(), "a wrong old password must be rejected");
    assert!(
        cached_old.is_none(),
        "a rejected password must not be cached"
    );
}

#[test]
fn reencrypt_propagates_prompt_error() {
    fast_kdf();
    let envelope = encrypt_bytes(SAMPLE, "old-pw").unwrap();
    let mut cached_old: Option<String> = None;
    let result = reencrypt_envelope(&envelope, "new-pw", &mut cached_old, || {
        Err(anyhow!("user cancelled"))
    });
    assert!(result.is_err());
}

#[test]
fn encrypt_secret_roundtrips_and_grows() {
    fast_kdf();
    let key = [0x42u8; 32];
    let blob = encrypt_secret(&key, "pw").unwrap();

    // The compact binary blob is larger than the 32-byte plaintext (fixed 83 bytes).
    assert_eq!(
        blob.len(),
        83,
        "32-byte secret should encrypt to an 83-byte blob"
    );
    assert!(blob.len() > key.len());

    let recovered = decrypt_secret(&blob, "pw").unwrap();
    assert_eq!(recovered, key);
}

#[test]
fn encrypt_secret_wrong_password_fails() {
    fast_kdf();
    let blob = encrypt_secret(&[9u8; 32], "right").unwrap();
    assert!(decrypt_secret(&blob, "wrong").is_err());
}

#[test]
fn encrypt_secret_rejects_tampered_blob() {
    fast_kdf();
    let mut blob = encrypt_secret(&[1u8; 32], "pw").unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0xff; // flip a ciphertext/tag byte
    assert!(decrypt_secret(&blob, "pw").is_err());
}

#[test]
fn tampered_ciphertext_is_rejected() {
    fast_kdf();
    let mut json: Value = serde_json::from_slice(&encrypt_bytes(SAMPLE, "pw").unwrap()).unwrap();
    // Corrupt the ciphertext; GCM authentication must reject it.
    json["ciphertext"] = Value::String("AAAA".to_string());
    let tampered = serde_json::to_vec(&json).unwrap();
    assert!(decrypt_bytes(&tampered, "pw").is_err());
}
