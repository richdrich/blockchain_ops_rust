//! The AES-256-GCM step every backend shares: encrypt a data key under a
//! wrapping key, with the record header as associated data.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

use crate::data_key::{DATA_KEY_LEN, DataKey};
use crate::error::KeystoreError;
use crate::record::{BackendId, CIPHERTEXT_LEN, NONCE_LEN, WrappedKey};

/// Wraps `key` under `wrapping_key` with a fresh random nonce.
pub(crate) fn seal(
    backend: BackendId,
    params: Vec<u8>,
    wrapping_key: &[u8; 32],
    key: &DataKey,
) -> Result<WrappedKey, KeystoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    seal_with_nonce(backend, params, wrapping_key, key, nonce)
}

/// Wraps `key` under `wrapping_key` with the given nonce. Only [`seal`] and the
/// fixed test vectors call this; a nonce must never be reused with a key.
pub(crate) fn seal_with_nonce(
    backend: BackendId,
    params: Vec<u8>,
    wrapping_key: &[u8; 32],
    key: &DataKey,
    nonce: [u8; NONCE_LEN],
) -> Result<WrappedKey, KeystoreError> {
    let header = WrappedKey::header(backend, &params)?;
    let cipher = Aes256Gcm::new_from_slice(wrapping_key)
        .map_err(|e| KeystoreError::Crypto(format!("AES-256-GCM key: {e}")))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: key.as_bytes(),
                aad: &header,
            },
        )
        .map_err(|e| KeystoreError::Crypto(format!("AES-256-GCM encryption: {e}")))?;
    Ok(WrappedKey::new(backend, params, nonce, ciphertext))
}

/// Unwraps `wrapped` under `wrapping_key`.
pub(crate) fn open(
    wrapped: &WrappedKey,
    wrapping_key: &[u8; 32],
) -> Result<DataKey, KeystoreError> {
    if wrapped.ciphertext().len() != CIPHERTEXT_LEN {
        return Err(KeystoreError::Malformed(
            "ciphertext has the wrong length".into(),
        ));
    }
    let header = WrappedKey::header(wrapped.backend(), wrapped.params())?;
    let cipher = Aes256Gcm::new_from_slice(wrapping_key)
        .map_err(|e| KeystoreError::Crypto(format!("AES-256-GCM key: {e}")))?;
    let mut plaintext = cipher
        .decrypt(
            Nonce::from_slice(wrapped.nonce()),
            Payload {
                msg: wrapped.ciphertext(),
                aad: &header,
            },
        )
        .map_err(|_| KeystoreError::WrongKeyOrTampered)?;
    if plaintext.len() != DATA_KEY_LEN {
        zeroize::Zeroize::zeroize(&mut plaintext);
        return Err(KeystoreError::Malformed(
            "unwrapped key has the wrong length".into(),
        ));
    }
    let mut bytes = [0u8; DATA_KEY_LEN];
    bytes.copy_from_slice(&plaintext);
    zeroize::Zeroize::zeroize(&mut plaintext);
    Ok(DataKey::from_bytes(bytes))
}
