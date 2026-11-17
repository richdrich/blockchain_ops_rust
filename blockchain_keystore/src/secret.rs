//! A 32-byte secret the caller supplies: for a key held by a platform store this
//! crate can't call directly.
//!
//! For example, on iOS the native code reads a Keychain item and passes its
//! bytes in through a binding; on Android, the same with a Keystore-protected
//! value. The platform decides when the secret is available (for example, only
//! while the device is unlocked); this backend only wraps under it.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aead;
use crate::data_key::DataKey;
use crate::error::KeystoreError;
use crate::record::{BackendId, NONCE_LEN, WrappedKey};
use crate::wrapper::{KeyWrapper, SecurityLevel};

/// The secret length.
pub const SECRET_LEN: usize = 32;

/// The HKDF info string. It separates the wrapping key from any other key the
/// caller derives from the same secret. It keeps the crate's original name
/// (`hardware_keystore`) because it is part of the record format: changing it
/// would stop every existing secret-wrapper record opening.
const HKDF_INFO: &[u8] = b"hardware_keystore secret wrapper v1";

/// Wraps a data key under a key derived with HKDF-SHA256 from a secret the
/// caller supplies.
///
/// The secret is never used directly as an AES key. The record carries no
/// parameters: everything needed to open it is the secret.
pub struct SecretWrapper {
    wrapping_key: Zeroizing<[u8; 32]>,
    level: SecurityLevel,
}

impl SecretWrapper {
    /// A wrapper for `secret`.
    ///
    /// `level` is where the caller's platform holds the secret, and is reported
    /// by [`KeyWrapper::security_level`]. A secret read out of a hardware-backed
    /// store into this process is still in ordinary memory while it is used, so
    /// pass [`SecurityLevel::Software`] unless the platform store adds its own
    /// protection the caller relies on.
    pub fn new(secret: &[u8; SECRET_LEN], level: SecurityLevel) -> Self {
        let mut wrapping_key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, secret)
            .expand(HKDF_INFO, wrapping_key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self {
            wrapping_key,
            level,
        }
    }

    /// Wraps with the given nonce. Only for fixed test vectors: a nonce must
    /// never be reused.
    #[doc(hidden)]
    pub fn wrap_with_nonce(
        &self,
        key: &DataKey,
        nonce: [u8; NONCE_LEN],
    ) -> Result<WrappedKey, KeystoreError> {
        aead::seal_with_nonce(
            BackendId::Secret,
            Vec::new(),
            &self.wrapping_key,
            key,
            nonce,
        )
    }
}

impl KeyWrapper for SecretWrapper {
    fn backend(&self) -> BackendId {
        BackendId::Secret
    }

    fn security_level(&self) -> SecurityLevel {
        self.level
    }

    fn wrap(&self, key: &DataKey) -> Result<WrappedKey, KeystoreError> {
        aead::seal(BackendId::Secret, Vec::new(), &self.wrapping_key, key)
    }

    fn unwrap(&self, wrapped: &WrappedKey) -> Result<DataKey, KeystoreError> {
        wrapped.require_backend(BackendId::Secret)?;
        if !wrapped.params().is_empty() {
            return Err(KeystoreError::Malformed(
                "secret-wrapper records carry no parameters".into(),
            ));
        }
        aead::open(wrapped, &self.wrapping_key)
    }
}
