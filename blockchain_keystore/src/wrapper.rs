//! The interface every backend implements.

use crate::data_key::DataKey;
use crate::error::KeystoreError;
use crate::record::{BackendId, WrappedKey};

/// Where a backend's wrapping key is held, from weakest to strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// In ordinary memory or files: a password-derived key, or a secret handed
    /// over by the caller.
    Software,
    /// In a trusted execution environment, such as the Android Keystore's TEE.
    TrustedEnvironment,
    /// In a dedicated secure processor: the Apple Secure Enclave or Android StrongBox.
    SecureElement,
    /// In a Trusted Platform Module (TPM).
    Tpm,
}

/// Wraps and unwraps a data key under a key this backend holds or derives.
///
/// Implementations have no default methods: each backend states all of its
/// behaviour.
pub trait KeyWrapper: Send + Sync {
    /// Which backend this is; written into every record it makes.
    fn backend(&self) -> BackendId;

    /// Where this backend's wrapping key is held.
    fn security_level(&self) -> SecurityLevel;

    /// Encrypts `key` into a record only this backend, with the same password,
    /// secret or platform key, can open.
    fn wrap(&self, key: &DataKey) -> Result<WrappedKey, KeystoreError>;

    /// Opens a record this backend made.
    ///
    /// Returns [`KeystoreError::WrongBackend`] for another backend's record,
    /// [`KeystoreError::WrongKeyOrTampered`] when it doesn't decrypt, and
    /// [`KeystoreError::Unavailable`] when the wrapping key can't be used now.
    fn unwrap(&self, wrapped: &WrappedKey) -> Result<DataKey, KeystoreError>;
}
