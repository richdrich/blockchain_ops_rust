//! An in-memory wrapper for consumers' unit tests (the `test-support` feature).
//!
//! It wraps for real, under a random key that lives only as long as the fake,
//! and can be switched to report [`KeystoreError::Unavailable`], to test how a
//! caller handles a locked device or a cancelled prompt.

use std::sync::atomic::{AtomicBool, Ordering};

use rand::RngCore;
use zeroize::Zeroizing;

use crate::aead;
use crate::data_key::DataKey;
use crate::error::KeystoreError;
use crate::record::{BackendId, WrappedKey};
use crate::wrapper::{KeyWrapper, SecurityLevel};

/// A test wrapper with its own random key and an availability switch.
pub struct FakeWrapper {
    wrapping_key: Zeroizing<[u8; 32]>,
    level: SecurityLevel,
    available: AtomicBool,
}

impl FakeWrapper {
    /// A fake that reports `level` and starts available.
    pub fn new(level: SecurityLevel) -> Self {
        let mut wrapping_key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(wrapping_key.as_mut());
        Self {
            wrapping_key,
            level,
            available: AtomicBool::new(true),
        }
    }

    /// Makes wrap and unwrap succeed (`true`) or return
    /// [`KeystoreError::Unavailable`] (`false`).
    pub fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::SeqCst);
    }

    fn check_available(&self) -> Result<(), KeystoreError> {
        if self.available.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(KeystoreError::Unavailable(
                "fake wrapper switched off".into(),
            ))
        }
    }
}

impl KeyWrapper for FakeWrapper {
    fn backend(&self) -> BackendId {
        BackendId::Fake
    }

    fn security_level(&self) -> SecurityLevel {
        self.level
    }

    fn wrap(&self, key: &DataKey) -> Result<WrappedKey, KeystoreError> {
        self.check_available()?;
        aead::seal(BackendId::Fake, Vec::new(), &self.wrapping_key, key)
    }

    fn unwrap(&self, wrapped: &WrappedKey) -> Result<DataKey, KeystoreError> {
        self.check_available()?;
        wrapped.require_backend(BackendId::Fake)?;
        aead::open(wrapped, &self.wrapping_key)
    }
}
