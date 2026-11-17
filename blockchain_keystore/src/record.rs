//! The wrapped-key record: a data key encrypted by one backend, with what that
//! backend needs to open it again.
//!
//! Layout, all integers little-endian:
//!
//! ```text
//! version (1) | backend (1) | params length (2) | params | nonce (12) | ciphertext (32 + 16 tag)
//! ```
//!
//! The header (`version`, `backend`, the params length and the params) is the
//! associated data of the AES-256-GCM encryption, so changing any of it, for
//! example lowering a stored Argon2 cost, makes the record fail to open.

use crate::data_key::DATA_KEY_LEN;
use crate::error::KeystoreError;

/// The record format version this crate writes and reads.
pub const RECORD_VERSION: u8 = 1;

/// The AES-GCM nonce length.
pub(crate) const NONCE_LEN: usize = 12;
/// The AES-GCM tag length.
const TAG_LEN: usize = 16;
/// version, backend, params length.
const FIXED_HEADER_LEN: usize = 4;
/// The ciphertext of a data key, with its tag.
pub(crate) const CIPHERTEXT_LEN: usize = DATA_KEY_LEN + TAG_LEN;

/// Which backend made a wrapped-key record. The values are part of the record
/// format and never change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendId {
    /// [`SoftwareWrapper`](crate::software::SoftwareWrapper): Argon2id over a password.
    Software,
    /// [`SecretWrapper`](crate::secret::SecretWrapper): HKDF over a caller-supplied secret.
    Secret,
    /// The `test-support` fake. Never seen in production records.
    Fake,
}

impl BackendId {
    /// The byte stored in a record for this backend.
    pub fn as_byte(self) -> u8 {
        match self {
            BackendId::Software => 1,
            BackendId::Secret => 2,
            BackendId::Fake => 0xFF,
        }
    }

    /// The backend for a byte read from a record.
    pub fn from_byte(byte: u8) -> Result<Self, KeystoreError> {
        match byte {
            1 => Ok(BackendId::Software),
            2 => Ok(BackendId::Secret),
            0xFF => Ok(BackendId::Fake),
            other => Err(KeystoreError::UnknownBackend(other)),
        }
    }
}

/// A data key wrapped by one backend: an opaque, versioned byte record that the
/// caller stores and later hands back to the same backend to unwrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    backend: BackendId,
    params: Vec<u8>,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl WrappedKey {
    /// Builds a record. Used by the backends; `ciphertext` must be the AES-GCM
    /// output for a data key.
    pub(crate) fn new(
        backend: BackendId,
        params: Vec<u8>,
        nonce: [u8; NONCE_LEN],
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            backend,
            params,
            nonce,
            ciphertext,
        }
    }

    /// The backend that made this record.
    pub fn backend(&self) -> BackendId {
        self.backend
    }

    /// The backend's parameters, as stored.
    pub(crate) fn params(&self) -> &[u8] {
        &self.params
    }

    /// The AES-GCM nonce.
    pub(crate) fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// The encrypted data key and its tag.
    pub(crate) fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The header bytes, which are the associated data of the encryption.
    pub(crate) fn header(backend: BackendId, params: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        let params_len = u16::try_from(params.len())
            .map_err(|_| KeystoreError::Malformed("backend parameters too long".into()))?;
        let mut header = Vec::with_capacity(FIXED_HEADER_LEN + params.len());
        header.push(RECORD_VERSION);
        header.push(backend.as_byte());
        header.extend_from_slice(&params_len.to_le_bytes());
        header.extend_from_slice(params);
        Ok(header)
    }

    /// Checks that this record was made by `expected`, before a backend tries
    /// to open it.
    pub(crate) fn require_backend(&self, expected: BackendId) -> Result<(), KeystoreError> {
        if self.backend == expected {
            Ok(())
        } else {
            Err(KeystoreError::WrongBackend {
                expected,
                found: self.backend,
            })
        }
    }

    /// The record as bytes, to store.
    pub fn to_bytes(&self) -> Result<Vec<u8>, KeystoreError> {
        let mut out = Self::header(self.backend, &self.params)?;
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Parses a stored record. This checks the layout only; whether it opens is
    /// up to the backend.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeystoreError> {
        if bytes.len() < FIXED_HEADER_LEN {
            return Err(KeystoreError::Malformed("record too short".into()));
        }
        if bytes[0] != RECORD_VERSION {
            return Err(KeystoreError::UnsupportedVersion(bytes[0]));
        }
        let backend = BackendId::from_byte(bytes[1])?;
        let params_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let expected_len = FIXED_HEADER_LEN + params_len + NONCE_LEN + CIPHERTEXT_LEN;
        if bytes.len() != expected_len {
            return Err(KeystoreError::Malformed(format!(
                "record is {} bytes, expected {expected_len}",
                bytes.len()
            )));
        }
        let params_end = FIXED_HEADER_LEN + params_len;
        let nonce_end = params_end + NONCE_LEN;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[params_end..nonce_end]);
        Ok(Self {
            backend,
            params: bytes[FIXED_HEADER_LEN..params_end].to_vec(),
            nonce,
            ciphertext: bytes[nonce_end..].to_vec(),
        })
    }
}
