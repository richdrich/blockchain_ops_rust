//! What can go wrong wrapping or unwrapping a data key.

use std::fmt;

use crate::record::BackendId;

/// An error from wrapping or unwrapping a data key.
///
/// [`Unavailable`](KeystoreError::Unavailable) is kept apart from
/// [`WrongKeyOrTampered`](KeystoreError::WrongKeyOrTampered) so a caller can
/// wait and retry in the first case (for example, the device is locked) but
/// must not in the second.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreError {
    /// The wrapping key can't be used right now, for example because the device
    /// is locked or the user cancelled a prompt. Retrying later may succeed.
    Unavailable(String),
    /// The record didn't decrypt: the password or secret is wrong, or the record
    /// has been changed. Retrying with the same input won't help.
    WrongKeyOrTampered,
    /// The record was written in a format version this crate doesn't read.
    UnsupportedVersion(u8),
    /// The record names a backend id this crate doesn't know.
    UnknownBackend(u8),
    /// The record was made by a different backend from the one asked to open it.
    WrongBackend {
        /// The backend asked to open the record.
        expected: BackendId,
        /// The backend that made the record.
        found: BackendId,
    },
    /// The record is truncated, or its parameters are out of range.
    Malformed(String),
    /// The underlying cipher or key derivation failed for a reason other than
    /// a wrong key.
    Crypto(String),
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeystoreError::Unavailable(reason) => {
                write!(f, "the wrapping key is not available now: {reason}")
            }
            KeystoreError::WrongKeyOrTampered => {
                write!(
                    f,
                    "the data key did not unwrap (wrong key, or the record was changed)"
                )
            }
            KeystoreError::UnsupportedVersion(version) => {
                write!(f, "unsupported wrapped-key record version {version}")
            }
            KeystoreError::UnknownBackend(id) => write!(f, "unknown key-wrapping backend id {id}"),
            KeystoreError::WrongBackend { expected, found } => write!(
                f,
                "the record was made by the {found:?} backend, not {expected:?}"
            ),
            KeystoreError::Malformed(reason) => write!(f, "malformed wrapped-key record: {reason}"),
            KeystoreError::Crypto(reason) => write!(f, "key wrapping failed: {reason}"),
        }
    }
}

impl std::error::Error for KeystoreError {}
