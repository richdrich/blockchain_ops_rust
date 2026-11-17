//! The data key a caller encrypts its payload under.

use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A data key is 32 bytes: an AES-256 or ChaCha20 key.
pub const DATA_KEY_LEN: usize = 32;

/// A 32-byte data key, cleared from memory when dropped.
///
/// It deliberately doesn't implement `Debug` or `Clone`, so it isn't printed or
/// copied by accident.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKey([u8; DATA_KEY_LEN]);

impl DataKey {
    /// A new random data key from the operating system's random number generator.
    pub fn generate() -> Self {
        let mut bytes = [0u8; DATA_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// A data key with the given bytes, for example one read back from storage.
    pub fn from_bytes(bytes: [u8; DATA_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The key's bytes, to pass to a cipher.
    pub fn as_bytes(&self) -> &[u8; DATA_KEY_LEN] {
        &self.0
    }
}

impl PartialEq for DataKey {
    /// Compares in constant time, so a comparison doesn't leak where two keys differ.
    fn eq(&self, other: &Self) -> bool {
        let mut difference = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            difference |= a ^ b;
        }
        difference == 0
    }
}

impl Eq for DataKey {}
