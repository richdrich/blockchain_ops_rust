//! Argon2id over a password: the backend for when no platform key exists.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::aead;
use crate::data_key::DataKey;
use crate::error::KeystoreError;
use crate::record::{BackendId, NONCE_LEN, WrappedKey};
use crate::wrapper::{KeyWrapper, SecurityLevel};

/// The salt length.
const SALT_LEN: usize = 16;
/// The stored parameters: memory cost (4), passes (4), lanes (4), salt (16).
const PARAMS_LEN: usize = 12 + SALT_LEN;

/// The largest memory cost a record may ask for, in KiB (2 GiB), so a crafted
/// record can't make an unwrap allocate without bound.
pub const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024;
/// The most passes a record may ask for.
pub const MAX_PASSES: u32 = 64;
/// The most lanes a record may ask for.
pub const MAX_LANES: u32 = 16;

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Cost {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub passes: u32,
    /// Degree of parallelism.
    pub lanes: u32,
}

impl Argon2Cost {
    /// The cost new wraps use by default: 64 MiB, 3 passes, 1 lane, the same as
    /// `blockchain_account_vault`'s envelope.
    pub const DEFAULT: Argon2Cost = Argon2Cost {
        memory_kib: 64 * 1024,
        passes: 3,
        lanes: 1,
    };

    /// The Argon2 minimum. Only for tests that wrap many keys: a key derived
    /// at this cost is cheap to guess.
    pub const INSECURE_MINIMUM: Argon2Cost = Argon2Cost {
        memory_kib: 8,
        passes: 1,
        lanes: 1,
    };

    fn check(self) -> Result<(), KeystoreError> {
        if self.memory_kib > MAX_MEMORY_KIB || self.passes > MAX_PASSES || self.lanes > MAX_LANES {
            return Err(KeystoreError::Malformed(format!(
                "Argon2 cost out of range: {} KiB, {} passes, {} lanes",
                self.memory_kib, self.passes, self.lanes
            )));
        }
        Ok(())
    }
}

/// Wraps a data key under a key derived from a password with Argon2id.
///
/// The cost and a fresh random salt are stored in each record, so a record
/// still opens if the default cost changes.
pub struct SoftwareWrapper {
    password: Zeroizing<String>,
    cost: Argon2Cost,
}

impl SoftwareWrapper {
    /// A wrapper for `password`, wrapping at the default cost.
    pub fn new(password: impl Into<String>) -> Self {
        Self::with_cost(password, Argon2Cost::DEFAULT)
    }

    /// A wrapper for `password`, wrapping at `cost`. Unwrapping always uses the
    /// cost stored in the record.
    pub fn with_cost(password: impl Into<String>, cost: Argon2Cost) -> Self {
        Self {
            password: Zeroizing::new(password.into()),
            cost,
        }
    }

    /// Wraps with the given salt and nonce. Only for fixed test vectors: a salt
    /// and nonce must never be reused.
    #[doc(hidden)]
    pub fn wrap_with_salt_and_nonce(
        &self,
        key: &DataKey,
        salt: [u8; SALT_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> Result<WrappedKey, KeystoreError> {
        let wrapping_key = derive(&self.password, &salt, self.cost)?;
        aead::seal_with_nonce(
            BackendId::Software,
            encode_params(self.cost, &salt),
            &wrapping_key,
            key,
            nonce,
        )
    }
}

impl KeyWrapper for SoftwareWrapper {
    fn backend(&self) -> BackendId {
        BackendId::Software
    }

    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::Software
    }

    fn wrap(&self, key: &DataKey) -> Result<WrappedKey, KeystoreError> {
        self.cost.check()?;
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let wrapping_key = derive(&self.password, &salt, self.cost)?;
        aead::seal(
            BackendId::Software,
            encode_params(self.cost, &salt),
            &wrapping_key,
            key,
        )
    }

    fn unwrap(&self, wrapped: &WrappedKey) -> Result<DataKey, KeystoreError> {
        wrapped.require_backend(BackendId::Software)?;
        let (cost, salt) = decode_params(wrapped.params())?;
        let wrapping_key = derive(&self.password, &salt, cost)?;
        aead::open(wrapped, &wrapping_key)
    }
}

fn derive(
    password: &str,
    salt: &[u8; SALT_LEN],
    cost: Argon2Cost,
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    cost.check()?;
    let params = Params::new(cost.memory_kib, cost.passes, cost.lanes, Some(32))
        .map_err(|e| KeystoreError::Malformed(format!("invalid Argon2 cost: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| KeystoreError::Crypto(format!("Argon2id: {e}")))?;
    Ok(key)
}

fn encode_params(cost: Argon2Cost, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut params = Vec::with_capacity(PARAMS_LEN);
    params.extend_from_slice(&cost.memory_kib.to_le_bytes());
    params.extend_from_slice(&cost.passes.to_le_bytes());
    params.extend_from_slice(&cost.lanes.to_le_bytes());
    params.extend_from_slice(salt);
    params
}

fn decode_params(params: &[u8]) -> Result<(Argon2Cost, [u8; SALT_LEN]), KeystoreError> {
    if params.len() != PARAMS_LEN {
        return Err(KeystoreError::Malformed(format!(
            "software parameters are {} bytes, expected {PARAMS_LEN}",
            params.len()
        )));
    }
    let word = |at: usize| {
        u32::from_le_bytes([params[at], params[at + 1], params[at + 2], params[at + 3]])
    };
    let cost = Argon2Cost {
        memory_kib: word(0),
        passes: word(4),
        lanes: word(8),
    };
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&params[12..]);
    Ok((cost, salt))
}
