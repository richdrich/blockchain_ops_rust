//! A slot secret derived from an Algorand recovery phrase.
//!
//! A [`sealed_store`](crate::sealed_store) can carry a recovery slot that opens
//! with the account's 25-word phrase, so a store copied to a new device (for
//! example from a backup) opens once the user enters the phrase. This module
//! turns the phrase into the 32-byte secret for a
//! [`blockchain_keystore::secret::SecretWrapper`].

use anyhow::{Result, bail};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::mnemonic::mnemonic_to_bytes;

/// An Algorand account's private key seed is 32 bytes (25 words).
const SEED_LEN: usize = 32;

/// Derives a 32-byte slot secret from an Algorand 25-word `mnemonic`, with
/// HKDF-SHA256 over the seed and `label` as the info string.
///
/// The label keeps the derived secret separate from every other use of the
/// seed, including signing: choose one per purpose, such as
/// `"bingle state file recovery v1"`. The mnemonic's checksum word is verified.
pub fn recovery_secret(mnemonic: &str, label: &str) -> Result<Zeroizing<[u8; 32]>> {
    if label.is_empty() {
        bail!("the recovery label must not be empty");
    }
    let seed = Zeroizing::new(mnemonic_to_bytes(mnemonic.trim(), SEED_LEN)?);
    let mut secret = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, &seed)
        .expand(label.as_bytes(), secret.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Ok(secret)
}
