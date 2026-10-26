//! New Algorand accounts, optionally with a chosen address prefix.
//!
//! An account is an Ed25519 key pair. Its 32-byte private seed is written as the usual 25-word
//! Algorand mnemonic (the `passphrase`), and its address is the base32 of the public key followed
//! by the last 4 bytes of the key's SHA-512/256 digest, 58 characters without padding.
//!
//! A vanity address is found by brute force: keys are generated until the address starts with the
//! wanted characters. Each character is one of 32, so each one multiplies the expected number of
//! tries by 32 ([`expected_tries`]).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use anyhow::{Result, anyhow, bail};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512_256};

use crate::mnemonic::bytes_to_mnemonic;

/// The longest prefix [`find_vanity_account`] accepts. Eight characters is about 10^12 tries,
/// already far beyond a workstation; longer would never finish.
pub const MAX_PREFIX_LEN: usize = 8;

const SEED_LEN: usize = 32;
const CHECKSUM_LEN: usize = 4;

/// An account as a key file holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// the 58-character Algorand address.
    pub address: String,
    /// the 25-word mnemonic of the private seed.
    pub passphrase: String,
}

impl Account {
    /// The account derived from a 32-byte private seed.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let public_key = public_key(seed);
        Self {
            address: address_of(&public_key),
            passphrase: bytes_to_mnemonic(seed),
        }
    }

    /// The account key file's contents: `{"address", "passphrase"}` JSON, the format bingle_admin
    /// writes and [`json_field`](crate::vault::json_field) reads.
    pub fn to_key_file_json(&self) -> Result<Vec<u8>> {
        let json = serde_json::json!({
            "address": self.address,
            "passphrase": self.passphrase,
        });
        let mut bytes = serde_json::to_vec_pretty(&json)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// A vanity account and how many keys were tried to find it.
#[derive(Debug, Clone)]
pub struct VanityAccount {
    /// the account found.
    pub account: Account,
    /// keys generated across all threads, including the match.
    pub tries: u64,
}

/// A new account from the operating system's random source.
pub fn generate_account() -> Account {
    Account::from_seed(&random_seed())
}

/// Upper-case `prefix` and check that every character can begin an address (base32: `A`–`Z` and
/// `2`–`7`) and that it is at most [`MAX_PREFIX_LEN`] long.
pub fn normalise_prefix(prefix: &str) -> Result<String> {
    let prefix = prefix.to_ascii_uppercase();
    if prefix.is_empty() {
        bail!("the prefix must not be empty");
    }
    if prefix.len() > MAX_PREFIX_LEN {
        bail!("the prefix is at most {MAX_PREFIX_LEN} characters");
    }
    if let Some(bad) = prefix.chars().find(|c| !matches!(c, 'A'..='Z' | '2'..='7')) {
        bail!("'{bad}' can't appear in an address: use A-Z and 2-7 (no 0, 1, 8 or 9)");
    }
    Ok(prefix)
}

/// The mean number of keys to try for a prefix of `len` characters: 32 to the power `len`.
pub fn expected_tries(len: usize) -> u64 {
    32u64.saturating_pow(u32::try_from(len).unwrap_or(u32::MAX))
}

/// Generate keys on `threads` threads until an address starts with `prefix`, which
/// [`normalise_prefix`] must accept.
pub fn find_vanity_account(prefix: &str, threads: usize) -> Result<VanityAccount> {
    let prefix = normalise_prefix(prefix)?;
    let search = VanitySearch::new(&prefix);
    std::thread::scope(|scope| {
        for _ in 0..threads.max(1) {
            scope.spawn(|| search.run());
        }
    });
    let found = search
        .found
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
        .ok_or_else(|| anyhow!("the search stopped without a match"))?;
    Ok(VanityAccount {
        account: Account::from_seed(&found),
        tries: search.tries.into_inner(),
    })
}

/// The state the search threads share.
struct VanitySearch<'a> {
    prefix: &'a str,
    // only the leading public key bytes that decide the prefix are encoded on each try.
    leading_bytes: usize,
    done: AtomicBool,
    tries: AtomicU64,
    found: Mutex<Option<[u8; SEED_LEN]>>,
}

impl<'a> VanitySearch<'a> {
    fn new(prefix: &'a str) -> Self {
        Self {
            prefix,
            leading_bytes: (prefix.len() * 5).div_ceil(8),
            done: AtomicBool::new(false),
            tries: AtomicU64::new(0),
            found: Mutex::new(None),
        }
    }

    fn run(&self) {
        let mut tries = 0u64;
        while !self.done.load(Ordering::Relaxed) {
            let seed = random_seed();
            tries += 1;
            let public_key = public_key(&seed);
            if BASE32_NOPAD
                .encode(&public_key[..self.leading_bytes])
                .starts_with(self.prefix)
            {
                let mut found = self.found.lock().unwrap_or_else(PoisonError::into_inner);
                if found.is_none() {
                    *found = Some(seed);
                }
                self.done.store(true, Ordering::Relaxed);
            }
        }
        self.tries.fetch_add(tries, Ordering::Relaxed);
    }
}

fn random_seed() -> [u8; SEED_LEN] {
    let mut seed = [0u8; SEED_LEN];
    OsRng.fill_bytes(&mut seed);
    seed
}

fn public_key(seed: &[u8; SEED_LEN]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

fn address_of(public_key: &[u8; 32]) -> String {
    let digest = Sha512_256::digest(public_key);
    let mut bytes = Vec::with_capacity(public_key.len() + CHECKSUM_LEN);
    bytes.extend_from_slice(public_key);
    bytes.extend_from_slice(&digest[digest.len() - CHECKSUM_LEN..]);
    BASE32_NOPAD.encode(&bytes)
}
