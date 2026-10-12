//! Generalised Algorand-style mnemonic encoding for arbitrary byte lengths.
//!
//! This follows the same transformation as `algonaut::crypto::mnemonic`
//! (see <https://dev.algorand.co/concepts/accounts/keys-signing/>): the bytes are
//! packed little-endian into 11-bit groups indexing the BIP39 English word list,
//! followed by a single checksum word derived from the first 11 bits of the
//! SHA512/256 digest.
//!
//! Unlike algonaut's function, which only accepts a 32-byte key, this generalises
//! to any length: `ceil(len * 8 / 11)` data words plus one checksum word. For a
//! 32-byte input the output is byte-for-byte identical to algonaut's 25-word
//! mnemonic (asserted in the tests), so an unencrypted private key prints as the
//! usual mnemonic, while a longer encrypted blob simply yields more words.

use anyhow::{Result, anyhow, bail};
use sha2::{Digest, Sha512_256};

const BITS_PER_WORD: usize = 11;

/// The BIP39 English word list (2048 words), vendored to match algonaut exactly.
static WORDLIST: &str = include_str!("wordlist.txt");

fn wordlist() -> Vec<&'static str> {
    WORDLIST
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// Encode arbitrary bytes as an Algorand-style mnemonic (space-separated words).
pub fn bytes_to_mnemonic(bytes: &[u8]) -> String {
    let words = wordlist();
    let mut out: Vec<&str> = to_u11(bytes)
        .into_iter()
        .map(|i| words[i as usize])
        .collect();
    out.push(checksum_word(bytes, &words));
    out.join(" ")
}

/// Decode a mnemonic produced by [`bytes_to_mnemonic`] back into `expected_len`
/// bytes, verifying the checksum. The length is required because the trailing
/// zero padding of the final 11-bit group makes it ambiguous otherwise (callers
/// know it from context: 32 for a raw key, or the encrypted blob length).
pub fn mnemonic_to_bytes(mnemonic: &str, expected_len: usize) -> Result<Vec<u8>> {
    let words = wordlist();
    let mut parts: Vec<&str> = mnemonic.split_whitespace().collect();
    let check = parts.pop().ok_or_else(|| anyhow!("empty mnemonic"))?;

    let mut nums = Vec::with_capacity(parts.len());
    for w in &parts {
        let n = words
            .iter()
            .position(|x| x == w)
            .ok_or_else(|| anyhow!("word not in list: {w}"))?;
        nums.push(n as u32);
    }

    let mut bytes = to_bytes(&nums);
    if bytes.len() < expected_len {
        bail!(
            "mnemonic decodes to {} bytes, expected {}",
            bytes.len(),
            expected_len
        );
    }
    bytes.truncate(expected_len);

    if check != checksum_word(&bytes, &words) {
        bail!("mnemonic checksum mismatch");
    }
    Ok(bytes)
}

fn checksum_word(data: &[u8], words: &[&'static str]) -> &'static str {
    let digest = Sha512_256::digest(data);
    words[to_u11(&digest[0..2])[0] as usize]
}

/// Pack bytes little-endian into 11-bit groups (LSB first), zero-padding the
/// final group. Matches algonaut's `to_u11_array`.
fn to_u11(bytes: &[u8]) -> Vec<u32> {
    let mut buf = 0u32;
    let mut bit_count = 0u32;
    let mut out = Vec::with_capacity((bytes.len() * 8).div_ceil(BITS_PER_WORD));
    for &b in bytes {
        buf |= u32::from(b) << bit_count;
        bit_count += 8;
        if bit_count >= BITS_PER_WORD as u32 {
            out.push(buf & 0x7ff);
            buf >>= BITS_PER_WORD as u32;
            bit_count -= BITS_PER_WORD as u32;
        }
    }
    if bit_count != 0 {
        out.push(buf & 0x7ff);
    }
    out
}

/// Inverse of [`to_u11`]: unpack 11-bit groups back into bytes. Matches
/// algonaut's `to_byte_array` (the final byte may be trailing padding).
fn to_bytes(nums: &[u32]) -> Vec<u8> {
    let mut buf = 0u32;
    let mut bit_count = 0u32;
    let mut out = Vec::with_capacity((nums.len() * BITS_PER_WORD).div_ceil(8));
    for &n in nums {
        buf |= n << bit_count;
        bit_count += BITS_PER_WORD as u32;
        while bit_count >= 8 {
            out.push((buf & 0xff) as u8);
            buf >>= 8;
            bit_count -= 8;
        }
    }
    if bit_count != 0 {
        out.push((buf & 0xff) as u8);
    }
    out
}
