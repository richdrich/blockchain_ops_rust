//! Password-based encryption for key files.
//!
//! The on-disk formats here are the ones `bingle_admin` has always written, and
//! must stay byte-compatible with them: a file sealed by either tool opens with
//! the other.
//!
//! Uses Argon2id (a memory-hard KDF that is deliberately slow to iterate) to
//! derive a 256-bit key from a password, then AES-256-GCM to authenticate and
//! encrypt the plaintext. The output is a self-describing JSON envelope that
//! carries the salt, nonce, KDF parameters and ciphertext.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;

/// Marker written into every envelope so encrypted files can be recognised.
pub const ENVELOPE_MARKER: u32 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Argon2id cost parameters. Chosen to be slow enough to frustrate brute-force
/// iteration of candidate passwords while remaining acceptable interactively.
/// memory in KiB, iterations, parallelism.
const ARGON2_M_COST: u32 = 64 * 1024; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

/// Minimal Argon2 cost used only when `BINGLE_INSECURE_FAST_KDF` is set in the
/// environment, so the deliberately slow KDF can be exercised repeatedly in the
/// test suite without dominating runtime. Never set that variable in production:
/// it makes derived keys cheap to brute-force.
const ARGON2_FAST_M_COST: u32 = 8; // 8 KiB (argon2 minimum)
const ARGON2_FAST_T_COST: u32 = 1;
const ARGON2_FAST_P_COST: u32 = 1;

/// Environment variable that selects the fast, insecure KDF cost (tests only).
pub const FAST_KDF_ENV: &str = "BINGLE_INSECURE_FAST_KDF";

/// The Argon2 (m, t, p) cost to use for *new* encryptions. Decryption always
/// uses the parameters stored in the envelope, so lowering this for tests does
/// not affect the ability to open files written with the secure parameters.
fn argon2_cost() -> (u32, u32, u32) {
    if std::env::var_os(FAST_KDF_ENV).is_some() {
        (ARGON2_FAST_M_COST, ARGON2_FAST_T_COST, ARGON2_FAST_P_COST)
    } else {
        (ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)
    }
}

/// Derive a 256-bit key from `password` and `salt` using Argon2id with the
/// current cost (secure by default; reduced when `FAST_KDF_ENV` is set).
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let (m, t, p) = argon2_cost();
    derive_key_with(password, salt, m, t, p)
}

/// Derive a 256-bit key from `password` and `salt` using explicit Argon2id cost.
fn derive_key_with(password: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; KEY_LEN]> {
    let params =
        Params::new(m, t, p, Some(KEY_LEN)).map_err(|e| anyhow!("invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2 key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypt `plaintext` with `password`, returning a JSON envelope as bytes.
///
/// A fresh random salt and nonce are generated on every call, so encrypting the
/// same input twice yields different envelopes.
pub fn encrypt_bytes(plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let (m, t, p) = argon2_cost();
    let key = derive_key_with(password, &salt, m, t, p)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("failed to build AES-256-GCM cipher: {e}"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| anyhow!("AES-256-GCM encryption failed: {e}"))?;

    let envelope = serde_json::json!({
        "bingle_encrypted": ENVELOPE_MARKER,
        "kdf": "argon2id",
        "m": m,
        "t": t,
        "p": p,
        "salt": B64.encode(salt),
        "nonce": B64.encode(nonce_bytes),
        "ciphertext": B64.encode(&ciphertext),
    });
    Ok(serde_json::to_vec_pretty(&envelope)?)
}

/// Decrypt a JSON envelope produced by [`encrypt_bytes`] using `password`.
///
/// Returns an error if the password is wrong (GCM authentication failure) or the
/// envelope is malformed.
pub fn decrypt_bytes(envelope: &[u8], password: &str) -> Result<Vec<u8>> {
    let json: serde_json::Value =
        serde_json::from_slice(envelope).context("encrypted file is not valid JSON")?;

    if json.get("bingle_encrypted").and_then(|v| v.as_u64()) != Some(ENVELOPE_MARKER as u64) {
        bail!("file is not a bingle encrypted envelope");
    }

    let m = json.get("m").and_then(|v| v.as_u64());
    let t = json.get("t").and_then(|v| v.as_u64());
    let p = json.get("p").and_then(|v| v.as_u64());
    let (m, t, p) = match (m, t, p) {
        (Some(m), Some(t), Some(p)) => (m as u32, t as u32, p as u32),
        _ => bail!("envelope is missing argon2 cost parameters"),
    };

    let salt = decode_field(&json, "salt")?;
    let nonce_bytes = decode_field(&json, "nonce")?;
    let ciphertext = decode_field(&json, "ciphertext")?;
    if nonce_bytes.len() != NONCE_LEN {
        bail!("envelope nonce has wrong length");
    }

    let key = derive_key_with(password, &salt, m, t, p)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("failed to build AES-256-GCM cipher: {e}"))?;
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_slice())
        .map_err(|_| anyhow!("decryption failed (wrong password or corrupted file)"))
}

fn decode_field(json: &serde_json::Value, field: &str) -> Result<Vec<u8>> {
    let s = json
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("envelope is missing '{field}' field"))?;
    B64.decode(s)
        .with_context(|| format!("envelope '{field}' is not valid base64"))
}

/// Re-encrypt an existing envelope under `new_password`, changing the password.
///
/// - If `new_password` already decrypts the envelope, returns `Ok(None)` (nothing
///   to do — the file is already keyed to the new password).
/// - Otherwise the plaintext is recovered using an *old* password: the cached
///   `old_password` is tried first, and only if that is absent or fails is
///   `prompt_old` invoked to obtain one. A successful old password is stored back
///   into `old_password` so subsequent calls reuse it without prompting again.
///   The recovered plaintext is re-encrypted under `new_password` and returned as
///   `Ok(Some(new_envelope))`.
pub fn reencrypt_envelope<F>(
    envelope: &[u8],
    new_password: &str,
    old_password: &mut Option<String>,
    mut prompt_old: F,
) -> Result<Option<Vec<u8>>>
where
    F: FnMut() -> Result<String>,
{
    if !is_encrypted_envelope(envelope) {
        bail!("file is not a bingle encrypted envelope");
    }

    // Already encrypted with the new password: no change required.
    if decrypt_bytes(envelope, new_password).is_ok() {
        return Ok(None);
    }

    // Try the cached old password before prompting.
    let plaintext = match old_password
        .as_deref()
        .and_then(|pw| decrypt_bytes(envelope, pw).ok())
    {
        Some(pt) => pt,
        None => {
            let pw = prompt_old()?;
            let pt = decrypt_bytes(envelope, &pw)
                .map_err(|_| anyhow!("old password did not decrypt this file"))?;
            *old_password = Some(pw);
            pt
        }
    };

    Ok(Some(encrypt_bytes(&plaintext, new_password)?))
}

/// True if `bytes` is a bingle encrypted envelope.
pub fn is_encrypted_envelope(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| v.get("bingle_encrypted").and_then(|m| m.as_u64()))
        == Some(ENVELOPE_MARKER as u64)
}

/// Version byte for the compact binary secret format produced by
/// [`encrypt_secret`].
const SECRET_VERSION: u8 = 1;
/// Header size: version(1) + m_cost(4) + t_cost(1) + p_cost(1).
const SECRET_HEADER_LEN: usize = 7;

/// Encrypt a small secret (e.g. a raw 32-byte private key) into a compact,
/// self-describing *binary* blob — as opposed to the JSON envelope used for
/// account files. This is intended for embedding in a QR code / mnemonic.
///
/// Layout: `version(1) | m_cost(u32 LE) | t_cost(u8) | p_cost(u8) | salt(16) |
/// nonce(12) | ciphertext+tag`. For a 32-byte input the blob is 83 bytes, i.e.
/// always larger than the plaintext.
pub fn encrypt_secret(plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let (m, t, p) = argon2_cost();
    let key = derive_key_with(password, &salt, m, t, p)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("failed to build AES-256-GCM cipher: {e}"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| anyhow!("AES-256-GCM encryption failed: {e}"))?;

    let t: u8 = t
        .try_into()
        .map_err(|_| anyhow!("argon2 t_cost too large for secret blob"))?;
    let p: u8 = p
        .try_into()
        .map_err(|_| anyhow!("argon2 p_cost too large for secret blob"))?;

    let mut out = Vec::with_capacity(SECRET_HEADER_LEN + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.push(SECRET_VERSION);
    out.extend_from_slice(&m.to_le_bytes());
    out.push(t);
    out.push(p);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt_secret`].
pub fn decrypt_secret(blob: &[u8], password: &str) -> Result<Vec<u8>> {
    if blob.len() < SECRET_HEADER_LEN + SALT_LEN + NONCE_LEN {
        bail!("encrypted secret is too short");
    }
    if blob[0] != SECRET_VERSION {
        bail!("unsupported encrypted secret version {}", blob[0]);
    }
    let m = u32::from_le_bytes([blob[1], blob[2], blob[3], blob[4]]);
    let t = blob[5] as u32;
    let p = blob[6] as u32;

    let mut off = SECRET_HEADER_LEN;
    let salt = &blob[off..off + SALT_LEN];
    off += SALT_LEN;
    let nonce_bytes = &blob[off..off + NONCE_LEN];
    off += NONCE_LEN;
    let ciphertext = &blob[off..];

    let key = derive_key_with(password, salt, m, t, p)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("failed to build AES-256-GCM cipher: {e}"))?;
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| anyhow!("decryption failed (wrong password or corrupted secret)"))
}
