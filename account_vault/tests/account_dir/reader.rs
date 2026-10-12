//! Unit tests for `account_vault::account_dir::AccountDir` — resolving plaintext vs
//! encrypted account files and caching the password across reads.
//!

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use account_vault::account_dir::AccountDir;
use account_vault::envelope::{FAST_KDF_ENV, encrypt_bytes};
use anyhow::{Result, anyhow};

const PLAIN_A: &[u8] = br#"{"address":"AAA","passphrase":"pa"}"#;
const PLAIN_B: &[u8] = br#"{"address":"BBB","passphrase":"pb"}"#;

static FAST_KDF: Once = Once::new();
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir() -> PathBuf {
    // Use the reduced (test-only) KDF cost for the encrypted fixtures below.
    // Set here — before any encrypt_bytes call — so every test is fast.
    FAST_KDF.call_once(|| unsafe { std::env::set_var(FAST_KDF_ENV, "1") });

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // Include a process-unique counter so parallel tests never share a directory.
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("bingle_accountdir_{nanos}_{unique}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn never_prompt() -> Result<String> {
    panic!("password prompt must not be called")
}

#[test]
fn reads_plaintext_without_prompting() {
    let dir = temp_dir();
    std::fs::write(dir.join("APP_ADMIN.json"), PLAIN_A).unwrap();

    let mut accounts = AccountDir::new(&dir);
    assert!(accounts.exists("APP_ADMIN"));
    assert!(!accounts.is_encrypted("APP_ADMIN"));

    let bytes = accounts.read_bytes("APP_ADMIN", never_prompt).unwrap();
    assert_eq!(bytes, PLAIN_A);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn reads_encrypted_file_prompting_once_and_caches() {
    let dir = temp_dir();
    std::fs::write(
        dir.join("A.json.enc"),
        encrypt_bytes(PLAIN_A, "pw").unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("B.json.enc"),
        encrypt_bytes(PLAIN_B, "pw").unwrap(),
    )
    .unwrap();

    let mut accounts = AccountDir::new(&dir);
    assert!(accounts.exists("A"));
    assert!(accounts.is_encrypted("A"));
    assert!(accounts.cached_password().is_none());

    let calls = Cell::new(0usize);
    let prompt = || {
        calls.set(calls.get() + 1);
        Ok("pw".to_string())
    };

    assert_eq!(accounts.read_bytes("A", prompt).unwrap(), PLAIN_A);
    // Second encrypted read reuses the cached password — prompt not called again.
    assert_eq!(accounts.read_bytes("B", prompt).unwrap(), PLAIN_B);
    assert_eq!(calls.get(), 1, "password should be requested only once");
    assert_eq!(accounts.cached_password(), Some("pw"));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn seeded_cached_password_avoids_prompt() {
    let dir = temp_dir();
    std::fs::write(
        dir.join("A.json.enc"),
        encrypt_bytes(PLAIN_A, "pw").unwrap(),
    )
    .unwrap();

    let mut accounts = AccountDir::new(&dir).with_cached_password(Some("pw".to_string()));
    assert_eq!(accounts.read_bytes("A", never_prompt).unwrap(), PLAIN_A);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn wrong_password_is_rejected() {
    let dir = temp_dir();
    std::fs::write(
        dir.join("A.json.enc"),
        encrypt_bytes(PLAIN_A, "pw").unwrap(),
    )
    .unwrap();

    let mut accounts = AccountDir::new(&dir);
    let result = accounts.read_bytes("A", || Ok("wrong".to_string()));
    assert!(result.is_err(), "a wrong password must be rejected");
    assert!(
        accounts.cached_password().is_none(),
        "a rejected password must not be cached"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn prompt_error_propagates() {
    let dir = temp_dir();
    std::fs::write(
        dir.join("A.json.enc"),
        encrypt_bytes(PLAIN_A, "pw").unwrap(),
    )
    .unwrap();

    let mut accounts = AccountDir::new(&dir);
    let result = accounts.read_bytes("A", || Err(anyhow!("cancelled")));
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn discover_names_finds_all_sorted_and_deduped() {
    let dir = temp_dir();
    std::fs::write(dir.join("APP_ADMIN.json"), PLAIN_A).unwrap();
    std::fs::write(
        dir.join("ASSET_RESERVE.json.enc"),
        encrypt_bytes(PLAIN_B, "pw").unwrap(),
    )
    .unwrap();
    // Present as both plaintext and encrypted -> counted once.
    std::fs::write(dir.join("APP_CREATOR.json"), PLAIN_A).unwrap();
    std::fs::write(
        dir.join("APP_CREATOR.json.enc"),
        encrypt_bytes(PLAIN_A, "pw").unwrap(),
    )
    .unwrap();
    // Non-account files are ignored.
    std::fs::write(dir.join("notes.txt"), b"ignore me").unwrap();

    let accounts = AccountDir::new(&dir);
    let names = accounts.discover_names().unwrap();
    assert_eq!(
        names,
        vec![
            "APP_ADMIN".to_string(),
            "APP_CREATOR".to_string(),
            "ASSET_RESERVE".to_string()
        ]
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn missing_account_errors() {
    let dir = temp_dir();
    let mut accounts = AccountDir::new(&dir);
    assert!(!accounts.exists("NOPE"));
    assert!(accounts.read_bytes("NOPE", never_prompt).is_err());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn plaintext_takes_precedence_over_enc() {
    let dir = temp_dir();
    std::fs::write(dir.join("A.json"), PLAIN_A).unwrap();
    std::fs::write(
        dir.join("A.json.enc"),
        encrypt_bytes(PLAIN_B, "pw").unwrap(),
    )
    .unwrap();

    let mut accounts = AccountDir::new(&dir);
    assert!(!accounts.is_encrypted("A"), "plaintext presence wins");
    // Plaintext is returned without needing a password.
    assert_eq!(accounts.read_bytes("A", never_prompt).unwrap(), PLAIN_A);

    std::fs::remove_dir_all(&dir).ok();
}
