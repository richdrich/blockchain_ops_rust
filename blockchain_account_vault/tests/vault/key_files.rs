//! Unit tests for `blockchain_account_vault::vault`: discovering, sealing and opening key files, and building
//! their backup pages.

use std::cell::Cell;

use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use blockchain_account_vault::envelope::{decrypt_secret, is_encrypted_envelope};
use blockchain_account_vault::mnemonic::mnemonic_to_bytes;
use blockchain_account_vault::vault::{
    KeyFile, MAX_PRINTABLE_SECRET_LEN, Vault, backup_page, discover, json_field,
};

use crate::support::{ADDRESS, PASSPHRASE, PASSWORD, SEED_FILE, account_json, fast_kdf, write};

fn no_prompt() -> Result<String> {
    Err(anyhow!("no password should have been asked for"))
}

#[test]
fn a_key_file_is_the_same_named_in_either_form() {
    assert_eq!(KeyFile::at("d/x.key.enc"), KeyFile::at("d/x.key"));
    assert_eq!(
        KeyFile::at("d/x.key").sealed_path(),
        std::path::PathBuf::from("d/x.key.enc")
    );
}

#[test]
fn discovery_finds_json_and_key_files_once_each_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("B.json"), "{}");
    write(&dir.path().join("A.json.enc"), "{}");
    write(&dir.path().join("seed.key"), "x");
    write(&dir.path().join("seed.key.enc"), "x");
    write(&dir.path().join("notes.txt"), "x");
    write(&dir.path().join("allowlist.yaml"), "x");
    write(&dir.path().join("node-0/account.key"), "x");

    let flat: Vec<String> = discover(dir.path(), false)
        .unwrap()
        .iter()
        .map(|file| file.name_under(dir.path()))
        .collect();
    assert_eq!(flat, ["A", "B", "seed"]);

    let deep: Vec<String> = discover(dir.path(), true)
        .unwrap()
        .iter()
        .map(|file| file.name_under(dir.path()))
        .collect();
    assert_eq!(deep, ["A", "B", "node-0/account", "seed"]);
}

#[test]
fn sealing_replaces_the_plaintext_and_opening_gives_it_back() {
    fast_kdf();
    let dir = tempfile::tempdir().unwrap();
    let file = KeyFile::at(dir.path().join("consensus.key"));
    write(file.plain_path(), SEED_FILE);

    let vault = Vault::with_password(PASSWORD.to_string());
    assert!(vault.seal(&file).unwrap());

    assert!(!file.plain_path().exists(), "the plaintext must be gone");
    assert!(file.is_sealed());
    let on_disk = std::fs::read(file.sealed_path()).unwrap();
    assert!(is_encrypted_envelope(&on_disk));
    assert!(!String::from_utf8_lossy(&on_disk).contains(SEED_FILE.trim()));

    // sealing again is a no-op.
    assert!(!vault.seal(&file).unwrap());

    let prompts = Cell::new(0);
    let opened = Vault::new()
        .open(&file, || {
            prompts.set(prompts.get() + 1);
            Ok(PASSWORD.to_string())
        })
        .unwrap();
    assert_eq!(opened.bytes, SEED_FILE.as_bytes());
    assert!(opened.was_sealed);
    assert_eq!(prompts.get(), 1);
}

#[cfg(unix)]
#[test]
fn a_sealed_file_is_readable_by_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    fast_kdf();
    let dir = tempfile::tempdir().unwrap();
    let file = KeyFile::at(dir.path().join("consensus.key"));
    write(file.plain_path(), SEED_FILE);
    Vault::with_password(PASSWORD.to_string())
        .seal(&file)
        .unwrap();
    let mode = std::fs::metadata(file.sealed_path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_plain_key_file_opens_without_a_password() {
    let dir = tempfile::tempdir().unwrap();
    let file = KeyFile::at(dir.path().join("consensus.key"));
    write(file.plain_path(), SEED_FILE);
    let opened = Vault::new().open(&file, no_prompt).unwrap();
    assert_eq!(opened.bytes, SEED_FILE.as_bytes());
    assert!(!opened.was_sealed);
}

#[test]
fn the_password_is_asked_for_once_across_files() {
    fast_kdf();
    let dir = tempfile::tempdir().unwrap();
    let sealer = Vault::with_password(PASSWORD.to_string());
    let files: Vec<KeyFile> = ["a.key", "b.key", "c.json"]
        .iter()
        .map(|name| KeyFile::at(dir.path().join(name)))
        .collect();
    for file in &files {
        write(file.plain_path(), SEED_FILE);
        sealer.seal(file).unwrap();
    }

    let prompts = Cell::new(0);
    let mut vault = Vault::new();
    for file in &files {
        vault
            .open(file, || {
                prompts.set(prompts.get() + 1);
                Ok(PASSWORD.to_string())
            })
            .unwrap();
    }
    assert_eq!(prompts.get(), 1);
    assert_eq!(vault.password(), Some(PASSWORD));
}

#[test]
fn a_wrong_password_opens_nothing_and_is_not_remembered() {
    fast_kdf();
    let dir = tempfile::tempdir().unwrap();
    let file = KeyFile::at(dir.path().join("consensus.key"));
    write(file.plain_path(), SEED_FILE);
    Vault::with_password(PASSWORD.to_string())
        .seal(&file)
        .unwrap();

    let mut vault = Vault::new();
    let error = vault
        .open(&file, || Ok("not the password".to_string()))
        .err()
        .expect("a wrong password must fail")
        .to_string();
    assert!(error.contains("does not open"), "{error}");
    assert_eq!(vault.password(), None);

    let checker = Vault::with_password("not the password".to_string());
    assert!(checker.check_opens(&file.sealed_path()).is_err());
    assert!(
        Vault::with_password(PASSWORD.to_string())
            .check_opens(&file.sealed_path())
            .is_ok()
    );
}

#[test]
fn sealing_refuses_a_key_file_that_is_on_disk_in_both_forms() {
    fast_kdf();
    let dir = tempfile::tempdir().unwrap();
    let file = KeyFile::at(dir.path().join("consensus.key"));
    write(file.plain_path(), SEED_FILE);
    write(&file.sealed_path(), "stale");
    let error = Vault::with_password(PASSWORD.to_string())
        .seal(&file)
        .unwrap_err()
        .to_string();
    assert!(error.contains("both"), "{error}");
    assert!(
        file.plain_path().exists(),
        "the plaintext must survive a refusal"
    );
}

#[test]
fn a_missing_key_file_is_an_error_to_open_and_to_seal() {
    let dir = tempfile::tempdir().unwrap();
    let file = KeyFile::at(dir.path().join("absent.key"));
    assert!(Vault::new().open(&file, no_prompt).is_err());
    assert!(
        Vault::with_password(PASSWORD.to_string())
            .seal(&file)
            .is_err()
    );
}

#[test]
fn a_field_is_read_from_an_account_file() {
    let bytes = account_json().into_bytes();
    assert_eq!(json_field(&bytes, "address").unwrap(), ADDRESS);
    assert_eq!(json_field(&bytes, "passphrase").unwrap(), PASSPHRASE);
    assert!(json_field(&bytes, "absent").is_err());
    assert!(json_field(SEED_FILE.as_bytes(), "address").is_err());
}

#[test]
fn an_unsealed_account_prints_as_its_own_25_words() {
    let page = backup_page("APP_ADMIN", account_json().as_bytes(), None).unwrap();
    assert_eq!(page.address.as_deref(), Some(ADDRESS));
    assert!(!page.encrypted);
    assert_eq!(page.secret_len, 32);
    assert_eq!(page.mnemonic, PASSPHRASE);
}

#[test]
fn a_sealed_account_prints_its_key_encrypted_under_the_same_password() {
    fast_kdf();
    let page = backup_page("APP_ADMIN", account_json().as_bytes(), Some(PASSWORD)).unwrap();
    assert!(page.encrypted);
    assert_ne!(page.mnemonic, PASSPHRASE);

    // the page restores: words -> blob -> key, and the QR code holds the same blob.
    let blob = mnemonic_to_bytes(&page.mnemonic, page.secret_len).unwrap();
    assert_eq!(B64.decode(&page.qr_payload).unwrap(), blob);
    let key = decrypt_secret(&blob, PASSWORD).unwrap();
    assert_eq!(key, mnemonic_to_bytes(PASSPHRASE, 32).unwrap());
}

#[test]
fn a_secret_that_is_not_an_account_prints_as_its_own_bytes() {
    fast_kdf();
    let plain = backup_page("node-0/consensus", SEED_FILE.as_bytes(), None).unwrap();
    assert_eq!(plain.address, None);
    assert_eq!(plain.secret_len, SEED_FILE.len());
    assert_eq!(
        mnemonic_to_bytes(&plain.mnemonic, plain.secret_len).unwrap(),
        SEED_FILE.as_bytes()
    );

    let sealed = backup_page("node-0/consensus", SEED_FILE.as_bytes(), Some(PASSWORD)).unwrap();
    let blob = mnemonic_to_bytes(&sealed.mnemonic, sealed.secret_len).unwrap();
    assert_eq!(
        decrypt_secret(&blob, PASSWORD).unwrap(),
        SEED_FILE.as_bytes()
    );
}

#[test]
fn a_secret_too_large_for_a_page_is_refused_by_name() {
    let large = vec![b'x'; MAX_PRINTABLE_SECRET_LEN + 1];
    let error = backup_page("BIG", &large, None).err().unwrap().to_string();
    assert!(error.contains("BIG"), "{error}");
    assert!(backup_page("FITS", &large[1..], None).is_ok());
}

#[test]
fn the_largest_secret_still_fits_the_page_when_sealed() {
    fast_kdf();
    let largest = vec![b'x'; MAX_PRINTABLE_SECRET_LEN];
    let page = backup_page("FITS", &largest, Some(PASSWORD)).unwrap();
    assert!(blockchain_account_vault::pdf::render_backup_pdf(&[page]).is_ok());
}

#[test]
fn an_account_with_a_bad_passphrase_is_refused_by_name() {
    let bad = r#"{"address": "X", "passphrase": "not twenty five words"}"#;
    let error = backup_page("APP_ADMIN", bad.as_bytes(), None)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("APP_ADMIN"), "{error}");
}
