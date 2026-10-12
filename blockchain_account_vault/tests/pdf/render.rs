//! Unit tests for `blockchain_account_vault::pdf` — PDF rendering of backup pages.
//!

use blockchain_account_vault::pdf::{BackupPage, MAX_MNEMONIC_WORDS, render_backup_pdf};

fn sample(name: &str, encrypted: bool) -> BackupPage {
    BackupPage {
        name: name.to_string(),
        address: Some("P577PSTDICQ6PQFBR5YMDMJ2YVK7LT5V4GOPNVDLCEDJIL7XGRWC5BRFWA".to_string()),
        encrypted,
        secret_len: 16,
        qr_payload: "AAECAwQFBgcICQoLDA0ODw==".to_string(),
        mnemonic: "abandon ability able about above absent absorb abstract absurd \
                   abuse access accident account accuse achieve acid acoustic acquire \
                   across act action actor actress"
            .to_string(),
    }
}

#[test]
fn renders_a_valid_pdf() {
    let pages = vec![sample("APP_CREATOR", false), sample("APP_ADMIN", true)];
    let bytes = render_backup_pdf(&pages).unwrap();

    assert!(bytes.starts_with(b"%PDF"), "output should be a PDF");
    assert!(bytes.len() > 1000, "PDF should have real content");
}

#[test]
fn single_account_renders() {
    let bytes = render_backup_pdf(&[sample("ASSET_RESERVE", false)]).unwrap();
    assert!(bytes.starts_with(b"%PDF"));
}

#[test]
fn empty_input_errors() {
    assert!(render_backup_pdf(&[]).is_err());
}

#[test]
fn a_secret_that_is_not_an_account_renders() {
    let mut page = sample("node-0/consensus", true);
    page.address = None;
    let bytes = render_backup_pdf(&[page]).unwrap();
    assert!(bytes.starts_with(b"%PDF"));
}

#[test]
fn a_mnemonic_too_long_for_the_page_is_refused() {
    let mut page = sample("TOO_LONG", false);
    page.mnemonic = vec!["abandon"; MAX_MNEMONIC_WORDS + 1].join(" ");
    let error = render_backup_pdf(&[page]).unwrap_err().to_string();
    assert!(error.contains("TOO_LONG"), "{error}");
}
