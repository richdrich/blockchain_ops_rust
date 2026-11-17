//! `recovery`: a slot secret derived from an Algorand recovery phrase.

use blockchain_account_vault::recovery::recovery_secret;

use crate::support::PASSPHRASE;

const LABEL: &str = "bingle state file recovery v1";

/// HKDF-SHA256 (no salt) over the all-zero seed that `PASSPHRASE` encodes, with `LABEL` as the
/// info string. Computed once and checked with an independent HKDF implementation.
const EXPECTED: &str = "6996166c39507709ff35dfa49ab2942a2fc4f55418b9e99185fd6d2128906658";

#[test]
fn matches_the_fixed_vector() {
    let secret = recovery_secret(PASSPHRASE, LABEL).unwrap();
    assert_eq!(hex::encode(secret.as_ref()), EXPECTED);
}

#[test]
fn is_deterministic_and_ignores_surrounding_whitespace() {
    let a = recovery_secret(PASSPHRASE, LABEL).unwrap();
    let b = recovery_secret(&format!("  {PASSPHRASE}\n"), LABEL).unwrap();
    assert_eq!(a.as_ref(), b.as_ref());
}

#[test]
fn differs_across_labels() {
    let a = recovery_secret(PASSPHRASE, LABEL).unwrap();
    let b = recovery_secret(PASSPHRASE, "another purpose v1").unwrap();
    assert_ne!(a.as_ref(), b.as_ref());
}

#[test]
fn rejects_a_bad_checksum_and_an_empty_label() {
    let bad = PASSPHRASE.replace("invest", "abandon");
    assert!(recovery_secret(&bad, LABEL).is_err());
    assert!(recovery_secret(PASSPHRASE, "").is_err());
}
