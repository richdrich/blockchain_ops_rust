//! Tests for `blockchain_account_vault::account`: new accounts and the vanity prefix search.

use blockchain_account_vault::account::{
    Account, MAX_PREFIX_LEN, expected_tries, find_vanity_account, generate_account,
    normalise_prefix,
};
use blockchain_account_vault::vault::json_field;

#[test]
fn from_seed_matches_algonaut() {
    for seed in [[0u8; 32], [0xABu8; 32], [7u8; 32]] {
        let ours = Account::from_seed(&seed);
        let theirs = algonaut::transaction::account::Account::from_seed(seed);
        assert_eq!(ours.address, theirs.address().to_string());
        assert_eq!(ours.passphrase, theirs.mnemonic());
    }
}

#[test]
fn generated_accounts_are_valid_and_distinct() {
    let first = generate_account();
    let second = generate_account();
    assert_ne!(first.address, second.address);
    for account in [&first, &second] {
        assert_eq!(account.address.len(), 58);
        let restored = algonaut::transaction::account::Account::from_mnemonic(&account.passphrase)
            .expect("the passphrase must be a valid Algorand mnemonic");
        assert_eq!(restored.address().to_string(), account.address);
    }
}

#[test]
fn key_file_json_has_address_and_passphrase() {
    let account = Account::from_seed(&[1u8; 32]);
    let bytes = account.to_key_file_json().unwrap();
    assert_eq!(json_field(&bytes, "address").unwrap(), account.address);
    assert_eq!(
        json_field(&bytes, "passphrase").unwrap(),
        account.passphrase
    );
}

#[test]
fn normalise_prefix_upper_cases_and_rejects_non_base32() {
    assert_eq!(normalise_prefix("b2z7").unwrap(), "B2Z7");
    for bad in ["", "AB0", "1", "A8", "A9", "A-B", "É"] {
        assert!(normalise_prefix(bad).is_err(), "{bad:?} must be rejected");
    }
    assert!(normalise_prefix(&"A".repeat(MAX_PREFIX_LEN)).is_ok());
    assert!(normalise_prefix(&"A".repeat(MAX_PREFIX_LEN + 1)).is_err());
}

#[test]
fn expected_tries_is_32_per_character() {
    assert_eq!(expected_tries(1), 32);
    assert_eq!(expected_tries(4), 1_048_576);
}

#[test]
fn vanity_search_finds_a_matching_valid_address() {
    let found = find_vanity_account("q7", 2).unwrap();
    assert!(
        found.account.address.starts_with("Q7"),
        "{}",
        found.account.address
    );
    assert!(found.tries >= 1);
    let restored =
        algonaut::transaction::account::Account::from_mnemonic(&found.account.passphrase).unwrap();
    assert_eq!(restored.address().to_string(), found.account.address);
}

#[test]
fn vanity_search_rejects_a_bad_prefix() {
    assert!(find_vanity_account("ab1", 1).is_err());
}
