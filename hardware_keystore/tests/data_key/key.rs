//! The data key itself: generation and comparison.

use hardware_keystore::{DATA_KEY_LEN, DataKey};

#[test]
fn generated_keys_differ() {
    assert!(DataKey::generate() != DataKey::generate());
}

#[test]
fn from_bytes_round_trips() {
    let bytes = [7u8; DATA_KEY_LEN];
    let key = DataKey::from_bytes(bytes);
    assert_eq!(key.as_bytes(), &bytes);
    assert!(key == DataKey::from_bytes(bytes));
}

#[test]
fn keys_differing_in_one_byte_are_not_equal() {
    let mut other = [7u8; DATA_KEY_LEN];
    other[DATA_KEY_LEN - 1] = 8;
    assert!(DataKey::from_bytes([7u8; DATA_KEY_LEN]) != DataKey::from_bytes(other));
}
