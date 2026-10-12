//! Unit tests for `account_vault::mnemonic` — the generalised Algorand-style
//! mnemonic encoder.
//!

use account_vault::mnemonic::{bytes_to_mnemonic, mnemonic_to_bytes};

#[test]
fn matches_algonaut_for_32_byte_key() {
    // For a 32-byte key the generalised encoder must be identical to algonaut's
    // 25-word mnemonic (same word list, packing and checksum).
    for seed in [[0u8; 32], [0xABu8; 32], {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }] {
        let ours = bytes_to_mnemonic(&seed);
        let algonaut = algonaut::crypto::mnemonic::from_key(&seed).unwrap();
        assert_eq!(ours, algonaut, "mnemonic must match algonaut for {seed:?}");
        assert_eq!(ours.split_whitespace().count(), 25);
    }
}

#[test]
fn round_trips_32_bytes() {
    let seed = [7u8; 32];
    let mnemonic = bytes_to_mnemonic(&seed);
    let recovered = mnemonic_to_bytes(&mnemonic, 32).unwrap();
    assert_eq!(recovered, seed);
}

#[test]
fn round_trips_larger_blob() {
    // An 83-byte encrypted-secret-sized blob yields more words but must still
    // round-trip exactly.
    let blob: Vec<u8> = (0..83u16).map(|i| (i * 7 % 256) as u8).collect();
    let mnemonic = bytes_to_mnemonic(&blob);
    // ceil(83*8 / 11) = 61 data words + 1 checksum word.
    assert_eq!(mnemonic.split_whitespace().count(), 62);
    let recovered = mnemonic_to_bytes(&mnemonic, blob.len()).unwrap();
    assert_eq!(recovered, blob);
}

#[test]
fn word_count_grows_with_length() {
    let short = bytes_to_mnemonic(&[1u8; 32]).split_whitespace().count();
    let long = bytes_to_mnemonic(&[1u8; 83]).split_whitespace().count();
    assert!(long > short, "a longer secret must produce more words");
}

#[test]
fn detects_checksum_error() {
    let seed = [3u8; 32];
    let mnemonic = bytes_to_mnemonic(&seed);
    // Replace the first word with a different valid word; checksum must fail.
    let mut words: Vec<&str> = mnemonic.split_whitespace().collect();
    words[0] = if words[0] == "abandon" {
        "ability"
    } else {
        "abandon"
    };
    let tampered = words.join(" ");
    assert!(mnemonic_to_bytes(&tampered, 32).is_err());
}

#[test]
fn rejects_unknown_word() {
    let mnemonic = bytes_to_mnemonic(&[0u8; 32]);
    let tampered = mnemonic.replacen("abandon", "notaword", 1);
    assert!(mnemonic_to_bytes(&tampered, 32).is_err());
}
