use algo_ops::{AlgoChainConfig, AlgoOps, byte_key_to_address};
use base64::{Engine as _, engine::general_purpose};

fn default_cfg() -> AlgoChainConfig {
    // No network calls are made in these tests, but AlgoOps requires a config
    AlgoChainConfig::default()
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn derives_address_from_mnemonic_when_constructed() {
    // Known test mnemonic/address pair.
    let mnemonic = "theme term glow reflect essence artefact tired bicycle february demand vacuum tent faculty arch elevator rent already anchor rough cry sketch nurse mom able inquiry";
    let expected_address = "4TKGNGRAUHMQI4EOQ34L2AIDX2VGS4OZNZIOE6BLEQFZUDRSB6RJRBPVRE";

    let ops = AlgoOps::new(Some(mnemonic.to_string()), None, Some(default_cfg()));

    // Ensure the address is derived immediately and matches expected
    let addr = ops
        .address
        .as_ref()
        .expect("address should be derived from mnemonic");
    assert_eq!(addr, expected_address);
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn derives_address_from_legacy_b64_seed_when_constructed() {
    // Fixed 32-byte seed so the expected address is deterministic
    let seed: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let b64 = general_purpose::STANDARD.encode(seed);
    let passphrase = format!("b64:{}", b64);

    // Compute expected address from the corresponding public key
    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pk: [u8; 32] = verifying_key.to_bytes();
    let expected_address = byte_key_to_address(&pk).expect("should compute address from pubkey");

    let ops = AlgoOps::new(Some(passphrase), None, Some(default_cfg()));

    let addr = ops
        .address
        .as_ref()
        .expect("address should be derived from legacy b64 seed");
    assert_eq!(addr, &expected_address);
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn address_from_passphrase_derives_expected_address() {
    // Same known test mnemonic/address pair as above.
    let mnemonic = "theme term glow reflect essence artefact tired bicycle february demand vacuum tent faculty arch elevator rent already anchor rough cry sketch nurse mom able inquiry";
    let expected_address = "4TKGNGRAUHMQI4EOQ34L2AIDX2VGS4OZNZIOE6BLEQFZUDRSB6RJRBPVRE";

    let addr = AlgoOps::address_from_passphrase(mnemonic)
        .expect("valid mnemonic should derive an address");
    assert_eq!(addr, expected_address);
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn address_from_passphrase_rejects_invalid_mnemonic() {
    let result = AlgoOps::address_from_passphrase("not a valid mnemonic at all");
    assert!(
        result.is_err(),
        "an invalid mnemonic must not derive an address"
    );
}
