//! Fixed vectors for the record format. The records below were written once and are never
//! regenerated: if a change to `hardware_keystore` stops them opening, or makes the same inputs
//! give different bytes, it has broken every record already stored.

use hardware_keystore::secret::SecretWrapper;
use hardware_keystore::software::{Argon2Cost, SoftwareWrapper};
use hardware_keystore::{DataKey, KeyWrapper, SecurityLevel, WrappedKey};

const DATA_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const PASSWORD: &str = "correct horse battery staple";
const SECRET: [u8; 32] = [0xa5; 32];
const SALT: [u8; 16] = [0x5a; 16];
const NONCE: [u8; 12] = [0x3c; 12];

const SOFTWARE_RECORD: &str = "01011c000800000001000000010000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a3c3c3c3c3c3c3c3c3c3c3c3c115fd454e7bbfe26cf98492592e42a7e5caabd406cd6640ccf1f006bbadfd69a2181aa80430aa067bf76a9ecda9ea9e8";
const SECRET_RECORD: &str = "010200003c3c3c3c3c3c3c3c3c3c3c3c1619dc4215b82a16bd0f0d3e16df546c0ab49324859516306757943787cbaecc27af7622cc298633bb4b75a5a557df8f";

#[test]
fn software_record_is_stable() {
    let wrapper = SoftwareWrapper::with_cost(PASSWORD, Argon2Cost::INSECURE_MINIMUM);
    let wrapped = wrapper
        .wrap_with_salt_and_nonce(&DataKey::from_bytes(DATA_KEY), SALT, NONCE)
        .unwrap();
    assert_eq!(hex::encode(wrapped.to_bytes().unwrap()), SOFTWARE_RECORD);
}

#[test]
fn software_record_opens() {
    let parsed = WrappedKey::from_bytes(&hex::decode(SOFTWARE_RECORD).unwrap()).unwrap();
    let wrapper = SoftwareWrapper::new(PASSWORD);
    assert_eq!(wrapper.unwrap(&parsed).unwrap().as_bytes(), &DATA_KEY);
}

#[test]
fn secret_record_is_stable() {
    let wrapper = SecretWrapper::new(&SECRET, SecurityLevel::Software);
    let wrapped = wrapper
        .wrap_with_nonce(&DataKey::from_bytes(DATA_KEY), NONCE)
        .unwrap();
    assert_eq!(hex::encode(wrapped.to_bytes().unwrap()), SECRET_RECORD);
}

#[test]
fn secret_record_opens() {
    let parsed = WrappedKey::from_bytes(&hex::decode(SECRET_RECORD).unwrap()).unwrap();
    let wrapper = SecretWrapper::new(&SECRET, SecurityLevel::Software);
    assert_eq!(wrapper.unwrap(&parsed).unwrap().as_bytes(), &DATA_KEY);
}
