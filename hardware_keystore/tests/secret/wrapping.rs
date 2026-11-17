//! The secret backend: HKDF over a caller-supplied secret.

use hardware_keystore::secret::SecretWrapper;
use hardware_keystore::software::{Argon2Cost, SoftwareWrapper};
use hardware_keystore::{BackendId, DataKey, KeyWrapper, KeystoreError, SecurityLevel, WrappedKey};

const SECRET: [u8; 32] = [0x42; 32];

#[test]
fn round_trips() {
    let key = DataKey::generate();
    let wrapper = SecretWrapper::new(&SECRET, SecurityLevel::Software);
    let bytes = wrapper.wrap(&key).unwrap().to_bytes().unwrap();
    let parsed = WrappedKey::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.backend(), BackendId::Secret);
    let again = SecretWrapper::new(&SECRET, SecurityLevel::Software);
    assert!(again.unwrap(&parsed).unwrap() == key);
}

#[test]
fn wrong_secret_is_rejected() {
    let wrapped = SecretWrapper::new(&SECRET, SecurityLevel::Software)
        .wrap(&DataKey::generate())
        .unwrap();
    let other = SecretWrapper::new(&[0x43; 32], SecurityLevel::Software);
    assert_eq!(
        other.unwrap(&wrapped).err(),
        Some(KeystoreError::WrongKeyOrTampered)
    );
}

#[test]
fn a_tampered_ciphertext_is_rejected() {
    let wrapper = SecretWrapper::new(&SECRET, SecurityLevel::Software);
    let mut bytes = wrapper
        .wrap(&DataKey::generate())
        .unwrap()
        .to_bytes()
        .unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let edited = WrappedKey::from_bytes(&bytes).unwrap();
    assert_eq!(
        wrapper.unwrap(&edited).err(),
        Some(KeystoreError::WrongKeyOrTampered)
    );
}

#[test]
fn another_backends_record_is_refused() {
    let software = SoftwareWrapper::with_cost("pw", Argon2Cost::INSECURE_MINIMUM)
        .wrap(&DataKey::generate())
        .unwrap();
    let wrapper = SecretWrapper::new(&SECRET, SecurityLevel::Software);
    assert_eq!(
        wrapper.unwrap(&software).err(),
        Some(KeystoreError::WrongBackend {
            expected: BackendId::Secret,
            found: BackendId::Software,
        })
    );
}

#[test]
fn reports_the_level_it_was_given() {
    let wrapper = SecretWrapper::new(&SECRET, SecurityLevel::SecureElement);
    assert_eq!(wrapper.backend(), BackendId::Secret);
    assert_eq!(wrapper.security_level(), SecurityLevel::SecureElement);
}
