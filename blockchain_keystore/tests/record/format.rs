//! The wrapped-key record layout: parsing and rejecting bad records.

use blockchain_keystore::secret::SecretWrapper;
use blockchain_keystore::{
    BackendId, DataKey, KeyWrapper, KeystoreError, RECORD_VERSION, SecurityLevel, WrappedKey,
};

fn secret_record() -> Vec<u8> {
    SecretWrapper::new(&[1u8; 32], SecurityLevel::Software)
        .wrap(&DataKey::generate())
        .unwrap()
        .to_bytes()
        .unwrap()
}

#[test]
fn layout_is_header_nonce_ciphertext() {
    let bytes = secret_record();
    assert_eq!(bytes[0], RECORD_VERSION);
    assert_eq!(bytes[1], BackendId::Secret.as_byte());
    assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 0);
    // 4 header bytes, no params, a 12-byte nonce, a 32-byte key and a 16-byte tag.
    assert_eq!(bytes.len(), 4 + 12 + 32 + 16);
}

#[test]
fn an_unknown_version_is_rejected() {
    let mut bytes = secret_record();
    bytes[0] = 2;
    assert_eq!(
        WrappedKey::from_bytes(&bytes).err(),
        Some(KeystoreError::UnsupportedVersion(2))
    );
}

#[test]
fn an_unknown_backend_is_rejected() {
    let mut bytes = secret_record();
    bytes[1] = 9;
    assert_eq!(
        WrappedKey::from_bytes(&bytes).err(),
        Some(KeystoreError::UnknownBackend(9))
    );
}

#[test]
fn truncated_and_padded_records_are_rejected() {
    let bytes = secret_record();
    assert!(matches!(
        WrappedKey::from_bytes(&bytes[..bytes.len() - 1]),
        Err(KeystoreError::Malformed(_))
    ));
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(matches!(
        WrappedKey::from_bytes(&longer),
        Err(KeystoreError::Malformed(_))
    ));
    assert!(matches!(
        WrappedKey::from_bytes(&bytes[..3]),
        Err(KeystoreError::Malformed(_))
    ));
}

#[test]
fn backend_ids_round_trip() {
    for backend in [BackendId::Software, BackendId::Secret, BackendId::Fake] {
        assert_eq!(BackendId::from_byte(backend.as_byte()).unwrap(), backend);
    }
}
