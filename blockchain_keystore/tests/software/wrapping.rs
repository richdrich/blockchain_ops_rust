//! The software backend: Argon2id over a password.

use blockchain_keystore::software::{Argon2Cost, MAX_MEMORY_KIB, SoftwareWrapper};
use blockchain_keystore::{
    BackendId, DataKey, KeyWrapper, KeystoreError, SecurityLevel, WrappedKey,
};

fn wrapper(password: &str) -> SoftwareWrapper {
    SoftwareWrapper::with_cost(password, Argon2Cost::INSECURE_MINIMUM)
}

#[test]
fn round_trips() {
    let key = DataKey::generate();
    let wrapped = wrapper("correct horse").wrap(&key).unwrap();
    assert_eq!(wrapped.backend(), BackendId::Software);
    let unwrapped = wrapper("correct horse").unwrap(&wrapped).unwrap();
    assert!(unwrapped == key);
}

#[test]
fn round_trips_through_bytes() {
    let key = DataKey::generate();
    let bytes = wrapper("pw").wrap(&key).unwrap().to_bytes().unwrap();
    let parsed = WrappedKey::from_bytes(&bytes).unwrap();
    assert!(wrapper("pw").unwrap(&parsed).unwrap() == key);
}

#[test]
fn wrapping_twice_gives_different_records() {
    let key = DataKey::generate();
    let a = wrapper("pw").wrap(&key).unwrap().to_bytes().unwrap();
    let b = wrapper("pw").wrap(&key).unwrap().to_bytes().unwrap();
    assert_ne!(a, b, "a fresh salt and nonce every time");
}

#[test]
fn wrong_password_is_rejected() {
    let wrapped = wrapper("right").wrap(&DataKey::generate()).unwrap();
    assert_eq!(
        wrapper("wrong").unwrap(&wrapped).err(),
        Some(KeystoreError::WrongKeyOrTampered)
    );
}

#[test]
fn lowering_the_stored_cost_is_rejected() {
    // the cost is in the header, which is authenticated: a record edited to a
    // cheaper cost must not open.
    let wrapped = SoftwareWrapper::with_cost(
        "pw",
        Argon2Cost {
            memory_kib: 16,
            passes: 2,
            lanes: 1,
        },
    )
    .wrap(&DataKey::generate())
    .unwrap();
    let mut bytes = wrapped.to_bytes().unwrap();
    // params start after version, backend and the 2-byte length; the memory cost is first.
    bytes[4..8].copy_from_slice(&8u32.to_le_bytes());
    let edited = WrappedKey::from_bytes(&bytes).unwrap();
    assert_eq!(
        wrapper("pw").unwrap(&edited).err(),
        Some(KeystoreError::WrongKeyOrTampered)
    );
}

#[test]
fn an_unbounded_memory_cost_is_refused_before_deriving() {
    let wrapped = wrapper("pw").wrap(&DataKey::generate()).unwrap();
    let mut bytes = wrapped.to_bytes().unwrap();
    bytes[4..8].copy_from_slice(&(MAX_MEMORY_KIB + 1).to_le_bytes());
    let edited = WrappedKey::from_bytes(&bytes).unwrap();
    assert!(matches!(
        wrapper("pw").unwrap(&edited),
        Err(KeystoreError::Malformed(_))
    ));
}

#[test]
fn reports_software_level() {
    let w = wrapper("pw");
    assert_eq!(w.backend(), BackendId::Software);
    assert_eq!(w.security_level(), SecurityLevel::Software);
}
