//! The `test-support` fake: real wrapping, plus a switch for "not available now".

use hardware_keystore::fake::FakeWrapper;
use hardware_keystore::{BackendId, DataKey, KeyWrapper, KeystoreError, SecurityLevel};

#[test]
fn round_trips_while_available() {
    let fake = FakeWrapper::new(SecurityLevel::SecureElement);
    let key = DataKey::generate();
    let wrapped = fake.wrap(&key).unwrap();
    assert_eq!(wrapped.backend(), BackendId::Fake);
    assert!(fake.unwrap(&wrapped).unwrap() == key);
    assert_eq!(fake.security_level(), SecurityLevel::SecureElement);
}

#[test]
fn reports_unavailable_distinctly_and_recovers() {
    let fake = FakeWrapper::new(SecurityLevel::Software);
    let key = DataKey::generate();
    let wrapped = fake.wrap(&key).unwrap();

    fake.set_available(false);
    assert!(matches!(
        fake.unwrap(&wrapped),
        Err(KeystoreError::Unavailable(_))
    ));
    assert!(matches!(
        fake.wrap(&key),
        Err(KeystoreError::Unavailable(_))
    ));

    fake.set_available(true);
    assert!(fake.unwrap(&wrapped).unwrap() == key);
}

#[test]
fn another_fakes_record_does_not_open() {
    let wrapped = FakeWrapper::new(SecurityLevel::Software)
        .wrap(&DataKey::generate())
        .unwrap();
    assert_eq!(
        FakeWrapper::new(SecurityLevel::Software)
            .unwrap(&wrapped)
            .err(),
        Some(KeystoreError::WrongKeyOrTampered)
    );
}
