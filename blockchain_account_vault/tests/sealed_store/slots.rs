//! `sealed_store`: sealing, opening with each slot type, slot changes, and tampering.

use blockchain_account_vault::sealed_store::{SealedStore, SealedStoreError};
use hardware_keystore::fake::FakeWrapper;
use hardware_keystore::secret::SecretWrapper;
use hardware_keystore::software::{Argon2Cost, SoftwareWrapper};
use hardware_keystore::{DataKey, KeyWrapper, KeystoreError, SecurityLevel};

const PAYLOAD: &[u8] = b"contacts, blocks and messages";

fn password() -> SoftwareWrapper {
    SoftwareWrapper::with_cost("correct horse", Argon2Cost::INSECURE_MINIMUM)
}

fn device() -> SecretWrapper {
    SecretWrapper::new(&[0x11; 32], SecurityLevel::Software)
}

fn recovery() -> SecretWrapper {
    SecretWrapper::new(&[0x22; 32], SecurityLevel::Software)
}

fn sealed_with_password_and_device() -> (SealedStore, DataKey) {
    SealedStore::seal(PAYLOAD, &[("password", &password()), ("device", &device())]).unwrap()
}

#[test]
fn opens_with_each_slot_type() {
    let fake = FakeWrapper::new(SecurityLevel::SecureElement);
    let (store, data_key) = SealedStore::seal(
        PAYLOAD,
        &[
            ("password", &password()),
            ("device", &device()),
            ("hardware", &fake),
        ],
    )
    .unwrap();
    let bytes = store.to_bytes().unwrap();
    let store = SealedStore::from_bytes(&bytes).unwrap();

    let wrappers: [(&str, &dyn KeyWrapper); 3] = [
        ("password", &password()),
        ("device", &device()),
        ("hardware", &fake),
    ];
    for (label, wrapper) in wrappers {
        let opened = store.open(label, wrapper).unwrap();
        assert_eq!(opened.payload.as_slice(), PAYLOAD, "slot {label}");
        assert!(opened.data_key == data_key, "slot {label}");
    }
}

#[test]
fn open_any_finds_the_slot_for_the_wrappers_backend() {
    let (store, _) = SealedStore::seal(
        PAYLOAD,
        &[
            ("password", &password()),
            ("device", &device()),
            ("recovery", &recovery()),
        ],
    )
    .unwrap();
    let (label, opened) = store.open_any(&recovery()).unwrap();
    assert_eq!(
        label, "recovery",
        "skips the device slot, which is the same backend"
    );
    assert_eq!(opened.payload.as_slice(), PAYLOAD);
    assert_eq!(
        store
            .open_any(&SecretWrapper::new(&[0x33; 32], SecurityLevel::Software))
            .err(),
        Some(SealedStoreError::NoSlotOpened)
    );
}

#[test]
fn open_any_stops_at_an_unavailable_slot() {
    let fake = FakeWrapper::new(SecurityLevel::SecureElement);
    let (store, _) = SealedStore::seal(PAYLOAD, &[("hardware", &fake)]).unwrap();
    fake.set_available(false);
    assert!(matches!(
        store.open_any(&fake),
        Err(SealedStoreError::Keystore(KeystoreError::Unavailable(_)))
    ));
    assert!(matches!(
        store.open("hardware", &fake),
        Err(SealedStoreError::Keystore(KeystoreError::Unavailable(_)))
    ));
}

#[test]
fn wrong_key_and_unknown_label_are_reported() {
    let (store, _) = sealed_with_password_and_device();
    let wrong = SoftwareWrapper::with_cost("wrong", Argon2Cost::INSECURE_MINIMUM);
    assert_eq!(
        store.open("password", &wrong).err(),
        Some(SealedStoreError::Keystore(
            KeystoreError::WrongKeyOrTampered
        ))
    );
    assert_eq!(
        store.open("nope", &password()).err(),
        Some(SealedStoreError::NoSuchSlot("nope".into()))
    );
}

#[test]
fn adding_a_slot_keeps_the_payload_ciphertext() {
    let (mut store, data_key) = sealed_with_password_and_device();
    let before = store.ciphertext().to_vec();
    store.add_slot(&data_key, "recovery", &recovery()).unwrap();
    assert_eq!(store.ciphertext(), before.as_slice());

    let store = SealedStore::from_bytes(&store.to_bytes().unwrap()).unwrap();
    assert_eq!(
        store
            .open("recovery", &recovery())
            .unwrap()
            .payload
            .as_slice(),
        PAYLOAD
    );
    assert_eq!(
        store
            .open("password", &password())
            .unwrap()
            .payload
            .as_slice(),
        PAYLOAD
    );
}

#[test]
fn removing_a_slot_keeps_the_ciphertext_and_the_slot_no_longer_opens() {
    let (mut store, data_key) = sealed_with_password_and_device();
    let before = store.ciphertext().to_vec();
    store.remove_slot(&data_key, "password").unwrap();
    assert_eq!(store.ciphertext(), before.as_slice());

    let store = SealedStore::from_bytes(&store.to_bytes().unwrap()).unwrap();
    assert_eq!(
        store.open("password", &password()).err(),
        Some(SealedStoreError::NoSuchSlot("password".into()))
    );
    assert_eq!(
        store.open_any(&password()).err(),
        Some(SealedStoreError::NoSlotOpened)
    );
    assert_eq!(
        store.open("device", &device()).unwrap().payload.as_slice(),
        PAYLOAD
    );
}

#[test]
fn slot_changes_need_the_right_data_key() {
    let (mut store, _) = sealed_with_password_and_device();
    let other = DataKey::generate();
    assert_eq!(
        store.add_slot(&other, "recovery", &recovery()).err(),
        Some(SealedStoreError::Tampered)
    );
    assert_eq!(
        store.remove_slot(&other, "device").err(),
        Some(SealedStoreError::Tampered)
    );
    assert_eq!(
        store.reseal(&other, b"new").err(),
        Some(SealedStoreError::Tampered)
    );
}

#[test]
fn slot_rules_are_enforced() {
    let (mut store, data_key) = SealedStore::seal(PAYLOAD, &[("device", &device())]).unwrap();
    assert_eq!(
        store.remove_slot(&data_key, "device").err(),
        Some(SealedStoreError::LastSlot)
    );
    assert_eq!(
        store.add_slot(&data_key, "device", &recovery()).err(),
        Some(SealedStoreError::DuplicateSlot("device".into()))
    );
    assert_eq!(
        store.add_slot(&data_key, "", &recovery()).err(),
        Some(SealedStoreError::InvalidLabel(String::new()))
    );
    assert_eq!(
        SealedStore::seal(PAYLOAD, &[("a", &device()), ("a", &recovery())])
            .err()
            .map(|e| e.to_string()),
        Some(SealedStoreError::DuplicateSlot("a".into()).to_string())
    );
    assert_eq!(
        SealedStore::seal(PAYLOAD, &[]).err().map(|e| e.to_string()),
        Some(SealedStoreError::LastSlot.to_string())
    );
}

#[test]
fn reseal_keeps_the_slots_and_changes_the_payload() {
    let (store, data_key) = sealed_with_password_and_device();
    let resealed = store.reseal(&data_key, b"newer state").unwrap();
    assert_eq!(resealed.slots(), store.slots());
    assert_ne!(resealed.ciphertext(), store.ciphertext());
    assert_eq!(
        resealed
            .open("device", &device())
            .unwrap()
            .payload
            .as_slice(),
        b"newer state"
    );
}

#[test]
fn tampering_is_rejected() {
    let (store, _) = sealed_with_password_and_device();
    let bytes = store.to_bytes().unwrap();

    // the last byte is in the payload tag.
    let mut payload = bytes.clone();
    let last = payload.len() - 1;
    payload[last] ^= 1;
    let edited = SealedStore::from_bytes(&payload).unwrap();
    assert_eq!(
        edited.open("device", &device()).err(),
        Some(SealedStoreError::Tampered)
    );

    // the first slot's label: "password" becomes "passwore".
    let mut label = bytes.clone();
    label[2 + 8] ^= 1;
    let edited = SealedStore::from_bytes(&label).unwrap();
    assert_eq!(
        edited.open("device", &device()).err(),
        Some(SealedStoreError::Tampered)
    );
}

#[test]
fn a_slot_swapped_in_from_another_store_is_rejected() {
    // two stores whose "device" slot opens with the same wrapper, but wraps different data keys.
    let (mine, _) =
        SealedStore::seal(PAYLOAD, &[("password", &password()), ("device", &device())]).unwrap();
    let (theirs, _) = SealedStore::seal(
        b"other",
        &[("password", &password()), ("device", &device())],
    )
    .unwrap();
    let mine_bytes = mine.to_bytes().unwrap();
    let theirs_bytes = theirs.to_bytes().unwrap();

    // header: version (1), count (1), then each slot: label length (1), label, record length (2),
    // record. Both stores have the same slot lengths, so the device slot is at the same range.
    let password_record_len = record_len_at(&mine_bytes, 2 + 1 + 8);
    let device_start = 2 + 1 + 8 + 2 + password_record_len;
    let device_record_len = record_len_at(&mine_bytes, device_start + 1 + 6);
    let device_end = device_start + 1 + 6 + 2 + device_record_len;
    let mut swapped = mine_bytes.clone();
    swapped[device_start..device_end].copy_from_slice(&theirs_bytes[device_start..device_end]);

    let edited = SealedStore::from_bytes(&swapped).unwrap();
    assert_eq!(
        edited.open("device", &device()).err(),
        Some(SealedStoreError::Tampered)
    );
    assert_eq!(
        edited.open("password", &password()).err(),
        Some(SealedStoreError::Tampered)
    );
}

fn record_len_at(bytes: &[u8], at: usize) -> usize {
    u16::from_le_bytes([bytes[at], bytes[at + 1]]) as usize
}

#[test]
fn malformed_bytes_are_rejected() {
    let (store, _) = sealed_with_password_and_device();
    let bytes = store.to_bytes().unwrap();
    let mut version = bytes.clone();
    version[0] = 9;
    assert_eq!(
        SealedStore::from_bytes(&version).err(),
        Some(SealedStoreError::UnsupportedVersion(9))
    );
    assert!(matches!(
        SealedStore::from_bytes(&bytes[..20]),
        Err(SealedStoreError::Malformed(_))
    ));
    let mut no_slots = bytes.clone();
    no_slots[1] = 0;
    assert!(matches!(
        SealedStore::from_bytes(&no_slots),
        Err(SealedStoreError::Malformed(_))
    ));
}
