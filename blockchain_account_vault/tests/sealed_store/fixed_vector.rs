//! A fixed vector for the `sealed_store` format. The store below was written once and is never
//! regenerated: if a change stops it opening, it has broken every store already written.

use blockchain_account_vault::sealed_store::SealedStore;
use hardware_keystore::SecurityLevel;
use hardware_keystore::secret::SecretWrapper;
use hardware_keystore::software::SoftwareWrapper;

const PAYLOAD: &[u8] = b"sealed_store fixed vector payload";
const SECRET: [u8; 32] = [0xa5; 32];
const PASSWORD: &str = "correct horse battery staple";

/// Sealed with a "password" slot (`SoftwareWrapper` at the Argon2 minimum cost) and a "device"
/// slot (`SecretWrapper` over `SECRET`).
const STORE: &str = "01020870617373776f72645c0001011c00080000000100000001000000ae5057b2f091f8d723e77c332b922c78e79d474f4d558451883a7b0284bb8a4ab81d9f3bd2947be66463f228a646f7427176f46cf5665ada5373b017e24dede5724ac2065f92443f588caa9d06646576696365400001020000d7851608c0d65758c95474c255c8d385267896c1ef03c0492b039bcf34c57f64d0c85ab5b59a0b0a14011e90bae0fd686dee8014862e80cf814bd392f5a75557a7214f94cefd3badf0ce6484d348e3dca7bd0f11194ce6f24bd2bde981fb7ffcc22a5dc2971ec88afa76729d7c966f6aa757e7bc4954845f0bfba45185b2791b50f0188d75f6438fed0053611e1581e3646b2c752d73ce33dd";

#[test]
fn opens_with_the_password_slot() {
    let store = SealedStore::from_bytes(&hex::decode(STORE).unwrap()).unwrap();
    let opened = store
        .open("password", &SoftwareWrapper::new(PASSWORD))
        .unwrap();
    assert_eq!(opened.payload.as_slice(), PAYLOAD);
}

#[test]
fn opens_with_the_device_slot() {
    let store = SealedStore::from_bytes(&hex::decode(STORE).unwrap()).unwrap();
    let opened = store
        .open(
            "device",
            &SecretWrapper::new(&SECRET, SecurityLevel::Software),
        )
        .unwrap();
    assert_eq!(opened.payload.as_slice(), PAYLOAD);
}

#[test]
fn round_trips_its_bytes() {
    let bytes = hex::decode(STORE).unwrap();
    assert_eq!(
        SealedStore::from_bytes(&bytes).unwrap().to_bytes().unwrap(),
        bytes
    );
}

/// Prints a new store in the vector's format. Ignored: run it by hand only to make a vector for a
/// new format version, never to replace `STORE`.
#[test]
#[ignore]
fn print_a_new_vector() {
    use hardware_keystore::software::Argon2Cost;
    let password = SoftwareWrapper::with_cost(PASSWORD, Argon2Cost::INSECURE_MINIMUM);
    let device = SecretWrapper::new(&SECRET, SecurityLevel::Software);
    let (store, _) =
        SealedStore::seal(PAYLOAD, &[("password", &password), ("device", &device)]).unwrap();
    println!("{}", hex::encode(store.to_bytes().unwrap()));
}
