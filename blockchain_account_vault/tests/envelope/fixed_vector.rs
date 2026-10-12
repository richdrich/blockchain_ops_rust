//! A fixed vector for the on-disk formats. The envelope and the blob below were written once and
//! are never regenerated: if a change to `blockchain_account_vault::envelope` stops them opening, it has broken
//! every key file already sealed, by this crate or by `bingle_admin`, which writes the same formats.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use blockchain_account_vault::envelope::{decrypt_bytes, decrypt_secret, is_encrypted_envelope};

use crate::support::{PASSWORD, account_json};

const ENVELOPE: &str = r#"{
  "bingle_encrypted": 1,
  "ciphertext": "yN2fj0XqZ7vV0mco7l8qaxy5ugnudaU5NM4wCxKe6MxEVDm4/f+1GX7eJZop+g7HDh43Vshc24SGIDqQaM70vfN1TGAItu49giFdN+nrW7E5MblGhiP2RoMdlcm2KDMvxTa+cUqXRf3uKTrwwLmYFFiJJ+guFdlb95zy/Q2DonFhzBbYOUQrffuWjXcNgCYtid5BgeU36A6rWploXAqSP+lUBy4PHOxqrdvSv+e8dZ17tK1FsTno0wM6ik2SO8nDbeELNnFYhdn8iVzC5NbNvmcAfRVwyZaONtPsdAoyyXYhyhl5vxT0KVSi9vwqPce7pifDJfETHvdnr8oiKeTRrFTdln/rh7+nLmrg1pEUrNVDVIu02XELlGvGVEOOW6Yt4Ij+zEn6vhoDncc894LXFxo=",
  "kdf": "argon2id",
  "m": 8,
  "nonce": "pV3OwS2JA1Lyloxw",
  "p": 1,
  "salt": "Jg3g7FKg6GWNERGB3nofVw==",
  "t": 1
}"#;

const SECRET_BLOB: &str = "AQgAAAABAVvzMvK935XcqofjvCPMYigw+7GXIC9iTztVUlwBwmClDdTTcL85YuDx2Y/LD4ovdaZ/qJZ/eroIhkJkB9LKpzBuEyAIHMFDtiuP81A=";

#[test]
fn a_stored_envelope_still_opens() {
    assert!(is_encrypted_envelope(ENVELOPE.as_bytes()));
    let plaintext = decrypt_bytes(ENVELOPE.as_bytes(), PASSWORD).unwrap();
    assert_eq!(plaintext, account_json().as_bytes());
}

#[test]
fn a_stored_envelope_refuses_another_password() {
    assert!(decrypt_bytes(ENVELOPE.as_bytes(), "another password").is_err());
}

#[test]
fn a_stored_secret_blob_still_opens() {
    let blob = B64.decode(SECRET_BLOB).unwrap();
    assert_eq!(decrypt_secret(&blob, PASSWORD).unwrap(), [7u8; 32]);
}
