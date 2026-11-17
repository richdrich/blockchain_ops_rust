# blockchain_keystore

Wrap and unwrap a 32-byte data key under a password, a secret the caller supplies, or (in later versions) a key held by platform hardware.

Something encrypted at rest (a state file, a directory of key files) is encrypted under a random data key. The data key is kept only in wrapped form, encrypted under something the user or the platform holds. This crate is that wrapping step, behind one interface, so the code that stores the data doesn't care where the wrapping key lives.

## The interface

```rust
pub trait KeyWrapper: Send + Sync {
    fn backend(&self) -> BackendId;
    fn security_level(&self) -> SecurityLevel;
    fn wrap(&self, key: &DataKey) -> Result<WrappedKey, KeystoreError>;
    fn unwrap(&self, wrapped: &WrappedKey) -> Result<DataKey, KeystoreError>;
}
```

- `DataKey` is 32 bytes, cleared from memory when dropped, and has no `Debug` or `Clone`.
- `SecurityLevel` says where the wrapping key is held: `Software`, `TrustedEnvironment`, `SecureElement` or `Tpm`.
- `KeystoreError::Unavailable` means "not now" (for example, the device is locked or the user cancelled a prompt) and is worth retrying. `KeystoreError::WrongKeyOrTampered` means the record won't open with this key, and isn't.

## Backends

| Backend | Wrapping key | Use |
|---|---|---|
| `software::SoftwareWrapper` | Argon2id over a password (default 64 MiB, 3 passes, 1 lane, the same as `blockchain_account_vault`'s envelope) | where no platform key exists |
| `secret::SecretWrapper` | HKDF-SHA256 over a 32-byte secret the caller supplies | a key held by a platform store this crate can't call directly, such as an iOS Keychain item read by native code and passed in through a binding |
| `fake::FakeWrapper` (feature `test-support`) | a random in-memory key, with a switch to report `Unavailable` | consumers' unit tests only |

Backends that keep the wrapping key in platform hardware (macOS Secure Enclave, Windows Hello, a Linux Trusted Platform Module (TPM)), and signing and key agreement, come in later versions; the investigation is issue #141 in this repository.

## The record

`WrappedKey::to_bytes` and `WrappedKey::from_bytes` give the stored form. All integers are little-endian:

```text
version (1) | backend (1) | params length (2) | params | nonce (12) | ciphertext (32 + 16 tag)
```

- `version` is 1.
- `backend` is 1 for software, 2 for secret, 255 for the test fake.
- Software params are the Argon2 memory cost in KiB, passes and lanes (4 bytes each), then a 16-byte salt. Secret records carry no params.
- The data key is encrypted with AES-256-GCM under the derived wrapping key, with the header (version, backend, params length and params) as associated data. A record whose header has been changed, for example to a cheaper Argon2 cost, doesn't open.
- Unwrapping refuses an Argon2 cost above 2 GiB of memory, 64 passes or 16 lanes, so a crafted record can't make it allocate without bound.

Every wrap uses a fresh random nonce, and the software backend a fresh random salt. Fixed test vectors in `tests/record/fixed_vector.rs` pin the format.

## Example

```rust
use blockchain_keystore::{DataKey, KeyWrapper, WrappedKey};
use blockchain_keystore::software::SoftwareWrapper;

let wrapper = SoftwareWrapper::new("a long passphrase");
let data_key = DataKey::generate();
let stored = wrapper.wrap(&data_key)?.to_bytes()?;

let opened = wrapper.unwrap(&WrappedKey::from_bytes(&stored)?)?;
assert!(opened == data_key);
```
