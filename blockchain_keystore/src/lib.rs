//! Wrap and unwrap a 32-byte data key.
//!
//! A caller that encrypts something (a state file, a directory of key files)
//! does it under a random [`DataKey`], and keeps the data key only in wrapped
//! form, encrypted under something the user or the platform holds. This crate
//! is that wrapping step, behind one interface, [`KeyWrapper`], so the same
//! code works whether the wrapping key comes from a password, from a secret a
//! platform store hands over, or (in later versions) from a key that never
//! leaves platform hardware.
//!
//! - [`software::SoftwareWrapper`]: Argon2id over a password. The fallback where
//!   no platform key exists.
//! - [`secret::SecretWrapper`]: a 32-byte secret the caller supplies, for a key
//!   held by a platform store this crate can't call directly, such as an iOS
//!   Keychain item read by native code and passed in through a binding.
//! - `fake::FakeWrapper` (with the `test-support` feature): an in-memory
//!   wrapper for consumers' unit tests.
//!
//! Every wrapping is a [`WrappedKey`]: a small versioned record that names the
//! backend that made it and carries that backend's parameters, so later
//! backends can be added without migrating existing records.

#![warn(missing_docs)]

pub mod data_key;
pub mod error;
#[cfg(feature = "test-support")]
pub mod fake;
pub mod record;
pub mod secret;
pub mod software;
pub mod wrapper;

mod aead;

pub use data_key::{DATA_KEY_LEN, DataKey};
pub use error::KeystoreError;
pub use record::{BackendId, RECORD_VERSION, WrappedKey};
pub use wrapper::{KeyWrapper, SecurityLevel};
