//! Key files sealed under a password, and their paper backups.
//!
//! A project that signs for Algorand accounts ends up with key files on disk: an
//! account as `{"address", "passphrase"}` JSON, or a bare seed. This crate keeps
//! them encrypted between uses and prints a backup sheet for each.
//!
//! - [`account`]: new Algorand accounts, optionally with a chosen address
//!   prefix.
//! - [`envelope`]: the encryption. Argon2id stretches the password into a key,
//!   and AES-256-GCM encrypts and authenticates the file under it.
//! - [`account_dir`]: reads named accounts from a directory, sealed or not,
//!   asking for the password at most once.
//! - [`vault`]: finds the key files in a directory, seals them, opens one, and
//!   builds its backup page.
//! - [`mnemonic`]: writes any bytes as Algorand-style words.
//! - [`pdf`]: renders the backup pages.
//!
//! The `blockchain-account-vault` tool drives these from the command line. The file formats
//! are the ones `bingle_admin` writes, so the two are interchangeable.

pub mod account;
pub mod account_dir;
pub mod envelope;
pub mod mnemonic;
pub mod pdf;
pub mod vault;
