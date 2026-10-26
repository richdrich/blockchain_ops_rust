//! Shared fixtures for the vault and command-line tests.

use std::path::Path;
use std::sync::Once;

use blockchain_account_vault::envelope::FAST_KDF_ENV;

static FAST_KDF: Once = Once::new();

/// Select the reduced key-derivation cost, so tests that seal many files stay fast. Written once,
/// before any key derivation in this process reads it.
pub fn fast_kdf() {
    FAST_KDF.call_once(|| unsafe { std::env::set_var(FAST_KDF_ENV, "1") });
}

pub const PASSWORD: &str = "correct horse battery staple";

/// An account key file's two fields. The passphrase is the valid 25 words of an all-zero key; the
/// address is a label here, since nothing in this crate derives one.
pub const ADDRESS: &str = "VCMJKWOY5P5P7SKMZFFOCEROPJCZOTIJMNIYNUCKH7LRO45JMJP6UYBIJA";
pub const PASSPHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";

/// An account key file's contents.
pub fn account_json() -> String {
    format!(r#"{{"address": "{ADDRESS}", "passphrase": "{PASSPHRASE}"}}"#)
}

/// A bare seed as a node writes it: base64 of 32 bytes and a newline.
pub const SEED_FILE: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n";

pub fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}
