//! Reading account files that may be stored as plaintext `NAME.json` or as an
//! encrypted `NAME.json.enc` envelope.
//!
//! A single [`AccountDir`] is used per command invocation so that the password
//! for encrypted files is requested at most once and reused for every subsequent
//! encrypted file in the same directory.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use crate::envelope::{decrypt_bytes, is_encrypted_envelope};

/// A directory of per-role account files, with a cached password for any
/// encrypted entries.
pub struct AccountDir {
    dir: PathBuf,
    cached_password: Option<String>,
}

impl AccountDir {
    /// Create a reader for `dir`. No password is requested until an encrypted
    /// file is actually read.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            cached_password: None,
        }
    }

    /// Seed the cached password (e.g. from an earlier read in the same run) so
    /// the first encrypted read does not have to prompt.
    pub fn with_cached_password(mut self, password: Option<String>) -> Self {
        self.cached_password = password;
        self
    }

    /// The password that has successfully decrypted a file so far, if any.
    pub fn cached_password(&self) -> Option<&str> {
        self.cached_password.as_deref()
    }

    fn plaintext_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.json"))
    }

    fn enc_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.json.enc"))
    }

    /// True if either a plaintext or encrypted file exists for `name`.
    pub fn exists(&self, name: &str) -> bool {
        self.plaintext_path(name).exists() || self.enc_path(name).exists()
    }

    /// True if the account for `name` is stored only as an encrypted envelope.
    pub fn is_encrypted(&self, name: &str) -> bool {
        !self.plaintext_path(name).exists() && self.enc_path(name).exists()
    }

    /// Discover all account names in the directory, taken from `NAME.json` and
    /// `NAME.json.enc` files. Returned sorted and de-duplicated (a name present
    /// as both plaintext and encrypted appears once).
    pub fn discover_names(&self) -> Result<Vec<String>> {
        let mut names = std::collections::BTreeSet::new();
        let entries = std::fs::read_dir(&self.dir)
            .with_context(|| format!("failed to read accounts directory {:?}", self.dir))?;
        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            if let Some(stem) = name.strip_suffix(".json.enc") {
                names.insert(stem.to_string());
            } else if let Some(stem) = name.strip_suffix(".json") {
                names.insert(stem.to_string());
            }
        }
        Ok(names.into_iter().collect())
    }

    /// Read `name`'s account file, returning its decrypted JSON bytes.
    ///
    /// A plaintext `NAME.json` is returned as-is (unless it actually holds an
    /// envelope, in which case it is decrypted); otherwise `NAME.json.enc` is
    /// decrypted. When decryption is required the cached password is tried first,
    /// and only if it is absent or wrong is `prompt` invoked. A password that
    /// successfully decrypts is cached for subsequent reads.
    pub fn read_bytes<F>(&mut self, name: &str, prompt: F) -> Result<Vec<u8>>
    where
        F: FnMut() -> Result<String>,
    {
        let plaintext = self.plaintext_path(name);
        if plaintext.exists() {
            let bytes = std::fs::read(&plaintext)
                .with_context(|| format!("failed to read {plaintext:?}"))?;
            if is_encrypted_envelope(&bytes) {
                return self.decrypt(name, &bytes, prompt);
            }
            return Ok(bytes);
        }

        let enc = self.enc_path(name);
        if enc.exists() {
            let bytes = std::fs::read(&enc).with_context(|| format!("failed to read {enc:?}"))?;
            return self.decrypt(name, &bytes, prompt);
        }

        bail!(
            "no account file for '{name}' in {:?} (looked for {name}.json and {name}.json.enc)",
            self.dir
        )
    }

    fn decrypt<F>(&mut self, name: &str, envelope: &[u8], mut prompt: F) -> Result<Vec<u8>>
    where
        F: FnMut() -> Result<String>,
    {
        if let Some(pw) = self.cached_password.as_deref() {
            if let Ok(plaintext) = decrypt_bytes(envelope, pw) {
                return Ok(plaintext);
            }
        }
        let pw = prompt()?;
        let plaintext = decrypt_bytes(envelope, &pw)
            .map_err(|_| anyhow!("password did not decrypt encrypted account file for '{name}'"))?;
        self.cached_password = Some(pw);
        Ok(plaintext)
    }
}

/// Convenience: the directory a reader points at.
impl AsRef<Path> for AccountDir {
    fn as_ref(&self) -> &Path {
        &self.dir
    }
}
