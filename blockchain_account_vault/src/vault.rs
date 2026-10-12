//! Key files in a directory: finding them, sealing them, opening one, and
//! building its backup page.
//!
//! A **key file** is a `*.json` or `*.key` file. An account is
//! `{"address", "passphrase"}` JSON, whatever the extension; anything else is an
//! opaque secret, such as a bare seed. Its **sealed** form is the same name with
//! `.enc` appended, holding the [`envelope`](crate::envelope) of the original
//! bytes. A key file is named by its plaintext path throughout, whichever of the
//! two forms is on disk.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::envelope::{decrypt_bytes, encrypt_bytes, encrypt_secret, is_encrypted_envelope};
use crate::mnemonic::{bytes_to_mnemonic, mnemonic_to_bytes};
use crate::pdf::BackupPage;

/// Appended to a key file's name to give its sealed form.
pub const SEALED_SUFFIX: &str = ".enc";

/// The extensions that mark a file as a key file.
const KEY_FILE_EXTENSIONS: [&str; 2] = ["json", "key"];

/// The largest opaque secret a backup page can carry. Sealed, a secret of this
/// size fills the page's mnemonic area.
pub const MAX_PRINTABLE_SECRET_LEN: usize = 96;

/// An Algorand private key is 32 bytes, which is 25 mnemonic words.
const ACCOUNT_KEY_LEN: usize = 32;

/// One key file, named by its plaintext path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyFile {
    plain: PathBuf,
}

impl KeyFile {
    /// The key file at `path`, which may be given in either form: `x.key` and
    /// `x.key.enc` name the same key file.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = path.into();
        let plain = match path.to_str().and_then(|p| p.strip_suffix(SEALED_SUFFIX)) {
            Some(stripped) => PathBuf::from(stripped),
            None => path,
        };
        Self { plain }
    }

    /// Where the plaintext form is, or would be.
    pub fn plain_path(&self) -> &Path {
        &self.plain
    }

    /// Where the sealed form is, or would be.
    pub fn sealed_path(&self) -> PathBuf {
        let mut name = self.plain.clone().into_os_string();
        name.push(SEALED_SUFFIX);
        PathBuf::from(name)
    }

    /// True if the key file is on disk in either form.
    pub fn exists(&self) -> bool {
        self.plain.exists() || self.sealed_path().exists()
    }

    /// True if only the sealed form is on disk.
    pub fn is_sealed(&self) -> bool {
        !self.plain.exists() && self.sealed_path().exists()
    }

    /// The name a backup page carries: the path beneath `root` without its
    /// extension, so `APP_ADMIN.json` is `APP_ADMIN` and `node-0/account.key`
    /// is `node-0/account`.
    pub fn name_under(&self, root: &Path) -> String {
        let relative = self.plain.strip_prefix(root).unwrap_or(&self.plain);
        relative
            .with_extension("")
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    }
}

/// Whether a file name is a key file's, in either form.
fn is_key_file_name(name: &str) -> bool {
    let plain = name.strip_suffix(SEALED_SUFFIX).unwrap_or(name);
    Path::new(plain)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| KEY_FILE_EXTENSIONS.contains(&extension))
}

/// Find the key files in `dir`, and in the directories beneath it when
/// `recursive`. Sorted, and a key file on disk in both forms appears once.
pub fn discover(dir: &Path, recursive: bool) -> Result<Vec<KeyFile>> {
    let mut found = BTreeSet::new();
    collect(dir, recursive, &mut found)?;
    Ok(found.into_iter().collect())
}

fn collect(dir: &Path, recursive: bool, found: &mut BTreeSet<KeyFile>) -> Result<()> {
    let entries =
        std::fs::read_dir(dir).with_context(|| format!("failed to read directory {dir:?}"))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                collect(&path, recursive, found)?;
            }
        } else if is_key_file_name(&entry.file_name().to_string_lossy()) {
            found.insert(KeyFile::at(path));
        }
    }
    Ok(())
}

/// What [`Vault::open`] read.
pub struct Opened {
    /// the key file's plaintext bytes.
    pub bytes: Vec<u8>,
    /// whether they had to be decrypted.
    pub was_sealed: bool,
}

/// Opens and seals key files under one password, which is asked for at most
/// once and then reused for every later file.
pub struct Vault {
    password: Option<String>,
}

impl Vault {
    /// A vault that does not know its password yet. Opening a sealed file asks
    /// for it.
    pub fn new() -> Self {
        Self { password: None }
    }

    /// A vault that already holds its password, for sealing.
    pub fn with_password(password: String) -> Self {
        Self {
            password: Some(password),
        }
    }

    /// The password that has opened a file so far, or that the vault was given.
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Read a key file's plaintext, decrypting it if it is sealed. `prompt` is
    /// called only if a password is needed and the vault's one is absent or
    /// does not open the file. Nothing is written to disk.
    pub fn open<F>(&mut self, file: &KeyFile, prompt: F) -> Result<Opened>
    where
        F: FnMut() -> Result<String>,
    {
        let plain = file.plain_path();
        if plain.exists() {
            let bytes =
                std::fs::read(plain).with_context(|| format!("failed to read {plain:?}"))?;
            // a plaintext name may still hold an envelope; treat it as sealed.
            if is_encrypted_envelope(&bytes) {
                return self.decrypt(plain, &bytes, prompt);
            }
            return Ok(Opened {
                bytes,
                was_sealed: false,
            });
        }
        let sealed = file.sealed_path();
        if sealed.exists() {
            let bytes =
                std::fs::read(&sealed).with_context(|| format!("failed to read {sealed:?}"))?;
            return self.decrypt(&sealed, &bytes, prompt);
        }
        bail!("no key file at {plain:?} (nor {sealed:?})")
    }

    fn decrypt<F>(&mut self, path: &Path, envelope: &[u8], mut prompt: F) -> Result<Opened>
    where
        F: FnMut() -> Result<String>,
    {
        if let Some(password) = self.password.as_deref() {
            if let Ok(bytes) = decrypt_bytes(envelope, password) {
                return Ok(Opened {
                    bytes,
                    was_sealed: true,
                });
            }
        }
        let password = prompt()?;
        let bytes = decrypt_bytes(envelope, &password)
            .map_err(|_| anyhow!("the password does not open {path:?}"))?;
        self.password = Some(password);
        Ok(Opened {
            bytes,
            was_sealed: true,
        })
    }

    /// Check that the vault's password opens the sealed file at `sealed`.
    pub fn check_opens(&self, sealed: &Path) -> Result<()> {
        let password = self.required_password()?;
        let envelope =
            std::fs::read(sealed).with_context(|| format!("failed to read {sealed:?}"))?;
        decrypt_bytes(&envelope, password)
            .map(|_| ())
            .map_err(|_| anyhow!("the password does not open {sealed:?}"))
    }

    /// Seal a key file under the vault's password and delete its plaintext.
    /// Returns `false` if it was sealed already.
    ///
    /// The sealed file is written beside the original, read back and decrypted,
    /// and only when that gives the original bytes is the plaintext removed.
    pub fn seal(&self, file: &KeyFile) -> Result<bool> {
        let password = self.required_password()?;
        let plain = file.plain_path();
        let sealed = file.sealed_path();
        if !plain.exists() {
            if sealed.exists() {
                return Ok(false);
            }
            bail!("no key file at {plain:?}");
        }
        if sealed.exists() {
            bail!("both {plain:?} and {sealed:?} exist; remove the one that is out of date");
        }

        let bytes = std::fs::read(plain).with_context(|| format!("failed to read {plain:?}"))?;
        // an envelope under a plaintext name only needs its sealed name.
        let envelope = if is_encrypted_envelope(&bytes) {
            decrypt_bytes(&bytes, password)
                .map_err(|_| anyhow!("the password does not open {plain:?}"))?;
            bytes
        } else {
            let envelope = encrypt_bytes(&bytes, password)?;
            let reopened = decrypt_bytes(&envelope, password)?;
            if reopened != bytes {
                bail!("sealing {plain:?} did not round-trip; it is left as it was");
            }
            envelope
        };

        write_private(&sealed, &envelope)?;
        let written =
            std::fs::read(&sealed).with_context(|| format!("failed to re-read {sealed:?}"))?;
        if written != envelope {
            // best effort: the plaintext is still there, so nothing is lost.
            let _ = std::fs::remove_file(&sealed);
            bail!("{sealed:?} did not read back as written; {plain:?} is left as it was");
        }
        std::fs::remove_file(plain).with_context(|| format!("failed to remove {plain:?}"))?;
        Ok(true)
    }

    fn required_password(&self) -> Result<&str> {
        self.password
            .as_deref()
            .ok_or_else(|| anyhow!("the vault has no password yet"))
    }
}

/// Write `bytes` to a new file that only its owner can read.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {path:?}"))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {path:?}"))?;
    file.sync_all()
        .with_context(|| format!("failed to flush {path:?}"))
}

/// The address and passphrase of an account key file, or `None` if `bytes` is
/// not one.
fn account_fields(bytes: &[u8]) -> Option<(String, String)> {
    let json: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let address = json.get("address")?.as_str()?;
    let passphrase = json.get("passphrase")?.as_str()?;
    Some((address.to_string(), passphrase.to_string()))
}

/// Read one string field of a JSON key file, such as `address` or `passphrase`.
pub fn json_field(bytes: &[u8], field: &str) -> Result<String> {
    let json: serde_json::Value =
        serde_json::from_slice(bytes).context("the key file is not JSON")?;
    json.get(field)
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("the key file has no string field '{field}'"))
}

/// Build the backup page for a key file's plaintext `bytes`.
///
/// An account's page carries its address and its 32-byte private key. Any other
/// file's page carries the file's bytes as they are. With `password` the secret
/// on the page is encrypted under it first, which is what a sealed file gets; a
/// file kept in the clear is printed in the clear.
pub fn backup_page(name: &str, bytes: &[u8], password: Option<&str>) -> Result<BackupPage> {
    let (address, secret) = match account_fields(bytes) {
        Some((address, passphrase)) => {
            let key = mnemonic_to_bytes(passphrase.trim(), ACCOUNT_KEY_LEN)
                .map_err(|e| anyhow!("invalid passphrase for '{name}': {e}"))?;
            (Some(address), key)
        }
        None => {
            if bytes.len() > MAX_PRINTABLE_SECRET_LEN {
                bail!(
                    "'{name}' is {} bytes, and a backup page holds a secret of at most {MAX_PRINTABLE_SECRET_LEN}",
                    bytes.len()
                );
            }
            (None, bytes.to_vec())
        }
    };
    let secret = match password {
        Some(password) => encrypt_secret(&secret, password)?,
        None => secret,
    };
    Ok(BackupPage {
        name: name.to_string(),
        address,
        encrypted: password.is_some(),
        secret_len: secret.len(),
        qr_payload: B64.encode(&secret),
        mnemonic: bytes_to_mnemonic(&secret),
    })
}
