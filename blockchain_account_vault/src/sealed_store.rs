//! A payload sealed under one data key, with that key wrapped once per slot.
//!
//! Each slot is a [`blockchain_keystore::KeyWrapper`] wrapping of the data key
//! with a label, so a password, a key held by the platform and a recovery
//! secret are all just slots. Any one slot opens the payload. Adding or
//! removing a slot needs the data key (an opened store), and never re-encrypts
//! the payload.
//!
//! Two keys are derived from the data key with HKDF-SHA256: one encrypts the
//! payload with AES-256-GCM, the other computes an HMAC-SHA256 over the header
//! (the version and every slot). Without the data key, no one can add, remove,
//! reorder or swap in a slot, because the header MAC no longer verifies.
//!
//! Layout, all integers little-endian:
//!
//! ```text
//! version (1) | slot count (1) | slots | header MAC (32) | nonce (12) | ciphertext (payload + 16 tag)
//! slot: label length (1) | label (UTF-8) | record length (2) | blockchain_keystore record
//! ```

use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use blockchain_keystore::{BackendId, DataKey, KeyWrapper, KeystoreError, WrappedKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

/// The format version this module writes and reads.
pub const SEALED_STORE_VERSION: u8 = 1;
/// The most slots a store may have.
pub const MAX_SLOTS: usize = 255;
/// The longest slot label, in bytes.
pub const MAX_LABEL_LEN: usize = 255;

const MAC_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const PAYLOAD_KEY_INFO: &[u8] = b"blockchain_account_vault sealed_store payload v1";
const HEADER_KEY_INFO: &[u8] = b"blockchain_account_vault sealed_store header v1";
/// The payload's associated data: binds the ciphertext to this format.
const PAYLOAD_AAD: &[u8] = b"blockchain_account_vault sealed_store v1";

/// What can go wrong sealing, opening or changing a sealed store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedStoreError {
    /// A slot's wrapper failed. [`KeystoreError::Unavailable`] here means the
    /// slot's key can't be used now, and opening may succeed later.
    Keystore(KeystoreError),
    /// No slot has this label.
    NoSuchSlot(String),
    /// A slot with this label already exists.
    DuplicateSlot(String),
    /// The label is empty or longer than [`MAX_LABEL_LEN`] bytes.
    InvalidLabel(String),
    /// Removing the slot would leave the store with no way to open it.
    LastSlot,
    /// The store would have more than [`MAX_SLOTS`] slots.
    TooManySlots,
    /// None of the slots made by the given wrapper's backend opened.
    NoSlotOpened,
    /// The data key is wrong for this store, or the header or payload has been
    /// changed.
    Tampered,
    /// The store was written in a format version this module doesn't read.
    UnsupportedVersion(u8),
    /// The bytes aren't a well-formed store.
    Malformed(String),
}

impl fmt::Display for SealedStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealedStoreError::Keystore(e) => write!(f, "{e}"),
            SealedStoreError::NoSuchSlot(label) => write!(f, "no slot labelled '{label}'"),
            SealedStoreError::DuplicateSlot(label) => {
                write!(f, "a slot labelled '{label}' already exists")
            }
            SealedStoreError::InvalidLabel(label) => {
                write!(f, "slot label '{label}' must be 1 to {MAX_LABEL_LEN} bytes")
            }
            SealedStoreError::LastSlot => write!(f, "can't remove the last slot"),
            SealedStoreError::TooManySlots => write!(f, "a store holds at most {MAX_SLOTS} slots"),
            SealedStoreError::NoSlotOpened => write!(f, "no slot opened with this key"),
            SealedStoreError::Tampered => write!(
                f,
                "the sealed store did not verify (wrong data key, or it was changed)"
            ),
            SealedStoreError::UnsupportedVersion(v) => {
                write!(f, "unsupported sealed store version {v}")
            }
            SealedStoreError::Malformed(reason) => write!(f, "malformed sealed store: {reason}"),
        }
    }
}

impl std::error::Error for SealedStoreError {}

impl From<KeystoreError> for SealedStoreError {
    fn from(e: KeystoreError) -> Self {
        SealedStoreError::Keystore(e)
    }
}

/// One way to open a store: a label and the data key wrapped by one backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    label: String,
    wrapped: WrappedKey,
}

impl Slot {
    /// The slot's label, such as `"password"`, `"device"` or `"recovery"`.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The backend that wrapped this slot's copy of the data key.
    pub fn backend(&self) -> BackendId {
        self.wrapped.backend()
    }
}

/// A store's payload and data key, after opening it.
pub struct Opened {
    /// The data key: keep it to reseal, or to add or remove slots.
    pub data_key: DataKey,
    /// The decrypted payload, cleared from memory when dropped.
    pub payload: Zeroizing<Vec<u8>>,
}

/// A payload sealed under a data key that one or more slots wrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedStore {
    slots: Vec<Slot>,
    mac: [u8; MAC_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl SealedStore {
    /// Seals `payload` under a new random data key, wrapped by each of `slots`
    /// (label and wrapper). Returns the store and the data key.
    pub fn seal(
        payload: &[u8],
        slots: &[(&str, &dyn KeyWrapper)],
    ) -> Result<(SealedStore, DataKey), SealedStoreError> {
        if slots.is_empty() {
            return Err(SealedStoreError::LastSlot);
        }
        if slots.len() > MAX_SLOTS {
            return Err(SealedStoreError::TooManySlots);
        }
        let data_key = DataKey::generate();
        let mut wrapped = Vec::with_capacity(slots.len());
        for (label, wrapper) in slots {
            check_label(label)?;
            if wrapped.iter().any(|s: &Slot| s.label == *label) {
                return Err(SealedStoreError::DuplicateSlot(label.to_string()));
            }
            wrapped.push(Slot {
                label: label.to_string(),
                wrapped: wrapper.wrap(&data_key)?,
            });
        }
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let store = Self::assemble(&data_key, wrapped, payload, nonce)?;
        Ok((store, data_key))
    }

    /// Opens the store with the slot labelled `label`, using `wrapper`.
    pub fn open(&self, label: &str, wrapper: &dyn KeyWrapper) -> Result<Opened, SealedStoreError> {
        let slot = self
            .slots
            .iter()
            .find(|s| s.label == label)
            .ok_or_else(|| SealedStoreError::NoSuchSlot(label.to_string()))?;
        let data_key = wrapper.unwrap(&slot.wrapped)?;
        let payload = self.decrypt(&data_key)?;
        Ok(Opened { data_key, payload })
    }

    /// Opens the store with whichever slot made by `wrapper`'s backend opens,
    /// trying them in order. Returns that slot's label with the opened store.
    ///
    /// A slot that reports [`KeystoreError::Unavailable`] stops the search and
    /// returns that error, so a caller can wait and retry; a slot that doesn't
    /// open with this wrapper is skipped.
    pub fn open_any(&self, wrapper: &dyn KeyWrapper) -> Result<(String, Opened), SealedStoreError> {
        for slot in self
            .slots
            .iter()
            .filter(|s| s.backend() == wrapper.backend())
        {
            match wrapper.unwrap(&slot.wrapped) {
                Ok(data_key) => {
                    let payload = self.decrypt(&data_key)?;
                    return Ok((slot.label.clone(), Opened { data_key, payload }));
                }
                Err(KeystoreError::WrongKeyOrTampered) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(SealedStoreError::NoSlotOpened)
    }

    /// Seals a new `payload` under the same data key and slots, with a fresh
    /// nonce: what a caller does on every save. `data_key` must be this store's.
    pub fn reseal(
        &self,
        data_key: &DataKey,
        payload: &[u8],
    ) -> Result<SealedStore, SealedStoreError> {
        self.verify_header(data_key)?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Self::assemble(data_key, self.slots.clone(), payload, nonce)
    }

    /// Adds a slot labelled `label` that `wrapper` opens. The payload
    /// ciphertext is unchanged. `data_key` must be this store's.
    pub fn add_slot(
        &mut self,
        data_key: &DataKey,
        label: &str,
        wrapper: &dyn KeyWrapper,
    ) -> Result<(), SealedStoreError> {
        self.verify_header(data_key)?;
        check_label(label)?;
        if self.slots.iter().any(|s| s.label == label) {
            return Err(SealedStoreError::DuplicateSlot(label.to_string()));
        }
        if self.slots.len() >= MAX_SLOTS {
            return Err(SealedStoreError::TooManySlots);
        }
        self.slots.push(Slot {
            label: label.to_string(),
            wrapped: wrapper.wrap(data_key)?,
        });
        self.mac = header_mac(data_key, &encode_header(&self.slots)?)?;
        Ok(())
    }

    /// Removes the slot labelled `label`. The payload ciphertext is unchanged.
    /// `data_key` must be this store's, and the last slot can't be removed.
    pub fn remove_slot(&mut self, data_key: &DataKey, label: &str) -> Result<(), SealedStoreError> {
        self.verify_header(data_key)?;
        let index = self
            .slots
            .iter()
            .position(|s| s.label == label)
            .ok_or_else(|| SealedStoreError::NoSuchSlot(label.to_string()))?;
        if self.slots.len() == 1 {
            return Err(SealedStoreError::LastSlot);
        }
        self.slots.remove(index);
        self.mac = header_mac(data_key, &encode_header(&self.slots)?)?;
        Ok(())
    }

    /// The slots, in order.
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// The payload ciphertext with its tag, for callers that check it is
    /// unchanged by a slot change.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The store as bytes, to write to disk.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SealedStoreError> {
        let mut out = encode_header(&self.slots)?;
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Parses stored bytes. This checks the layout only; the header MAC is
    /// checked when the store is opened.
    pub fn from_bytes(bytes: &[u8]) -> Result<SealedStore, SealedStoreError> {
        let mut reader = Reader { bytes, at: 0 };
        let version = reader.byte()?;
        if version != SEALED_STORE_VERSION {
            return Err(SealedStoreError::UnsupportedVersion(version));
        }
        let count = reader.byte()? as usize;
        if count == 0 {
            return Err(SealedStoreError::Malformed("no slots".into()));
        }
        let mut slots: Vec<Slot> = Vec::with_capacity(count);
        for _ in 0..count {
            let label_len = reader.byte()? as usize;
            let label = std::str::from_utf8(reader.take(label_len)?)
                .map_err(|_| SealedStoreError::Malformed("slot label is not UTF-8".into()))?
                .to_string();
            check_label(&label)
                .map_err(|_| SealedStoreError::Malformed("empty slot label".into()))?;
            if slots.iter().any(|s| s.label == label) {
                return Err(SealedStoreError::Malformed(format!(
                    "duplicate slot '{label}'"
                )));
            }
            let record_len = u16::from_le_bytes(reader.array::<2>()?) as usize;
            let wrapped = WrappedKey::from_bytes(reader.take(record_len)?)?;
            slots.push(Slot { label, wrapped });
        }
        let mac = reader.array::<MAC_LEN>()?;
        let nonce = reader.array::<NONCE_LEN>()?;
        let ciphertext = reader.rest();
        if ciphertext.len() < TAG_LEN {
            return Err(SealedStoreError::Malformed("ciphertext too short".into()));
        }
        Ok(SealedStore {
            slots,
            mac,
            nonce,
            ciphertext: ciphertext.to_vec(),
        })
    }

    fn assemble(
        data_key: &DataKey,
        slots: Vec<Slot>,
        payload: &[u8],
        nonce: [u8; NONCE_LEN],
    ) -> Result<SealedStore, SealedStoreError> {
        let mac = header_mac(data_key, &encode_header(&slots)?)?;
        let cipher = payload_cipher(data_key)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: payload,
                    aad: PAYLOAD_AAD,
                },
            )
            .map_err(|e| SealedStoreError::Malformed(format!("AES-256-GCM encryption: {e}")))?;
        Ok(SealedStore {
            slots,
            mac,
            nonce,
            ciphertext,
        })
    }

    fn verify_header(&self, data_key: &DataKey) -> Result<(), SealedStoreError> {
        let mut mac = header_hmac(data_key)?;
        mac.update(&encode_header(&self.slots)?);
        mac.verify_slice(&self.mac)
            .map_err(|_| SealedStoreError::Tampered)
    }

    fn decrypt(&self, data_key: &DataKey) -> Result<Zeroizing<Vec<u8>>, SealedStoreError> {
        self.verify_header(data_key)?;
        let cipher = payload_cipher(data_key)?;
        cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: PAYLOAD_AAD,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| SealedStoreError::Tampered)
    }
}

fn check_label(label: &str) -> Result<(), SealedStoreError> {
    if label.is_empty() || label.len() > MAX_LABEL_LEN {
        return Err(SealedStoreError::InvalidLabel(label.to_string()));
    }
    Ok(())
}

fn encode_header(slots: &[Slot]) -> Result<Vec<u8>, SealedStoreError> {
    let count = u8::try_from(slots.len()).map_err(|_| SealedStoreError::TooManySlots)?;
    let mut out = vec![SEALED_STORE_VERSION, count];
    for slot in slots {
        let record = slot.wrapped.to_bytes()?;
        let record_len = u16::try_from(record.len())
            .map_err(|_| SealedStoreError::Malformed("slot record too long".into()))?;
        out.push(slot.label.len() as u8);
        out.extend_from_slice(slot.label.as_bytes());
        out.extend_from_slice(&record_len.to_le_bytes());
        out.extend_from_slice(&record);
    }
    Ok(out)
}

fn derive(data_key: &DataKey, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, data_key.as_bytes())
        .expand(info, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn payload_cipher(data_key: &DataKey) -> Result<Aes256Gcm, SealedStoreError> {
    Aes256Gcm::new_from_slice(derive(data_key, PAYLOAD_KEY_INFO).as_ref())
        .map_err(|e| SealedStoreError::Malformed(format!("AES-256-GCM key: {e}")))
}

fn header_hmac(data_key: &DataKey) -> Result<Hmac<Sha256>, SealedStoreError> {
    <Hmac<Sha256> as Mac>::new_from_slice(derive(data_key, HEADER_KEY_INFO).as_ref())
        .map_err(|e| SealedStoreError::Malformed(format!("HMAC key: {e}")))
}

fn header_mac(data_key: &DataKey, header: &[u8]) -> Result<[u8; MAC_LEN], SealedStoreError> {
    let mut mac = header_hmac(data_key)?;
    mac.update(header);
    Ok(mac.finalize().into_bytes().into())
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], SealedStoreError> {
        let end = self
            .at
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| SealedStoreError::Malformed("truncated".into()))?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, SealedStoreError> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SealedStoreError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn rest(&mut self) -> &'a [u8] {
        let slice = &self.bytes[self.at..];
        self.at = self.bytes.len();
        slice
    }
}
