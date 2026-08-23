//! Chain-agnostic blockchain operation traits.
//!
//! These traits cover the operations that read naturally on any chain, while chain-specific
//! power (application calls, asset configuration) stays on the concrete implementation and is
//! reached directly or through a native escape hatch. The Algorand implementation lives in the
//! `algo_ops` crate. See `spec/algo_ops_api_surface.md`.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Operations meaningful against any blockchain.
///
/// Amounts and balances are expressed as `f64` in units of the chain's default asset (for
/// Algorand, whole ALGO), rather than the chain's smallest indivisible unit.
pub trait BlockChainOps {
    /// Generate a new keypair, returning `(address, private-key mnemonic)`.
    fn generate_keypair() -> (String, String)
    where
        Self: Sized;

    /// Create a new address on this instance and return it.
    fn create_address(&mut self) -> Result<String>;

    /// This account's own address.
    fn address(&self) -> Result<String>;

    /// This account's public key bytes.
    fn public_key(&self) -> Result<[u8; 32]>;

    /// Export this account's private key bytes.
    fn private_key(&self) -> Result<Vec<u8>>;

    /// Sign UTF-8 text, returning a base64 signature.
    fn sign(&self, text: &str) -> Result<String>;

    /// Verify a base64 signature over UTF-8 text.
    fn verify(&self, text: &str, sig_b64: &str) -> Result<bool>;

    /// Send a native-token payment to `to`, in default-asset units.
    fn send_payment(&self, to: &str, payment_amount: f64) -> Result<()>;

    /// Balance of this account, in default-asset units.
    fn account_balance(&self) -> Result<Option<f64>>;

    /// Balance of an arbitrary account, in default-asset units.
    fn account_balance_at(&self, account: &str) -> Result<f64>;

    /// Wait for a transaction to confirm, giving up after `timeout` units (chain-defined; for
    /// Algorand, rounds).
    fn wait_for_confirmation(&self, tx_id: &str, timeout: u64) -> Result<()>;
}

/// Neutral view of a pending or confirmed transaction, returned by the [`TransactionQueryOps`]
/// reads.
///
/// Carries only plain types (no chain-SDK types on the boundary) so a consumer built against a
/// different SDK version can read a confirmation back without a version bump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedTxn {
    /// The round the transaction was confirmed in; `0` while it is still pending.
    pub confirmed_round: u64,
    /// The transaction note, decoded from its on-chain bytes; `None` if it carried no note.
    pub note: Option<Vec<u8>>,
}

/// Reads that locate a confirmed transaction and return it as a neutral [`ConfirmedTxn`].
///
/// Opt-in (like [`AssetOps`]) rather than part of [`BlockChainOps`]: while most chains carry a
/// free-form note on a transaction, *searching* for a confirmed transaction by its note needs
/// indexer-style infrastructure that not every chain provides. Implemented only by chains that
/// can serve these lookups.
pub trait TransactionQueryOps {
    /// Look up a transaction by its id, returning `None` when the chain no longer knows it.
    ///
    /// While the transaction is still pending it is known but its `confirmed_round` is `0`.
    fn confirmed_transaction(&self, tx_id: &str) -> Result<Option<ConfirmedTxn>>;

    /// Find a confirmed transaction whose note exactly equals `note`, or `None` if there is none.
    ///
    /// Matching is on the full note bytes: a transaction whose note merely starts with `note` is
    /// not a match.
    fn find_transaction_by_note(&self, note: &[u8]) -> Result<Option<ConfirmedTxn>>;

    /// Find a confirmed transaction whose note *starts with* `prefix` — a **byte** prefix, not a bit
    /// prefix — or `None` if there is none.
    ///
    /// The byte-prefix sibling of [`TransactionQueryOps::find_transaction_by_note`]: a transaction
    /// whose note is longer than `prefix` is a valid match, provided its leading bytes equal `prefix`.
    /// Callers wanting a field-aligned prefix must lay the note out on byte boundaries.
    fn find_transaction_by_note_prefix(&self, prefix: &[u8]) -> Result<Option<ConfirmedTxn>>;
}

/// Operations for chains that have first-class assets (Algorand Standard Assets, Ethereum
/// tokens, etc.). Implemented only by chains that support assets.
pub trait AssetOps {
    /// Transfer `amount` indivisible units of asset `asset_id` to `to`.
    fn send_asset(&self, asset_id: u64, amount: u64, to: &str) -> Result<()>;

    /// Holding of asset `asset_id` for `account`, in indivisible units.
    fn asset_holding(&self, account: &str, asset_id: u64) -> Result<u64>;
}
