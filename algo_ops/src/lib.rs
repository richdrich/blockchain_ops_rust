//! Algorand implementation of the [`blockchain_ops`] traits, over `algonaut`.
//!
//! `AlgoOps` is the low-level Algorand operations struct; it implements [`BlockChainOps`],
//! [`AssetOps`], and [`TransactionQueryOps`] and provides the Algorand-specific
//! [`AlgoOps::new_for_algorand`] constructor.

#[macro_use]
mod logging;

pub mod error;
mod ops;

pub use error::AlgoError;
pub use ops::{
    AlgoChainConfig, AlgoOps, AlgoSuggestedParams, AppArg, ConfirmedTxn, KeyProvider, QueryMode,
    RateLimitConfig, RateLimitMode, ScannedTxn, TransactionGroupBuilder, TxnScanCache,
    TxnScanFilter, TxnScanPage, address_to_byte_key, byte_key_to_address,
};

// The token bucket is an internal type, re-exported only under `test-support` so its pure
// `poll` logic can be unit-tested with injected `Instant`s (like `is_retryable`).
#[cfg(feature = "test-support")]
pub use ops::RateLimiter;

use anyhow::Result;
use blockchain_ops::{AssetOps, BlockChainOps};

// Re-exported so consumers can bring the query trait into scope as `algo_ops::TransactionQueryOps`
// (alongside `algo_ops::ConfirmedTxn`) without also depending on `blockchain_ops` directly. The
// re-export also brings the name into this module for the `impl` below.
pub use blockchain_ops::TransactionQueryOps;

/// Number of micro-units in one whole ALGO.
const MICRO_PER_ALGO: f64 = 1_000_000.0;

impl BlockChainOps for AlgoOps {
    fn generate_keypair() -> (String, String) {
        AlgoOps::generate_keypair()
    }

    fn create_address(&mut self) -> Result<String> {
        AlgoOps::create_address(self)
    }

    fn address(&self) -> Result<String> {
        AlgoOps::address_str(self)
    }

    fn public_key(&self) -> Result<[u8; 32]> {
        AlgoOps::public_key_bytes(self)
    }

    fn private_key(&self) -> Result<Vec<u8>> {
        AlgoOps::private_key_bytes(self)
    }

    fn sign(&self, text: &str) -> Result<String> {
        AlgoOps::sign(self, text)
    }

    fn verify(&self, text: &str, sig_b64: &str) -> Result<bool> {
        AlgoOps::verify(self, text, sig_b64)
    }

    fn send_payment(&self, to: &str, payment_amount: f64) -> Result<()> {
        AlgoOps::send_algo(self, to, payment_amount)
    }

    fn account_balance(&self) -> Result<Option<f64>> {
        AlgoOps::account_balance(self)
    }

    fn account_balance_at(&self, account: &str) -> Result<f64> {
        // The inherent accessor returns micro-ALGO; express it in whole ALGO for the trait.
        Ok(AlgoOps::microalgos_at(self, account)? as f64 / MICRO_PER_ALGO)
    }

    fn wait_for_confirmation(&self, tx_id: &str, timeout: u64) -> Result<()> {
        AlgoOps::wait_for_confirmation(self, tx_id, timeout)
    }
}

impl AssetOps for AlgoOps {
    fn send_asset(&self, asset_id: u64, amount: u64, to: &str) -> Result<()> {
        AlgoOps::send_asset(self, asset_id, amount, to)
    }

    fn asset_holding(&self, account: &str, asset_id: u64) -> Result<u64> {
        AlgoOps::asset_holding(self, account, asset_id)
    }
}

impl TransactionQueryOps for AlgoOps {
    fn confirmed_transaction(&self, tx_id: &str) -> Result<Option<ConfirmedTxn>> {
        AlgoOps::confirmed_transaction(self, tx_id)
    }

    fn find_transaction_by_note(&self, note: &[u8]) -> Result<Option<ConfirmedTxn>> {
        AlgoOps::find_transaction_by_note(self, note)
    }

    fn find_transaction_by_note_prefix(&self, prefix: &[u8]) -> Result<Option<ConfirmedTxn>> {
        AlgoOps::find_transaction_by_note_prefix(self, prefix)
    }

    fn find_transactions_by_note_prefix(&self, prefix: &[u8]) -> Result<Vec<ConfirmedTxn>> {
        AlgoOps::find_transactions_by_note_prefix(self, prefix)
    }

    fn find_transaction_by_note_and_sender(
        &self,
        note: &[u8],
        sender: &str,
    ) -> Result<Option<ConfirmedTxn>> {
        AlgoOps::find_transaction_by_note_and_sender(self, note, sender)
    }

    fn find_transaction_by_note_prefix_and_sender(
        &self,
        prefix: &[u8],
        sender: &str,
    ) -> Result<Option<ConfirmedTxn>> {
        AlgoOps::find_transaction_by_note_prefix_and_sender(self, prefix, sender)
    }

    fn find_transactions_by_note_prefix_and_sender(
        &self,
        prefix: &[u8],
        sender: &str,
    ) -> Result<Vec<ConfirmedTxn>> {
        AlgoOps::find_transactions_by_note_prefix_and_sender(self, prefix, sender)
    }
}

impl AlgoOps {
    /// Algorand-specific constructor — the public entry point for building an `AlgoOps`.
    ///
    /// The lower-level `new` is `pub(crate)`, so all external construction goes through this
    /// named factory (and, eventually, a chain-specific factory trait). For indexer-only use,
    /// pass `None, None, config`.
    pub fn new_for_algorand(
        passphrase: Option<String>,
        address: Option<String>,
        config: Option<AlgoChainConfig>,
    ) -> Self {
        AlgoOps::new(passphrase, address, config)
    }
}
