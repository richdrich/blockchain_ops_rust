//! Chain-agnostic blockchain operation traits.
//!
//! These traits cover the operations that read naturally on any chain, while chain-specific
//! power (application calls, asset configuration) stays on the concrete implementation and is
//! reached directly or through a native escape hatch. The Algorand implementation lives in the
//! `algo_ops` crate. See `spec/algo_ops_api_surface.md`.

use anyhow::Result;

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

/// Operations for chains that have first-class assets (Algorand Standard Assets, Ethereum
/// tokens, etc.). Implemented only by chains that support assets.
pub trait AssetOps {
    /// Transfer `amount` indivisible units of asset `asset_id` to `to`.
    fn send_asset(&self, asset_id: u64, amount: u64, to: &str) -> Result<()>;

    /// Holding of asset `asset_id` for `account`, in indivisible units.
    fn asset_holding(&self, account: &str, asset_id: u64) -> Result<u64>;
}
