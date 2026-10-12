//! `unit` test target: every blockchain_account_vault test. None needs an external service.
//!
//! Each file under `tests/<module>/` mirrors a `src` module and is included here as a submodule, so
//! the whole bucket builds as one test binary (after the sidewinder_ops pattern).

#[path = "support/mod.rs"]
mod support;

#[path = "account_dir/reader.rs"]
mod account_dir_reader;
#[path = "bin/blockchain_account_vault.rs"]
mod bin_blockchain_account_vault;
#[path = "envelope/encryption.rs"]
mod envelope_encryption;
#[path = "envelope/fixed_vector.rs"]
mod envelope_fixed_vector;
#[path = "mnemonic/encoding.rs"]
mod mnemonic_encoding;
#[path = "pdf/render.rs"]
mod pdf_render;
#[path = "vault/key_files.rs"]
mod vault_key_files;
