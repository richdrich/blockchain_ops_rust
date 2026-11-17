//! `unit` test target: every hardware_keystore test. None needs an external service.
//!
//! Each file under `tests/<module>/` mirrors a `src` module and is included here as a submodule, so
//! the whole bucket builds as one test binary (after the blockchain_account_vault pattern).

#[path = "data_key/key.rs"]
mod data_key_key;
#[path = "fake/availability.rs"]
mod fake_availability;
#[path = "record/fixed_vector.rs"]
mod record_fixed_vector;
#[path = "record/format.rs"]
mod record_format;
#[path = "secret/wrapping.rs"]
mod secret_wrapping;
#[path = "software/wrapping.rs"]
mod software_wrapping;
