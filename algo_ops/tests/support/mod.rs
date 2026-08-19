//! Shared test-support scaffolding for the algo_ops test suite.
//!
//! Ported from the bingle_rust `bingle_core` test tree and trimmed to the
//! Algorand-only surface: none of this depends on `AlgoBingle`, the bingle API,
//! or the engine — only on `algo_ops` itself and the algokit localnet.
//!
//! Included into each test binary via `#[path = "../support/mod.rs"] mod support;`.
#![allow(dead_code)]

pub mod blockchain_users;
pub mod setup_localnet;
pub mod test_util;
