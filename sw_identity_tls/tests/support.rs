//! Shared helpers for the sw_identity_tls test suite.

use std::collections::HashSet;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use sw_identity_tls::{IdentityCert, generate};

/// A deterministic Ed25519 identity from a single seed byte, so tests are reproducible.
pub(crate) fn identity(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// An identity-bound certificate for the identity seeded by `seed`.
pub(crate) fn cert(seed: u8) -> IdentityCert {
    generate(&identity(seed)).expect("generate identity certificate")
}

/// An allow-set from a list of addresses.
pub(crate) fn allow<I: IntoIterator<Item = String>>(addresses: I) -> Arc<HashSet<String>> {
    Arc::new(addresses.into_iter().collect())
}

/// The first index at which `needle` occurs in `haystack`, if any.
pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
