//! Decoding "is this account a permitted member" from an application's per-account local state.
//!
//! *Which* local-state key/bit means "member" is the membership application's own schema (the Bingle
//! write side, bingle_rust#234/#376), so it is expressed as an injected [`MembershipDecoder`] rather than
//! hard-coded — this crate carries no application-specific encoding. The same decoders drive both the
//! endpoint [`resolver`](crate::resolver) (which node accounts to surface) and the on-chain membership
//! sources in the sidewinder `sw-membership` crate (which accounts are members).

use std::sync::Arc;

/// Decides, from an account's decoded local state for the membership app, whether the account is a
/// permitted member. The exact key/bit is the membership application's schema, so it is injected; see
/// [`key_set_decoder`] for the common "a named key is set" shape and [`bit_decoder`] for a packed
/// bitfield.
pub type MembershipDecoder = Arc<dyn Fn(&[(String, String)]) -> bool + Send + Sync>;

/// A decoder that treats an account as a member iff its local state holds `key` with a **truthy** value
/// — a non-empty value other than `"0"` or `"false"`. Covers the usual "set bit / flag = member" schema
/// (`algo_ops` decodes a `uint` flag to its decimal string and a byte value to its UTF-8 form).
pub fn key_set_decoder(key: impl Into<String>) -> MembershipDecoder {
    let key = key.into();
    Arc::new(move |local_state: &[(String, String)]| {
        local_state.iter().any(|(k, v)| *k == key && is_truthy(v))
    })
}

/// Whether a decoded local-state value counts as a set flag: non-empty and not an explicit zero/false.
fn is_truthy(value: &str) -> bool {
    !matches!(value, "" | "0" | "false")
}

/// A decoder that treats an account as a member iff **bit `bit`** of the `uint` local-state value under
/// `key` is set. This is the Bingle membership shape (bingle_rust#234): the allow flags are packed into
/// one `uint` bitfield local-state slot — `allow_sw_node` and `allow_sw_client` are distinct bits — so
/// the cluster-node and client sources decode the same key at different bit positions. `algo_ops`
/// renders a `uint` value as its decimal string; a value that does not parse (a missing or non-`uint`
/// slot) reads as not-a-member (fail closed).
pub fn bit_decoder(key: impl Into<String>, bit: u8) -> MembershipDecoder {
    let key = key.into();
    Arc::new(move |local_state: &[(String, String)]| {
        local_state.iter().any(|(k, v)| {
            *k == key
                && v.parse::<u64>()
                    .is_ok_and(|packed| packed & (1u64 << bit) != 0)
        })
    })
}
