//! Offline unit tests for the local-state membership-bit decoders. Pure decode helpers, no node call.

use sw_identity_tls::{bit_decoder, key_set_decoder};

fn ls(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn key_set_decoder_treats_a_truthy_named_key_as_member() {
    let decode = key_set_decoder("allow_sw_client");
    assert!(decode(&ls(&[("allow_sw_client", "1")])));
    assert!(decode(&ls(&[("other", "0"), ("allow_sw_client", "1")])));
}

#[test]
fn key_set_decoder_fails_closed_on_missing_or_falsey() {
    let decode = key_set_decoder("allow_sw_client");
    assert!(!decode(&ls(&[]))); // key absent
    assert!(!decode(&ls(&[("allow_sw_client", "0")])));
    assert!(!decode(&ls(&[("allow_sw_client", "false")])));
    assert!(!decode(&ls(&[("allow_sw_client", "")])));
    assert!(!decode(&ls(&[("allow_sw_node", "1")]))); // different key
}

#[test]
fn bit_decoder_tests_the_named_bit_of_a_packed_uint() {
    // bit 2 = allow_sw_node, bit 3 = allow_sw_client (illustrative layout, per bingle_rust#232).
    let is_node = bit_decoder("allow", 2);
    let is_client = bit_decoder("allow", 3);

    // packed = 0b0100 = 4: only allow_sw_node set.
    assert!(is_node(&ls(&[("allow", "4")])));
    assert!(!is_client(&ls(&[("allow", "4")])));

    // packed = 0b1100 = 12: both set (and lower allow_static/allow_relay bits clear).
    assert!(is_node(&ls(&[("allow", "12")])));
    assert!(is_client(&ls(&[("allow", "12")])));

    // packed = 0b0011 = 3: only the legacy allow_static/allow_relay bits — neither Sidewinder flag.
    assert!(!is_node(&ls(&[("allow", "3")])));
    assert!(!is_client(&ls(&[("allow", "3")])));
}

#[test]
fn bit_decoder_fails_closed_on_missing_or_unparseable() {
    let is_node = bit_decoder("allow", 2);
    assert!(!is_node(&ls(&[]))); // key absent
    assert!(!is_node(&ls(&[("allow", "")]))); // empty
    assert!(!is_node(&ls(&[("allow", "0x04")]))); // a byte-slice value, not a uint decimal
    assert!(!is_node(&ls(&[("other", "4")]))); // different key
}
