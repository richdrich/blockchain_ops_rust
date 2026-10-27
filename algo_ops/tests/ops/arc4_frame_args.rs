//! Unit tests for the ARC-4 argument framing shared by `AlgoOps::call_app_arc4_args` and
//! `TransactionGroupBuilder::call_app_arc4_args` (#109, #131): which arguments get the 2-byte
//! big-endian length prefix of a dynamic ARC-4 type, and which pass through unchanged.

use algo_ops::{AppArg, arc4_frame_args};

/// The wire bytes of each framed argument.
fn framed_bytes(method: Option<&str>, args: &[AppArg]) -> Vec<Vec<u8>> {
    arc4_frame_args(method, args)
        .expect("framing succeeds")
        .iter()
        .map(AppArg::to_bytes)
        .collect()
}

#[test]
fn a_string_argument_is_length_prefixed() {
    assert_eq!(
        framed_bytes(
            Some("register(string)void"),
            &[AppArg::Utf8("alice".to_string())]
        ),
        vec![b"\x00\x05alice".to_vec()]
    );
}

#[test]
fn a_byte_slice_argument_is_length_prefixed_and_empty_frames_to_zero_length() {
    assert_eq!(
        framed_bytes(
            Some("store_bytes(byte[])void"),
            &[AppArg::Bytes(vec![0xAA, 0xBB, 0xCC])]
        ),
        vec![vec![0x00, 0x03, 0xAA, 0xBB, 0xCC]]
    );
    assert_eq!(
        framed_bytes(
            Some("store_bytes(byte[])void"),
            &[AppArg::Bytes(Vec::new())]
        ),
        vec![vec![0x00, 0x00]],
        "an empty byte[] is a zero length prefix, not an empty arg"
    );
}

#[test]
fn fixed_size_arguments_pass_through_unchanged() {
    let address_bytes = vec![7u8; 32];
    assert_eq!(
        framed_bytes(
            Some("mixed(uint64,address,byte[],string)void"),
            &[
                AppArg::Uint(42),
                AppArg::Bytes(address_bytes.clone()),
                AppArg::Bytes(vec![1, 2]),
                AppArg::Utf8("x".to_string()),
            ]
        ),
        vec![
            42u64.to_be_bytes().to_vec(),
            address_bytes,
            vec![0x00, 0x02, 1, 2],
            b"\x00\x01x".to_vec(),
        ],
        "only the dynamic byte[]/string args are framed, by position"
    );
}

#[test]
fn arguments_without_a_signature_pass_through_unchanged() {
    assert_eq!(
        framed_bytes(None, &[AppArg::Bytes(vec![1, 2, 3])]),
        vec![vec![1, 2, 3]],
        "with no method signature there is no type to frame by"
    );
}

#[test]
fn an_argument_over_the_u16_length_limit_is_an_error() {
    let err = arc4_frame_args(
        Some("store_bytes(byte[])void"),
        &[AppArg::Bytes(vec![0u8; 65_536])],
    )
    .expect_err("a byte[] longer than u16::MAX cannot be framed");
    assert!(
        err.to_string().contains("u16 length limit"),
        "unexpected error: {err}"
    );
}
