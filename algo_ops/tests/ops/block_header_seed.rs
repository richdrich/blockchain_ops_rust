//! `parse_block_header_seed` reads only the block header seed, so a block whose body carries a
//! state-proof (`stpf`) transaction — which algonaut's typed block decode cannot handle — still yields
//! its seed (issue #66). These are deterministic (no running node), so they live in the `unit` target
//! and pin the regression regardless of chain height.

use algo_ops::AlgoOps;

/// a block JSON carrying a state-proof (`stpf`) transaction alongside a payment. The seed is a real
/// 32-byte value; the point is that the `txns` list — including the `stpf` algonaut cannot decode — is
/// ignored entirely.
const BLOCK_WITH_STATE_PROOF: &[u8] = br#"{"block":{
    "rnd":514,
    "seed":"RlaWgJPgZfn/bcuSP3/E6WGuyXCW6iqEceEzQKzpZJo=",
    "txns":[
        {"txn":{"type":"stpf","sprnd":512,"sp":{"P":123,"S":{"pth":[],"hsh":{"t":1}}}}},
        {"txn":{"type":"pay","amt":1000}}
    ]
}}"#;

#[test]
fn parses_the_seed_from_a_block_with_a_state_proof_transaction() {
    let seed = AlgoOps::parse_block_header_seed(BLOCK_WITH_STATE_PROOF, 514)
        .expect("the seed parses even though the block carries an stpf transaction");
    assert_eq!(seed.len(), 32, "the block seed is 32 bytes");
    assert!(seed.iter().any(|b| *b != 0), "the seed is non-zero");
    // the first bytes of base64-decoded "RlaWgJPg…", pinning the exact value read from the header.
    assert_eq!(&seed[..4], &[0x46, 0x56, 0x96, 0x80]);
}

#[test]
fn rejects_a_block_missing_the_seed() {
    let body = br#"{"block":{"rnd":1,"txns":[]}}"#;
    assert!(
        AlgoOps::parse_block_header_seed(body, 1).is_err(),
        "a block header without a seed is an error, not a silent empty seed"
    );
}

#[test]
fn rejects_a_seed_that_is_not_32_bytes() {
    // "AAAA" is valid base64 for three zero bytes — the wrong length for a block seed.
    let body = br#"{"block":{"seed":"AAAA"}}"#;
    assert!(
        AlgoOps::parse_block_header_seed(body, 1).is_err(),
        "a seed of the wrong length is rejected"
    );
}
