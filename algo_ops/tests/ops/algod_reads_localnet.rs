//! Localnet integration tests for the generic algod read primitives (`round`,
//! `block_seed`, `suggested_params`). In the `integration` target, which a bare
//! `cargo test` skips; run with `cargo test --test integration`.

use crate::support::test_util::{self, localnet_config};
use algo_ops::AlgoOps;

#[test]
#[cfg(not(target_os = "ios"))]
pub fn round_returns_committed_round() {
    test_util::assert_localnet_available();
    let ops = AlgoOps::new_for_algorand(None, None, Some(localnet_config()));
    let round = ops.round().expect("round should succeed on localnet");
    assert!(
        round > 0,
        "expected a non-zero committed round, got {round}"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn suggested_params_are_populated() {
    test_util::assert_localnet_available();
    let ops = AlgoOps::new_for_algorand(None, None, Some(localnet_config()));
    let params = ops
        .suggested_params()
        .expect("suggested_params should succeed on localnet");

    assert!(params.min_fee > 0, "expected a positive network min fee");
    assert!(
        params.last_round > 0,
        "expected a non-zero last round, got {}",
        params.last_round
    );
    assert!(
        params.genesis_hash.iter().any(|b| *b != 0),
        "expected a non-zero genesis hash"
    );
    assert!(
        !params.genesis_id.is_empty(),
        "expected a non-empty genesis id"
    );
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn block_seed_is_32_bytes() {
    test_util::assert_localnet_available();
    let ops = AlgoOps::new_for_algorand(None, None, Some(localnet_config()));

    // The last committed round is guaranteed to have a block; read its seed.
    let round = ops.round().expect("round should succeed on localnet");
    let seed = ops
        .block_seed(round)
        .expect("block_seed should succeed for the last committed round");
    assert_eq!(seed.len(), 32, "block seed should be 32 bytes");
    assert!(
        seed.iter().any(|b| *b != 0),
        "expected a non-zero block seed"
    );
}
