//! Unit coverage for `AlgoOps::find_transactions_by_note_prefix` that needs no node: the empty-prefix
//! guard is checked before any indexer call, so it is exercised offline. The matching behaviour
//! against a real indexer lives in the `integration` bucket
//! (`find_transaction_by_note_prefix_localnet.rs`).

use algo_ops::AlgoOps;

#[test]
fn empty_prefix_is_rejected() {
    // An empty prefix would match every note; the guard fires before any indexer call, so an
    // indexer-only handle (no key, default config) is enough to observe it.
    let ops = AlgoOps::new_for_algorand(None, None, None);
    assert!(
        ops.find_transactions_by_note_prefix(b"").is_err(),
        "an empty prefix must be rejected rather than matching every note"
    );
}
