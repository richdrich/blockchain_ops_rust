//! Offline unit coverage for the sender-authenticated note searches: the empty-prefix/note and
//! empty-sender guards fire before any indexer call, so they are exercised without a node. The
//! matching behaviour against a real indexer lives in the `integration` bucket
//! (`find_transaction_by_note_and_sender_localnet.rs`).

use algo_ops::AlgoOps;

fn indexer_only() -> AlgoOps {
    // A guard fires before any indexer call, so an indexer-only handle (no key, default config) is
    // enough to observe it.
    AlgoOps::new_for_algorand(None, None, None)
}

#[test]
fn empty_note_or_sender_is_rejected_by_the_exact_search() {
    let ops = indexer_only();
    assert!(
        ops.find_transaction_by_note_and_sender(b"", "SOME-ADDRESS")
            .is_err(),
        "an empty note must be rejected"
    );
    assert!(
        ops.find_transaction_by_note_and_sender(b"note", "")
            .is_err(),
        "an empty sender must be rejected"
    );
}

#[test]
fn empty_prefix_or_sender_is_rejected_by_the_prefix_searches() {
    let ops = indexer_only();
    assert!(
        ops.find_transaction_by_note_prefix_and_sender(b"", "SOME-ADDRESS")
            .is_err(),
        "an empty prefix must be rejected (single-hit)"
    );
    assert!(
        ops.find_transaction_by_note_prefix_and_sender(b"prefix", "")
            .is_err(),
        "an empty sender must be rejected (single-hit)"
    );
    assert!(
        ops.find_transactions_by_note_prefix_and_sender(b"", "SOME-ADDRESS")
            .is_err(),
        "an empty prefix must be rejected (list)"
    );
    assert!(
        ops.find_transactions_by_note_prefix_and_sender(b"prefix", "")
            .is_err(),
        "an empty sender must be rejected (list)"
    );
}
