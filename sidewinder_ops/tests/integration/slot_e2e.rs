//! End-to-end `Slot` read-after-write against a running Sidewinder node nest.
//!
//! This is the outside-in driver from issue #46: build and sign a `Slot.set` with an enrolled
//! `algo_ops` key, submit it to one node, poll to the `final` stage on a (possibly different) node,
//! and assert the returned result. It is configured entirely from the environment (see
//! [`crate::support::nest_from_env`]) and **skips cleanly** — returns without failing — when the
//! nest is not configured or not reachable, so a bare `cargo test --test integration` stays green
//! without infrastructure. Bring-up is documented in `tests/integration/README.md`.

use crate::support::{nest_client, nest_from_env};
use algo_ops::AlgoOps;
use sidewinder_ops::{
    AppArg, PendingTransaction, SidewinderClient, SidewinderErrorKind, SidewinderOps, Stage,
    TransactionRequest,
};
use std::time::{Duration, Instant};

/// The transaction type the nest's boot configuration binds `Slot.set` to (see sidewinder's e2e
/// harness). A nest that binds it elsewhere can override this with `SIDEWINDER_SLOT_SET_TYPE`.
fn slot_set_type() -> u32 {
    std::env::var("SIDEWINDER_SLOT_SET_TYPE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2)
}

/// How long to wait for a submitted transaction to reach the `final` stage before failing. Anchoring
/// to the parent chain dominates this, so it is generous.
const FINALITY_TIMEOUT: Duration = Duration::from_secs(120);

#[test]
fn slot_set_reads_its_own_writes_across_the_nest() {
    let Some(config) = nest_from_env() else {
        eprintln!(
            "skipping slot_set_reads_its_own_writes_across_the_nest: set SIDEWINDER_NODES, \
             SIDEWINDER_ACCOUNT_MNEMONIC (and SIDEWINDER_TOKEN) to run — see \
             tests/integration/README.md"
        );
        return;
    };

    let submit = nest_client(&config.node_urls[0], &config);

    // Reachability gate: skip (do not fail) when the nest is not up or not ready to serve.
    match submit.health() {
        Ok(true) => {}
        Ok(false) => {
            eprintln!(
                "skipping: node {} is up but reports not-ready (503)",
                config.node_urls[0]
            );
            return;
        }
        Err(e) => {
            eprintln!("skipping: node {} unreachable: {e}", config.node_urls[0]);
            return;
        }
    }

    // Read back on the last node in the list, so a multi-node nest exercises cross-node visibility;
    // with a single node this is the same node.
    let read = nest_client(config.node_urls.last().expect("a node url"), &config);
    let typ = slot_set_type();

    // A fresh, unique slot address, so the first write sees an empty previous value.
    let slot_id = AlgoOps::unique_note();

    // First set on the fresh slot: `Slot.set` returns the (empty) previous value.
    let previous = set_and_finalize(&submit, &read, typ, &slot_id, b"first-value");
    assert_eq!(
        decode_arc4_bytes(&previous),
        b"",
        "a fresh slot has no previous value"
    );

    // Second set: the returned previous value is the first write, and it is visible on the read node
    // — read-after-write across the nest.
    let previous = set_and_finalize(&submit, &read, typ, &slot_id, b"second-value");
    assert_eq!(
        decode_arc4_bytes(&previous),
        b"first-value",
        "set returns the prior value, finalised and visible across the nest"
    );
}

/// Build, sign, submit a `Slot.set(slot_id, value)` on `submit`, poll it to `final` on `read`, and
/// return the raw (Algorand Request for Comments 4, ARC-4, encoded) result bytes.
fn set_and_finalize(
    submit: &SidewinderClient,
    read: &SidewinderClient,
    typ: u32,
    slot_id: &[u8],
    value: &[u8],
) -> Vec<u8> {
    let params = submit.params().expect("suggested params");
    let request = TransactionRequest {
        txn_type: typ,
        args: vec![
            AppArg::Bytes(slot_id.to_vec()),
            AppArg::Bytes(value.to_vec()),
        ],
        max_fee: params.min_fee,
        first_valid: params.last_round,
        last_valid: params.last_round + params.max_validity_window,
        instance: params.instance_id,
        // A unique note keeps two sets of the same slot from colliding on the content address.
        note: Some(AlgoOps::unique_note()),
        group: None,
    };

    let txid = submit.submit_transaction(&request).expect("submit");
    let pending = poll_to_final(read, &txid);
    assert_eq!(pending.stage, Stage::Final, "transaction did not finalise");
    assert!(
        pending.error.is_none(),
        "transaction failed: {:?}",
        pending.error
    );
    pending
        .result
        .expect("a finalised transaction carries a result")
}

/// Poll `txid` on `client` until it reaches `final` (or `failed`), long-polling each request. A read
/// node may not know a just-submitted txid yet, so a `not found` is tolerated as propagation lag
/// until the deadline; any other error, or missing finality within [`FINALITY_TIMEOUT`], fails.
fn poll_to_final(client: &SidewinderClient, txid: &str) -> PendingTransaction {
    let deadline = Instant::now() + FINALITY_TIMEOUT;
    loop {
        match client.watch(txid, false, 5) {
            Ok(pending) if matches!(pending.stage, Stage::Final | Stage::Failed) => return pending,
            Ok(_) => {}
            Err(e) => {
                let not_yet_visible = e
                    .downcast_ref::<sidewinder_ops::SidewinderError>()
                    .is_some_and(|se| se.kind == SidewinderErrorKind::NotFound);
                if !not_yet_visible {
                    panic!("polling {txid} failed: {e}");
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "transaction {txid} did not reach the final stage within {FINALITY_TIMEOUT:?}"
        );
        // The node returns immediately on a not-found; pace the retry so we do not busy-loop.
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Decode an ARC-4 `byte[]`: a 2-byte big-endian length prefix followed by exactly that many bytes.
/// `Slot`'s declared return type is `byte[]`, so its result is carried this way.
fn decode_arc4_bytes(result: &[u8]) -> Vec<u8> {
    assert!(
        result.len() >= 2,
        "an ARC-4 byte[] result has a 2-byte length prefix, got {} bytes",
        result.len()
    );
    let len = u16::from_be_bytes([result[0], result[1]]) as usize;
    assert_eq!(
        result.len(),
        2 + len,
        "ARC-4 byte[] length prefix ({len}) must match the payload length"
    );
    result[2..].to_vec()
}
