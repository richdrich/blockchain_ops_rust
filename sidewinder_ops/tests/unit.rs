//! `unit` test target: sidewinder_ops client tests that need no external services.
//!
//! Each file under `tests/client/` and `tests/transaction/` (mirroring the `src` layout) is
//! included as a submodule so the whole bucket builds as one test binary (after the algo_ops
//! pattern). The client tests drive an in-process mock HTTP node (`tests/support/mock_node.rs`);
//! the build/sign tests need no node at all. The external multi-node integration test is issue #46.

#[path = "support/mod.rs"]
mod support;

#[path = "client/health.rs"]
mod health;
#[path = "client/misc.rs"]
mod misc;
#[path = "client/node_status.rs"]
mod node_status;
#[path = "client/operations.rs"]
mod operations;
#[path = "client/params.rs"]
mod params;
#[path = "client/pending.rs"]
mod pending;
#[path = "client/submit.rs"]
mod submit;

#[path = "transaction/build_sign.rs"]
mod build_sign;
