//! `integration` test target: sidewinder_ops driven against an external Sidewinder node nest.
//!
//! This target is marked `test = false` in `Cargo.toml`, so a bare `cargo test` skips it. Run it
//! explicitly with `cargo test --test integration`. Unlike the algo_ops localnet bucket, these
//! tests **skip cleanly** (return without failing) when the nest is not configured or not reachable
//! — the nest is bespoke infrastructure, not an always-on service — so the bucket stays green even
//! when run with no nest available. Configuration and bring-up are documented in
//! `tests/integration/README.md`.

#[path = "support/mod.rs"]
mod support;

#[path = "integration/slot_e2e.rs"]
mod slot_e2e;
