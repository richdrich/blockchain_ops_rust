//! Client for a [Sidewinder](https://github.com/richdrich/sidewinder) sidechain node.
//!
//! [`SidewinderClient`] wraps the node's Representational State Transfer (REST) surface — the reconciled
//! `sidewinder_rest.yaml` v0.1.1 contract — behind the [`SidewinderOps`] trait, one method per
//! endpoint. It is built on an [`algo_ops::AlgoOps`] handle (the enrolled parent-chain account, which
//! signs the transactions the client builds) plus a [`SidewinderConfig`] naming the node URL and
//! bearer token.
//!
//! Beyond wrapping the endpoints, the client builds, canonically encodes, and signs transactions:
//! [`SidewinderClient::build_signed_transaction`] turns a [`TransactionRequest`] into the bytes and
//! identifier, and [`SidewinderClient::submit_transaction`] builds, signs, and submits in one call.
//!
//! The client speaks only the HTTP contract; it takes no code dependency on the `sidewinder` crates and
//! keeps neutral types on the boundary (e.g. [`PendingTransaction`], [`NodeStatus`]), so a consumer
//! stays decoupled from the node's internal versions. Certificate and proof bytes are surfaced opaque
//! and are not verified (a v0.0.2 non-goal).

mod client;
mod config;
mod error;
mod transaction;
mod types;

// Re-exported so a caller can build transaction arguments as `sidewinder_ops::AppArg` without a
// second `use algo_ops::AppArg;` — the argument packing is shared with algo_ops, not reimplemented.
pub use algo_ops::AppArg;
pub use client::{SidewinderClient, SidewinderOps};
pub use config::SidewinderConfig;
pub use error::{SidewinderError, SidewinderErrorKind};
pub use transaction::{SignedTransaction, TransactionRequest};
pub use types::{
    Disposition, Event, EventSchema, NodeStatus, OperationSchema, PendingTransaction, Stage,
    SuggestedParams, TxnError,
};
