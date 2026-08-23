//! Client for a [Sidewinder](https://github.com/richdrich/sidewinder) sidechain node.
//!
//! [`SidewinderClient`] wraps the node's Representational State Transfer (REST) surface — the reconciled
//! `sidewinder_rest.yaml` v0.1.1 contract — behind the [`SidewinderOps`] trait, one method per
//! endpoint. It is built on an [`algo_ops::AlgoOps`] handle (the enrolled parent-chain account, which
//! signs transactions from issue #45 on) plus a [`SidewinderConfig`] naming the node URL and bearer
//! token.
//!
//! The client speaks only the HTTP contract; it takes no code dependency on the `sidewinder` crates and
//! keeps neutral types on the boundary (e.g. [`PendingTransaction`], [`NodeStatus`]), so a consumer
//! stays decoupled from the node's internal versions. Certificate and proof bytes are surfaced opaque
//! and are not verified (a v0.0.2 non-goal).

mod client;
mod config;
mod error;
mod types;

pub use client::{SidewinderClient, SidewinderOps};
pub use config::SidewinderConfig;
pub use error::{SidewinderError, SidewinderErrorKind};
pub use types::{
    Disposition, Event, EventSchema, NodeStatus, OperationSchema, PendingTransaction, Stage,
    SuggestedParams, TxnError,
};
