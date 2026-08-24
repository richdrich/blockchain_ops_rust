//! Neutral boundary types for the Sidewinder Representational State Transfer (REST) surface.
//!
//! These carry only plain types — no `sidewinder` crate types and no `reqwest`/wire types — so a
//! consumer stays decoupled from the node's internal versions. They are built against the reconciled
//! `sidewinder_rest.yaml` v0.1.1 contract; fields the v0 node does not emit (`anchorRound`,
//! `Event.data`, `EventSchema.args`, `Error.code`) are deliberately absent.
//!
//! Byte fields arrive base64-encoded in the node's JavaScript Object Notation (JSON) and are decoded
//! to `Vec<u8>` here. The `*Wire` structs below are the private serde mirrors of the JSON; the public
//! types are produced from them by the `into_*` methods, which carry the operation name for error
//! context (a plain `TryFrom` cannot) and are where base64 and enum decoding happen.

use crate::error::SidewinderError;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

/// Decode a base64 byte field, tagging the operation and field on failure.
fn decode_b64(operation: &str, field: &str, value: &str) -> Result<Vec<u8>, SidewinderError> {
    STANDARD.decode(value).map_err(|e| {
        SidewinderError::malformed_response(operation, &format!("bad base64 in `{field}`: {e}"))
    })
}

/// Lifecycle stage of a transaction (`stage` in the REST response).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Pending,
    Provisional,
    Final,
    Failed,
}

impl Stage {
    fn parse(operation: &str, value: &str) -> Result<Self, SidewinderError> {
        match value {
            "pending" => Ok(Stage::Pending),
            "provisional" => Ok(Stage::Provisional),
            "final" => Ok(Stage::Final),
            "failed" => Ok(Stage::Failed),
            other => Err(SidewinderError::malformed_response(
                operation,
                &format!("unknown stage `{other}`"),
            )),
        }
    }
}

/// How a failed transaction was disposed of (`disposition` in an error body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    ReSelected,
    Escalated,
    Failed,
}

impl Disposition {
    fn parse(operation: &str, value: &str) -> Result<Self, SidewinderError> {
        match value {
            "reselected" => Ok(Disposition::ReSelected),
            "escalated" => Ok(Disposition::Escalated),
            "failed" => Ok(Disposition::Failed),
            other => Err(SidewinderError::malformed_response(
                operation,
                &format!("unknown disposition `{other}`"),
            )),
        }
    }
}

/// A transaction failure (`error` in the pending response, present when `stage` is `Failed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnError {
    pub message: String,
    pub disposition: Option<Disposition>,
    // No `code`: the v0 node does not populate it.
}

/// An event emitted during execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The 4-byte event selector.
    pub selector: Vec<u8>,
    /// Event name; an empty string when the selector is not known.
    pub name: String,
    // No `data`: the v0 node does not emit it.
}

/// The current response for a transaction (`GET /v2/transactions/pending/{txid}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTransaction {
    pub tx_id: String,
    pub stage: Stage,
    /// The operation's return value; present once the stage is past `Pending`.
    pub result: Option<Vec<u8>>,
    pub logs: Vec<Vec<u8>>,
    pub events: Vec<Event>,
    /// Result certificate, present only when `proof` was requested. Opaque v0 bytes — not verified.
    pub certificate: Option<Vec<u8>>,
    /// Merkle inclusion proof, present only when `proof` was requested. Opaque v0 bytes — not verified.
    pub proof: Option<Vec<u8>>,
    /// Present when `stage` is `Failed`.
    pub error: Option<TxnError>,
    // No `anchor_round`: the v0 node does not emit it.
}

/// Suggested parameters for building a transaction (`GET /v2/transactions/params`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestedParams {
    pub instance_id: Vec<u8>,
    pub last_round: u64,
    pub min_fee: u64,
    pub max_validity_window: u64,
}

/// The node's view of the parent chain and node set (`GET /v2/status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    pub instance_id: Vec<u8>,
    pub last_round: u64,
    /// Membership epoch of the node set. The v0 node always reports `0` (node set not yet modelled).
    pub node_set_epoch: u64,
    pub synced: bool,
    pub version: Option<String>,
}

/// One declared event in an operation's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSchema {
    pub name: String,
    pub signature: String,
    pub selector: Vec<u8>,
    // No `args`: the v0 node does not emit it.
}

/// Operation configuration for a transaction type (`GET /v2/operations/{typ}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationSchema {
    pub typ: u32,
    pub name: Option<String>,
    pub return_type: String,
    pub events: Vec<EventSchema>,
}

// ── wire mirrors ─────────────────────────────────────────────────────────────
// Private serde views of the node's JSON. Unknown fields (e.g. a future `anchorRound`, or `Error.code`)
// are ignored, so the client keeps deserializing responses from a newer node.

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PostTransactionResponseWire {
    pub tx_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PendingWire {
    pub tx_id: String,
    pub stage: String,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub logs: Vec<String>,
    #[serde(default)]
    pub events: Vec<EventWire>,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub proof: Option<String>,
    #[serde(default)]
    pub error: Option<ErrorWire>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EventWire {
    pub selector: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ErrorWire {
    pub message: String,
    #[serde(default)]
    pub disposition: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SuggestedParamsWire {
    pub instance_id: String,
    pub last_round: u64,
    pub min_fee: u64,
    pub max_validity_window: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NodeStatusWire {
    pub instance_id: String,
    pub last_round: u64,
    pub node_set_epoch: u64,
    pub synced: bool,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OperationSchemaWire {
    pub typ: u32,
    #[serde(default)]
    pub name: Option<String>,
    pub return_type: String,
    #[serde(default)]
    pub events: Vec<EventSchemaWire>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EventSchemaWire {
    pub name: String,
    pub signature: String,
    pub selector: String,
}

// ── wire → neutral conversions ───────────────────────────────────────────────
// Each carries the operation name for error context via a plain method (TryFrom cannot).

impl EventWire {
    fn into_event(self, operation: &str) -> Result<Event, SidewinderError> {
        Ok(Event {
            selector: decode_b64(operation, "events[].selector", &self.selector)?,
            name: self.name,
        })
    }
}

impl ErrorWire {
    fn into_txn_error(self, operation: &str) -> Result<TxnError, SidewinderError> {
        let disposition = match self.disposition {
            Some(ref d) => Some(Disposition::parse(operation, d)?),
            None => None,
        };
        Ok(TxnError {
            message: self.message,
            disposition,
        })
    }
}

impl PendingWire {
    pub(crate) fn into_pending(
        self,
        operation: &str,
    ) -> Result<PendingTransaction, SidewinderError> {
        let stage = Stage::parse(operation, &self.stage)?;
        let result = match self.result {
            Some(ref r) => Some(decode_b64(operation, "result", r)?),
            None => None,
        };
        let logs = self
            .logs
            .iter()
            .map(|log| decode_b64(operation, "logs[]", log))
            .collect::<Result<Vec<_>, _>>()?;
        let events = self
            .events
            .into_iter()
            .map(|event| event.into_event(operation))
            .collect::<Result<Vec<_>, _>>()?;
        let certificate = match self.certificate {
            Some(ref c) => Some(decode_b64(operation, "certificate", c)?),
            None => None,
        };
        let proof = match self.proof {
            Some(ref p) => Some(decode_b64(operation, "proof", p)?),
            None => None,
        };
        let error = match self.error {
            Some(e) => Some(e.into_txn_error(operation)?),
            None => None,
        };
        Ok(PendingTransaction {
            tx_id: self.tx_id,
            stage,
            result,
            logs,
            events,
            certificate,
            proof,
            error,
        })
    }
}

impl SuggestedParamsWire {
    pub(crate) fn into_params(self, operation: &str) -> Result<SuggestedParams, SidewinderError> {
        Ok(SuggestedParams {
            instance_id: decode_b64(operation, "instanceId", &self.instance_id)?,
            last_round: self.last_round,
            min_fee: self.min_fee,
            max_validity_window: self.max_validity_window,
        })
    }
}

impl NodeStatusWire {
    pub(crate) fn into_status(self, operation: &str) -> Result<NodeStatus, SidewinderError> {
        Ok(NodeStatus {
            instance_id: decode_b64(operation, "instanceId", &self.instance_id)?,
            last_round: self.last_round,
            node_set_epoch: self.node_set_epoch,
            synced: self.synced,
            version: self.version,
        })
    }
}

impl EventSchemaWire {
    fn into_schema(self, operation: &str) -> Result<EventSchema, SidewinderError> {
        Ok(EventSchema {
            name: self.name,
            signature: self.signature,
            selector: decode_b64(operation, "events[].selector", &self.selector)?,
        })
    }
}

impl OperationSchemaWire {
    pub(crate) fn into_schema(self, operation: &str) -> Result<OperationSchema, SidewinderError> {
        let events = self
            .events
            .into_iter()
            .map(|event| event.into_schema(operation))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(OperationSchema {
            typ: self.typ,
            name: self.name,
            return_type: self.return_type,
            events,
        })
    }
}
