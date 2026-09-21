//! Chain-agnostic core types shared by every other Tripwire crate.
//!
//! This crate has no chain-specific dependency (no `alloy`, no RPC
//! client) — that boundary is what makes the detection engine reusable
//! across chains without rewriting it (see ARCHITECTURE.md §3.1).

mod address;
mod chain;
mod confidence;
mod decision;
mod event;
mod signature;

pub use address::{Address, AddressParseError};
pub use chain::ChainId;
pub use confidence::{Confidence, EvidenceHit, SignatureMatch};
pub use decision::{CountedEvidence, PauseDecision};
pub use event::{BlockHeader, CallFrame, CallKind, LogEvent, TxEvent};
pub use signature::{Condition, ConditionKind, Signature, SignatureCategory};
