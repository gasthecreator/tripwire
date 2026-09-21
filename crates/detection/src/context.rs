//! The seam between the pure detection engine and the outside world.
//!
//! The engine itself does no I/O. A `ContextSource` supplies what a raw
//! transaction lacks: the call trace when the node can't serve one, and the
//! [`Baseline`] the fund-flow / oracle / governance conditions compare
//! against. It lives here (not in the daemon) so that production
//! implementations, tests, and the replay harness all share one contract.

use async_trait::async_trait;
use tripwire_core::TxEvent;

use crate::conditions::Baseline;

#[async_trait]
pub trait ContextSource: Send + Sync {
    /// Fill in fields the chain adapter couldn't (chiefly `call_frames`).
    async fn enrich(&self, tx: &mut TxEvent);
    /// Real-world context for scoring `tx`. Sources must fail *closed*: if
    /// a value can't be established, leave it unset so the condition that
    /// needs it is simply not satisfied, never guessed.
    async fn baseline(&self, tx: &TxEvent) -> Baseline;
}

/// No extra context: transactions are scored as the adapter returned them,
/// against an empty baseline. Call-pattern and reentrancy conditions still
/// work when the adapter supplies traces; fund-flow, oracle and governance
/// conditions fail closed.
pub struct NoContext;

#[async_trait]
impl ContextSource for NoContext {
    async fn enrich(&self, _tx: &mut TxEvent) {}
    async fn baseline(&self, _tx: &TxEvent) -> Baseline {
        Baseline::default()
    }
}
