//! The detect -> confirm -> pause state machine (ARCHITECTURE.md §3.2).
//!
//! One `tick()` follows the chain forward, evaluates every transaction that
//! touches the protected contract, and drives any resulting pause decisions
//! through three gates before a pause is submitted:
//!
//! 1. **Canonical:** the block containing the triggering transaction must
//!    still be on the canonical chain (a reorg that drops it cancels the
//!    pause — acting on a transaction that never happened would be a
//!    self-inflicted outage).
//! 2. **Confirmed:** the block must be `min_confirmations` deep.
//! 3. **Not already paused:** don't burn gas on a pause that would revert.
//!
//! Detection itself happens the moment a block is seen (0 confirmations);
//! only the *action* waits. A decision that hasn't cleared the gates yet is
//! kept as pending and re-checked every tick — it is never dropped just
//! because it wasn't ready the first time.

use std::collections::VecDeque;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use chain_adapter::{ChainAdapter, ChainAdapterError};
use thiserror::Error;
use tripwire_core::{Address, BlockHeader, ChainId, Confidence, PauseDecision, Signature, TxEvent};

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("chain error: {0}")]
    Chain(#[from] ChainAdapterError),
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct PauseError(pub String);

/// Submits and inspects pauses. Implemented for the real `GuardianClient`
/// in `main.rs`; tests use an in-memory fake.
#[async_trait]
pub trait Pauser: Send + Sync {
    async fn is_paused(&self, target: &Address) -> Result<bool, PauseError>;
    /// Submits the pause and returns its transaction hash once confirmed.
    async fn submit_pause(&self, decision: &PauseDecision) -> Result<String, PauseError>;
}

pub use detection::{ContextSource, NoContext};

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub chain_id: ChainId,
    /// The protected contract (the one registered with the Guardian).
    pub target: Address,
    /// Every address whose involvement makes a transaction worth scoring:
    /// the target plus any contracts that custody its assets (e.g. one vault
    /// per asset). Always includes `target`.
    pub watched_addresses: Vec<Address>,
    pub threshold: Confidence,
    /// Blocks that must be built on top of the triggering block before the
    /// pause is submitted. `0` acts as soon as the block is seen.
    pub min_confirmations: u64,
    /// How many recent block hashes to remember for reorg detection.
    pub reorg_window: usize,
    /// Cap on blocks processed per tick, so catching up after downtime
    /// can't starve pending-pause handling.
    pub max_blocks_per_tick: u64,
}

impl EngineConfig {
    pub fn new(chain_id: ChainId, target: Address, threshold: Confidence) -> Self {
        Self {
            chain_id,
            target,
            watched_addresses: vec![target],
            threshold,
            min_confirmations: 1,
            reorg_window: 64,
            max_blocks_per_tick: 32,
        }
    }
}

#[derive(Debug)]
struct PendingPause {
    decision: PauseDecision,
    block: BlockHeader,
    first_seen: Instant,
    attempts: u32,
}

/// One submitted pause, with how long after first seeing the triggering
/// transaction it landed — the number this product's value rests on.
#[derive(Debug, Clone)]
pub struct PauseRecord {
    pub pause_tx_hash: String,
    pub triggering_tx_hash: String,
    pub latency: std::time::Duration,
    pub attempts: u32,
}

/// What one tick did. Returned (not just logged) so callers and tests can
/// assert on behaviour and so metrics can be derived from it.
#[derive(Debug, Default, Clone)]
pub struct TickReport {
    pub head: u64,
    pub blocks_processed: u64,
    /// `Some(depth)` if the chain reorganised under us this tick.
    pub reorg_depth: Option<u64>,
    /// Transactions that touched the target and were scored.
    pub evaluated: usize,
    pub pauses: Vec<PauseRecord>,
    /// Pending pauses cancelled because their block was reorged away.
    pub dropped_by_reorg: usize,
    /// Pending pauses cancelled because the target was already paused.
    pub dropped_already_paused: usize,
    pub pause_errors: usize,
    /// Still waiting for confirmations (or a retry) after this tick.
    pub pending: usize,
}

pub struct Engine<C, P, X> {
    chain: C,
    pauser: P,
    context: X,
    signatures: Vec<Signature>,
    cfg: EngineConfig,
    /// Recent processed blocks, ascending; the last is the tip we follow.
    canonical: VecDeque<BlockHeader>,
    pending: Vec<PendingPause>,
}

impl<C: ChainAdapter, P: Pauser, X: ContextSource> Engine<C, P, X> {
    pub fn new(
        chain: C,
        pauser: P,
        context: X,
        signatures: Vec<Signature>,
        cfg: EngineConfig,
    ) -> Self {
        Self {
            chain,
            pauser,
            context,
            signatures,
            cfg,
            canonical: VecDeque::new(),
            pending: Vec::new(),
        }
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// The last block fully processed, if the engine has started.
    pub fn tip(&self) -> Option<&BlockHeader> {
        self.canonical.back()
    }

    pub async fn tick(&mut self) -> Result<TickReport, EngineError> {
        let mut report = TickReport::default();
        let head = self.chain.latest_block_number().await?;
        report.head = head;

        if self.canonical.is_empty() {
            // Start following from the current head; history before the
            // daemon started is not re-scanned.
            let h = self.chain.block_header(head).await?;
            tracing::info!(block = h.number, "engine started following chain");
            self.canonical.push_back(h);
            return Ok(report);
        }

        self.reconcile_reorg(&mut report).await?;
        self.process_new_blocks(head, &mut report).await?;
        self.drive_pending(head, &mut report).await;
        report.pending = self.pending.len();
        Ok(report)
    }

    /// Walks the tip back until it matches the chain again. Everything
    /// popped was reorged away; pending pauses in those blocks are dropped.
    async fn reconcile_reorg(&mut self, report: &mut TickReport) -> Result<(), EngineError> {
        let mut depth = 0u64;
        while let Some(tip) = self.canonical.back().cloned() {
            match self.chain.block_header(tip.number).await {
                Ok(h) if h.hash == tip.hash => break,
                Ok(_) | Err(ChainAdapterError::BlockNotFound(_)) => {
                    self.canonical.pop_back();
                    depth += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }
        if depth == 0 {
            return Ok(());
        }

        report.reorg_depth = Some(depth);
        tracing::warn!(depth, "chain reorganised; rewinding");

        if self.canonical.is_empty() {
            // Deeper than our memory: we can no longer prove which pending
            // decisions are still canonical. Cancel them (fail toward not
            // pausing on unverifiable evidence) and re-anchor at the head.
            tracing::error!(
                window = self.cfg.reorg_window,
                "reorg deeper than the tracked window; dropping pending pauses and re-anchoring"
            );
            report.dropped_by_reorg += self.pending.len();
            self.pending.clear();
            let head = self.chain.latest_block_number().await?;
            let h = self.chain.block_header(head).await?;
            self.canonical.push_back(h);
            return Ok(());
        }

        let before = self.pending.len();
        let canonical = &self.canonical;
        self.pending.retain(|p| {
            canonical
                .iter()
                .any(|b| b.number == p.block.number && b.hash == p.block.hash)
        });
        report.dropped_by_reorg += before - self.pending.len();
        Ok(())
    }

    async fn process_new_blocks(
        &mut self,
        head: u64,
        report: &mut TickReport,
    ) -> Result<(), EngineError> {
        let Some(tip) = self.canonical.back().map(|b| b.number) else {
            return Ok(());
        };
        let start = tip + 1;
        if head < start {
            return Ok(());
        }
        let end = head.min(start + self.cfg.max_blocks_per_tick - 1);

        for n in start..=end {
            let parent = self.canonical.back().cloned().expect("non-empty");
            // The header is read before *and* after the transactions, and
            // its parent must be our tip: if the chain moved underneath the
            // read, stop and let the next tick reconcile instead of scoring
            // a mix of two different blocks.
            let h1 = match self.chain.block_header(n).await {
                Ok(h) => h,
                Err(ChainAdapterError::BlockNotFound(_)) => break,
                Err(e) => return Err(e.into()),
            };
            if h1.parent_hash != parent.hash {
                break;
            }
            let events = self.chain.get_block_tx_events(n).await?;
            match self.chain.block_header(n).await {
                Ok(h2) if h2.hash == h1.hash => {}
                Ok(_) | Err(ChainAdapterError::BlockNotFound(_)) => break,
                Err(e) => return Err(e.into()),
            }

            self.evaluate_block(&h1, events, report).await;

            self.canonical.push_back(h1);
            while self.canonical.len() > self.cfg.reorg_window {
                self.canonical.pop_front();
            }
            report.blocks_processed += 1;
        }
        Ok(())
    }

    async fn evaluate_block(
        &mut self,
        header: &BlockHeader,
        events: Vec<TxEvent>,
        report: &mut TickReport,
    ) {
        for mut tx in events {
            if !touches_any(&tx, &self.cfg.watched_addresses) {
                continue;
            }
            self.context.enrich(&mut tx).await;
            let baseline = self.context.baseline(&tx).await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let decision = detection::evaluate(
                &self.signatures,
                self.cfg.chain_id,
                self.cfg.target,
                &tx,
                &baseline,
                self.cfg.threshold,
                now,
            );
            report.evaluated += 1;

            if !decision.matches.is_empty() {
                tracing::info!(
                    tx_hash = %tx.tx_hash,
                    block = header.number,
                    confidence = decision.confidence.value(),
                    threshold = decision.threshold.value(),
                    evidence = ?decision.counted_evidence,
                    "signature match"
                );
            }
            if decision.should_pause()
                && !self
                    .pending
                    .iter()
                    .any(|p| p.decision.triggering_tx_hash == decision.triggering_tx_hash)
            {
                tracing::warn!(
                    tx_hash = %tx.tx_hash,
                    block = header.number,
                    required_confirmations = self.cfg.min_confirmations,
                    "pause threshold crossed; awaiting confirmations"
                );
                self.pending.push(PendingPause {
                    decision,
                    block: header.clone(),
                    first_seen: Instant::now(),
                    attempts: 0,
                });
            }
        }
    }

    async fn drive_pending(&mut self, head: u64, report: &mut TickReport) {
        let pendings = std::mem::take(&mut self.pending);
        let mut still = Vec::new();
        for mut p in pendings {
            let canonical = self
                .canonical
                .iter()
                .any(|b| b.number == p.block.number && b.hash == p.block.hash);
            if !canonical {
                report.dropped_by_reorg += 1;
                tracing::warn!(tx = %p.decision.triggering_tx_hash, "pending pause cancelled: block reorged away");
                continue;
            }
            if head.saturating_sub(p.block.number) < self.cfg.min_confirmations {
                still.push(p);
                continue;
            }

            match self.pauser.is_paused(&self.cfg.target).await {
                Ok(true) => {
                    report.dropped_already_paused += 1;
                    tracing::info!(tx = %p.decision.triggering_tx_hash, "target already paused; nothing to do");
                    continue;
                }
                Ok(false) => {}
                // Can't tell: fail toward action. A redundant attempt costs
                // gas; a skipped pause costs the protocol.
                Err(e) => {
                    tracing::warn!(error = %e, "could not read paused state; attempting pause anyway")
                }
            }

            p.attempts += 1;
            tracing::warn!(tx = %p.decision.triggering_tx_hash, attempt = p.attempts, "PAUSING target");
            match self.pauser.submit_pause(&p.decision).await {
                Ok(pause_tx_hash) => {
                    let latency = p.first_seen.elapsed();
                    tracing::warn!(%pause_tx_hash, latency_ms = latency.as_millis() as u64, "pause confirmed");
                    report.pauses.push(PauseRecord {
                        pause_tx_hash,
                        triggering_tx_hash: p.decision.triggering_tx_hash.clone(),
                        latency,
                        attempts: p.attempts,
                    });
                }
                Err(e) => {
                    // Keep it: a failed pause must be retried, not forgotten.
                    report.pause_errors += 1;
                    tracing::error!(error = %e, attempt = p.attempts, "pause submission failed; will retry next tick");
                    still.push(p);
                }
            }
        }
        self.pending = still;
    }
}

/// Whether a transaction involves the protected contract in any way the
/// evidence available could show — not just when it is the direct `to`.
///
/// This matters: both real exploits replayed in this repo (Beanstalk, Euler)
/// were sent to an attacker's own contract, so filtering on `tx.to ==
/// target` would have missed them entirely. A transaction touches the target
/// if it is sent to/from it, any call frame involves it, or any log was
/// emitted by it or names it in a topic (an ERC-20 `Transfer` to or from the
/// target carries its address as an indexed topic).
pub fn touches_any(tx: &TxEvent, addresses: &[Address]) -> bool {
    addresses.iter().any(|a| touches_target(tx, a))
}

/// [`touches_any`] for a single address.
pub fn touches_target(tx: &TxEvent, target: &Address) -> bool {
    if tx.to.as_ref() == Some(target) || &tx.from == target {
        return true;
    }
    if tx
        .call_frames
        .iter()
        .any(|f| &f.to == target || &f.from == target)
    {
        return true;
    }
    let padded = format!("{:0>64}", target.to_string().trim_start_matches("0x"));
    tx.logs.iter().any(|l| {
        &l.address == target
            || l.topics
                .iter()
                .any(|t| t.trim_start_matches("0x").eq_ignore_ascii_case(&padded))
    })
}

#[cfg(test)]
mod tests;
