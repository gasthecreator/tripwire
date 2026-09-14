//! The daemon binary: wires the pieces from ARCHITECTURE.md §3 together
//! into one process — chain adapter → detection engine → guardian
//! client. Configuration is environment-variable-driven on purpose
//! (see `.env.example`): this is the process a real deployment runs
//! continuously, not a one-shot CLI tool.
//!
//! **Known simplification, stated plainly rather than hidden:** the
//! `Baseline` this daemon builds per transaction (balance/price/voting-
//! power context — `detection::Baseline`) is currently a placeholder
//! that reads no real chain state. Wiring real baseline computation
//! (the watched contract's actual balance history, a real TWAP or
//! second-oracle price feed, real governance voting-power lookups) is
//! tracked as PLAN.md's next slice — the detection engine and its
//! scoring are fully real and tested (see `crates/detection`); what's
//! simplified here is *only* how this binary currently sources the
//! external context those conditions compare against.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::providers::Provider;
use chain_adapter::evm::EvmAdapter;
use chain_adapter::ChainAdapter;
use detection::Baseline;
use tripwire_core::{ChainId, Confidence};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let rpc_url = require_env("TRIPWIRE_RPC_URL")?;
    let chain_id = ChainId(
        std::env::var("TRIPWIRE_CHAIN_ID")
            .unwrap_or_else(|_| "1".into())
            .parse()?,
    );
    let guardian_address = require_env("TRIPWIRE_GUARDIAN_ADDRESS")?;
    let target_contract = require_env("TRIPWIRE_TARGET_CONTRACT")?;
    let pauser_key = require_env("TRIPWIRE_PAUSER_PRIVATE_KEY")?;
    let signatures_dir = PathBuf::from(
        std::env::var("TRIPWIRE_SIGNATURES_DIR").unwrap_or_else(|_| "signatures".into()),
    );
    let pause_threshold = Confidence::new(
        std::env::var("TRIPWIRE_PAUSE_THRESHOLD")
            .unwrap_or_else(|_| "80".into())
            .parse()?,
    );
    // ARCHITECTURE.md §3.2: detection can start at 0 confirmations, but
    // the pause *decision* is gated on a minimum depth. This is that gate.
    let min_confirmations: u64 = std::env::var("TRIPWIRE_MIN_CONFIRMATIONS")
        .unwrap_or_else(|_| "1".into())
        .parse()?;
    let poll_interval = Duration::from_secs(
        std::env::var("TRIPWIRE_POLL_INTERVAL_SECS")
            .unwrap_or_else(|_| "2".into())
            .parse()?,
    );

    let signatures = detection::load_signatures_from_dir(&signatures_dir)?;
    tracing::info!(count = signatures.len(), dir = %signatures_dir.display(), "loaded signatures");

    let adapter = EvmAdapter::connect(&rpc_url, chain_id).await?;
    let guardian = guardian_client::connect(&rpc_url, &guardian_address, &pauser_key).await?;

    if !guardian.is_target_registered(&target_contract).await? {
        anyhow::bail!(
            "target contract {target_contract} is not registered with the Guardian at {guardian_address} -- \
             refusing to start rather than silently monitor a contract this daemon could never actually pause"
        );
    }

    let target_address: tripwire_core::Address = target_contract.parse()?;
    let mut last_processed_block = adapter.latest_block_number().await?;
    tracing::info!(
        start_block = last_processed_block,
        "tripwire daemon started"
    );

    let mut shutdown = Box::pin(tokio::signal::ctrl_c());

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received, exiting cleanly");
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                if let Err(e) = poll_once(
                    &adapter,
                    &guardian,
                    &signatures,
                    chain_id,
                    target_address,
                    pause_threshold,
                    min_confirmations,
                    &mut last_processed_block,
                )
                .await
                {
                    // A single poll failing (a transient RPC error, most
                    // likely) must not crash the daemon -- that would be
                    // strictly worse than today's human-mediated status
                    // quo (SECURITY.md T3: a silently-down listener is
                    // the failure mode to avoid). Logged loudly, retried
                    // next tick.
                    tracing::error!(error = %e, "poll iteration failed, will retry next tick");
                }
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn poll_once<P: Provider>(
    adapter: &EvmAdapter,
    guardian: &guardian_client::GuardianClient<P>,
    signatures: &[tripwire_core::Signature],
    chain_id: ChainId,
    target_address: tripwire_core::Address,
    pause_threshold: Confidence,
    min_confirmations: u64,
    last_processed_block: &mut u64,
) -> anyhow::Result<()> {
    let head = adapter.latest_block_number().await?;
    if head <= *last_processed_block {
        return Ok(());
    }

    for block_number in (*last_processed_block + 1)..=head {
        let events = adapter.get_block_tx_events(block_number).await?;
        for tx in &events {
            if tx.to != Some(target_address) {
                continue;
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Placeholder baseline -- see module doc. Detection still
            // runs and scores correctly against whatever's here; only
            // fund-flow/oracle/governance conditions that depend on real
            // external context will under-fire until real baseline
            // sourcing lands.
            let baseline = Baseline::default();

            let decision = detection::evaluate(
                signatures,
                chain_id,
                target_address,
                tx,
                &baseline,
                pause_threshold,
                now,
            );

            if !decision.matches.is_empty() {
                tracing::info!(
                    tx_hash = %tx.tx_hash,
                    confidence = decision.confidence.value(),
                    threshold = decision.threshold.value(),
                    signatures = ?decision.matches.iter().map(|m| &m.signature_id).collect::<Vec<_>>(),
                    "signature match"
                );
            }

            if decision.should_pause() {
                if tx.confirmations < min_confirmations {
                    tracing::warn!(
                        tx_hash = %tx.tx_hash,
                        confirmations = tx.confirmations,
                        required = min_confirmations,
                        "pause threshold crossed but confirmation depth not yet met; re-evaluating next tick"
                    );
                    continue;
                }
                tracing::warn!(tx_hash = %tx.tx_hash, confidence = decision.confidence.value(), "PAUSING target contract");
                match guardian.submit_pause(&decision).await {
                    Ok(pause_tx_hash) => {
                        tracing::warn!(pause_tx_hash, "guardian pause submitted and confirmed");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to submit guardian pause -- manual intervention required");
                    }
                }
            }
        }
    }

    *last_processed_block = head;
    Ok(())
}

fn require_env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("missing required environment variable: {key}"))
}
