//! The daemon binary: wires the real chain adapter and Guardian client into
//! the reorg-aware engine (`tripwire_daemon::engine`) and ticks it.
//!
//! Configuration is environment-driven (see `.env.example`); this is the
//! process a deployment runs continuously.

use std::path::PathBuf;
use std::time::Duration;

use chain_adapter::evm::EvmAdapter;
use tripwire_core::{ChainId, Confidence};
use tripwire_daemon::{Engine, EngineConfig, NoContext};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let rpc_url = require_env("TRIPWIRE_RPC_URL")?;
    let chain_id = ChainId(env_or("TRIPWIRE_CHAIN_ID", "1").parse()?);
    let guardian_address = require_env("TRIPWIRE_GUARDIAN_ADDRESS")?;
    let target_contract = require_env("TRIPWIRE_TARGET_CONTRACT")?;
    let pauser_key = require_env("TRIPWIRE_PAUSER_PRIVATE_KEY")?;
    let signatures_dir = PathBuf::from(env_or("TRIPWIRE_SIGNATURES_DIR", "signatures"));
    let poll_interval = Duration::from_millis(env_or("TRIPWIRE_POLL_INTERVAL_MS", "2000").parse()?);

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

    let mut cfg = EngineConfig::new(
        chain_id,
        target_contract.parse()?,
        Confidence::new(env_or("TRIPWIRE_PAUSE_THRESHOLD", "80").parse()?),
    );
    cfg.min_confirmations = env_or("TRIPWIRE_MIN_CONFIRMATIONS", "1").parse()?;
    cfg.reorg_window = env_or("TRIPWIRE_REORG_WINDOW", "64").parse()?;
    cfg.max_blocks_per_tick = env_or("TRIPWIRE_MAX_BLOCKS_PER_TICK", "32").parse()?;

    let mut engine = Engine::new(adapter, guardian, NoContext, signatures, cfg);
    tracing::info!(?poll_interval, "tripwire daemon started");

    let mut shutdown = Box::pin(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received, exiting cleanly");
                return Ok(());
            }
            _ = tokio::time::sleep(poll_interval) => {
                // A failed tick (a transient RPC error, most likely) must not
                // crash the daemon: that would be strictly worse than the
                // human-mediated status quo (SECURITY.md T3). Engine state is
                // only advanced per fully-read block, so the retry is safe.
                match engine.tick().await {
                    Ok(r) if r.blocks_processed > 0 || !r.pauses.is_empty() || r.reorg_depth.is_some() => {
                        tracing::info!(?r, "tick");
                    }
                    Ok(r) => tracing::debug!(head = r.head, pending = r.pending, "tick"),
                    Err(e) => tracing::error!(error = %e, "tick failed, will retry"),
                }
            }
        }
    }
}

fn require_env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("missing required environment variable: {key}"))
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}
