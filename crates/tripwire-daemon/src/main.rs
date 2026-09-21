//! The daemon binary: wires the real chain adapter and Guardian client into
//! the reorg-aware engine (`tripwire_daemon::engine`) and ticks it.
//!
//! Configuration is environment-driven (see `.env.example`); this is the
//! process a deployment runs continuously.

use std::path::PathBuf;
use std::time::Duration;

use chain_adapter::evm::EvmAdapter;
use std::sync::Arc;
use tripwire_context::{ContextConfig, EvmContext, TraceFallback};
use tripwire_core::{Address, ChainId, Confidence};
use tripwire_daemon::health::{
    self, Alert, Health, HealthConfig, LogNotifier, Notifier, Severity, TickOutcome,
    WebhookNotifier,
};
use tripwire_daemon::{Engine, EngineConfig};

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
    let policy = guardian_client::SubmitPolicy {
        priority_fee_multiplier_pct: env_or("TRIPWIRE_PAUSE_PRIORITY_MULTIPLIER_PCT", "200")
            .parse()?,
        min_priority_fee_wei: gwei_to_wei(&env_or("TRIPWIRE_PAUSE_MIN_PRIORITY_GWEI", "2"))?,
        max_fee_ceiling_wei: gwei_to_wei(&env_or("TRIPWIRE_PAUSE_MAX_FEE_GWEI", "500"))?,
        attempt_timeout: Duration::from_secs(
            env_or("TRIPWIRE_PAUSE_ATTEMPT_TIMEOUT_SECS", "6").parse()?,
        ),
        max_attempts: env_or("TRIPWIRE_PAUSE_MAX_ATTEMPTS", "6").parse()?,
        ..Default::default()
    };
    tracing::info!(?policy, "pause submission policy");
    let guardian = guardian_client::connect(&rpc_url, &guardian_address, &pauser_key)
        .await?
        .with_policy(policy);

    if !guardian.is_target_registered(&target_contract).await? {
        anyhow::bail!(
            "target contract {target_contract} is not registered with the Guardian at {guardian_address} -- \
             refusing to start rather than silently monitor a contract this daemon could never actually pause"
        );
    }

    let target: Address = target_contract.parse()?;
    let mut cfg = EngineConfig::new(
        chain_id,
        target,
        Confidence::new(env_or("TRIPWIRE_PAUSE_THRESHOLD", "80").parse()?),
    );
    cfg.min_confirmations = env_or("TRIPWIRE_MIN_CONFIRMATIONS", "1").parse()?;
    cfg.reorg_window = env_or("TRIPWIRE_REORG_WINDOW", "64").parse()?;
    cfg.max_blocks_per_tick = env_or("TRIPWIRE_MAX_BLOCKS_PER_TICK", "32").parse()?;

    // What the protocol custodies. Without this the fund-flow conditions
    // (the "harm" evidence a pause needs) can never be satisfied, and the
    // daemon can only act on call-pattern evidence, which by design stays
    // below the pause threshold. So refuse to run silently blind.
    let watched_tokens = parse_addresses(&env_or("TRIPWIRE_WATCHED_TOKENS", ""))?;
    let extra_holders = parse_addresses(&env_or("TRIPWIRE_EXTRA_HOLDERS", ""))?;
    let protocol_contracts = parse_addresses(&env_or("TRIPWIRE_PROTOCOL_CONTRACTS", ""))?;
    let watch_native = env_or("TRIPWIRE_WATCH_NATIVE", "false").parse::<bool>()?;
    if watched_tokens.is_empty() && !watch_native {
        tracing::warn!(
            "TRIPWIRE_WATCHED_TOKENS is empty and TRIPWIRE_WATCH_NATIVE is false: fund-flow evidence is \
             disabled, so this daemon can essentially never reach the pause threshold"
        );
    }

    let mut holders = vec![target];
    holders.extend(extra_holders);
    cfg.watched_addresses = holders.clone();

    let mut ctx_cfg = ContextConfig::new(target);
    ctx_cfg.holders = holders;
    ctx_cfg.watched_tokens = watched_tokens;
    ctx_cfg.protocol_contracts = protocol_contracts;
    ctx_cfg.watch_native = watch_native;
    ctx_cfg.track_amm_prices = env_or("TRIPWIRE_TRACK_AMM_PRICES", "true").parse::<bool>()?;
    ctx_cfg.trace_fallback = match env_or("TRIPWIRE_TRACE_FALLBACK", "none").as_str() {
        "none" => TraceFallback::None,
        "cast_run" => TraceFallback::CastRun {
            rpc_url: rpc_url.clone(),
            timeout: Duration::from_secs(env_or("TRIPWIRE_TRACE_TIMEOUT_SECS", "90").parse()?),
        },
        other => {
            anyhow::bail!("TRIPWIRE_TRACE_FALLBACK must be `none` or `cast_run`, got `{other}`")
        }
    };
    let context = EvmContext::connect(&rpc_url, ctx_cfg).map_err(anyhow::Error::msg)?;

    let mut engine = Engine::new(adapter, guardian, context, signatures, cfg);
    tracing::info!(?poll_interval, "tripwire daemon started");

    // --- liveness, metrics, alerting (SECURITY.md T3) ---------------------
    let health = Arc::new(Health::new(
        HealthConfig {
            stale_after: Duration::from_secs(env_or("TRIPWIRE_STALE_AFTER_SECS", "30").parse()?),
            chain_stall_after: Duration::from_secs(
                env_or("TRIPWIRE_CHAIN_STALL_AFTER_SECS", "300").parse()?,
            ),
            max_consecutive_failures: env_or("TRIPWIRE_MAX_TICK_FAILURES", "5").parse()?,
        },
        health::unix_now(),
    ));
    let notifier: Arc<dyn Notifier> = match env_or("TRIPWIRE_ALERT_WEBHOOK_URL", "").as_str() {
        "" => {
            tracing::warn!(
                "TRIPWIRE_ALERT_WEBHOOK_URL is unset: liveness alerts go to the logs only"
            );
            Arc::new(LogNotifier)
        }
        url => Arc::new(WebhookNotifier::new(url.to_string())),
    };
    let metrics_addr = env_or("TRIPWIRE_METRICS_ADDR", "127.0.0.1:9464");
    if !metrics_addr.is_empty() {
        let h = health.clone();
        tokio::spawn(async move {
            if let Err(e) = health::serve(&metrics_addr, h).await {
                tracing::error!(error = %e, "health endpoint stopped");
            }
        });
    }
    // The watchdog runs in its own task on purpose: if a tick hangs, the main
    // loop cannot report it, but this task still can.
    {
        let (h, n) = (health.clone(), notifier.clone());
        let mut w = health::Watchdog::new(Duration::from_secs(
            env_or("TRIPWIRE_ALERT_REMINDER_SECS", "600").parse()?,
        ));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let now = health::unix_now();
                if let Some(a) = w.observe(&h.status(now), now) {
                    n.notify(&a).await;
                }
            }
        });
    }
    // Longer than the worst-case pause submission (attempts x timeout), so a
    // legitimately slow pause is not cancelled; a genuinely hung RPC call is.
    let tick_timeout = Duration::from_secs(env_or("TRIPWIRE_TICK_TIMEOUT_SECS", "120").parse()?);

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
                match tokio::time::timeout(tick_timeout, engine.tick()).await {
                    Ok(Ok(r)) => {
                        health.record_ok(health::unix_now(), &TickOutcome {
                            head: r.head,
                            blocks_processed: r.blocks_processed,
                            pauses: r.pauses.len(),
                            pause_errors: r.pause_errors,
                            reorged: r.reorg_depth.is_some(),
                        });
                        for p in &r.pauses {
                            notifier.notify(&Alert {
                                severity: Severity::Critical,
                                kind: "paused".into(),
                                message: format!(
                                    "PAUSED {target_contract}: pause tx {} for triggering tx {} ({} ms)",
                                    p.pause_tx_hash, p.triggering_tx_hash, p.latency.as_millis()
                                ),
                                unix: health::unix_now(),
                            }).await;
                        }
                        if r.blocks_processed > 0 || !r.pauses.is_empty() || r.reorg_depth.is_some() {
                            tracing::info!(?r, "tick");
                        } else {
                            tracing::debug!(head = r.head, pending = r.pending, "tick");
                        }
                    }
                    Ok(Err(e)) => {
                        health.record_err(&e.to_string());
                        tracing::error!(error = %e, "tick failed, will retry");
                    }
                    Err(_) => {
                        health.record_timeout();
                        tracing::error!(?tick_timeout, "tick timed out, will retry");
                    }
                }
            }
        }
    }
}

fn require_env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("missing required environment variable: {key}"))
}

fn parse_addresses(csv: &str) -> anyhow::Result<Vec<Address>> {
    csv.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<Address>()
                .map_err(|e| anyhow::anyhow!("bad address `{s}`: {e}"))
        })
        .collect()
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}

/// Parses a (possibly fractional) gwei amount into wei.
fn gwei_to_wei(s: &str) -> anyhow::Result<u128> {
    let g: f64 = s.trim().parse()?;
    anyhow::ensure!(
        g.is_finite() && g >= 0.0,
        "gwei amount must be finite and non-negative: {s}"
    );
    Ok((g * 1e9).round() as u128)
}
