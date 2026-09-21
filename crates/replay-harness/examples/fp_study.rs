//! False-positive study: how often would the shipped detector, as configured
//! for a real protocol, wrongly pause it on *legitimate* traffic?
//!
//! Method (see the generated report for numbers and caveats):
//! 1. For each protocol, discover its custody contracts and assets on-chain
//!    (Aave V2 aTokens, Compound V2 cTokens, Curve 3pool).
//! 2. Draw a seeded random sample of 10-block windows across a historical
//!    range and collect every ERC-20 transfer *out of* those contracts.
//!    Each distinct transaction is one member of the population — anything
//!    that cannot move funds out of the protocol cannot pause it (a pause
//!    needs a harm fact; enforced by a test), so this is exactly the
//!    population that matters.
//! 3. Score each with the production context source and the shipped
//!    signatures. Only transactions that already have a fund-flow fact but
//!    haven't crossed the threshold could still be pushed over by a
//!    call-pattern fact, so only those get a call trace (`cast run`), capped
//!    per protocol; the cap is reported.
//!
//! Run:  ETH_RPC_URL=... cargo run --release -p replay-harness --example fp_study
//! Knobs (env): FP_SEED, FP_WINDOWS, FP_LO, FP_HI, FP_TRACE_CAP, FP_OUT.

use std::collections::BTreeMap;
use std::sync::Arc;

use alloy::primitives::{Address as AAddress, B256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::Filter;
use alloy::sol;
use chain_adapter::evm::EvmAdapter;
use detection::ContextSource;
use replay_harness::study::{self, Outcome};
use replay_harness::{cast_trace, support};
use tokio::task::JoinSet;
use tripwire_context::{ContextConfig, EvmContext};
use tripwire_core::{Address, ChainId, Confidence, PauseDecision, Signature, TxEvent};

sol! {
    #[sol(rpc)]
    interface IAaveV2Pool {
        function getReservesList() external view returns (address[] memory);
        struct ReserveData {
            uint256 configuration;
            uint128 liquidityIndex;
            uint128 variableBorrowIndex;
            uint128 currentLiquidityRate;
            uint128 currentVariableBorrowRate;
            uint128 currentStableBorrowRate;
            uint40 lastUpdateTimestamp;
            address aTokenAddress;
            address stableDebtTokenAddress;
            address variableDebtTokenAddress;
            address interestRateStrategyAddress;
            uint8 id;
        }
        function getReserveData(address asset) external view returns (ReserveData memory);
    }
    #[sol(rpc)]
    interface IComptroller { function getAllMarkets() external view returns (address[] memory); }
    #[sol(rpc)]
    interface ICToken { function underlying() external view returns (address); }
    #[sol(rpc)]
    interface ICurve3Pool { function coins(uint256 i) external view returns (address); }
    #[sol(rpc)]
    interface IErc20Meta { function decimals() external view returns (uint8); }
}

const TRANSFER: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const AAVE_V2_POOL: &str = "0x7d2768dE32b0b80b7a3454c06BdAC94A69DDc7A9";
const COMPOUND_COMPTROLLER: &str = "0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B";
const CURVE_3POOL: &str = "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7";
const LOG_CONCURRENCY: usize = 3;
const LOG_ATTEMPTS: u32 = 8;
const CONCURRENCY: usize = 4;

struct Protocol {
    name: &'static str,
    holders: Vec<AAddress>,
    tokens: Vec<AAddress>,
}

struct Sampled {
    outcome: Outcome,
    tx: TxEvent,
    baseline: detection::Baseline,
}

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

fn core(a: &AAddress) -> Address {
    a.to_string().parse().unwrap()
}

async fn discover(p: &RootProvider) -> Vec<Protocol> {
    let mut out = Vec::new();

    let pool = IAaveV2Pool::new(AAVE_V2_POOL.parse().unwrap(), p);
    let reserves = pool.getReservesList().call().await.expect("aave reserves");
    let mut holders = Vec::new();
    for r in &reserves {
        holders.push(
            pool.getReserveData(*r)
                .call()
                .await
                .expect("reserve data")
                .aTokenAddress,
        );
    }
    out.push(Protocol {
        name: "Aave V2",
        holders,
        tokens: reserves,
    });

    let comp = IComptroller::new(COMPOUND_COMPTROLLER.parse().unwrap(), p);
    let markets = comp.getAllMarkets().call().await.expect("compound markets");
    let (mut holders, mut tokens) = (Vec::new(), Vec::new());
    for m in markets {
        // cETH has no `underlying()`: native ETH is out of scope for this
        // ERC-20 study (it needs traces for every transaction).
        if let Ok(u) = ICToken::new(m, p).underlying().call().await {
            holders.push(m);
            tokens.push(u);
        }
    }
    out.push(Protocol {
        name: "Compound V2",
        holders,
        tokens,
    });

    let curve = ICurve3Pool::new(CURVE_3POOL.parse().unwrap(), p);
    let mut coins = Vec::new();
    for i in 0..3u64 {
        coins.push(
            curve
                .coins(alloy::primitives::U256::from(i))
                .call()
                .await
                .expect("coin"),
        );
    }
    out.push(Protocol {
        name: "Curve 3pool",
        holders: vec![CURVE_3POOL.parse().unwrap()],
        tokens: coins,
    });
    out
}

fn padded(a: &AAddress) -> B256 {
    B256::left_padding_from(a.as_slice())
}

async fn collect_tx_hashes(
    p: &RootProvider,
    proto: &Protocol,
    windows: &[(u64, u64)],
) -> (BTreeMap<String, u64>, usize) {
    let topic1: Vec<B256> = proto.holders.iter().map(padded).collect();
    let mut txs = BTreeMap::new();
    let mut failed = 0usize;
    let mut set = JoinSet::new();
    let mut queue: Vec<(u64, u64)> = windows.to_vec();
    queue.reverse();
    loop {
        while set.len() < LOG_CONCURRENCY {
            let Some((from, to)) = queue.pop() else { break };
            let (p, tokens, topic1) = (p.clone(), proto.tokens.clone(), topic1.clone());
            set.spawn(async move {
                let filter = Filter::new()
                    .from_block(from)
                    .to_block(to)
                    .address(tokens)
                    .event_signature(TRANSFER.parse::<B256>().unwrap())
                    .topic1(topic1);
                // Exponential backoff: rate limiting (429) is expected on a
                // metered endpoint and must never silently thin the sample.
                let mut delay = 250u64;
                for attempt in 0..LOG_ATTEMPTS {
                    match p.get_logs(&filter).await {
                        Ok(logs) => return Some(logs),
                        Err(e) if attempt + 1 == LOG_ATTEMPTS => {
                            eprintln!("  window {from}-{to}: getLogs failed: {e}")
                        }
                        Err(_) => {
                            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                            delay = (delay * 2).min(8_000);
                        }
                    }
                }
                None
            });
        }
        match set.join_next().await {
            Some(Ok(Some(logs))) => {
                for l in logs {
                    if let (Some(h), Some(b)) = (l.transaction_hash, l.block_number) {
                        txs.insert(format!("{h:#x}"), b);
                    }
                }
            }
            Some(Ok(None)) | Some(Err(_)) => failed += 1,
            None => break,
        }
    }
    (txs, failed)
}

fn evaluate(
    sigs: &[Signature],
    tx: &TxEvent,
    baseline: &detection::Baseline,
    target: Address,
) -> PauseDecision {
    detection::evaluate(
        sigs,
        ChainId::ETHEREUM_MAINNET,
        target,
        tx,
        baseline,
        Confidence::new(80.0),
        tx.timestamp_unix,
    )
}

#[tokio::main]
async fn main() {
    let Some(rpc) = support::rpc_url_or_skip() else {
        return;
    };
    let seed = env_u64("FP_SEED", 20_260_921);
    let n_windows = env_u64("FP_WINDOWS", 2_500) as usize;
    let lo = env_u64("FP_LO", 17_000_000);
    let hi = env_u64("FP_HI", 20_500_000);
    let trace_cap = env_u64("FP_TRACE_CAP", 10) as usize;
    let netting = env_u64("FP_NETTING", 1) != 0;
    let out_path = std::env::var("FP_OUT").unwrap_or_else(|_| "docs/FALSE_POSITIVES.md".into());

    // Retry with backoff on 429/transient errors: this runs against a metered
    // endpoint and a thinned sample is worse than a slow one.
    let client = alloy::rpc::client::ClientBuilder::default()
        .layer(alloy::transports::layers::RetryBackoffLayer::new(
            12, 500, 300,
        ))
        .http(rpc.parse().unwrap());
    let provider = ProviderBuilder::new()
        .disable_recommended_fillers()
        .connect_client(client);
    let adapter = Arc::new(
        EvmAdapter::connect(&rpc, ChainId::ETHEREUM_MAINNET)
            .await
            .unwrap(),
    );
    let sigs = Arc::new(support::shipped_signatures());

    println!("discovering protocols on-chain...");
    let protocols = discover(&provider).await;

    let mut incomplete = false;
    let mut trace_notes: Vec<String> = Vec::new();
    let mut all_outcomes: Vec<Outcome> = Vec::new();
    let mut summaries = Vec::new();
    let mut paused_details: Vec<String> = Vec::new();
    let mut candidate_details: Vec<String> = Vec::new();

    for proto in &protocols {
        let windows = study::sample_windows(seed ^ proto.name.len() as u64, lo, hi, n_windows, 10);
        let blocks_sampled = windows.iter().map(|(a, b)| b - a + 1).sum::<u64>();
        println!(
            "\n== {} ({} holders, {} tokens): {} windows",
            proto.name,
            proto.holders.len(),
            proto.tokens.len(),
            windows.len()
        );
        let (txs, failed_windows) = collect_tx_hashes(&provider, proto, &windows).await;
        if failed_windows > 0 {
            eprintln!("   INCOMPLETE: {failed_windows} windows could not be fetched");
            incomplete = true;
        }
        println!("   {} distinct transactions with an outflow", txs.len());

        let mut cfg = ContextConfig::new(core(&proto.holders[0]));
        cfg.holders = proto.holders.iter().map(core).collect();
        cfg.watched_tokens = proto.tokens.iter().map(core).collect();
        // The protocol's own core contracts, so callback re-entry across
        // them is measurable (they hold no watched balance themselves).
        cfg.protocol_contracts = match proto.name {
            "Aave V2" => vec![AAVE_V2_POOL.parse().unwrap()],
            "Compound V2" => vec![COMPOUND_COMPTROLLER.parse().unwrap()],
            _ => vec![],
        };
        // Value netting (default): a swap or a collateral-backed borrow is not
        // a drain. Aave and Compound are valued by their own oracles at the
        // block before each transaction; Curve 3pool's stablecoins at $1.
        if netting {
            let valuer: Arc<dyn tripwire_context::TokenValuer> = match proto.name {
                "Aave V2" => Arc::new(
                    tripwire_context::AaveV2Oracle::connect(&rpc, &AAVE_V2_POOL.parse().unwrap())
                        .await
                        .expect("aave oracle"),
                ),
                "Compound V2" => {
                    let map = proto
                        .tokens
                        .iter()
                        .zip(&proto.holders)
                        .map(|(t, h)| (core(t), core(h)))
                        .collect();
                    Arc::new(
                        tripwire_context::CompoundOracle::connect(
                            &rpc,
                            &COMPOUND_COMPTROLLER.parse().unwrap(),
                            map,
                        )
                        .await
                        .expect("compound oracle"),
                    )
                }
                _ => {
                    let mut f = tripwire_context::FixedValues::new();
                    for t in &proto.tokens {
                        let d = IErc20Meta::new(*t, &provider)
                            .decimals()
                            .call()
                            .await
                            .expect("decimals");
                        f = f.with_stable(core(t), d);
                    }
                    Arc::new(f)
                }
            };
            cfg.valuer = Some(valuer);
        }
        let ctx = Arc::new(EvmContext::connect(&rpc, cfg).unwrap());
        let target = core(&proto.holders[0]);

        // Tier 1: cheap, concurrent, no traces.
        let mut set = JoinSet::new();
        let mut sampled: Vec<Sampled> = Vec::new();
        let mut pending: Vec<(String, u64)> = txs.into_iter().collect();
        let name = proto.name.to_string();
        let mut done = 0usize;
        let total = pending.len();
        loop {
            while set.len() < CONCURRENCY {
                let Some((hash, block)) = pending.pop() else {
                    break;
                };
                let (adapter, ctx, sigs, name) =
                    (adapter.clone(), ctx.clone(), sigs.clone(), name.clone());
                set.spawn(async move {
                    let mut tx = None;
                    let mut last_err = String::new();
                    let mut delay = 250u64;
                    for _ in 0..LOG_ATTEMPTS {
                        match adapter.get_tx_event(&hash).await {
                            Ok(t) => {
                                tx = Some(t);
                                break;
                            }
                            Err(e) => {
                                last_err = e.to_string();
                                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                                delay = (delay * 2).min(8_000);
                            }
                        }
                    }
                    let Some(tx) = tx else {
                        eprintln!("   get_tx_event({hash}) failed: {last_err}");
                        return None;
                    };
                    let baseline = ctx.baseline(&tx).await;
                    let d = evaluate(&sigs, &tx, &baseline, target);
                    let fraction = if baseline.balance_baseline_wei == 0 {
                        0.0
                    } else {
                        baseline.outflow_wei as f64 / baseline.balance_baseline_wei as f64
                    };
                    let keys: Vec<String> =
                        d.counted_evidence.iter().map(|e| e.key.clone()).collect();
                    Some(Sampled {
                        outcome: Outcome {
                            protocol: name,
                            tx_hash: hash,
                            block,
                            max_outflow_fraction: fraction,
                            had_harm_fact: keys.iter().any(|k| k == "fund_flow"),
                            traced: false,
                            confidence: d.confidence.value(),
                            paused: d.should_pause(),
                            evidence_keys: keys,
                        },
                        tx,
                        baseline,
                    })
                });
            }
            match set.join_next().await {
                Some(Ok(Some(s))) => sampled.push(s),
                Some(_) => {
                    eprintln!("   INCOMPLETE: a transaction could not be fetched/scored");
                    incomplete = true;
                }
                None => break,
            }
            done += 1;
            if done.is_multiple_of(200) {
                println!("   scored {done}/{total}");
            }
        }

        // Tier 2: transactions with a harm fact that haven't paused could be
        // pushed over by a call-pattern fact; trace the largest, capped.
        let mut cand: Vec<usize> = sampled
            .iter()
            .enumerate()
            .filter(|(_, s)| s.outcome.had_harm_fact && !s.outcome.paused)
            .map(|(i, _)| i)
            .collect();
        cand.sort_by(|&a, &b| {
            sampled[b]
                .outcome
                .max_outflow_fraction
                .partial_cmp(&sampled[a].outcome.max_outflow_fraction)
                .unwrap()
        });
        let capped = cand.len() > trace_cap;
        println!(
            "   {} candidates with a fund-flow fact ({}traced: {})",
            cand.len(),
            if capped { "capped, " } else { "" },
            cand.len().min(trace_cap)
        );
        let budget = std::time::Duration::from_secs(env_u64("FP_TRACE_BUDGET_SECS", 1_200));
        let started = std::time::Instant::now();
        let (mut n_traced, mut n_failed, mut n_out_of_time) = (0usize, 0usize, 0usize);
        for &i in cand.iter().take(trace_cap) {
            if started.elapsed() > budget {
                n_out_of_time += 1;
                continue;
            }
            let s = &mut sampled[i];
            // Retry: a transient failure (rate limit, dropped connection)
            // should not leave a candidate untraced -- it could have been the
            // one that pauses.
            let mut traced = cast_trace::fetch_frames(&s.outcome.tx_hash, &rpc);
            for _ in 0..2 {
                if traced.is_ok() {
                    break;
                }
                traced = cast_trace::fetch_frames(&s.outcome.tx_hash, &rpc);
            }
            match traced {
                Ok(frames) => {
                    s.tx.call_frames = frames;
                    let d = evaluate(&sigs, &s.tx, &s.baseline, target);
                    s.outcome.traced = true;
                    n_traced += 1;
                    s.outcome.confidence = d.confidence.value();
                    s.outcome.paused = d.should_pause();
                    s.outcome.evidence_keys =
                        d.counted_evidence.iter().map(|e| e.key.clone()).collect();
                }
                Err(e) => {
                    // Counted and reported, not hidden: this candidate is
                    // untraced and could in principle have paused.
                    eprintln!("   trace failed for {}: {e}", s.outcome.tx_hash);
                    n_failed += 1;
                }
            }
        }
        let beyond_cap = cand.len().saturating_sub(trace_cap);
        trace_notes.push(format!(
            "  - {}: {} candidates below the threshold with a fund-flow fact; {} traced; {} untraced ({} beyond the cap of {}, {} failed after retries, {} skipped after the {}s time budget).",
            proto.name, cand.len(), n_traced, cand.len() - n_traced, beyond_cap, trace_cap, n_failed, n_out_of_time, budget.as_secs()
        ));
        for s in sampled
            .iter()
            .filter(|s| s.outcome.traced || s.outcome.paused)
        {
            let line = format!(
                "- [{}](https://etherscan.io/tx/{}) block {} — worst-asset outflow {:.1}% of balance, confidence {:.0}, **{}**, evidence: `{}`",
                &s.outcome.tx_hash[..12], s.outcome.tx_hash, s.outcome.block,
                s.outcome.max_outflow_fraction * 100.0, s.outcome.confidence,
                if s.outcome.paused { "WOULD PAUSE" } else { "no pause" },
                s.outcome.evidence_keys.join(", ")
            );
            if s.outcome.paused {
                paused_details.push(format!("{} — {}", proto.name, line));
            }
            candidate_details.push(format!("{} — {}", proto.name, line));
        }

        let outcomes: Vec<Outcome> = sampled.into_iter().map(|s| s.outcome).collect();
        summaries.push(study::summarize(proto.name, blocks_sampled, &outcomes));
        all_outcomes.extend(outcomes);
    }

    let table = study::render_summary_table(&summaries);
    let b = study::fraction_buckets(&all_outcomes);
    println!("\n{table}\nbuckets <1% / 1-5% / 5-20% / 20-50% / >=50%: {b:?}");

    let report = format!(
"# False-positive study

*Generated by `cargo run --release -p replay-harness --example fp_study` on a real archive node. Do not edit by hand; rerun to regenerate. Reproducible from the seed given the same chain.*

## Question

If the shipped detector, configured for a real protocol, ran on that protocol's ordinary traffic, how often would it wrongly pause it?

## Method

- **Protocols** (discovered on-chain, not hard-coded): Aave V2 (every reserve's aToken as a custody contract, underlying as the watched asset), Compound V2 (every cToken with an ERC-20 underlying), Curve 3pool.
- **Sample:** {n_windows} seeded-random windows of 10 blocks per protocol, drawn from blocks {lo}–{hi} (seed {seed}). For each, every ERC-20 transfer *out of* the protocol's custody contracts is collected; each distinct transaction is one member of the population.
- **Why only transactions with an outflow:** a pause requires a fund-flow (\"harm\") fact — enforced by a test on the shipped signatures — so a transaction that moves nothing out of the protocol cannot pause it, whatever else it does.
- **Scoring:** the production `tripwire-context` baseline (real balances at the previous block, {netting_desc}, Uniswap-V2 price movement) and the **shipped, un-tuned signatures** at the default threshold of 80.
- **Traces:** only transactions that already have a fund-flow fact but sit below the threshold could be pushed over by a call-pattern fact (flash-loan entrypoint, re-entry), so only those were traced with `cast run`, largest first, capped at {trace_cap} per protocol.

## Results

{table}
Distribution of the largest single-asset outflow fraction over all sampled transactions — <1%: {b0}, 1–5%: {b1}, 5–20%: {b2}, 20–50%: {b3}, ≥50%: {b4}.

## Transactions the detector would have paused

{paused}

## Every transaction that was traced

{cands}

## Limits — read before quoting a number

- The sample is windows, not every block; the rate is an estimate with the interval shown. A zero count is an upper bound, not proof of zero.
- Custody-contract configuration is one reasonable choice per protocol; a differently configured deployment will see different fractions.
- Tracing is bounded (cap, time budget, failures). Untraced candidates could in principle have paused; per protocol:\n{trace_notes}
- Native ETH outflows and non-Uniswap-V2 price movement are out of scope here.
- Legitimate traffic is drawn from history that may contain a small number of exploit transactions; any \"would pause\" above should be read individually.
- Three real exploits are detected by the same configuration (see `PLAN.md`); three is not a recall estimate.
",
        n_windows = n_windows, lo = lo, hi = hi, seed = seed, trace_cap = trace_cap,
        table = table,
        netting_desc = if netting { "fund flow measured as net *value* lost across all the protocol's watched assets, valued at the block before each transaction: Aave V2 and Compound V2 by their own oracles, Curve 3pool's stablecoins at $1" } else { "ERC-20 logs net of inflows, one asset at a time" },
        trace_notes = trace_notes.join("\n"),
        b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4],
        paused = if paused_details.is_empty() { "None in the sample.".to_string() } else { paused_details.join("\n") },
        cands = if candidate_details.is_empty() { "None.".to_string() } else { candidate_details.join("\n") },
    );
    if incomplete {
        // Never publish numbers from a run that silently lost data.
        let bad = format!("{out_path}.incomplete");
        std::fs::write(&bad, report).unwrap();
        eprintln!("run INCOMPLETE; wrote {bad}, left {out_path} untouched");
        std::process::exit(1);
    }
    std::fs::write(&out_path, report).unwrap();
    println!("wrote {out_path}");
}
