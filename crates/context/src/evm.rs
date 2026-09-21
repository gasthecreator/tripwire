//! The RPC-backed [`ContextSource`]: real balances and pool reserves as of
//! the block *before* a transaction, combined with what the transaction
//! itself shows (its logs and call trace) to produce a [`Baseline`].
//!
//! Everything fails closed: if a balance or reserve can't be fetched, the
//! corresponding baseline field stays unset, so the condition that needs it
//! is simply not satisfied — a missing number is never guessed.

use std::collections::HashMap;
use std::time::Duration;

use alloy::eips::BlockId;
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::sol;
use async_trait::async_trait;
use detection::{Baseline, ContextSource};
use tokio::sync::Mutex;
use tripwire_core::{Address, TxEvent};

use crate::amm;
use crate::cast_trace;
use crate::outflow::{self, AssetFlow};

sol! {
    #[sol(rpc)]
    interface IERC20Balance {
        function balanceOf(address owner) external view returns (uint256);
    }

    #[sol(rpc)]
    interface IUniswapV2PairReserves {
        function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    }
}

/// How to obtain a call trace when the adapter returned none.
#[derive(Debug, Clone)]
pub enum TraceFallback {
    /// Leave frames empty: call-pattern conditions simply can't match.
    None,
    /// Re-execute the transaction locally with Foundry's `cast run`, which
    /// needs only ordinary state-read RPC methods. Faithful but slow (tens
    /// of seconds against a remote node, since every state read is a round
    /// trip) and it requires Foundry on the host. A node that serves
    /// `debug_traceTransaction` (or a local archive node) is the production
    /// answer; this exists so the daemon works on plans and public endpoints
    /// that don't.
    CastRun { rpc_url: String, timeout: Duration },
}

#[derive(Debug, Clone)]
pub struct ContextConfig {
    /// The protected (pausable) contract. Its balances are watched unless
    /// `holders` says otherwise.
    pub target: Address,
    /// Every contract whose balances are watched. Assets are often spread
    /// over several contracts (e.g. one vault per asset); defaults to just
    /// `target`.
    pub holders: Vec<Address>,
    /// ERC-20 tokens whose outflow from `target` is monitored. This is
    /// per-protocol configuration — the assets a protocol custodies — not
    /// something inferred from the transaction being judged.
    pub watched_tokens: Vec<Address>,
    /// Also watch native ETH (requires a call trace).
    pub watch_native: bool,
    /// Measure Uniswap-V2-style pool price movement from `Sync` events.
    pub track_amm_prices: bool,
    /// Cap on distinct pools whose reference reserves are fetched per tx.
    pub max_pairs: usize,
    pub trace_fallback: TraceFallback,
}

impl ContextConfig {
    pub fn new(target: Address) -> Self {
        Self {
            target,
            holders: vec![target],
            watched_tokens: Vec::new(),
            watch_native: false,
            track_amm_prices: true,
            max_pairs: 16,
            trace_fallback: TraceFallback::None,
        }
    }
}

#[derive(Default)]
struct Cache {
    block: u64,
    balances: HashMap<(Address, Address), Option<u128>>,
    reserves: HashMap<Address, Option<(u128, u128)>>,
}

pub struct EvmContext {
    provider: RootProvider,
    cfg: ContextConfig,
    cache: Mutex<Cache>,
}

fn to_alloy(a: &Address) -> alloy::primitives::Address {
    a.to_string()
        .parse()
        .expect("tripwire Address is valid hex")
}

impl EvmContext {
    pub fn connect(rpc_url: &str, cfg: ContextConfig) -> Result<Self, String> {
        let url = rpc_url
            .parse()
            .map_err(|e| format!("invalid RPC URL: {e}"))?;
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_http(url);
        Ok(Self {
            provider,
            cfg,
            cache: Mutex::new(Cache::default()),
        })
    }

    /// Cache is per reference block: drop it when the block changes so it
    /// can't grow without bound while following a chain.
    async fn cache_for(&self, block: u64) -> tokio::sync::MutexGuard<'_, Cache> {
        let mut c = self.cache.lock().await;
        if c.block != block {
            *c = Cache {
                block,
                ..Default::default()
            };
        }
        c
    }

    async fn token_balance(&self, token: &Address, holder: &Address, block: u64) -> Option<u128> {
        if let Some(v) = self.cache_for(block).await.balances.get(&(*token, *holder)) {
            return *v;
        }
        let res = IERC20Balance::new(to_alloy(token), &self.provider)
            .balanceOf(to_alloy(holder))
            .block(BlockId::number(block))
            .call()
            .await;
        let v = match res {
            Ok(b) => Some(u128::try_from(b).unwrap_or(u128::MAX)),
            Err(e) => {
                tracing::warn!(%token, block, error = %e, "could not read historical token balance");
                None
            }
        };
        self.cache_for(block)
            .await
            .balances
            .insert((*token, *holder), v);
        v
    }

    async fn native_balance(&self, holder: &Address, block: u64) -> Option<u128> {
        match self
            .provider
            .get_balance(to_alloy(holder))
            .block_id(BlockId::number(block))
            .await
        {
            Ok(b) => Some(u128::try_from(b).unwrap_or(u128::MAX)),
            Err(e) => {
                tracing::warn!(%holder, block, error = %e, "could not read historical ETH balance");
                None
            }
        }
    }

    async fn pair_reserves(&self, pair: &Address, block: u64) -> Option<(u128, u128)> {
        if let Some(v) = self.cache_for(block).await.reserves.get(pair) {
            return *v;
        }
        let res = IUniswapV2PairReserves::new(to_alloy(pair), &self.provider)
            .getReserves()
            .block(BlockId::number(block))
            .call()
            .await;
        let v = match res {
            Ok(r) => Some((
                u128::try_from(r.reserve0).unwrap_or(u128::MAX),
                u128::try_from(r.reserve1).unwrap_or(u128::MAX),
            )),
            // Not a V2 pair (or it didn't exist yet): no reference, no claim.
            Err(_) => None,
        };
        self.cache_for(block).await.reserves.insert(*pair, v);
        v
    }

    async fn fund_flow(&self, tx: &TxEvent, prev: u64) -> Option<AssetFlow> {
        let mut flows = Vec::new();
        for holder in &self.cfg.holders {
            for token in &self.cfg.watched_tokens {
                let out = outflow::erc20_net_outflow(&tx.logs, token, holder);
                // Only fetch a balance when something actually left.
                if out == 0 {
                    continue;
                }
                if let Some(bal) = self.token_balance(token, holder, prev).await {
                    flows.push(AssetFlow {
                        balance_before: bal,
                        outflow: out,
                    });
                }
            }
            if self.cfg.watch_native {
                let out = outflow::native_net_outflow(&tx.call_frames, holder);
                if out > 0 {
                    if let Some(bal) = self.native_balance(holder, prev).await {
                        flows.push(AssetFlow {
                            balance_before: bal,
                            outflow: out,
                        });
                    }
                }
            }
        }
        outflow::worst_flow(&flows)
    }

    async fn price_move(&self, tx: &TxEvent, prev: u64) -> Option<f64> {
        let syncs = amm::parse_syncs(&tx.logs);
        if syncs.is_empty() {
            return None;
        }
        let mut reference = HashMap::new();
        for pair in amm::distinct_pairs(&syncs, self.cfg.max_pairs) {
            if let Some(r) = self.pair_reserves(&pair, prev).await {
                reference.insert(pair, r);
            }
        }
        amm::max_relative_price_move(&reference, &syncs)
    }
}

#[async_trait]
impl ContextSource for EvmContext {
    async fn enrich(&self, tx: &mut TxEvent) {
        if !tx.call_frames.is_empty() {
            return;
        }
        let TraceFallback::CastRun { rpc_url, timeout } = &self.cfg.trace_fallback else {
            return;
        };
        let (hash, url) = (tx.tx_hash.clone(), rpc_url.clone());
        let job = tokio::task::spawn_blocking(move || cast_trace::fetch_frames(&hash, &url));
        match tokio::time::timeout(*timeout, job).await {
            Ok(Ok(Ok(frames))) => tx.call_frames = frames,
            Ok(Ok(Err(e))) => {
                tracing::warn!(tx = %tx.tx_hash, error = %e, "trace fallback failed; scoring without a call trace")
            }
            Ok(Err(e)) => {
                tracing::warn!(tx = %tx.tx_hash, error = %e, "trace fallback task failed")
            }
            Err(_) => {
                tracing::warn!(tx = %tx.tx_hash, ?timeout, "trace fallback timed out; scoring without a call trace")
            }
        }
    }

    async fn baseline(&self, tx: &TxEvent) -> Baseline {
        let mut b = Baseline::default();
        if tx.block_number == 0 {
            return b;
        }
        let prev = tx.block_number - 1;

        if let Some(flow) = self.fund_flow(tx, prev).await {
            b.balance_baseline_wei = flow.balance_before;
            b.outflow_wei = flow.outflow;
        }
        if self.cfg.track_amm_prices {
            if let Some(mv) = self.price_move(tx, prev).await {
                // Normalised: the reference is 1.0 and the observed price is
                // 1 + the largest relative move, so `OraclePriceDeviation`'s
                // percentage is exactly that move.
                b.reference_price = Some(1.0);
                b.observed_price = Some(1.0 + mv);
            }
        }
        b
    }
}
