//! The Ethereum (and EVM-compatible chain) adapter. The only chain
//! integration implemented in v1 (ARCHITECTURE.md §3.1) — every other
//! module in this crate, and everything in `detection`, is chain-agnostic
//! and unaffected by what's in this file.

use std::collections::HashMap;
use std::str::FromStr;

use alloy::consensus::Transaction as _;
use alloy::eips::BlockNumberOrTag;
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tripwire_core::{Address as CoreAddress, CallFrame, ChainId, LogEvent, TxEvent};

use crate::{ChainAdapter, ChainAdapterError};

pub struct EvmAdapter {
    chain_id: ChainId,
    provider: RootProvider,
    /// Whether this node answers `debug_traceTransaction`. Not every RPC
    /// endpoint exposes the debug namespace (most public free-tier
    /// endpoints don't); when it's unavailable, call-frame-dependent
    /// signatures (reentrancy) simply see an empty call trace rather
    /// than the adapter failing outright — degrading gracefully is the
    /// right default for a monitoring system, since refusing to run at
    /// all on a subset of nodes would be a worse outcome than running
    /// with reduced signature coverage. This is discovered once, lazily,
    /// on first use, and cached.
    supports_debug_trace: tokio::sync::OnceCell<bool>,
}

impl EvmAdapter {
    pub async fn connect(rpc_url: &str, chain_id: ChainId) -> Result<Self, ChainAdapterError> {
        let url = rpc_url
            .parse()
            .map_err(|e| ChainAdapterError::Transport(format!("invalid RPC URL: {e}")))?;
        // No fillers needed -- this adapter only reads chain state, it
        // never signs or sends transactions (that's guardian-client's
        // job). `disable_recommended_fillers()` keeps the provider type
        // a plain `RootProvider` instead of a filler-wrapped type this
        // struct would otherwise have to name.
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_http(url);
        Ok(Self {
            chain_id,
            provider,
            supports_debug_trace: tokio::sync::OnceCell::new(),
        })
    }

    async fn try_get_call_frames(&self, tx_hash: &str) -> Vec<CallFrame> {
        let supported = self
            .supports_debug_trace
            .get_or_init(|| async { self.probe_debug_trace().await })
            .await;
        if !*supported {
            return Vec::new();
        }
        self.fetch_call_frames(tx_hash).await.unwrap_or_else(|e| {
            tracing::warn!(tx_hash, error = %e, "debug_traceTransaction failed for this tx despite passing the capability probe; treating as no call trace");
            Vec::new()
        })
    }

    async fn probe_debug_trace(&self) -> bool {
        // A cheap, always-valid probe: trace block 0's (nonexistent on
        // most chains, but the *method* either exists or doesn't) --
        // simpler and more portable is to just attempt the real call on
        // first use and remember whether the transport reported the
        // method as unknown. We probe with a zero hash, which every
        // implementation rejects quickly either way (invalid params vs.
        // method not found), letting us tell those two failure modes apart.
        let result: Result<serde_json::Value, _> = self
            .provider
            .client()
            .request(
                "debug_traceTransaction",
                (
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                    json!({"tracer": "callTracer"}),
                ),
            )
            .await;
        match result {
            Ok(_) => true,
            Err(e) => !is_method_not_found(&e.to_string()),
        }
    }

    async fn fetch_call_frames(&self, tx_hash: &str) -> Result<Vec<CallFrame>, ChainAdapterError> {
        let raw: RawCallFrame = self
            .provider
            .client()
            .request(
                "debug_traceTransaction",
                (tx_hash, json!({"tracer": "callTracer"})),
            )
            .await
            .map_err(|e| ChainAdapterError::Transport(e.to_string()))?;
        let mut flattened = Vec::new();
        flatten_call_frame(&raw, 0, &mut flattened);
        Ok(flattened)
    }
}

fn is_method_not_found(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("method not found")
        || lower.contains("not supported")
        || lower.contains("unsupported")
        || lower.contains("does not exist")
        || lower.contains("not available")
}

/// Mirrors geth's `callTracer` JSON output shape. Fields this project
/// doesn't use (gas, output, error) are intentionally omitted rather
/// than mapped — this is a normalization boundary, not a full trace
/// archive.
#[derive(Debug, Deserialize)]
struct RawCallFrame {
    from: String,
    to: Option<String>,
    input: Option<String>,
    value: Option<String>,
    #[serde(default)]
    calls: Vec<RawCallFrame>,
}

fn flatten_call_frame(raw: &RawCallFrame, depth: u32, out: &mut Vec<CallFrame>) {
    let to = raw
        .to
        .as_deref()
        .and_then(|s| CoreAddress::from_str(s).ok())
        .unwrap_or(CoreAddress::ZERO);
    let from = CoreAddress::from_str(&raw.from).unwrap_or(CoreAddress::ZERO);
    let selector = raw
        .input
        .as_deref()
        .filter(|s| s.len() >= 10)
        .map(|s| s[0..10].to_string());
    let value_wei = raw
        .value
        .as_deref()
        .and_then(|v| u128::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);

    out.push(CallFrame {
        depth,
        from,
        to,
        selector,
        value_wei,
    });

    for child in &raw.calls {
        flatten_call_frame(child, depth + 1, out);
    }
}

#[async_trait]
impl ChainAdapter for EvmAdapter {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    async fn latest_block_number(&self) -> Result<u64, ChainAdapterError> {
        self.provider
            .get_block_number()
            .await
            .map_err(|e| ChainAdapterError::Transport(e.to_string()))
    }

    async fn get_block_tx_events(
        &self,
        block_number: u64,
    ) -> Result<Vec<TxEvent>, ChainAdapterError> {
        let head = self.latest_block_number().await?;
        let block = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .full()
            .await
            .map_err(|e| ChainAdapterError::Transport(e.to_string()))?
            .ok_or(ChainAdapterError::BlockNotFound(block_number))?;

        let confirmations = head.saturating_sub(block_number);
        let timestamp_unix = block.header.timestamp;

        let mut events = Vec::new();
        // Cache decoded receipt logs per tx so a transaction with many
        // internal calls doesn't refetch the same receipt repeatedly.
        let mut receipt_log_cache: HashMap<String, Vec<LogEvent>> = HashMap::new();

        for tx in block.transactions.txns() {
            let tx_hash = format!("{:#x}", tx.inner.tx_hash());
            let from = CoreAddress::from_str(&format!("{:#x}", tx.inner.signer()))
                .unwrap_or(CoreAddress::ZERO);
            let to = tx
                .inner
                .to()
                .and_then(|a| CoreAddress::from_str(&format!("{a:#x}")).ok());
            let value_wei = tx.inner.value().to::<u128>();

            let logs = match receipt_log_cache.get(&tx_hash) {
                Some(l) => l.clone(),
                None => {
                    let fetched = self.fetch_receipt_logs(&tx_hash).await.unwrap_or_default();
                    receipt_log_cache.insert(tx_hash.clone(), fetched.clone());
                    fetched
                }
            };

            let call_frames = self.try_get_call_frames(&tx_hash).await;

            events.push(TxEvent {
                chain: self.chain_id,
                tx_hash,
                block_number,
                confirmations,
                from,
                to,
                value_wei,
                logs,
                call_frames,
                timestamp_unix,
            });
        }

        Ok(events)
    }
}

impl EvmAdapter {
    async fn fetch_receipt_logs(&self, tx_hash: &str) -> Result<Vec<LogEvent>, ChainAdapterError> {
        let hash = alloy::primitives::TxHash::from_str(tx_hash)
            .map_err(|e| ChainAdapterError::Decode(e.to_string()))?;
        let receipt = self
            .provider
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| ChainAdapterError::Transport(e.to_string()))?;
        let Some(receipt) = receipt else {
            return Ok(Vec::new());
        };
        Ok(receipt
            .inner
            .logs()
            .iter()
            .map(|log| LogEvent {
                address: CoreAddress::from_str(&format!("{:#x}", log.address()))
                    .unwrap_or(CoreAddress::ZERO),
                topics: log.topics().iter().map(|t| format!("{t:#x}")).collect(),
                data: format!("0x{}", alloy::hex::encode(log.data().data.as_ref())),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flattens_nested_call_frames_with_correct_depth() {
        let raw = RawCallFrame {
            from: "0x0000000000000000000000000000000000000001".into(),
            to: Some("0x0000000000000000000000000000000000000002".into()),
            input: Some(
                "0xa9059cbb00000000000000000000000000000000000000000000000000000000".into(),
            ),
            value: Some("0x0".into()),
            calls: vec![RawCallFrame {
                from: "0x0000000000000000000000000000000000000002".into(),
                to: Some("0x0000000000000000000000000000000000000003".into()),
                input: None,
                value: Some("0x1".into()),
                calls: vec![],
            }],
        };
        let mut out = Vec::new();
        flatten_call_frame(&raw, 0, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].depth, 0);
        assert_eq!(out[0].selector.as_deref(), Some("0xa9059cbb"));
        assert_eq!(out[1].depth, 1);
        assert_eq!(out[1].selector, None);
        assert_eq!(out[1].value_wei, 1);
    }

    #[test]
    fn method_not_found_detection_is_case_insensitive() {
        assert!(is_method_not_found("Method not found"));
        assert!(is_method_not_found(
            "the method debug_traceTransaction does not exist/is not available"
        ));
        assert!(!is_method_not_found("invalid params: bad tx hash"));
    }
}
