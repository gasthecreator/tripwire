//! Shared plumbing for the historical-exploit replay tests: skip logic,
//! loading a real transaction (chain-adapter metadata + logs, `cast run`
//! call trace). Baselines come from the production `tripwire-context`
//! crate, not test-only code.

use chain_adapter::evm::EvmAdapter;
use chain_adapter::ChainAdapter;
use tripwire_core::{ChainId, TxEvent};

use crate::cast_trace;

/// The archive RPC URL if this environment can run live replays, else
/// `None` after printing why — matching every other network-dependent
/// test in the repo, which skips rather than fails.
pub fn rpc_url_or_skip() -> Option<String> {
    match std::env::var("ETH_RPC_URL") {
        Ok(u) if !u.is_empty() => {}
        _ => {
            eprintln!("SKIPPED: ETH_RPC_URL not set -- see CONTRIBUTING.md and README.md");
            return None;
        }
    }
    if !cast_trace::cast_available() {
        eprintln!("SKIPPED: `cast` not on PATH (install Foundry via foundryup)");
        return None;
    }
    std::env::var("ETH_RPC_URL").ok()
}

/// Loads a real mainnet transaction: sender, block, timestamp and receipt
/// logs from the chain adapter (ordinary free-tier RPC calls), and the
/// call trace from `cast run`, which re-executes the transaction locally
/// at its true block position (the adapter's own `debug_traceTransaction`
/// path returns nothing on free-tier plans).
pub async fn load_replayed_tx(rpc_url: &str, block: u64, tx_hash: &str) -> TxEvent {
    let adapter = EvmAdapter::connect(rpc_url, ChainId::ETHEREUM_MAINNET)
        .await
        .expect("failed to connect to archive RPC");
    let mut tx = adapter
        .get_block_tx_events(block)
        .await
        .expect("failed to fetch block -- confirm ETH_RPC_URL points to an archive node")
        .into_iter()
        .find(|e| e.tx_hash.eq_ignore_ascii_case(tx_hash))
        .unwrap_or_else(|| panic!("tx {tx_hash} not found in block {block}"));
    tx.call_frames = cast_trace::fetch_frames(tx_hash, rpc_url)
        .unwrap_or_else(|e| panic!("cast run failed: {e}"));
    tx
}

/// The general-purpose signatures shipped in `signatures/`, exactly as a
/// deployment would load them.
pub fn shipped_signatures() -> Vec<tripwire_core::Signature> {
    detection::load_signatures_from_dir(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../signatures"),
    )
    .expect("load shipped signatures")
}
