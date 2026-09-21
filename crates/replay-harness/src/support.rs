//! Shared plumbing for the historical-exploit replay tests: skip logic,
//! loading a real transaction (chain-adapter metadata + logs, `cast run`
//! call trace), and turning real on-chain fund movement into the
//! `Baseline` the detection engine's fund-flow condition consumes.

use std::process::Command;

use chain_adapter::evm::EvmAdapter;
use chain_adapter::ChainAdapter;
use detection::Baseline;
use tripwire_core::{Address, ChainId, LogEvent, TxEvent};

use crate::cast_trace::{self, TraceError};

const ERC20_TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

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

/// Net amount of `token` that left `holder` according to ERC-20 `Transfer`
/// logs: transfers out minus transfers in, floored at zero. A flash loan
/// that is borrowed and repaid within the transaction therefore nets out,
/// while a genuine drain does not.
pub fn erc20_net_outflow(logs: &[LogEvent], token: &Address, holder: &Address) -> u128 {
    let (mut out, mut inn) = (0u128, 0u128);
    for log in logs {
        // ERC-20 Transfer has 3 topics (ERC-721's has 4).
        if &log.address != token
            || log.topics.len() != 3
            || !log.topics[0].eq_ignore_ascii_case(ERC20_TRANSFER_TOPIC)
        {
            continue;
        }
        let value = hex_to_u128_saturating(&log.data);
        if topic_address(&log.topics[1]).as_ref() == Some(holder) {
            out = out.saturating_add(value);
        }
        if topic_address(&log.topics[2]).as_ref() == Some(holder) {
            inn = inn.saturating_add(value);
        }
    }
    out.saturating_sub(inn)
}

fn topic_address(topic: &str) -> Option<Address> {
    let hex = topic.trim_start_matches("0x");
    if hex.len() != 64 {
        return None;
    }
    format!("0x{}", &hex[24..]).parse().ok()
}

fn hex_to_u128_saturating(data: &str) -> u128 {
    let hex = data.trim_start_matches("0x").trim_start_matches('0');
    if hex.is_empty() {
        return 0;
    }
    u128::from_str_radix(hex, 16).unwrap_or(u128::MAX)
}

/// `token.balanceOf(holder)` at `block`, via `cast call` (an ordinary
/// archive state read, available on free RPC tiers).
pub fn erc20_balance_at(
    rpc_url: &str,
    token: &str,
    holder: &str,
    block: u64,
) -> Result<u128, TraceError> {
    let out = Command::new("cast")
        .args([
            "call",
            token,
            "balanceOf(address)(uint256)",
            holder,
            "--block",
            &block.to_string(),
            "--rpc-url",
            rpc_url,
        ])
        .output()
        .map_err(|_| TraceError::CastMissing)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).replace(rpc_url, "<rpc-url>");
        return Err(TraceError::CastFailed(stderr.trim().to_string()));
    }
    // Output looks like `8904507348306697267428294 [8.904e24]`.
    parse_cast_uint(&String::from_utf8_lossy(&out.stdout))
}

fn parse_cast_uint(stdout: &str) -> Result<u128, TraceError> {
    stdout
        .split_whitespace()
        .next()
        .and_then(|t| t.parse::<u128>().ok())
        .ok_or_else(|| TraceError::Malformed(format!("unexpected cast call output: {stdout:?}")))
}

/// Builds a fund-flow `Baseline` from real chain data for one watched
/// (token, holder) pair: the holder's balance in the block *before* the
/// transaction as the denominator, and the transaction's net ERC-20
/// outflow as the numerator.
pub fn fund_flow_baseline(
    rpc_url: &str,
    tx: &TxEvent,
    token: &str,
    holder: &str,
) -> Result<Baseline, TraceError> {
    let balance = erc20_balance_at(rpc_url, token, holder, tx.block_number - 1)?;
    let outflow = erc20_net_outflow(
        &tx.logs,
        &token
            .parse()
            .map_err(|e| TraceError::Malformed(format!("{e}")))?,
        &holder
            .parse()
            .map_err(|e| TraceError::Malformed(format!("{e}")))?,
    );
    Ok(Baseline {
        balance_baseline_wei: balance,
        outflow_wei: outflow,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0x6b175474e89094c44da98b954eedeac495271d0f";
    const HOLDER: &str = "0x27182842e098f60e3d576794a5bffb0777e025d3";
    const OTHER: &str = "0x00000000000000000000000000000000000000aa";

    fn pad(addr: &str) -> String {
        format!("0x{:0>64}", addr.trim_start_matches("0x"))
    }

    fn transfer(token: &str, from: &str, to: &str, value: u128) -> LogEvent {
        LogEvent {
            address: token.parse().unwrap(),
            topics: vec![ERC20_TRANSFER_TOPIC.into(), pad(from), pad(to)],
            data: format!("0x{value:064x}"),
        }
    }

    fn addr(s: &str) -> Address {
        s.parse().unwrap()
    }

    #[test]
    fn counts_transfers_out_of_the_holder() {
        let logs = vec![transfer(TOKEN, HOLDER, OTHER, 700)];
        assert_eq!(erc20_net_outflow(&logs, &addr(TOKEN), &addr(HOLDER)), 700);
    }

    #[test]
    fn a_flash_loan_borrowed_and_repaid_nets_to_the_real_drain() {
        // Mirrors Euler: 30M in, 38.9M out => 8.9M net drained.
        let logs = vec![
            transfer(TOKEN, OTHER, HOLDER, 30_000),
            transfer(TOKEN, HOLDER, OTHER, 38_900),
        ];
        assert_eq!(erc20_net_outflow(&logs, &addr(TOKEN), &addr(HOLDER)), 8_900);
    }

    #[test]
    fn net_inflow_floors_at_zero() {
        let logs = vec![transfer(TOKEN, OTHER, HOLDER, 500)];
        assert_eq!(erc20_net_outflow(&logs, &addr(TOKEN), &addr(HOLDER)), 0);
    }

    #[test]
    fn ignores_other_tokens_and_non_transfer_or_nft_logs() {
        let mut nft = transfer(TOKEN, HOLDER, OTHER, 1);
        nft.topics.push(pad("0x1")); // 4 topics: ERC-721 shape
        let mut not_transfer = transfer(TOKEN, HOLDER, OTHER, 9);
        not_transfer.topics[0] = pad("0xdead");
        let logs = vec![
            transfer(OTHER, HOLDER, OTHER, 999), // different token contract
            nft,
            not_transfer,
        ];
        assert_eq!(erc20_net_outflow(&logs, &addr(TOKEN), &addr(HOLDER)), 0);
    }

    #[test]
    fn oversized_values_saturate_instead_of_wrapping() {
        let mut log = transfer(TOKEN, HOLDER, OTHER, 0);
        log.data = format!("0x{}", "f".repeat(64));
        assert_eq!(
            erc20_net_outflow(&[log], &addr(TOKEN), &addr(HOLDER)),
            u128::MAX
        );
    }

    #[test]
    fn parses_cast_call_output_with_and_without_annotation() {
        assert_eq!(
            parse_cast_uint("8904507348306697267428294 [8.904e24]\n").unwrap(),
            8_904_507_348_306_697_267_428_294
        );
        assert_eq!(parse_cast_uint("0\n").unwrap(), 0);
        assert!(parse_cast_uint("not a number").is_err());
        assert!(parse_cast_uint("").is_err());
    }
}
