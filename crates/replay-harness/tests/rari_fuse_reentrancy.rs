//! Rari Capital / Fei Fuse pool exploit, 30 April 2022 (~$80M): a reentrancy
//! in Compound-fork `CEther.borrow`. The market sends ETH to the borrower
//! *before* recording the borrow, and the attacker's `receive()` used that
//! window to call the Comptroller's `exitMarket`, escaping the collateral
//! check while the debt was not yet booked.
//!
//! Replayed from real chain data and scored with only the shipped generic
//! signatures. Identification: block 14,684,814; the transaction is a
//! Balancer flash loan (150M USDC + 50K WETH) that borrows from the Fuse
//! "pool 127" markets (fUSDC/fUSDT/fFRAX/fETH-127, symbols read on-chain).
//!
//! Configuration an operator would supply: the four pool-127 markets as
//! watched holders; their ERC-20 underlyings as watched tokens; native ETH.

use detection::ContextSource;
use replay_harness::support;
use tripwire_context::{ContextConfig, EvmContext};
use tripwire_core::{Address, ChainId, Confidence};

const BLOCK: u64 = 14_684_814;
const TX_HASH: &str = "0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530";
const MARKETS: [&str; 4] = [
    "0xEbE0d1cb6A0b8569929e062d67bfbC07608f0A47", // fUSDC-127
    "0xe097783483D1b7527152eF8B150B99B9B2700c8d", // fUSDT-127
    "0x8922C1147E141C055fdDfc0ED5a119f3378c8ef8", // fFRAX-127
    "0x26267e41CeCa7C8E0f143554Af707336f27Fa051", // fETH-127 (native ETH)
];
/// Fuse pool 127's Comptroller: holds no balance but is part of the protocol,
/// and is where the attacker re-entered.
const COMPTROLLER: &str = "0x3f2D1BC6D02522dbcdb216b2e75eDDdAFE04B16F";
const TOKENS: [&str; 3] = [
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // USDC
    "0xdAC17F958D2ee523a2206206994597C13D831ec7", // USDT
    "0x853d955aCEf822Db058eb8505911ED77F175b99e", // FRAX
];

#[tokio::test]
async fn rari_fuse_reentrancy_exploit_with_shipped_generic_signatures() {
    let Some(rpc_url) = support::rpc_url_or_skip() else {
        return;
    };
    let tx = support::load_replayed_tx(&rpc_url, BLOCK, TX_HASH).await;
    println!(
        "Replayed real Rari tx: {} call frames (max depth {}), {} logs",
        tx.call_frames.len(),
        tx.max_call_depth(),
        tx.logs.len()
    );

    let mut cfg = ContextConfig::new(MARKETS[0].parse().unwrap());
    cfg.holders = MARKETS.iter().map(|a| a.parse().unwrap()).collect();
    cfg.watched_tokens = TOKENS.iter().map(|a| a.parse().unwrap()).collect();
    cfg.watch_native = true;
    cfg.protocol_contracts = vec![COMPTROLLER.parse().unwrap()];
    let ctx = EvmContext::connect(&rpc_url, cfg).expect("context");
    let baseline = ctx.baseline(&tx).await;
    println!(
        "worst-asset drain: {:.1}% (outflow {} of balance {})",
        100.0 * baseline.outflow_wei as f64 / baseline.balance_baseline_wei.max(1) as f64,
        baseline.outflow_wei,
        baseline.balance_baseline_wei
    );

    let score = |tx: &tripwire_core::TxEvent, b: &detection::Baseline| {
        detection::evaluate(
            &support::shipped_signatures(),
            ChainId::ETHEREUM_MAINNET,
            MARKETS[0].parse::<Address>().unwrap(),
            tx,
            b,
            Confidence::new(80.0),
            tx.timestamp_unix,
        )
    };
    let keys_of = |d: &tripwire_core::PauseDecision| -> Vec<String> {
        d.counted_evidence.iter().map(|e| e.key.clone()).collect()
    };

    let d = score(&tx, &baseline);
    println!(
        "GENERIC: confidence {:.1} pause={} evidence {:?}",
        d.confidence.value(),
        d.should_pause(),
        keys_of(&d)
    );
    let keys = keys_of(&d);
    assert!(keys.contains(&"fund_flow".to_string()), "{keys:?}");
    assert!(
        keys.contains(&"protocol_callback_reentry".to_string()),
        "the borrow -> receive() -> exitMarket re-entry must be recognised: {keys:?}"
    );
    assert!(d.should_pause());

    // The point of the new detector: without it, this attack is only caught
    // if it happens to use a flash loan. Remove the Balancer `flashLoan`
    // frame (as if the attacker had used their own capital) and it must
    // still pause on drain + re-entry.
    let mut no_flash = tx.clone();
    no_flash
        .call_frames
        .retain(|f| f.selector.as_deref() != Some("0x5c38449e"));
    let d = score(&no_flash, &baseline);
    let keys = keys_of(&d);
    assert!(
        !keys.iter().any(|k| k.starts_with("call_any:")),
        "flash-loan evidence should be gone: {keys:?}"
    );
    assert!(
        d.should_pause(),
        "drain + callback re-entry alone scored {}",
        d.confidence.value()
    );

    // Configuration matters and is honest about it: with no protocol set the
    // callback fact cannot be established, and the drain alone is below threshold.
    let mut blind = baseline.clone();
    blind.protocol_addresses.clear();
    let d = score(&no_flash, &blind);
    assert!(
        !d.should_pause(),
        "drain alone scored {}",
        d.confidence.value()
    );

    // The re-entry alone (no drain) must not pause.
    let mut no_drain = baseline.clone();
    no_drain.outflow_wei = 0;
    assert!(!score(&tx, &no_drain).should_pause());

    // The same attack with value netting on: USDC/USDT/FRAX at $1 and ETH at
    // an illustrative $2,900 (the price only needs to be the right order of
    // magnitude). The attacker deposits 150M USDC of flash-loaned collateral
    // and takes back far more value than they put in, so it must still show
    // as a loss.
    let mut cfg = ContextConfig::new(MARKETS[0].parse().unwrap());
    cfg.holders = MARKETS.iter().map(|a| a.parse().unwrap()).collect();
    cfg.watched_tokens = TOKENS.iter().map(|a| a.parse().unwrap()).collect();
    cfg.watch_native = true;
    cfg.protocol_contracts = vec![COMPTROLLER.parse().unwrap()];
    cfg.valuer = Some(std::sync::Arc::new(
        tripwire_context::FixedValues::new()
            .with_stable(TOKENS[0].parse().unwrap(), 6)
            .with_stable(TOKENS[1].parse().unwrap(), 6)
            .with_stable(TOKENS[2].parse().unwrap(), 18)
            .with_native(2_900.0),
    ));
    let netted = EvmContext::connect(&rpc_url, cfg).expect("context");
    let nb = netted.baseline(&tx).await;
    let lost = nb.outflow_wei as f64 / nb.balance_baseline_wei.max(1) as f64;
    println!("value-netted loss: {:.1}%", lost * 100.0);
    let nd = score(&tx, &nb);
    println!(
        "NETTED: confidence {:.1} evidence {:?}",
        nd.confidence.value(),
        keys_of(&nd)
    );
    assert!(lost > 0.5, "netted loss was {lost}");
    assert!(nd.should_pause(), "netted: {}", nd.confidence.value());
}
