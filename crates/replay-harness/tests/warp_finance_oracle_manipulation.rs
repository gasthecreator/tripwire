//! Warp Finance exploit, 17 December 2020 (~$7.8M): an LP-token price
//! oracle manipulated within one transaction. Replayed from real chain data
//! and scored by the real detection engine using **only the shipped generic
//! signatures** — no incident-tuned signature — so this is a genuine test of
//! generic detection on an oracle-manipulation attack.
//!
//! **How the transaction was identified** (Etherscan gives it no label, and
//! the write-ups omit the hash, so it was found on-chain and corroborated
//! by independent facts):
//! - Block 11473330's timestamp is exactly 22:24:41 UTC, the attack time
//!   Warp's own summary gives; the block was located by timestamp.
//! - Within it, the Uniswap V2 DAI/WETH pair's `Sync` events show a
//!   341,217 WETH swap that moved its WETH reserve from ~94K to ~436K.
//! - The transaction's receipt matches the published figures: 94,349.3 LP
//!   tokens minted, ~3.86M DAI and ~3.92M USDC borrowed (published: 94.349K
//!   LP, 3.86M DAI, 3.9M USDC) from two `WarpVaultSC` contracts (Etherscan
//!   shows both as verified Warp contracts).
//!
//! **Configuration** (what an operator would supply, not derived from this
//! transaction): the two Warp vaults as watched holders, DAI and USDC as
//! watched tokens.

use detection::ContextSource;
use replay_harness::support;
use tripwire_context::{ContextConfig, EvmContext};
use tripwire_core::{Address, ChainId, Confidence};

const BLOCK: u64 = 11_473_330;
const TX_HASH: &str = "0x8bb8dc5c7c830bac85fa48acad2505e9300a91c3ff239c9517d0cae33b595090";
const SENDER: &str = "0xeBc6bD6aC2C9AD4adf4BA57E9F709b8B9CF03C40";
const ATTACK_CONTRACT: &str = "0xdF8BEE861227FFC5EEA819C332A1C170Ae3dbACb";
const WARP_USDC_VAULT: &str = "0xae465fd39b519602ee28f062037f7b9c41fdc8cf";
const WARP_DAI_VAULT: &str = "0x6046c3ab74e6ce761d218b9117d5c63200f4b406";
const DAI: &str = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

#[tokio::test]
async fn warp_finance_exploit_is_caught_by_the_shipped_generic_signatures() {
    let Some(rpc_url) = support::rpc_url_or_skip() else {
        return;
    };

    let tx = support::load_replayed_tx(&rpc_url, BLOCK, TX_HASH).await;
    assert_eq!(tx.from.to_string(), SENDER.to_lowercase());
    assert_eq!(
        tx.to.map(|a| a.to_string()),
        Some(ATTACK_CONTRACT.to_lowercase())
    );
    println!(
        "Replayed real Warp tx: {} call frames (max depth {}), {} receipt logs",
        tx.call_frames.len(),
        tx.max_call_depth(),
        tx.logs.len()
    );

    let mut cfg = ContextConfig::new(WARP_USDC_VAULT.parse().unwrap());
    cfg.holders = vec![
        WARP_USDC_VAULT.parse().unwrap(),
        WARP_DAI_VAULT.parse().unwrap(),
    ];
    cfg.watched_tokens = vec![DAI.parse().unwrap(), USDC.parse().unwrap()];
    let ctx = EvmContext::connect(&rpc_url, cfg).expect("context");
    let baseline = ctx.baseline(&tx).await;
    let drained = baseline.outflow_wei as f64 / baseline.balance_baseline_wei as f64;
    let price_move = baseline.observed_price.unwrap() - 1.0;
    println!(
        "worst-asset drain: {:.1}% of the vault balance; largest AMM price move: {:.1}x",
        drained * 100.0,
        price_move
    );
    assert!(drained > 0.5, "a Warp vault lost most of an asset");
    assert!(
        price_move > 20.0,
        "the DAI/WETH pair's price moved ~21x within the transaction (95% crash), got {price_move}"
    );

    let d = detection::evaluate(
        &support::shipped_signatures(),
        ChainId::ETHEREUM_MAINNET,
        WARP_USDC_VAULT.parse::<Address>().unwrap(),
        &tx,
        &baseline,
        Confidence::new(80.0),
        tx.timestamp_unix,
    );
    println!(
        "GENERIC: confidence {:.1} pause={} evidence {:?}",
        d.confidence.value(),
        d.should_pause(),
        d.counted_evidence
    );

    let keys: Vec<&str> = d.counted_evidence.iter().map(|e| e.key.as_str()).collect();
    assert!(keys.contains(&"oracle_price_deviation"), "{keys:?}");
    assert!(keys.contains(&"fund_flow"), "{keys:?}");
    assert!(
        d.should_pause(),
        "a manipulated price plus a drained vault should pause: {keys:?} = {}",
        d.confidence.value()
    );

    // The price move alone -- what a legitimate whale trade in a thin pool
    // also looks like -- must NOT be enough: pausing needs evidence of harm.
    let mut price_only = baseline.clone();
    price_only.outflow_wei = 0;
    let p = detection::evaluate(
        &support::shipped_signatures(),
        ChainId::ETHEREUM_MAINNET,
        WARP_USDC_VAULT.parse::<Address>().unwrap(),
        &tx,
        &price_only,
        Confidence::new(80.0),
        tx.timestamp_unix,
    );
    assert!(
        !p.should_pause(),
        "price movement alone scored {}",
        p.confidence.value()
    );

    // Value netting must not blind the detector to this attack: the same
    // exploit, with the vaults' DAI and USDC valued at $1, still loses most
    // of the value it was custodying. (Only the watched custody assets are
    // netted; the LP token the attacker deposited is not one of them, and
    // prices are read at the block *before* the transaction.)
    let mut cfg = ContextConfig::new(WARP_USDC_VAULT.parse().unwrap());
    cfg.holders = vec![
        WARP_USDC_VAULT.parse().unwrap(),
        WARP_DAI_VAULT.parse().unwrap(),
    ];
    cfg.watched_tokens = vec![DAI.parse().unwrap(), USDC.parse().unwrap()];
    cfg.valuer = Some(std::sync::Arc::new(
        tripwire_context::FixedValues::new()
            .with_stable(DAI.parse().unwrap(), 18)
            .with_stable(USDC.parse().unwrap(), 6),
    ));
    let netted = EvmContext::connect(&rpc_url, cfg).expect("context");
    let nb = netted.baseline(&tx).await;
    let lost = nb.outflow_wei as f64 / nb.balance_baseline_wei as f64;
    println!(
        "value-netted loss: {:.1}% of the drained assets' value",
        lost * 100.0
    );
    let nd = detection::evaluate(
        &support::shipped_signatures(),
        ChainId::ETHEREUM_MAINNET,
        WARP_USDC_VAULT.parse::<Address>().unwrap(),
        &tx,
        &nb,
        Confidence::new(80.0),
        tx.timestamp_unix,
    );
    assert!(lost > 0.5, "netted loss was {lost}");
    assert!(nd.should_pause(), "netted: {}", nd.confidence.value());
}
