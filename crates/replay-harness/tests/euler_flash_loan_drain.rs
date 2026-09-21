//! Euler Finance exploit, 13 March 2023 (~$197M): the first attack
//! transaction, replayed from real chain data and scored by the real
//! detection engine.
//!
//! **Facts asserted and where each was verified (2026-09-21):**
//! - Transaction `0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d`,
//!   block 16817996: found on-chain (not from a web summary) by scanning
//!   Aave V2 `FlashLoan` events for a 30,000,000 DAI loan, then confirmed
//!   on Etherscan: 08:50:59 UTC, sender labelled "Euler Finance
//!   Exploiter 3", recipient "Euler Exploit Contract 1"
//!   (`0xeBC29199C817Dc47BA12E3F86102564D640CBf99`), status success.
//! - `donateToReserves(uint256,uint256)` selector `0x36f022aa`: computed
//!   from the declaration `function donateToReserves(uint subAccountId,
//!   uint amount) external nonReentrant` in Euler's own
//!   `contracts/modules/EToken.sol` (github.com/euler-xyz/euler-contracts,
//!   master as fetched 2026-09-21). This function is the exploited flaw:
//!   it lacked a health check on the donating account.
//! - `executeOperation(...)` `0x920f5c84`: Aave V2's fixed
//!   `IFlashLoanReceiver` callback, not incident-specific.
//! - Euler main proxy `0x27182842E098f60e3D576794A5bFFb0777E025d3` holds
//!   the assets; its DAI balance went 8,904,507 -> 0 across this
//!   transaction (measured from the archive node, see assertions).
//!
//! The signature is tuned to this incident (its selectors come from it),
//! so passing shows the pipeline works on real data, not that a generic
//! signature would have caught Euler; the shipped generic signatures are
//! scored on the same real data below, and they do pause on it.

use detection::ContextSource;
use replay_harness::support;
use tripwire_context::{ContextConfig, EvmContext};
use tripwire_core::{
    Address, ChainId, Condition, ConditionKind, Confidence, Signature, SignatureCategory,
};

const BLOCK: u64 = 16_817_996;
const TX_HASH: &str = "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d";
const EXPLOIT_CONTRACT: &str = "0xeBC29199C817Dc47BA12E3F86102564D640CBf99";
const EULER: &str = "0x27182842E098f60e3D576794A5bFFb0777E025d3";
const DAI: &str = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const USDT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
const WETH: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const WBTC: &str = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599";
const WSTETH: &str = "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0";
const AAVE_V2_FLASH_LOAN_CALLBACK: &str = "0x920f5c84";
const DONATE_TO_RESERVES: &str = "0x36f022aa";

fn call_presence(id: &str, selector: &str, weight: f64) -> Condition {
    Condition {
        id: id.into(),
        kind: ConditionKind::CallSequence {
            selectors: vec![selector.into()],
        },
        weight,
    }
}

fn euler_signature() -> Signature {
    Signature {
        id: "euler-donate-to-reserves-2023-03-13".into(),
        description: "Aave flash loan, then donateToReserves, draining a watched balance".into(),
        category: SignatureCategory::FlashLoanDrain,
        window_seconds: 60,
        conditions: vec![
            call_presence(
                "aave-flash-loan-callback",
                AAVE_V2_FLASH_LOAN_CALLBACK,
                25.0,
            ),
            call_presence("donate-to-reserves-called", DONATE_TO_RESERVES, 35.0),
            Condition {
                id: "watched-balance-drained".into(),
                kind: ConditionKind::FundFlowDelta {
                    threshold_pct: 50.0,
                },
                weight: 35.0,
            },
        ],
    }
}

#[tokio::test]
async fn euler_exploit_scores_above_pause_threshold() {
    let Some(rpc_url) = support::rpc_url_or_skip() else {
        return;
    };

    let tx = support::load_replayed_tx(&rpc_url, BLOCK, TX_HASH).await;
    assert_eq!(
        tx.to.map(|a| a.to_string()),
        Some(EXPLOIT_CONTRACT.to_lowercase()),
        "recipient must be the Etherscan-labelled Euler Exploit Contract 1"
    );
    println!(
        "Replayed real Euler tx: {} call frames (max depth {}), {} receipt logs",
        tx.call_frames.len(),
        tx.max_call_depth(),
        tx.logs.len()
    );
    assert!(
        tx.call_frames.len() > 100,
        "the real exploit is a wide call tree"
    );

    // Real fund flow, from the production context source: Euler's balances
    // in the block before, and the net outflow of each watched asset during
    // the transaction (the 30M flash loan is borrowed and repaid, so only
    // the real drain remains). The watched assets are Euler's own markets,
    // configured up front as an operator would — not derived from this tx.
    let mut cfg = ContextConfig::new(EULER.parse().unwrap());
    cfg.watched_tokens = [DAI, USDC, USDT, WETH, WBTC, WSTETH]
        .iter()
        .map(|a| a.parse().unwrap())
        .collect();
    let ctx = EvmContext::connect(&rpc_url, cfg).expect("context");
    let baseline = ctx.baseline(&tx).await;
    println!(
        "Euler worst-asset balance: {} wei, net outflow: {} wei",
        baseline.balance_baseline_wei, baseline.outflow_wei
    );
    assert_eq!(
        baseline.balance_baseline_wei, 8_904_507_348_306_697_267_428_294,
        "Euler's DAI balance at block 16817995"
    );
    assert_eq!(
        baseline.outflow_wei, baseline.balance_baseline_wei,
        "the transaction drained Euler's entire DAI balance"
    );

    let target: Address = EULER.parse().unwrap();
    let threshold = Confidence::new(80.0);
    let decision = detection::evaluate(
        &[euler_signature()],
        ChainId::ETHEREUM_MAINNET,
        target,
        &tx,
        &baseline,
        threshold,
        tx.timestamp_unix,
    );
    println!(
        "Confidence: {:.1} (threshold 80.0), matched {:?}",
        decision.confidence.value(),
        decision.matches
    );
    assert_eq!(
        decision.matches[0].matched_condition_ids.len(),
        3,
        "flash-loan callback, donateToReserves and the balance drain must all be present"
    );
    assert!(decision.should_pause());

    // The shipped generic signatures, with only Euler's own assets
    // configured: a call to Aave's flash-loan entrypoint plus a 100% drain
    // of an asset Euler held. Two distinct facts, one of them harm.
    let g = detection::evaluate(
        &support::shipped_signatures(),
        ChainId::ETHEREUM_MAINNET,
        target,
        &tx,
        &baseline,
        threshold,
        tx.timestamp_unix,
    );
    println!(
        "GENERIC: confidence {:.1} pause={} evidence {:?}",
        g.confidence.value(),
        g.should_pause(),
        g.counted_evidence
    );
    let keys: Vec<&str> = g.counted_evidence.iter().map(|e| e.key.as_str()).collect();
    assert!(keys.contains(&"fund_flow"), "{keys:?}");
    assert!(keys.iter().any(|k| k.starts_with("call_any:")), "{keys:?}");
    assert!(
        g.should_pause(),
        "generic set scored only {}",
        g.confidence.value()
    );

    // And the drain alone -- one fact -- must not pause (the double-counting
    // bug once made it score 100).
    let mut drain_only = tx.clone();
    drain_only.call_frames.clear();
    let d = detection::evaluate(
        &support::shipped_signatures(),
        ChainId::ETHEREUM_MAINNET,
        target,
        &drain_only,
        &baseline,
        threshold,
        tx.timestamp_unix,
    );
    assert!(
        !d.should_pause(),
        "a lone drain scored {}",
        d.confidence.value()
    );
}
