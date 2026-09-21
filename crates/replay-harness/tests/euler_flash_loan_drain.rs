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
//! scored on the same real data below to keep that visible.

use replay_harness::support;
use tripwire_core::{
    Address, ChainId, Condition, ConditionKind, Confidence, Signature, SignatureCategory,
};

const BLOCK: u64 = 16_817_996;
const TX_HASH: &str = "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d";
const EXPLOIT_CONTRACT: &str = "0xeBC29199C817Dc47BA12E3F86102564D640CBf99";
const EULER: &str = "0x27182842E098f60e3D576794A5bFFb0777E025d3";
const DAI: &str = "0x6b175474e89094c44da98b954eedeac495271d0f";
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

    // Real fund flow: Euler's DAI balance in the block before, and the
    // net DAI that left it during the transaction (the 30M flash loan is
    // borrowed and repaid, so only the real drain remains).
    let baseline = support::fund_flow_baseline(&rpc_url, &tx, DAI, EULER).expect("baseline");
    println!(
        "Euler DAI before: {} wei, net outflow: {} wei",
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

    // Shipped generic signatures on the same real data. Their placeholder
    // flash-loan and governance selectors don't match Euler, so the only
    // evidence they see is the balance drain, which three signatures each
    // report. Deduplicated, that is one fact worth at most 60 — below the
    // pause threshold: the generic set alone does NOT catch Euler, and,
    // crucially, would not pause on any lone large outflow either. (Before
    // evidence deduplication this scored 100.0 by summing the same outflow
    // three times; see WORKLOG.md.) Catching Euler with generic signatures
    // needs per-protocol tuning or a corroborating condition, as with
    // Beanstalk.
    let generic = detection::load_signatures_from_dir(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../signatures"),
    )
    .expect("load shipped signatures");
    let g = detection::evaluate(
        &generic,
        ChainId::ETHEREUM_MAINNET,
        target,
        &tx,
        &baseline,
        threshold,
        tx.timestamp_unix,
    );
    println!(
        "Shipped generic signatures on the same real data: confidence {:.1}, counted evidence {:?}",
        g.confidence.value(),
        g.counted_evidence
    );
    assert!(
        g.matches.len() >= 2,
        "several generic signatures see the drain"
    );
    assert_eq!(g.counted_evidence.len(), 1, "but it is one fact");
    assert_eq!(g.counted_evidence[0].key, "fund_flow");
    assert_eq!(g.confidence.value(), 60.0);
    assert!(!g.should_pause());
}
