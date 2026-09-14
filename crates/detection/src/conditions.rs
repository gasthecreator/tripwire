use std::collections::HashMap;
use tripwire_core::{Address, ConditionKind, TxEvent};

/// External context a condition evaluator needs beyond what's in a raw
/// `TxEvent` — a protocol balance baseline, a reference oracle price, a
/// governance voting-power baseline. Computing these values from chain
/// state is the caller's job (the `chain-adapter`/daemon layer); this
/// crate stays chain-agnostic and only reasons about the numbers once
/// they're in hand, per ARCHITECTURE.md §3.1's trait boundary.
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    /// The watched contract's balance (wei) at the start of the
    /// signature's evaluation window — the denominator for
    /// `FundFlowDelta`.
    pub balance_baseline_wei: u128,
    /// Net value that left the watched contract during this transaction,
    /// as computed upstream from the raw call trace.
    pub outflow_wei: u128,
    /// A reference price (TWAP, or an independent second oracle).
    pub reference_price: Option<f64>,
    /// The price this transaction's oracle-reporting call actually
    /// reported.
    pub observed_price: Option<f64>,
    /// Voting power baseline for the address a governance proposal
    /// concerns, before this transaction.
    pub voting_power_baseline: Option<f64>,
    /// Voting power for that same address after this transaction.
    pub observed_voting_power: Option<f64>,
}

/// Evaluates a single condition against one transaction and its
/// baseline context. This is the one place a new `ConditionKind` variant
/// gets real evaluation logic — matching and scoring above this layer
/// are generic over whatever conditions exist (ARCHITECTURE.md §3.3).
pub fn evaluate(kind: &ConditionKind, tx: &TxEvent, baseline: &Baseline) -> bool {
    match kind {
        ConditionKind::FundFlowDelta { threshold_pct } => {
            evaluate_fund_flow_delta(*threshold_pct, baseline)
        }
        ConditionKind::CallSequence { selectors } => evaluate_call_sequence(selectors, tx),
        ConditionKind::OraclePriceDeviation { threshold_pct } => {
            evaluate_oracle_price_deviation(*threshold_pct, baseline)
        }
        ConditionKind::ReentrancyDepth { min_depth_delta } => {
            evaluate_reentrancy_depth(*min_depth_delta, tx)
        }
        ConditionKind::GovernanceProposalAnomaly { threshold_pct } => {
            evaluate_governance_anomaly(*threshold_pct, baseline)
        }
    }
}

fn evaluate_fund_flow_delta(threshold_pct: f64, baseline: &Baseline) -> bool {
    if baseline.balance_baseline_wei == 0 {
        // No baseline to compare against: fail closed (not satisfied)
        // rather than divide by zero or treat any outflow as an
        // infinite percentage. A protocol with a genuinely zero balance
        // baseline has bigger problems than a missed signature match.
        return false;
    }
    let pct = (baseline.outflow_wei as f64 / baseline.balance_baseline_wei as f64) * 100.0;
    pct >= threshold_pct
}

fn evaluate_call_sequence(selectors: &[String], tx: &TxEvent) -> bool {
    if selectors.is_empty() {
        return true;
    }
    let observed: Vec<&str> = tx
        .call_frames
        .iter()
        .filter_map(|f| f.selector.as_deref())
        .collect();
    if observed.len() < selectors.len() {
        return false;
    }
    observed.windows(selectors.len()).any(|window| {
        window
            .iter()
            .zip(selectors.iter())
            .all(|(o, s)| o.eq_ignore_ascii_case(s))
    })
}

fn evaluate_oracle_price_deviation(threshold_pct: f64, baseline: &Baseline) -> bool {
    match (baseline.reference_price, baseline.observed_price) {
        (Some(reference), Some(observed)) if reference > 0.0 => {
            let deviation_pct = ((observed - reference).abs() / reference) * 100.0;
            deviation_pct >= threshold_pct
        }
        _ => false,
    }
}

fn evaluate_reentrancy_depth(min_depth_delta: u32, tx: &TxEvent) -> bool {
    let mut first_seen_depth: HashMap<(Address, Option<String>), u32> = HashMap::new();
    for frame in &tx.call_frames {
        let key = (frame.to, frame.selector.clone());
        match first_seen_depth.get(&key) {
            None => {
                first_seen_depth.insert(key, frame.depth);
            }
            Some(&first_depth) => {
                if frame.depth >= first_depth + min_depth_delta {
                    return true;
                }
            }
        }
    }
    false
}

fn evaluate_governance_anomaly(threshold_pct: f64, baseline: &Baseline) -> bool {
    match (
        baseline.voting_power_baseline,
        baseline.observed_voting_power,
    ) {
        (Some(base), Some(observed)) if base > 0.0 => {
            let pct_increase = ((observed - base) / base) * 100.0;
            pct_increase >= threshold_pct
        }
        (Some(0.0), Some(observed)) => observed > 0.0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tripwire_core::{CallFrame, ChainId};

    fn empty_tx() -> TxEvent {
        TxEvent {
            chain: ChainId::ETHEREUM_MAINNET,
            tx_hash: "0x1".into(),
            block_number: 1,
            confirmations: 0,
            from: Address::ZERO,
            to: None,
            value_wei: 0,
            logs: vec![],
            call_frames: vec![],
            timestamp_unix: 0,
        }
    }

    fn frame(depth: u32, to: &str, selector: Option<&str>) -> CallFrame {
        CallFrame {
            depth,
            from: Address::ZERO,
            to: Address::from_str(to).unwrap(),
            selector: selector.map(String::from),
            value_wei: 0,
        }
    }

    const VAULT: &str = "0x0000000000000000000000000000000000000002";
    const OTHER: &str = "0x0000000000000000000000000000000000000003";

    // --- fund flow delta ---

    #[test]
    fn fund_flow_fails_closed_with_zero_baseline() {
        let baseline = Baseline {
            balance_baseline_wei: 0,
            outflow_wei: 1_000_000,
            ..Default::default()
        };
        assert!(!evaluate_fund_flow_delta(1.0, &baseline));
    }

    #[test]
    fn fund_flow_below_threshold_does_not_fire() {
        let baseline = Baseline {
            balance_baseline_wei: 1_000_000,
            outflow_wei: 10_000, // 1%
            ..Default::default()
        };
        assert!(!evaluate_fund_flow_delta(50.0, &baseline));
    }

    #[test]
    fn fund_flow_at_exact_threshold_fires() {
        let baseline = Baseline {
            balance_baseline_wei: 1_000_000,
            outflow_wei: 500_000, // exactly 50%
            ..Default::default()
        };
        assert!(evaluate_fund_flow_delta(50.0, &baseline));
    }

    #[test]
    fn small_legitimate_withdrawal_does_not_fire_high_threshold() {
        // A normal user withdrawal: 2% of TVL. Should not look like a drain.
        let baseline = Baseline {
            balance_baseline_wei: 10_000_000,
            outflow_wei: 200_000,
            ..Default::default()
        };
        assert!(!evaluate_fund_flow_delta(80.0, &baseline));
    }

    // --- call sequence ---

    #[test]
    fn call_sequence_matches_contiguous_in_order() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xaaaaaaaa")),
            frame(1, VAULT, Some("0xbbbbbbbb")),
            frame(2, VAULT, Some("0xcccccccc")),
        ];
        assert!(evaluate_call_sequence(
            &["0xaaaaaaaa".into(), "0xbbbbbbbb".into()],
            &tx
        ));
    }

    #[test]
    fn call_sequence_does_not_match_wrong_order() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xbbbbbbbb")),
            frame(1, VAULT, Some("0xaaaaaaaa")),
        ];
        assert!(!evaluate_call_sequence(
            &["0xaaaaaaaa".into(), "0xbbbbbbbb".into()],
            &tx
        ));
    }

    #[test]
    fn call_sequence_does_not_match_non_contiguous() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xaaaaaaaa")),
            frame(1, VAULT, Some("0xdddddddd")),
            frame(2, VAULT, Some("0xbbbbbbbb")),
        ];
        assert!(!evaluate_call_sequence(
            &["0xaaaaaaaa".into(), "0xbbbbbbbb".into()],
            &tx
        ));
    }

    #[test]
    fn call_sequence_is_case_insensitive() {
        let mut tx = empty_tx();
        tx.call_frames = vec![frame(0, VAULT, Some("0xAAAAAAAA"))];
        assert!(evaluate_call_sequence(&["0xaaaaaaaa".into()], &tx));
    }

    #[test]
    fn call_sequence_empty_selectors_trivially_matches() {
        let tx = empty_tx();
        assert!(evaluate_call_sequence(&[], &tx));
    }

    #[test]
    fn call_sequence_no_match_on_empty_call_frames() {
        let tx = empty_tx();
        assert!(!evaluate_call_sequence(&["0xaaaaaaaa".into()], &tx));
    }

    // --- oracle price deviation ---

    #[test]
    fn oracle_deviation_fires_on_large_spike() {
        let baseline = Baseline {
            reference_price: Some(100.0),
            observed_price: Some(150.0), // +50%
            ..Default::default()
        };
        assert!(evaluate_oracle_price_deviation(30.0, &baseline));
    }

    #[test]
    fn oracle_deviation_fires_on_large_drop_via_abs_value() {
        let baseline = Baseline {
            reference_price: Some(100.0),
            observed_price: Some(40.0), // -60%
            ..Default::default()
        };
        assert!(evaluate_oracle_price_deviation(30.0, &baseline));
    }

    #[test]
    fn oracle_deviation_does_not_fire_on_normal_market_move() {
        let baseline = Baseline {
            reference_price: Some(100.0),
            observed_price: Some(103.0), // +3%, ordinary volatility
            ..Default::default()
        };
        assert!(!evaluate_oracle_price_deviation(20.0, &baseline));
    }

    #[test]
    fn oracle_deviation_fails_closed_when_data_missing() {
        let baseline = Baseline::default();
        assert!(!evaluate_oracle_price_deviation(1.0, &baseline));
    }

    #[test]
    fn oracle_deviation_fails_closed_on_zero_reference() {
        let baseline = Baseline {
            reference_price: Some(0.0),
            observed_price: Some(10.0),
            ..Default::default()
        };
        assert!(!evaluate_oracle_price_deviation(1.0, &baseline));
    }

    // --- reentrancy depth ---

    #[test]
    fn reentrancy_fires_when_same_target_selector_recurs_deeper() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xwithdraw")),
            frame(1, OTHER, Some("0xfallback")),
            frame(2, VAULT, Some("0xwithdraw")), // reenters withdraw() one level deeper
        ];
        assert!(evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn reentrancy_does_not_fire_for_different_selector() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xwithdraw")),
            frame(1, VAULT, Some("0xdeposit")), // different function, not reentrancy
        ];
        assert!(!evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn reentrancy_does_not_fire_for_different_target() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xwithdraw")),
            frame(1, OTHER, Some("0xwithdraw")), // same selector, different contract
        ];
        assert!(!evaluate_reentrancy_depth(1, &tx));
    }

    #[test]
    fn reentrancy_respects_min_depth_delta_boundary() {
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xwithdraw")),
            frame(1, VAULT, Some("0xwithdraw")), // only 1 deeper
        ];
        assert!(evaluate_reentrancy_depth(1, &tx));
        assert!(!evaluate_reentrancy_depth(2, &tx));
    }

    #[test]
    fn nested_legitimate_calls_do_not_look_like_reentrancy() {
        // A normal multi-hop swap: A -> B -> C, no repeated (to, selector).
        let mut tx = empty_tx();
        tx.call_frames = vec![
            frame(0, VAULT, Some("0xswap")),
            frame(1, OTHER, Some("0xtransfer")),
            frame(
                2,
                "0x0000000000000000000000000000000000000004",
                Some("0xtransfer"),
            ),
        ];
        assert!(!evaluate_reentrancy_depth(1, &tx));
    }

    // --- governance anomaly ---

    #[test]
    fn governance_anomaly_fires_on_flash_loaned_voting_power() {
        let baseline = Baseline {
            voting_power_baseline: Some(1_000.0),
            observed_voting_power: Some(1_000_000.0), // massive spike
            ..Default::default()
        };
        assert!(evaluate_governance_anomaly(100.0, &baseline));
    }

    #[test]
    fn governance_anomaly_fires_when_baseline_is_zero_and_power_appears() {
        let baseline = Baseline {
            voting_power_baseline: Some(0.0),
            observed_voting_power: Some(500.0),
            ..Default::default()
        };
        assert!(evaluate_governance_anomaly(10.0, &baseline));
    }

    #[test]
    fn governance_anomaly_does_not_fire_on_normal_delegation() {
        let baseline = Baseline {
            voting_power_baseline: Some(10_000.0),
            observed_voting_power: Some(10_500.0), // +5%, ordinary
            ..Default::default()
        };
        assert!(!evaluate_governance_anomaly(50.0, &baseline));
    }

    #[test]
    fn governance_anomaly_fails_closed_when_data_missing() {
        assert!(!evaluate_governance_anomaly(1.0, &Baseline::default()));
    }
}
