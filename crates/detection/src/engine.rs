use tripwire_core::{
    Address, ChainId, Confidence, PauseDecision, Signature, SignatureMatch, TxEvent,
};

use crate::conditions::{self, Baseline};

/// Evaluates every loaded signature against one transaction event and
/// baseline context, returning the matches that fired. A pure function —
/// no I/O, no chain access — so it's exhaustively unit-testable without
/// mocking anything, and safely callable from any chain adapter's hot
/// path (ARCHITECTURE.md §3.3).
pub fn evaluate_signatures(
    signatures: &[Signature],
    tx: &TxEvent,
    baseline: &Baseline,
) -> Vec<SignatureMatch> {
    signatures
        .iter()
        .filter_map(|sig| evaluate_one_signature(sig, tx, baseline))
        .collect()
}

fn evaluate_one_signature(
    sig: &Signature,
    tx: &TxEvent,
    baseline: &Baseline,
) -> Option<SignatureMatch> {
    let mut matched_ids = Vec::new();
    let mut weight_sum = 0.0_f64;

    for condition in &sig.conditions {
        if conditions::evaluate(&condition.kind, tx, baseline) {
            matched_ids.push(condition.id.clone());
            weight_sum += condition.weight;
        }
    }

    if matched_ids.is_empty() {
        return None;
    }

    Some(SignatureMatch {
        signature_id: sig.id.clone(),
        weight_contributed: Confidence::new(weight_sum),
        matched_condition_ids: matched_ids,
    })
}

/// Combines every signature's contribution into one overall confidence
/// and produces the auditable `PauseDecision` record. Matches are
/// *summed*, not maxed: corroboration across multiple different
/// signatures firing on the same incident should raise confidence
/// further, not be discarded in favor of only the single strongest match
/// (ARCHITECTURE.md §3.3) — this is what lets, e.g., a moderate
/// fund-flow anomaly plus a moderate reentrancy signal jointly cross a
/// threshold that neither would alone.
pub fn score(
    chain: ChainId,
    target_contract: Address,
    tx: &TxEvent,
    matches: Vec<SignatureMatch>,
    threshold: Confidence,
    now_unix: u64,
) -> PauseDecision {
    let confidence: Confidence = matches.iter().map(|m| m.weight_contributed).sum();
    PauseDecision {
        chain,
        target_contract,
        triggering_tx_hash: tx.tx_hash.clone(),
        confidence,
        threshold,
        matches,
        evaluated_at_unix: now_unix,
    }
}

/// Convenience wrapper: evaluate every signature and produce the final
/// decision in one call. Most callers (the daemon's hot path) want this;
/// the two-step `evaluate_signatures` + `score` split stays available for
/// callers that need the intermediate match list (e.g. a dashboard
/// showing per-signature breakdowns without re-running detection).
pub fn evaluate(
    signatures: &[Signature],
    chain: ChainId,
    target_contract: Address,
    tx: &TxEvent,
    baseline: &Baseline,
    threshold: Confidence,
    now_unix: u64,
) -> PauseDecision {
    let matches = evaluate_signatures(signatures, tx, baseline);
    score(chain, target_contract, tx, matches, threshold, now_unix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tripwire_core::{CallFrame, CallKind, Condition, ConditionKind, SignatureCategory};

    fn reentrancy_signature(weight: f64) -> Signature {
        Signature {
            id: "reentrancy-basic".into(),
            description: "test".into(),
            category: SignatureCategory::Reentrancy,
            window_seconds: 10,
            conditions: vec![Condition {
                id: "reenter".into(),
                kind: ConditionKind::ReentrancyDepth { min_depth_delta: 1 },
                weight,
            }],
        }
    }

    fn fund_flow_signature(weight: f64, threshold_pct: f64) -> Signature {
        Signature {
            id: "fund-flow-drain".into(),
            description: "test".into(),
            category: SignatureCategory::FundFlowAnomaly,
            window_seconds: 10,
            conditions: vec![Condition {
                id: "outflow".into(),
                kind: ConditionKind::FundFlowDelta { threshold_pct },
                weight,
            }],
        }
    }

    const VAULT: &str = "0x0000000000000000000000000000000000000002";

    fn tx_with_reentrancy() -> TxEvent {
        TxEvent {
            chain: ChainId::ETHEREUM_MAINNET,
            tx_hash: "0xexploit".into(),
            block_number: 100,
            confirmations: 0,
            from: Address::ZERO,
            to: Some(Address::from_str(VAULT).unwrap()),
            value_wei: 0,
            logs: vec![],
            call_frames: vec![
                CallFrame {
                    depth: 0,
                    from: Address::ZERO,
                    to: Address::from_str(VAULT).unwrap(),
                    selector: Some("0xwithdraw".into()),
                    value_wei: 0,
                    kind: CallKind::Call,
                },
                CallFrame {
                    depth: 1,
                    from: Address::ZERO,
                    to: Address::from_str(VAULT).unwrap(),
                    selector: Some("0xwithdraw".into()),
                    value_wei: 0,
                    kind: CallKind::Call,
                },
            ],
            timestamp_unix: 1000,
        }
    }

    fn benign_tx() -> TxEvent {
        TxEvent {
            chain: ChainId::ETHEREUM_MAINNET,
            tx_hash: "0xnormal".into(),
            block_number: 100,
            confirmations: 0,
            from: Address::ZERO,
            to: Some(Address::from_str(VAULT).unwrap()),
            value_wei: 0,
            logs: vec![],
            call_frames: vec![CallFrame {
                depth: 0,
                from: Address::ZERO,
                to: Address::from_str(VAULT).unwrap(),
                selector: Some("0xdeposit".into()),
                value_wei: 0,
                kind: CallKind::Call,
            }],
            timestamp_unix: 1000,
        }
    }

    #[test]
    fn single_strong_signature_crosses_threshold() {
        let sigs = vec![reentrancy_signature(90.0)];
        let decision = evaluate(
            &sigs,
            ChainId::ETHEREUM_MAINNET,
            Address::from_str(VAULT).unwrap(),
            &tx_with_reentrancy(),
            &Baseline::default(),
            Confidence::new(80.0),
            1000,
        );
        assert_eq!(decision.confidence.value(), 90.0);
        assert!(decision.should_pause());
        assert_eq!(decision.matches.len(), 1);
        assert_eq!(decision.matches[0].signature_id, "reentrancy-basic");
    }

    #[test]
    fn benign_transaction_produces_zero_confidence() {
        let sigs = vec![reentrancy_signature(90.0), fund_flow_signature(50.0, 50.0)];
        let decision = evaluate(
            &sigs,
            ChainId::ETHEREUM_MAINNET,
            Address::from_str(VAULT).unwrap(),
            &benign_tx(),
            &Baseline::default(),
            Confidence::new(80.0),
            1000,
        );
        assert_eq!(decision.confidence.value(), 0.0);
        assert!(!decision.should_pause());
        assert!(decision.matches.is_empty());
    }

    #[test]
    fn corroborating_signals_from_two_signatures_combine_to_cross_threshold() {
        // Neither signal alone reaches 80; together they do. This is the
        // whole point of scoring by sum instead of max (ARCHITECTURE.md §3.3).
        let sigs = vec![reentrancy_signature(45.0), fund_flow_signature(45.0, 10.0)];
        let baseline = Baseline {
            balance_baseline_wei: 1_000_000,
            outflow_wei: 200_000, // 20%, above the 10% threshold
            ..Default::default()
        };
        let decision = evaluate(
            &sigs,
            ChainId::ETHEREUM_MAINNET,
            Address::from_str(VAULT).unwrap(),
            &tx_with_reentrancy(),
            &baseline,
            Confidence::new(80.0),
            1000,
        );
        assert_eq!(decision.confidence.value(), 90.0);
        assert!(decision.should_pause());
        assert_eq!(decision.matches.len(), 2);
    }

    #[test]
    fn single_weak_signal_alone_does_not_cross_threshold() {
        // A single moderate signal shouldn't be enough on its own --
        // exactly the false-positive-resistance property SECURITY.md §2
        // (T2) and ARCHITECTURE.md §3.3 both argue for.
        let sigs = vec![reentrancy_signature(45.0)];
        let decision = evaluate(
            &sigs,
            ChainId::ETHEREUM_MAINNET,
            Address::from_str(VAULT).unwrap(),
            &tx_with_reentrancy(),
            &Baseline::default(),
            Confidence::new(80.0),
            1000,
        );
        assert_eq!(decision.confidence.value(), 45.0);
        assert!(!decision.should_pause());
    }

    #[test]
    fn decision_at_exact_threshold_triggers_pause() {
        let sigs = vec![reentrancy_signature(80.0)];
        let decision = evaluate(
            &sigs,
            ChainId::ETHEREUM_MAINNET,
            Address::from_str(VAULT).unwrap(),
            &tx_with_reentrancy(),
            &Baseline::default(),
            Confidence::new(80.0),
            1000,
        );
        assert!(decision.should_pause());
    }

    #[test]
    fn no_signatures_loaded_yields_zero_confidence_never_pauses() {
        let decision = evaluate(
            &[],
            ChainId::ETHEREUM_MAINNET,
            Address::from_str(VAULT).unwrap(),
            &tx_with_reentrancy(),
            &Baseline::default(),
            Confidence::new(0.1),
            1000,
        );
        assert_eq!(decision.confidence.value(), 0.0);
        assert!(!decision.should_pause());
    }

    #[test]
    fn triggering_tx_hash_is_preserved_for_audit() {
        let sigs = vec![reentrancy_signature(90.0)];
        let decision = evaluate(
            &sigs,
            ChainId::ETHEREUM_MAINNET,
            Address::from_str(VAULT).unwrap(),
            &tx_with_reentrancy(),
            &Baseline::default(),
            Confidence::new(80.0),
            1000,
        );
        assert_eq!(decision.triggering_tx_hash, "0xexploit");
    }
}
