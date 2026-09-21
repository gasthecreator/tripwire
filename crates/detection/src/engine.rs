use std::collections::HashMap;

use tripwire_core::{
    Address, ChainId, Confidence, CountedEvidence, EvidenceHit, PauseDecision, Signature,
    SignatureMatch, TxEvent,
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
    // Distinct evidence within this signature: several conditions can
    // observe the same fact at different thresholds (e.g. a 5% and a 50%
    // outflow tier); that fact counts once, at the highest weight.
    let mut best: HashMap<String, EvidenceHit> = HashMap::new();

    for condition in &sig.conditions {
        if conditions::evaluate(&condition.kind, tx, baseline) {
            matched_ids.push(condition.id.clone());
            let key = condition.kind.evidence_key();
            let hit = EvidenceHit {
                key: key.clone(),
                condition_id: condition.id.clone(),
                weight: condition.weight,
            };
            match best.get(&key) {
                Some(existing) if existing.weight >= hit.weight => {}
                _ => {
                    best.insert(key, hit);
                }
            }
        }
    }

    if matched_ids.is_empty() {
        return None;
    }

    let evidence = sorted_evidence(best.into_values().collect());
    let standalone: Confidence = evidence.iter().map(|h| Confidence::new(h.weight)).sum();
    Some(SignatureMatch {
        signature_id: sig.id.clone(),
        weight_contributed: standalone,
        matched_condition_ids: matched_ids,
        evidence,
    })
}

/// Deterministic order (heaviest first, then key) so decisions and their
/// audit records are reproducible.
fn sorted_evidence(mut hits: Vec<EvidenceHit>) -> Vec<EvidenceHit> {
    hits.sort_by(|a, b| {
        b.weight
            .partial_cmp(&a.weight)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.key.cmp(&b.key))
    });
    hits
}

/// Combines every signature's evidence into one overall confidence and
/// produces the auditable `PauseDecision` record.
///
/// Confidence is the sum over *distinct evidence*, each fact counted once
/// at the highest weight any matched condition gave it — not the sum of
/// every matched condition. Corroboration across genuinely different
/// facts (a call pattern plus a balance drain) raises confidence;
/// restating one fact in several signatures does not
/// (ARCHITECTURE.md §3.3). Before this, a single large outflow satisfying
/// a condition in three shipped signatures scored 60 + 40 + 30 and paused
/// on its own, so any legitimate withdrawal above ~20% of a balance would
/// have paused a protocol.
pub fn score(
    chain: ChainId,
    target_contract: Address,
    tx: &TxEvent,
    matches: Vec<SignatureMatch>,
    threshold: Confidence,
    now_unix: u64,
) -> PauseDecision {
    let mut best: HashMap<String, CountedEvidence> = HashMap::new();
    for m in &matches {
        // A match assembled by hand without per-fact evidence still counts,
        // as a single fact of its own, rather than silently scoring zero.
        let fallback;
        let hits: &[EvidenceHit] = if m.evidence.is_empty() && m.weight_contributed.value() > 0.0 {
            fallback = [EvidenceHit {
                key: format!("signature:{}", m.signature_id),
                condition_id: String::new(),
                weight: m.weight_contributed.value(),
            }];
            &fallback
        } else {
            &m.evidence
        };
        for h in hits {
            let candidate = CountedEvidence {
                key: h.key.clone(),
                weight: h.weight,
                signature_id: m.signature_id.clone(),
                condition_id: h.condition_id.clone(),
            };
            match best.get(&h.key) {
                Some(existing) if existing.weight >= candidate.weight => {}
                _ => {
                    best.insert(h.key.clone(), candidate);
                }
            }
        }
    }

    let mut counted_evidence: Vec<CountedEvidence> = best.into_values().collect();
    counted_evidence.sort_by(|a, b| {
        b.weight
            .partial_cmp(&a.weight)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.key.cmp(&b.key))
    });
    let confidence: Confidence = counted_evidence
        .iter()
        .map(|e| Confidence::new(e.weight))
        .sum();

    PauseDecision {
        chain,
        target_contract,
        triggering_tx_hash: tx.tx_hash.clone(),
        confidence,
        threshold,
        matches,
        counted_evidence,
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

    // --- evidence deduplication (found via the real Euler exploit) ---

    fn fund_flow_sig(id: &str, threshold_pct: f64, weight: f64) -> Signature {
        Signature {
            id: id.into(),
            description: "test".into(),
            category: SignatureCategory::FundFlowAnomaly,
            window_seconds: 10,
            conditions: vec![Condition {
                id: format!("{id}-outflow"),
                kind: ConditionKind::FundFlowDelta { threshold_pct },
                weight,
            }],
        }
    }

    fn twenty_five_percent_outflow() -> Baseline {
        Baseline {
            balance_baseline_wei: 1_000,
            outflow_wei: 250,
            ..Default::default()
        }
    }

    fn eval(sigs: &[Signature], tx: &TxEvent, baseline: &Baseline) -> PauseDecision {
        evaluate(
            sigs,
            ChainId::ETHEREUM_MAINNET,
            Address::from_str(VAULT).unwrap(),
            tx,
            baseline,
            Confidence::new(80.0),
            1000,
        )
    }

    #[test]
    fn one_fact_satisfying_three_signatures_is_counted_once_at_its_highest_weight() {
        // The Euler bug: a single outflow satisfied a condition in three
        // signatures (60 + 40 + 30) and scored 130 -> paused on its own.
        let sigs = vec![
            fund_flow_sig("a", 20.0, 60.0),
            fund_flow_sig("b", 15.0, 40.0),
            fund_flow_sig("c", 5.0, 30.0),
        ];
        let d = eval(&sigs, &benign_tx(), &twenty_five_percent_outflow());
        assert_eq!(
            d.matches.len(),
            3,
            "all three signatures still match (audit)"
        );
        assert_eq!(d.confidence.value(), 60.0);
        assert!(!d.should_pause());
        assert_eq!(d.counted_evidence.len(), 1);
        assert_eq!(d.counted_evidence[0].key, "fund_flow");
        assert_eq!(d.counted_evidence[0].signature_id, "a");
    }

    #[test]
    fn different_facts_still_add_up() {
        let sigs = vec![
            reentrancy_signature(45.0),
            fund_flow_sig("drain", 10.0, 45.0),
        ];
        let d = eval(&sigs, &tx_with_reentrancy(), &twenty_five_percent_outflow());
        assert_eq!(d.confidence.value(), 90.0);
        assert!(d.should_pause());
        assert_eq!(d.counted_evidence.len(), 2);
    }

    #[test]
    fn tiered_thresholds_within_one_signature_count_once() {
        let sig = Signature {
            id: "tiered".into(),
            description: "test".into(),
            category: SignatureCategory::FundFlowAnomaly,
            window_seconds: 10,
            conditions: vec![
                Condition {
                    id: "small".into(),
                    kind: ConditionKind::FundFlowDelta { threshold_pct: 5.0 },
                    weight: 20.0,
                },
                Condition {
                    id: "large".into(),
                    kind: ConditionKind::FundFlowDelta {
                        threshold_pct: 20.0,
                    },
                    weight: 50.0,
                },
            ],
        };
        let d = eval(&[sig], &benign_tx(), &twenty_five_percent_outflow());
        assert_eq!(d.confidence.value(), 50.0);
        assert_eq!(d.matches[0].matched_condition_ids, vec!["small", "large"]);
        assert_eq!(d.matches[0].weight_contributed.value(), 50.0);
        assert_eq!(d.counted_evidence[0].condition_id, "large");
    }

    #[test]
    fn only_conditions_that_actually_matched_count() {
        // 25% outflow satisfies the 20% tier but not the 30% tier.
        let sig = Signature {
            id: "tiered".into(),
            description: "test".into(),
            category: SignatureCategory::FundFlowAnomaly,
            window_seconds: 10,
            conditions: vec![
                Condition {
                    id: "mid".into(),
                    kind: ConditionKind::FundFlowDelta {
                        threshold_pct: 20.0,
                    },
                    weight: 30.0,
                },
                Condition {
                    id: "huge".into(),
                    kind: ConditionKind::FundFlowDelta {
                        threshold_pct: 30.0,
                    },
                    weight: 90.0,
                },
            ],
        };
        let d = eval(&[sig], &benign_tx(), &twenty_five_percent_outflow());
        assert_eq!(d.confidence.value(), 30.0);
    }

    fn selector_sig(id: &str, selector: &str, weight: f64) -> Signature {
        Signature {
            id: id.into(),
            description: "test".into(),
            category: SignatureCategory::FlashLoanDrain,
            window_seconds: 10,
            conditions: vec![Condition {
                id: format!("{id}-seq"),
                kind: ConditionKind::CallSequence {
                    selectors: vec![selector.into()],
                },
                weight,
            }],
        }
    }

    #[test]
    fn identical_call_patterns_in_two_signatures_count_once_distinct_ones_both() {
        let mut tx = benign_tx();
        tx.call_frames[0].selector = Some("0xdeposit".into());
        // same selector, different letter case, in two signatures
        let same = vec![
            selector_sig("x", "0xdeposit", 40.0),
            selector_sig("y", "0xDEPOSIT", 35.0),
        ];
        assert_eq!(
            eval(&same, &tx, &Baseline::default()).confidence.value(),
            40.0
        );
        // a genuinely different call pattern is different evidence
        tx.call_frames.push(CallFrame {
            depth: 0,
            from: Address::ZERO,
            to: Address::from_str(VAULT).unwrap(),
            selector: Some("0xother".into()),
            value_wei: 0,
            kind: CallKind::Call,
        });
        let distinct = vec![
            selector_sig("x", "0xdeposit", 40.0),
            selector_sig("y", "0xother", 35.0),
        ];
        assert_eq!(
            eval(&distinct, &tx, &Baseline::default())
                .confidence
                .value(),
            75.0
        );
    }

    #[test]
    fn counted_evidence_is_ordered_heaviest_first_for_reproducible_audit() {
        let sigs = vec![
            reentrancy_signature(30.0),
            fund_flow_sig("drain", 10.0, 55.0),
        ];
        let d = eval(&sigs, &tx_with_reentrancy(), &twenty_five_percent_outflow());
        let keys: Vec<_> = d.counted_evidence.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, vec!["fund_flow", "reentrancy"]);
    }

    #[test]
    fn hand_built_matches_without_evidence_still_score() {
        let tx = benign_tx();
        let matches = vec![SignatureMatch {
            signature_id: "legacy".into(),
            weight_contributed: Confidence::new(70.0),
            matched_condition_ids: vec![],
            evidence: vec![],
        }];
        let d = score(
            ChainId::ETHEREUM_MAINNET,
            Address::from_str(VAULT).unwrap(),
            &tx,
            matches,
            Confidence::new(80.0),
            0,
        );
        assert_eq!(d.confidence.value(), 70.0);
    }

    #[test]
    fn evidence_scoring_never_exceeds_the_bound() {
        let sigs = vec![
            reentrancy_signature(70.0),
            fund_flow_sig("drain", 10.0, 70.0),
            selector_sig("seq", "0xwithdraw", 70.0),
        ];
        let d = eval(&sigs, &tx_with_reentrancy(), &twenty_five_percent_outflow());
        assert_eq!(d.confidence.value(), 100.0);
    }
}
