use serde::{Deserialize, Serialize};

/// A behavioral exploit signature, loaded from YAML (ARCHITECTURE.md §3.3,
/// `signatures/*.yaml`). Deliberately plain data: adding a new exploit
/// signature never requires touching Rust code, only a new document
/// satisfying this schema — and if it needs a genuinely new
/// `ConditionKind` the engine doesn't evaluate yet, one new evaluator
/// function, never a change to matching or scoring itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    pub id: String,
    pub description: String,
    /// Human-assigned label, purely descriptive for reporting/dashboards
    /// — the numeric weight on each condition is what actually drives
    /// scoring, not this category.
    pub category: SignatureCategory,
    /// All conditions must occur within this many seconds of each other
    /// to count as one incident. Most exploit sequences live inside a
    /// single transaction's internal call trace or a tight handful of
    /// consecutive blocks, not a slow-burn pattern over hours.
    pub window_seconds: u64,
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureCategory {
    FlashLoanDrain,
    OracleManipulation,
    Reentrancy,
    GovernanceAnomaly,
    FundFlowAnomaly,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Condition {
    pub id: String,
    pub kind: ConditionKind,
    /// Contribution to the signature's total score if satisfied, on a
    /// 0-100 scale. Signature authors are nudged (not enforced in the
    /// type, but in review per CONTRIBUTING.md) toward conditions whose
    /// weights sum to require corroboration — no single condition alone
    /// should reach a typical `pause_threshold` (ARCHITECTURE.md §3.3,
    /// SECURITY.md T2).
    pub weight: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConditionKind {
    /// Fires if a single transaction's net value outflow from the
    /// watched contract exceeds `threshold_pct` of a rolling baseline
    /// balance.
    FundFlowDelta { threshold_pct: f64 },
    /// Fires if the transaction's flattened selector sequence contains
    /// `selectors` as a contiguous, in-order subsequence.
    CallSequence { selectors: Vec<String> },
    /// Fires if an oracle-reporting call's price deviates from a
    /// reference price (a TWAP, or a second independent oracle) by more
    /// than `threshold_pct` within the window.
    OraclePriceDeviation { threshold_pct: f64 },
    /// Fires if a state-changing call to a `(to, selector)` pair is made
    /// while an earlier, still-active call to the same pair is on the
    /// call stack at least `min_depth_delta` levels up. Read-only
    /// `STATICCALL`s and already-returned calls never count.
    ReentrancyDepth { min_depth_delta: u32 },
    /// Fires if a governance proposal's voting power for a single
    /// address increases by more than `threshold_pct` within the window
    /// — the flash-loaned-voting-power pattern (e.g. Beanstalk, Apr 2022).
    GovernanceProposalAnomaly { threshold_pct: f64 },
}

impl ConditionKind {
    /// Names the underlying *fact* this condition is evidence of, so the
    /// scorer can count each fact once no matter how many conditions (in
    /// how many signatures, at what thresholds) it satisfies.
    ///
    /// Without this, one large outflow that satisfied a `FundFlowDelta`
    /// condition in three different signatures was summed three times and
    /// reached the pause threshold on its own, defeating the rule that no
    /// single signal may trigger a pause (ARCHITECTURE.md §3.3,
    /// SECURITY.md T2). Found by scoring the real Euler exploit.
    ///
    /// The threshold is deliberately not part of the key: a 5% and a 50%
    /// outflow condition are the same observation. `CallSequence` is keyed
    /// by its (case-normalised) selector list, so distinct call patterns
    /// remain distinct evidence.
    pub fn evidence_key(&self) -> String {
        match self {
            ConditionKind::FundFlowDelta { .. } => "fund_flow".into(),
            ConditionKind::CallSequence { selectors } => format!(
                "call_sequence:{}",
                selectors
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            ConditionKind::OraclePriceDeviation { .. } => "oracle_price_deviation".into(),
            ConditionKind::ReentrancyDepth { .. } => "reentrancy".into(),
            ConditionKind::GovernanceProposalAnomaly { .. } => "governance_voting_power".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_YAML: &str = r#"
id: reentrancy-basic
description: Classic single-function reentrancy via external call before state update
category: reentrancy
window_seconds: 15
conditions:
  - id: reenter
    kind:
      type: reentrancy_depth
      min_depth_delta: 1
    weight: 90.0
  - id: fund_flow
    kind:
      type: fund_flow_delta
      threshold_pct: 10.0
    weight: 20.0
"#;

    #[test]
    fn parses_sample_signature_yaml() {
        let sig: Signature = serde_yaml::from_str(SAMPLE_YAML).unwrap();
        assert_eq!(sig.id, "reentrancy-basic");
        assert_eq!(sig.category, SignatureCategory::Reentrancy);
        assert_eq!(sig.window_seconds, 15);
        assert_eq!(sig.conditions.len(), 2);
        assert_eq!(
            sig.conditions[0].kind,
            ConditionKind::ReentrancyDepth { min_depth_delta: 1 }
        );
        assert_eq!(sig.conditions[1].weight, 20.0);
    }

    #[test]
    fn round_trips_through_json() {
        let sig: Signature = serde_yaml::from_str(SAMPLE_YAML).unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let back: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn rejects_unknown_condition_type() {
        let bad = SAMPLE_YAML.replace("reentrancy_depth", "not_a_real_kind");
        assert!(serde_yaml::from_str::<Signature>(&bad).is_err());
    }

    #[test]
    fn rejects_unknown_category() {
        let bad = SAMPLE_YAML.replace("category: reentrancy", "category: not_a_real_category");
        assert!(serde_yaml::from_str::<Signature>(&bad).is_err());
    }

    #[test]
    fn rejects_missing_required_field() {
        let bad = SAMPLE_YAML.replace("window_seconds: 15\n", "");
        assert!(serde_yaml::from_str::<Signature>(&bad).is_err());
    }

    #[test]
    fn call_sequence_condition_parses_selector_list() {
        let yaml = r#"
id: flash-loan-drain
description: Flash loan then drain sequence
category: flash_loan_drain
window_seconds: 1
conditions:
  - id: seq
    kind:
      type: call_sequence
      selectors: ["0xa9059cbb", "0x23b872dd"]
    weight: 100.0
"#;
        let sig: Signature = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            sig.conditions[0].kind,
            ConditionKind::CallSequence {
                selectors: vec!["0xa9059cbb".into(), "0x23b872dd".into()]
            }
        );
    }

    #[test]
    fn evidence_key_ignores_thresholds() {
        let a = ConditionKind::FundFlowDelta { threshold_pct: 5.0 };
        let b = ConditionKind::FundFlowDelta {
            threshold_pct: 50.0,
        };
        assert_eq!(a.evidence_key(), b.evidence_key());
        assert_eq!(
            ConditionKind::ReentrancyDepth { min_depth_delta: 1 }.evidence_key(),
            ConditionKind::ReentrancyDepth { min_depth_delta: 3 }.evidence_key()
        );
    }

    #[test]
    fn evidence_keys_differ_across_kinds() {
        let keys = [
            ConditionKind::FundFlowDelta { threshold_pct: 1.0 }.evidence_key(),
            ConditionKind::OraclePriceDeviation { threshold_pct: 1.0 }.evidence_key(),
            ConditionKind::ReentrancyDepth { min_depth_delta: 1 }.evidence_key(),
            ConditionKind::GovernanceProposalAnomaly { threshold_pct: 1.0 }.evidence_key(),
            ConditionKind::CallSequence {
                selectors: vec!["0xaa".into()],
            }
            .evidence_key(),
        ];
        let unique: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(unique.len(), keys.len());
    }

    #[test]
    fn call_sequence_evidence_is_keyed_by_normalised_selectors() {
        let lower = ConditionKind::CallSequence {
            selectors: vec!["0xabcdef12".into()],
        };
        let upper = ConditionKind::CallSequence {
            selectors: vec!["0xABCDEF12".into()],
        };
        let other = ConditionKind::CallSequence {
            selectors: vec!["0x11111111".into()],
        };
        let ordered = ConditionKind::CallSequence {
            selectors: vec!["0xaa".into(), "0xbb".into()],
        };
        let reversed = ConditionKind::CallSequence {
            selectors: vec!["0xbb".into(), "0xaa".into()],
        };
        assert_eq!(lower.evidence_key(), upper.evidence_key());
        assert_ne!(lower.evidence_key(), other.evidence_key());
        assert_ne!(ordered.evidence_key(), reversed.evidence_key());
    }
}
