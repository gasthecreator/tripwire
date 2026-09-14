use crate::{Address, ChainId, Confidence, SignatureMatch};
use serde::{Deserialize, Serialize};

/// The output of one detection evaluation. Constructing this does not
/// itself submit a pause transaction — it's the auditable record handed
/// to `guardian-client`, which separately applies the confirmation-depth
/// gate (ARCHITECTURE.md §3.2) before acting on it. Keeping "decided" and
/// "acted on" as distinct steps is deliberate: it's what makes a false
/// positive diagnosable from this record alone, without needing to
/// reconstruct chain state after the fact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PauseDecision {
    pub chain: ChainId,
    pub target_contract: Address,
    pub triggering_tx_hash: String,
    pub confidence: Confidence,
    pub threshold: Confidence,
    pub matches: Vec<SignatureMatch>,
    pub evaluated_at_unix: u64,
}

impl PauseDecision {
    pub fn should_pause(&self) -> bool {
        self.confidence.exceeds(self.threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample(confidence: f64, threshold: f64) -> PauseDecision {
        PauseDecision {
            chain: ChainId::ETHEREUM_MAINNET,
            target_contract: Address::from_str("0x0000000000000000000000000000000000000001")
                .unwrap(),
            triggering_tx_hash: "0xdead".into(),
            confidence: Confidence::new(confidence),
            threshold: Confidence::new(threshold),
            matches: vec![],
            evaluated_at_unix: 0,
        }
    }

    #[test]
    fn pauses_when_confidence_meets_threshold_exactly() {
        assert!(sample(80.0, 80.0).should_pause());
    }

    #[test]
    fn pauses_when_confidence_exceeds_threshold() {
        assert!(sample(95.0, 80.0).should_pause());
    }

    #[test]
    fn does_not_pause_just_below_threshold() {
        assert!(!sample(79.9, 80.0).should_pause());
    }

    #[test]
    fn does_not_pause_at_zero_confidence() {
        assert!(!sample(0.0, 1.0).should_pause());
    }

    #[test]
    fn serde_round_trip_preserves_matches() {
        let mut d = sample(90.0, 80.0);
        d.matches.push(SignatureMatch {
            signature_id: "reentrancy-basic".into(),
            weight_contributed: Confidence::new(90.0),
            matched_condition_ids: vec!["reenter".into()],
        });
        let json = serde_json::to_string(&d).unwrap();
        let back: PauseDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}
