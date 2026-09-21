use serde::{Deserialize, Serialize};

/// Confidence is deliberately bounded to `[0, 100]` and constructed only
/// through `Confidence::new` (which clamps) — never a bare `f64` passed
/// around uncontrolled — so a scoring bug can't silently produce a
/// nonsensical value (negative, over 100) that a threshold comparison
/// would mishandle. This is the type a `pause_threshold` in a signature
/// config is compared against (ARCHITECTURE.md §3.3).
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Confidence(f64);

impl Confidence {
    pub const ZERO: Confidence = Confidence(0.0);
    pub const MAX: Confidence = Confidence(100.0);

    pub fn new(value: f64) -> Self {
        // NaN.clamp() panics; a scoring bug producing NaN should surface
        // as zero confidence (fail closed toward "don't pause"), not a
        // panic in the detection hot path.
        if value.is_nan() {
            return Confidence::ZERO;
        }
        Confidence(value.clamp(0.0, 100.0))
    }

    pub fn value(self) -> f64 {
        self.0
    }

    pub fn exceeds(self, threshold: Confidence) -> bool {
        self.0 >= threshold.0
    }
}

impl std::ops::Add for Confidence {
    type Output = Confidence;
    fn add(self, rhs: Self) -> Self::Output {
        Confidence::new(self.0 + rhs.0)
    }
}

impl std::iter::Sum for Confidence {
    fn sum<I: Iterator<Item = Confidence>>(iter: I) -> Self {
        iter.fold(Confidence::ZERO, |acc, c| acc + c)
    }
}

/// One signature's contribution to an incident's overall score, kept
/// individually rather than only summed into a final number — a
/// triggered pause must be auditable after the fact (SECURITY.md §2 T2,
/// §3): showing which signals fired and by how much is what lets a false
/// positive be diagnosed and the threshold retuned from real evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureMatch {
    pub signature_id: String,
    /// This signature's standalone score: the sum of its distinct
    /// evidence (see `evidence`). Not what decides a pause — the
    /// decision's confidence deduplicates evidence *across* signatures.
    pub weight_contributed: Confidence,
    /// Every condition that matched, including ones whose evidence was
    /// already counted (audit trail).
    pub matched_condition_ids: Vec<String>,
    /// The signature's distinct pieces of evidence, each at the highest
    /// weight among the conditions that matched it.
    #[serde(default)]
    pub evidence: Vec<EvidenceHit>,
}

/// One observed fact and the weight a condition assigns it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceHit {
    /// `ConditionKind::evidence_key` of the condition that matched.
    pub key: String,
    /// The condition that supplied this (highest) weight.
    pub condition_id: String,
    pub weight: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_above_max() {
        assert_eq!(Confidence::new(150.0).value(), 100.0);
    }

    #[test]
    fn clamps_below_zero() {
        assert_eq!(Confidence::new(-10.0).value(), 0.0);
    }

    #[test]
    fn nan_fails_closed_to_zero() {
        assert_eq!(Confidence::new(f64::NAN).value(), 0.0);
    }

    #[test]
    fn exceeds_is_inclusive_of_exact_threshold() {
        let c = Confidence::new(75.0);
        assert!(c.exceeds(Confidence::new(75.0)));
        assert!(!c.exceeds(Confidence::new(75.01)));
    }

    #[test]
    fn addition_clamps_at_max() {
        let sum = Confidence::new(60.0) + Confidence::new(60.0);
        assert_eq!(sum.value(), 100.0);
    }

    #[test]
    fn sum_over_iterator_clamps() {
        let total: Confidence = vec![
            Confidence::new(40.0),
            Confidence::new(40.0),
            Confidence::new(40.0),
        ]
        .into_iter()
        .sum();
        assert_eq!(total.value(), 100.0);
    }

    #[test]
    fn sum_of_empty_iterator_is_zero() {
        let total: Confidence = Vec::<Confidence>::new().into_iter().sum();
        assert_eq!(total.value(), 0.0);
    }
}
