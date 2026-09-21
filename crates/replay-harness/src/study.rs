//! Pure parts of the false-positive study: deterministic sampling, the
//! statistics, and report rendering. The network-driven runner is
//! `examples/fp_study.rs`; everything here is unit-tested without a network.

use std::collections::BTreeSet;

/// SplitMix64: a tiny, well-known deterministic generator. Used so a study
/// run is reproducible from its seed (given the same chain), not to be
/// unpredictable.
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// `count` distinct, non-overlapping block windows `[start, start+width-1]`
/// drawn uniformly from `[lo, hi]`, sorted ascending. Window starts are
/// aligned to multiples of `width` (relative to `lo`) so windows can never
/// overlap. If fewer than `count` slots exist, all slots are returned.
pub fn sample_windows(seed: u64, lo: u64, hi: u64, count: usize, width: u64) -> Vec<(u64, u64)> {
    assert!(width > 0 && hi >= lo);
    let slots = (hi - lo + 1) / width;
    if slots == 0 {
        return Vec::new();
    }
    let want = (count as u64).min(slots) as usize;
    let mut rng = SplitMix64::new(seed);
    let mut chosen = BTreeSet::new();
    while chosen.len() < want {
        chosen.insert(rng.next_u64() % slots);
    }
    chosen
        .into_iter()
        .map(|s| {
            let start = lo + s * width;
            (start, start + width - 1)
        })
        .collect()
}

/// 95% (or any `z`) Wilson score interval for a binomial proportion.
/// Preferred over the normal approximation because it behaves at 0 and 1
/// and for small samples — exactly the regime a false-positive count of 0
/// lives in. `n == 0` gives the uninformative `(0, 1)`.
pub fn wilson_interval(successes: u64, n: u64, z: f64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let n_f = n as f64;
    let p = successes as f64 / n_f;
    let z2 = z * z;
    let denom = 1.0 + z2 / n_f;
    let center = (p + z2 / (2.0 * n_f)) / denom;
    let half = z * (p * (1.0 - p) / n_f + z2 / (4.0 * n_f * n_f)).sqrt() / denom;
    ((center - half).max(0.0), (center + half).min(1.0))
}

/// What happened to one sampled legitimate transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub protocol: String,
    pub tx_hash: String,
    pub block: u64,
    /// Largest fraction of any single watched asset's balance that left.
    pub max_outflow_fraction: f64,
    /// Whether a fund-flow ("harm") fact was present in the decision.
    pub had_harm_fact: bool,
    /// Whether a call trace was fetched for this transaction.
    pub traced: bool,
    pub confidence: f64,
    pub paused: bool,
    pub evidence_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProtocolSummary {
    pub protocol: String,
    /// Sampled transactions with at least one watched-asset outflow.
    pub population: u64,
    pub with_harm_fact: u64,
    pub traced: u64,
    pub paused: u64,
    /// Sampled blocks (for converting to a per-day rate).
    pub blocks_sampled: u64,
}

impl ProtocolSummary {
    pub fn false_pause_rate(&self) -> f64 {
        if self.population == 0 {
            0.0
        } else {
            self.paused as f64 / self.population as f64
        }
    }

    pub fn wilson_95(&self) -> (f64, f64) {
        wilson_interval(self.paused, self.population, 1.96)
    }

    /// Expected false pauses per day given the sampled density of
    /// transactions per block and ~7,200 blocks/day, at the point estimate
    /// and at the 95% upper bound.
    pub fn false_pauses_per_day(&self) -> (f64, f64) {
        if self.blocks_sampled == 0 {
            return (0.0, 0.0);
        }
        let txs_per_day = self.population as f64 / self.blocks_sampled as f64 * 7_200.0;
        (
            txs_per_day * self.false_pause_rate(),
            txs_per_day * self.wilson_95().1,
        )
    }
}

pub fn summarize(protocol: &str, blocks_sampled: u64, outcomes: &[Outcome]) -> ProtocolSummary {
    let mine: Vec<&Outcome> = outcomes.iter().filter(|o| o.protocol == protocol).collect();
    ProtocolSummary {
        protocol: protocol.to_string(),
        population: mine.len() as u64,
        with_harm_fact: mine.iter().filter(|o| o.had_harm_fact).count() as u64,
        traced: mine.iter().filter(|o| o.traced).count() as u64,
        paused: mine.iter().filter(|o| o.paused).count() as u64,
        blocks_sampled,
    }
}

/// Histogram of the max-outflow fraction: how big legitimate outflows
/// actually get, bucketed at the shipped conditions' thresholds.
pub fn fraction_buckets(outcomes: &[Outcome]) -> [u64; 5] {
    let mut b = [0u64; 5]; // <1%, 1-5%, 5-20%, 20-50%, >=50%
    for o in outcomes {
        let f = o.max_outflow_fraction;
        let i = if f < 0.01 {
            0
        } else if f < 0.05 {
            1
        } else if f < 0.20 {
            2
        } else if f < 0.50 {
            3
        } else {
            4
        };
        b[i] += 1;
    }
    b
}

pub fn render_summary_table(summaries: &[ProtocolSummary]) -> String {
    let mut s = String::from(
        "| Protocol | Sampled txs with an outflow | Outflow ≥ 5% of a balance | Traced | Paused | False-pause rate (95% CI) | Expected false pauses/day (point / 95% upper) |\n|---|---:|---:|---:|---:|---|---|\n",
    );
    for p in summaries {
        let (lo, hi) = p.wilson_95();
        let (d_pt, d_hi) = p.false_pauses_per_day();
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {:.3}% ({:.3}%–{:.3}%) | {:.2} / {:.2} |\n",
            p.protocol,
            p.population,
            p.with_harm_fact,
            p.traced,
            p.paused,
            p.false_pause_rate() * 100.0,
            lo * 100.0,
            hi * 100.0,
            d_pt,
            d_hi
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generator_is_deterministic_and_seed_sensitive() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        let mut c = SplitMix64::new(43);
        let (x, y, z) = (a.next_u64(), b.next_u64(), c.next_u64());
        assert_eq!(x, y);
        assert_ne!(x, z);
        // Known SplitMix64 value for seed 0 (published reference output).
        assert_eq!(SplitMix64::new(0).next_u64(), 0xE220_A839_7B1D_CDAF);
    }

    #[test]
    fn windows_are_distinct_sorted_in_range_non_overlapping_and_reproducible() {
        let w = sample_windows(7, 1_000, 1_000_000, 200, 10);
        assert_eq!(w.len(), 200);
        assert_eq!(w, sample_windows(7, 1_000, 1_000_000, 200, 10));
        assert_ne!(w, sample_windows(8, 1_000, 1_000_000, 200, 10));
        for pair in w.windows(2) {
            assert!(pair[0].1 < pair[1].0, "overlap or disorder: {pair:?}");
        }
        for &(s, e) in &w {
            assert!(s >= 1_000 && e <= 1_000_000);
            assert_eq!(e - s + 1, 10);
        }
    }

    #[test]
    fn asking_for_more_windows_than_slots_returns_every_slot() {
        let w = sample_windows(1, 0, 99, 1_000, 10);
        assert_eq!(w.len(), 10);
        assert_eq!(w[0], (0, 9));
        assert_eq!(w[9], (90, 99));
        assert!(sample_windows(1, 0, 4, 5, 10).is_empty());
    }

    #[test]
    fn wilson_matches_known_values() {
        // 0 of 100: upper bound ~3.7% (the "rule of three" gives 3%).
        let (lo, hi) = wilson_interval(0, 100, 1.96);
        assert_eq!(lo, 0.0);
        assert!((hi - 0.0370).abs() < 5e-4, "{hi}");
        // 50 of 100: symmetric around 0.5, ~[0.404, 0.596].
        let (lo, hi) = wilson_interval(50, 100, 1.96);
        assert!(
            (lo - 0.4038).abs() < 1e-3 && (hi - 0.5962).abs() < 1e-3,
            "{lo} {hi}"
        );
        // n = 0 is uninformative, and bounds stay within [0, 1].
        assert_eq!(wilson_interval(0, 0, 1.96), (0.0, 1.0));
        let (lo, hi) = wilson_interval(100, 100, 1.96);
        assert!(lo > 0.96 && hi > 0.9999 && hi <= 1.0);
    }

    fn outcome(p: &str, f: f64, harm: bool, traced: bool, paused: bool) -> Outcome {
        Outcome {
            protocol: p.into(),
            tx_hash: "0x1".into(),
            block: 1,
            max_outflow_fraction: f,
            had_harm_fact: harm,
            traced,
            confidence: 0.0,
            paused,
            evidence_keys: vec![],
        }
    }

    #[test]
    fn summary_counts_only_its_own_protocol() {
        let o = vec![
            outcome("A", 0.001, false, false, false),
            outcome("A", 0.3, true, true, true),
            outcome("B", 0.9, true, true, true),
        ];
        let a = summarize("A", 100, &o);
        assert_eq!(
            (a.population, a.with_harm_fact, a.traced, a.paused),
            (2, 1, 1, 1)
        );
        assert_eq!(a.false_pause_rate(), 0.5);
        let b = summarize("B", 100, &o);
        assert_eq!(b.population, 1);
        assert_eq!(summarize("C", 10, &o).population, 0);
        assert_eq!(summarize("C", 10, &o).false_pause_rate(), 0.0);
    }

    #[test]
    fn per_day_rate_scales_by_density_and_blocks_per_day() {
        let s = ProtocolSummary {
            protocol: "X".into(),
            population: 100,
            with_harm_fact: 0,
            traced: 0,
            paused: 1,
            blocks_sampled: 1_000,
        };
        // 100 txs / 1000 blocks * 7200 = 720 txs/day; 1% paused => 7.2/day
        let (pt, hi) = s.false_pauses_per_day();
        assert!((pt - 7.2).abs() < 1e-9);
        assert!(hi > pt);
        assert_eq!(
            ProtocolSummary::default().false_pauses_per_day(),
            (0.0, 0.0)
        );
    }

    #[test]
    fn buckets_split_at_the_shipped_thresholds() {
        let o: Vec<Outcome> = [0.0, 0.009, 0.01, 0.049, 0.05, 0.19, 0.2, 0.49, 0.5, 1.0]
            .iter()
            .map(|f| outcome("A", *f, false, false, false))
            .collect();
        assert_eq!(fraction_buckets(&o), [2, 2, 2, 2, 2]);
    }

    #[test]
    fn the_table_reports_zero_pauses_honestly_with_an_upper_bound() {
        let s = ProtocolSummary {
            protocol: "Aave V2".into(),
            population: 1_000,
            with_harm_fact: 20,
            traced: 20,
            paused: 0,
            blocks_sampled: 1_500,
        };
        let t = render_summary_table(&[s]);
        assert!(
            t.contains("| Aave V2 | 1000 | 20 | 20 | 0 | 0.000% (0.000%–0.38"),
            "{t}"
        );
    }
}
