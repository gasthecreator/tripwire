# Signatures

Each `*.yaml` file here is one behavioral exploit signature, loaded by
`detection::load_signatures_from_dir` at startup. See `ARCHITECTURE.md`
§3.3 for the schema's design reasoning and `crates/tripwire-core/src/signature.rs`
for the authoritative schema (`Signature`/`Condition`/`ConditionKind`).

**How weights combine (read before writing a signature):** confidence is
the sum over *distinct evidence*, each fact counted once at the highest
weight any matched condition gives it — not the sum of all matched
conditions. Conditions of the same kind observe the same fact
(`fund_flow_delta` at 5% and at 50% is one fact; an outflow condition in
three signatures is one fact), while `call_sequence` conditions are
distinct facts per selector sequence. So a single condition alone should
never carry a weight at or above your pause threshold unless you mean a
lone observation to pause; corroboration comes from *different* kinds of
evidence. The decision's `counted_evidence` shows exactly what counted.

**The harm rule (enforced by tests).** A pause needs evidence of actual
harm — funds leaving a watched contract, or voting power taken. Call
patterns (re-entry, flash-loan entrypoints, call sequences) and price
movement are common in legitimate transactions (chained flash swaps
re-enter their own callback in ordinary arbitrage; whales move thin
pools), so *all evidence without a harm fact, summed, must stay below the
default pause threshold* (`evidence_without_a_harm_fact_can_never_reach_
the_default_threshold`), while a harm fact plus any single supporting fact
does pause (`a_drain_plus_any_single_supporting_fact_pauses`). This
constrains weights: keep supporting facts light, and put the weight on the
harm fact. Real exploits drove these numbers — see `WORKLOG.md`.

Current supporting weights and their budget (all must sum below 80):
oracle price deviation 25, flash-loan entrypoint 15, governance call
sequence 15, reentrancy 10, protocol callback re-entry 10 = 75. Adding a
new supporting fact means paying for it from this budget; the test above
fails otherwise.

Adding a new signature is adding a new file here — it never requires a
Rust code change unless the signature needs a genuinely new
`ConditionKind` the engine doesn't evaluate yet (in which case: add the
evaluator in `crates/detection/src/conditions.rs`, with unit tests
including the adversarial/false-positive cases, before adding a
signature that depends on it).

| File | Category | Historical precedent |
|---|---|---|
| `reentrancy-basic.yaml` | Reentrancy | The DAO (2016), dForce (Feb 2020) |
| `flash-loan-drain.yaml` | Flash-loan drain | Euler Finance (Mar 2023), PancakeBunny (May 2021) |
| `oracle-manipulation.yaml` | Oracle manipulation | bZx (Feb 2020), Cream Finance (Oct 2021), Mango Markets (Oct 2022) |
| `governance-takeover.yaml` | Governance anomaly | Beanstalk Farms (Apr 2022) |

Selector placeholders (flash-loan entrypoints, governance
propose/execute selectors) are marked as such in each file — a real
deployment fills these in against the specific protocol's ABI during
onboarding (`docs/INTEGRATION.md`), they are not meant to be universal.
