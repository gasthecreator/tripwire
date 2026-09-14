# Signatures

Each `*.yaml` file here is one behavioral exploit signature, loaded by
`detection::load_signatures_from_dir` at startup. See `ARCHITECTURE.md`
§3.3 for the schema's design reasoning and `crates/tripwire-core/src/signature.rs`
for the authoritative schema (`Signature`/`Condition`/`ConditionKind`).

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
