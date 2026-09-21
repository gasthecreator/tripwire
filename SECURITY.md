# Security

This document threat-models Tripwire itself, not the protocols it
protects. That distinction matters: a system with automated on-chain
write access is a new attack surface on top of whatever it's guarding,
and it needs to survive scrutiny as one. See `ARCHITECTURE.md` §3.4 for
the design this threat model justifies.

## Reporting a vulnerability

This is a portfolio project, not a deployed production system handling
real funds — there is no bug bounty and nothing live to disclose against
under time pressure. That said, treat it with real disclosure hygiene
rather than a public issue tracker:

1. **GitHub Security Advisories (preferred):** open a
   [private vulnerability report](https://github.com/gasthecreator/tripwire/security/advisories/new)
   on this repository if you have GitHub UI access.
2. **Email:** send details to **gideonsanni2023@gmail.com** with the
   subject `Tripwire security`.

Include a description of the issue and its impact, reproduction steps
(PoC if you have one), affected commits, and a suggested fix if you have
one. Response time is best-effort, not SLA-bound, given the project's
current scope.

**Scope:** in scope is this repository's Rust event listener/detection
engine, `Guardian.sol`/`GuardedVault.sol`, and the replay-test harness.
Out of scope: vulnerabilities in upstream dependencies (report those
upstream), or issues in a third-party protocol that adopts the
integration pattern in `docs/INTEGRATION.md` unless this project's own
guidance introduced the unsafe default.

## 1. Assets and what's actually at risk

- **The guardian's pause authority.** Whoever can trigger `pause()` can
  freeze a protected protocol's operations. This is an availability
  primitive, not a solvency primitive by design (§3.4) — but availability
  attacks are real attacks with real cost (locked user funds, reputational
  damage, arbitrage/liquidation windows missed while paused).
- **The off-chain hot wallet's private key.** Holds `PAUSER_ROLE` and
  nothing else. Compromise gives an attacker the ability to pause
  protected protocols at will — a real DoS vector — but critically, not
  the ability to drain, upgrade, or reconfigure them, because the role is
  scoped to exactly one function.
- **The detection engine's decision logic and signature configs.** If an
  attacker can manipulate what the engine sees or how it scores, they can
  either suppress a real pause (worse than not having Tripwire at all,
  since a protocol using it may reduce other monitoring) or induce a
  false one (a DoS against the protocol).
- **The timelock/multisig unpause path.** Compromise here is the most
  severe: it's the recovery mechanism, and if it can be bypassed or
  front-run maliciously, false-positive recovery breaks down and legitimate
  operators lose the escape hatch this whole design depends on.

## 2. Threat model for the guardian contract

### T1 — Compromised or leaked hot wallet key
**Impact:** attacker can call `pause()` on any registered target at will.
**Mitigation:** the key is scoped to `PAUSER_ROLE` only — no admin, no
upgrade, no fund-moving capability exists on that role. Damage ceiling is
"protocol paused," which is recoverable via the timelock+multisig path.
Key is intended to be held in a secrets manager / HSM in any real
deployment, rotated on a schedule, and monitored for use outside the
listener service's own submission pattern (unexpected source IP,
unexpected calldata shape) — an anomaly on the *guardian's own* activity
is itself a signal worth alerting on, and this is called out explicitly
as a Slice 8 observability requirement, not left implicit.
**Residual risk:** accepted. A single narrowly-scoped hot key is the
deliberate speed/safety tradeoff documented in `ARCHITECTURE.md` §3.4 —
eliminating this risk entirely (e.g. requiring multisig on every pause)
reintroduces the human-latency gap this project exists to remove.

### T2 — False-positive-induced pause (griefing via detection manipulation)
**Impact:** an attacker who understands the detection signatures crafts
legitimate-looking-but-anomalous transactions (e.g. a large but honest
withdrawal timed to mimic a fund-flow-anomaly signature) specifically to
trigger an unwanted pause — a DoS against the protocol, potentially timed
to block a competitor's liquidation, arbitrage, or redemption.
**Mitigation:** confidence scoring requires multiple corroborating
*distinct facts* above a per-protocol threshold (§3.3), not a single
strong signal — raising the cost of crafting a convincing false
positive. "Distinct" is enforced: the same fact reported by several
signatures or thresholds is counted once (`evidence_key`), and this is
regression-tested against the shipped signature set — a scoring bug
once let one large outflow count three times, which would have made a
lone legitimate withdrawal pause a protocol.
Every triggering decision logs which signatures fired and their
individual weights, so a triggered pause is auditable and a pattern of
attempted griefing is detectable across incidents, not just per-incident.
**Residual risk:** not eliminated — no purely off-chain heuristic system
can be made immune to an adversary who has fully reverse-engineered its
signatures. This is why recovery (T4) has to be fast and low-friction:
the honest defense against griefing isn't a perfect detector, it's a
cheap, fast, well-understood path back to normal operation.

### T3 — Detection engine DoS / starvation
**Impact:** if the off-chain listener can be knocked offline or delayed
(RPC provider outage, network partition, resource exhaustion), the system
silently reverts to today's status quo — human-mediated pause — without
necessarily alerting anyone that the automated layer is down.
**Mitigation:** the listener's own liveness is a first-class metric
(Slice 8): heartbeat/health-check exposed, alerting fires if the listener
hasn't processed a new block within an expected window for the chain.
**Implemented** (see `docs/OPERATIONS.md`): `/healthz`, Prometheus `/metrics`
and `/status`; states for a stalled listener, repeated tick failures, a head
that stops advancing (stale RPC), and a *failed pause*; an independent
watchdog task that alerts (webhook + logs) even if the detection loop hangs;
tick timeouts. Tested with unit tests, real sockets, and by killing the chain
under a running daemon binary.
"Tripwire is silently down" must never look identical to "Tripwire
evaluated the last N blocks and found nothing."
**Residual risk:** open. A determined, resourced adversary who can DoS
the specific RPC endpoints the listener depends on could create a window
where the automated layer is down and undetected as such — multi-provider
RPC redundancy (a Slice 8+ hardening item) reduces but doesn't eliminate
this; it's tracked in `PLAN.md`, not solved in this document.

### T4 — Unpause recovery path failure or abuse
**Impact:** either (a) a legitimate false-positive pause can't be
reversed promptly, extending an availability incident, or (b) the
recovery path is abused to unpause during an actual ongoing exploit.
**Mitigation:** `DEFAULT_ADMIN_ROLE` (able to unpause) is held by an
OpenZeppelin `TimelockController` requiring a multisig-approved proposal
plus a mandatory delay — the delay is short enough to be a real recovery
path (target: minutes-to-low-hours, configurable per protocol) but long
enough that it cannot be used as an instant undo by whoever is currently
attacking the protocol, since the proposal is visible on-chain during the
delay and can itself be challenged/vetoed by protocol governance if the
timelock is configured with a veto role. The exact delay value is a
protocol-specific risk decision, not a value this project hardcodes.
**Residual risk:** a compromised multisig quorum could still push through
a malicious unpause during the delay window — this is the same risk any
multisig-gated system carries, not something specific to Tripwire, and is
out of scope to solve here beyond recommending protocols reuse a multisig
they already trust for other admin functions rather than standing up a
new one just for this.

### T5 — Reentrancy or logic bugs in `Guardian.sol` / `GuardedVault.sol` themselves
**Impact:** a bug in the guardian's own pause/role logic could be exploited
to either block legitimate pauses or bypass the role gate entirely.
**Mitigation:** built on OpenZeppelin's audited `AccessControl`, `Pausable`,
and `TimelockController` primitives rather than custom implementations of
any of the three (see `ARCHITECTURE.md` §6 stack rationale). Adversarial
unit tests in Slice 4 specifically target: non-pauser attempting to pause,
attempting to call `pause()` on an unregistered target, reentrancy attempts
into the guardian's own state during a pause call, and attempts to front-run
a legitimate pause with a conflicting state change.
**Residual risk:** this is a portfolio project, not an audited production
deployment — see the disclaimer in `README.md`. No claim is made here that
this contract is production-ready without an independent audit.

## 3. False-positive / false-negative handling philosophy

A binary trigger/no-trigger detector forces an impossible choice between
too many false positives (unacceptable griefing surface, T2) and too many
false negatives (the product doesn't do its job). The confidence-scoring
design (§3.3 in `ARCHITECTURE.md`) exists specifically so this isn't a
single global tuning knob: each protocol sets its own `pause_threshold`
based on its own risk tolerance (a protocol holding $2B behaves
differently than one holding $2M), and every decision — triggered or
not — is logged with the full signature breakdown that produced it, so
the threshold can be retuned from real evidence rather than guesswork.
Both the detection-rate and false-positive-rate numbers from Slice 6/7's
replay validation are reported together in `README.md`, deliberately,
because reporting only one is a materially misleading claim for a
product whose entire pitch is "trust me to act without asking first."

## 3.1 Static analysis

`contracts/` is scanned with [Slither](https://github.com/crytic/slither)
(`.github/workflows/security-scans.yml`, config at
`contracts/slither.config.json`). As of this writing the only finding is
`low-level-calls` in `GuardedVault.withdraw` — accepted and documented
inline at the call site (forwarding all gas is required to support
smart-contract-wallet depositors; `nonReentrant` is what makes it safe).
Three detectors are excluded from the config as noise rather than
findings: `solc-version`/`naming-convention`/`pragma` (style-only) and
`unindexed-event-address-parameters` (fires on OpenZeppelin's own
`Pausable` events, not this project's code). `unimplemented-functions`
is also excluded — a confirmed Slither false positive on
`GuardedVault.paused()`, which does implement `IPausable` via
`override(Pausable, IPausable)` and compiles and runs correctly; Slither's
resolver doesn't always cross-reference multi-parent `view` overrides.

The Rust workspace is scanned with `cargo audit`
(`.github/workflows/security-scans.yml`). As of this writing there are
zero errors (real, actionable vulnerabilities) — a real `ruint` issue
(RUSTSEC-2026-0220, RUSTSEC-2025-0137) surfaced during initial
development and was fixed by upgrading the whole workspace from `alloy`
0.9 to 1.x, not suppressed. Three warning-level advisories remain,
accepted as transitive alloy dependencies outside this project's direct
control: `derivative`/`paste` (unmaintained, not unsound) and `lru`
(RUSTSEC-2026-0253, a panic-safety issue in `LruCache::pop()` — this
project doesn't call that API directly, only alloy's internal RPC
caching does).

## 4. Out of scope for this project

- Formal verification of the Solidity contracts.
- A production secrets-management / HSM integration for the hot wallet
  (documented as a requirement, not implemented — this is infrastructure
  a real deployment provides, not something a portfolio repo should fake).
- Multi-chain support beyond the `ChainAdapter` trait boundary itself
  (see `ARCHITECTURE.md` §3.1) — no second chain adapter ships in v1.
- An actual third-party security audit. `docs/INTEGRATION.md` says this
  explicitly to anyone evaluating adoption.
