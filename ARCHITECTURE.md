# Architecture

## 1. Problem statement

DeFi protocols lose funds to exploits. The tooling that exists today — Forta,
Tenderly, OpenZeppelin Defender, Hypernative, and the newer Blockaid — is good
at the first half of the problem: recognizing that an exploit is happening,
often within seconds. All five of them stop at alerting. A human still has to
see the alert, understand it, and manually call the protocol's pause or
guardian function. That human-reaction step is the gap this system closes.

It is important to be precise about what closing that gap can and cannot do,
because the wrong framing here would make every downstream design decision
wrong too.

**What automated pausing cannot do:** stop the transaction that revealed the
exploit. A flash-loan attack, a single-block oracle manipulation, a
reentrancy drain — these execute atomically. The exploit transaction is
mined, included in a block, and finalized before any off-chain system can
observe it, decide anything, and get a response transaction mined ahead of
it. There is no "detect and pause before it completes" for this class of
attack, by construction. Any product pitch that implies otherwise is either
confused about EVM execution semantics or lying to a customer, and this
project does neither.

**What automated pausing can do:** stop the transactions that follow.
Real incidents are rarely a single atomic transaction and then silence.
The attacker (or copycats, once the exploit is public in the mempool or a
block explorer) frequently comes back for a second, third, and further
drain while the protocol team is still being paged, waking up, or in a
Discord call trying to agree on who has multisig access. The March 2026
Resolv USR exploit is the clean public example: the protocol was paused
"within minutes" of detection, and that pause stopped continued draining —
it did not, and could not, undo the initial loss. That is the actual,
honest value proposition of this system: collapse the detection-to-pause
step from minutes (human-mediated) to milliseconds-to-seconds (automated),
so the *second* transaction never lands. Every document in this repository
holds that line. If you find language anywhere in this codebase implying
prevention of the first exploit transaction, it's a bug — file it as one.

## 2. Competitive positioning

| Vendor | Detects exploits | Automates the pause |
|---|---|---|
| Forta | Yes | No — alert only |
| Tenderly | Yes | No — alert only |
| OpenZeppelin Defender | Yes | No — alert only |
| Hypernative | Yes | No — alert only |
| Blockaid | Yes (flagged Summer.fi, Jul 2026, in production) | No — alert only |
| **Tripwire** | Yes (reuses well-understood signatures) | **Yes — no human in the loop** |

None of these products are being out-detected here. Their detection
engineering is mature and this project doesn't pretend otherwise — the
signature types in `signatures/` (fund-flow anomalies, function-call
sequence anomalies, oracle/price deviation, reentrancy depth, governance
anomalies) are the same categories the industry already watches for. The
entire differentiated surface area is the last step: taking a
sufficiently-confident detection and submitting a pause transaction
automatically, with no Slack alert, no on-call engineer, no manual
multisig ceremony, in the loop for that first response.

That differentiation is also exactly why the guardian contract's own
threat model (§4, and see `SECURITY.md`) matters as much as the detection
logic. A detection engine that's merely wrong produces a bad alert a human
filters out. A detection engine wired to automatic on-chain action that's
wrong produces a real, board-visible incident: a legitimate user's large
withdrawal gets treated as an exploit and the whole protocol halts. This
system's credibility rests on making false positives rare, cheap to
recover from, and impossible for an attacker to induce as a denial-of-service
primitive against the very protocol it protects.

## 3. System components

```
                    ┌─────────────────────────────────────────────┐
                    │              Chain (multi-chain-ready)        │
                    │   pending txs / new blocks / logs             │
                    └───────────────────┬───────────────────────────┘
                                         │ subscribe (WS) + poll fallback
                                         ▼
                    ┌─────────────────────────────────────┐
                    │   Chain Adapter (trait, per-chain)     │
                    │   normalizes raw chain data → TxEvent  │
                    └───────────────────┬───────────────────┘
                                         ▼
                    ┌─────────────────────────────────────┐
                    │   Event Listener                       │
                    │   confirmation-depth gating,            │
                    │   reorg detection, dedup                │
                    └───────────────────┬───────────────────┘
                                         ▼
                    ┌─────────────────────────────────────┐
                    │   Detection State Machine              │
                    │   per-protocol signature matching,      │
                    │   confidence scoring                    │
                    └───────────────────┬───────────────────┘
                             score ≥ threshold?
                                         ▼
                    ┌─────────────────────────────────────┐
                    │   Guardian Client                       │
                    │   signs + submits pause() tx            │
                    └───────────────────┬───────────────────┘
                                         ▼
                    ┌─────────────────────────────────────┐
                    │   Guardian.sol (on-chain)               │
                    │   AccessControl-gated pause,             │
                    │   Timelock+multisig unpause              │
                    └─────────────────────────────────────┘
```

### 3.1 Chain Adapter

A `ChainAdapter` trait abstracts subscription, block/tx fetching, and log
decoding behind chain-agnostic types (`ChainId`, `TxEvent`, `LogEvent`).
Only an `EvmAdapter` (Ethereum mainnet) is implemented in v1. This is a
real architectural commitment, not a decoration: the detection state
machine and confidence scorer never see an RPC response or an EVM opcode —
they only see `TxEvent`/`LogEvent`. Adding a second EVM chain is a config
change (RPC URL, chain ID); adding a non-EVM chain (e.g. Solana) is a new
adapter implementing the same trait, with no changes to detection logic.
This is the concrete answer to the brief's "design for multi-chain from
the start" requirement — it's enforced by the trait boundary, not a
promise in prose.

### 3.2 Event Listener — reorg handling

**Tradeoff, stated explicitly:** every block of confirmation depth added
before acting reduces the chance of acting on a transaction that a reorg
later drops, and increases the time between exploit and pause. Ethereum
mainnet reorgs beyond 1-2 blocks are rare post-Merge but not impossible.

**Decision:** the listener treats "detect" and "act" as separate
confidence gates, not one. A transaction is fed into the state machine
the moment it's seen in a new block (0 confirmations) — detection can
start immediately, and a full analysis pipeline (log decoding, fund-flow
computation) takes long enough anyway that 1-block confirmation is usually
already available by the time a score is ready. The *pause transaction*
is not submitted until the triggering block has reached a configurable
minimum depth (default: 1 confirmation for the pause decision itself, with
the option raised to 2 for higher-value protocols where an unnecessary
pause is more costly than a few extra seconds of exposure). This is
recorded as a per-protocol config value, not a global constant, because
the right tradeoff genuinely differs by protocol TVL and risk tolerance —
that's a judgment call the protocol's own team should make when they
configure Tripwire for their contract, not one this project should
hardcode.

If a reorg is detected (a previously-seen block hash disappears from the
canonical chain) after a pause has already been submitted, the system
does **not** auto-unpause. An unpause is a strictly slower, human-gated
path (§3.4) by design — the cost of staying paused a few extra minutes on
a false alarm is bounded and known; the cost of auto-unpausing into an
still-in-progress exploit is not.

### 3.3 Detection State Machine

Exploit behavior is modeled as **signatures**, not as if/else branches in
Rust. Each signature is a YAML document (`signatures/*.yaml`) describing:

- a **trigger set** of typed conditions (e.g. `fund_flow_delta_pct`,
  `call_sequence`, `oracle_price_deviation_pct`, `reentrancy_depth`,
  `governance_proposal_anomaly`)
- a **weight** per condition
- a **time window** the conditions must occur within (most exploit
  sequences span a handful of transactions or a single transaction's
  internal call trace, not blocks of history)

The engine evaluates all loaded signatures against each incoming
`TxEvent`/`LogEvent` stream per protected contract, accumulates a
per-incident confidence score (0-100), and compares it to that contract's
configured `pause_threshold`. This satisfies the brief's requirement that
new signatures be addable without touching the core engine: a new exploit
class is a new YAML file plus, if it needs a genuinely new condition type
the engine doesn't already evaluate, one new condition evaluator function
— never a change to the matching/scoring core.

**Why a score and not a boolean:** a single strong signal (e.g. a single
large withdrawal) is common in legitimate protocol operation — large
depositors exist. A pause decision should require *multiple corroborating*
signals crossing a threshold, and that threshold, along with which
signatures fired and their individual scores, must be logged and
auditable after the fact so a false positive can be diagnosed, not just
reversed.

### 3.4 Guardian Contract

`Guardian.sol` holds `PAUSER_ROLE` (OpenZeppelin `AccessControl`) granted
to the off-chain service's hot wallet, and calls `pause()` on registered
`IPausable` target contracts. Unpausing requires `DEFAULT_ADMIN_ROLE`,
which is held by an OpenZeppelin `TimelockController` behind a Gnosis-Safe-
style multisig — not the hot wallet, and not any single EOA. See
`SECURITY.md` for the full threat model, including the guardian contract's
own attack surface (a griefer who can spoof a pause trigger has a new DoS
vector against the protocol, and this is threat-modeled with the same
rigor as the exploits the system defends against).

**Gas-cost vs. speed tradeoff, stated explicitly:** the fastest possible
pause path would let any address holding a signed message trigger `pause()`
directly and cheaply. The safest possible pause path would require
multisig confirmation before any pause — which reintroduces exactly the
human-latency gap this project exists to remove. The design lands
in between: a single, purpose-built hot wallet (the off-chain service's
key, rotated and monitored, never used for anything else) has narrow,
single-function pause authority and nothing else — it cannot upgrade
contracts, cannot move funds, cannot change roles. That narrow blast
radius is what makes "fast and automatic" an acceptable tradeoff against
"slow and human-gated": the worst a compromised or malfunctioning hot key
can do is pause the protocol (an availability hit, recoverable via
timelock) — never drain it (a solvency hit, unrecoverable).

### 3.5 Guarded target contract

`GuardedVault.sol` is a minimal demo lending/vault-style contract
implementing `IPausable` and calling into the guarded pattern, used as the
concrete target for replay tests. `docs/INTEGRATION.md` documents the
narrower surface a real, already-deployed protocol would need to expose
(effectively: a `pause()` entrypoint gated to a role Tripwire's Guardian
can be granted) to adopt this without a full contract rewrite.

## 4. Validation methodology

Every historical exploit is validated the same way: fork Ethereum mainnet
at `attack_block - 1` with Foundry/`anvil`, replay the real first exploit
transaction against the fork, and assert (a) the detection engine reaches
its pause threshold before or immediately after that transaction is
mined, and (b) a pause transaction targeting `GuardedVault` (standing in
for the real protocol) lands in a block before the historical second
malicious transaction would have. Latency is measured in wall-clock time
from "attack tx observed" to "pause tx confirmed," not in blocks, since
that's the number that matters to a protocol evaluating this system.

False-positive rate is measured separately, against a sample of normal
high-volume legitimate activity (large legitimate withdrawals, batch
transactions, MEV-bot activity, arbitrage) replayed the same way — the
detector must *not* cross the pause threshold on this sample. See
`replay-results/` for the full report once the harness is built; both
numbers are reported together in `README.md` because either one alone is
a misleading claim about this system.

## 5. Stack and why

| Layer | Choice | Why |
|---|---|---|
| Event listener + detection engine | Rust | Low-latency requirement is real, not aesthetic — this is the critical path the whole value proposition rests on. Also deliberate portfolio tech diversity: the two other active portfolio projects (Pharos, Cascade Operator) are both Go. |
| Guardian / target contracts | Solidity + OpenZeppelin | Battle-tested `AccessControl`/`Pausable`/`TimelockController` primitives. Rolling custom multisig or timelock logic for a security product is exactly the kind of unforced error a due-diligence review should catch — so it isn't attempted here. |
| Replay/test harness | Foundry | Native mainnet forking (`anvil --fork-url ... --fork-block-number ...`) at arbitrary historical blocks, fast Solidity-native test iteration, and it's the de facto standard a protocol security team will already know how to read. |
| Signature definitions | YAML (data, not code) | Directly satisfies "addable without rewriting the core engine" — a new signature is a config change and a PR review, not a Rust patch. |

## 6. Open design questions

Tracked and kept current in `PLAN.md` — this section intentionally stays
short and points there rather than duplicating a living list.
