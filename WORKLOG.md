# Worklog

A running, dated log of every substantive piece of work done on Tripwire.
Treat this the way you'd treat engineering documentation at an actual job:
if it's not logged here, it didn't happen. This is a record for a future
technical walkthrough as much as it is a build log — write entries so
someone with no context on the session can understand what changed and why.

Newest entries at the top.

---

## How to write an entry

```
## [YYYY-MM-DD] Short title

**Author:** Claude Code / Gideon

**What:** ...
**Why:** ...
**Verified:** how this was actually tested, against what (real infra > mocks)
```

---

## [2026-09-21] Real baselines, a third exploit (Warp Finance), and generic detection on all three

**Author:** Claude Code

**What:** (1) New `tripwire-context` crate = the production `ContextSource`
(trait moved into `detection` to avoid a dependency cycle): worst-asset
outflow fraction vs the holder's balance at block-1 (ERC-20 logs net of
inflows; native ETH from the trace), Uniswap-V2 spot-price movement from
`Sync` events vs `getReserves` at block-1, optional `cast run` trace
fallback (moved from replay-harness), multi-holder support, everything
failing closed. Wired into the daemon via env vars; the daemon warns
loudly if no watched assets are configured. (2) `CallAny` condition (any-of
selector set) and a rewritten `flash-loan-drain.yaml` covering the
well-known flash-loan entrypoints (only Aave's `0xab9c4b5d` validated on
real traces; the others computed from documented interfaces). (3) Third
real exploit, the oracle-manipulation slot: **Warp Finance** (Dec 2020),
identified by block timestamp + Uniswap `Sync` events and corroborated
against the published amounts. My first oracle candidate, Harvest Finance,
turned out useless for this: its Curve swaps executed only 0.03-0.05% off
parity, so a price-deviation percentage can't detect that class — a real
limitation, recorded, not papered over. (4) The replay tests now use the
production context, and score the **shipped, un-tuned** signatures.

**Result:** generic signatures pause on Beanstalk (100), Euler (85) and
Warp (100) with only each protocol's asset list configured.

**Two more scoring-policy bugs surfaced on the way, both by scoring real
data:** adding flash-loan evidence let call-pattern facts alone (re-entry
65 + flash entrypoint 25 = 90) pause Beanstalk with no fund movement; and
on Warp a price move (55) + a re-entry (30) = 85 paused with the drain
removed. Fix: an enforced "harm rule" — all evidence lacking a harm fact
(funds/voting power) must sum below the threshold — with weights retuned
(fund flow 70; price 30; re-entry, flash entrypoint, call sequence 15
each), plus a test that a harm fact plus any single supporting fact still
pauses so the invariant isn't met by making everything too weak.

**Verified:** 23 pure-logic tests + 9 live-anvil tests for the context
crate; 3 live mainnet replays each asserting generic pause AND the
adversarial variants (lone drain, price-only, no-baseline call patterns)
staying below threshold; 169 Rust tests, clippy/fmt clean. Every token
address configured for a replay was checked on-chain first.

**Honest limits:** three exploits are three data points, and the
false-positive rate on legitimate traffic is still unmeasured (next).
Governance voting-power sourcing and non-V2 oracles aren't implemented.

---

## [2026-09-21] The daemon was broken: rewrite as a reorg-aware engine, test on a real chain

**Author:** Claude Code

**What:** Re-reading `poll_once` against ARCHITECTURE.md §3.2 turned up
that the shipped daemon (marked "done" in PLAN.md Slice 5) had never been
tested end-to-end and was broken in ways no existing test could see: (1)
with the default `min_confirmations = 1`, a transaction seen in the head
block had 0 confirmations, hit `continue`, and its block was then marked
processed, so it was never looked at again — the daemon could not pause
anything; (2) it filtered on `tx.to == target`, but both real exploits
replayed in this repo were sent to attacker contracts (the target appears
only in logs/internal calls), so it would have missed both; (3) no reorg
handling despite the architecture promising it; (4) no idempotency (a
second exploit tx would try to re-pause and revert), and an RPC error
mid-loop reprocessed blocks. Rewrote it as `tripwire_daemon::engine`:
follows the chain with a remembered window of block hashes and rewinds on
reorg (including chain shortening and reorgs deeper than the window);
keeps pending pause decisions and re-checks them every tick against the
canonical chain and required depth; cancels a pause whose block was
reorged away; checks `paused()` first (fail toward action if unreadable);
retries failed pauses; reads each block's header before and after its
transactions and discards inconsistent reads; bounds catch-up per tick.
Relevance is now `touches_target` (to/from, internal calls, logs emitted
by or naming the target). Added `BlockHeader` + `block_header()` to the
chain adapter, `is_paused` to the guardian client, and `ContextSource` (a
hook for call-trace enrichment and real baselines) with `NoContext` as the
default.

**Verified:** 19 in-memory state-machine tests (reorg before/after
confirmation, re-inclusion, shortening, deeper than window, mid-read
change, retry, already-paused, duplicate txs, RPC failure, bounded
catch-up, `touches_target` shapes) and 3 tests on a live `anvil` node with
the real contracts, real adapter and real guardian client, including a
**real reorg** (snapshot + revert) that cancels the pending pause.
Local detect -> pause latency ~265 ms (one confirmation).

**Still true, not fixed here:** `NoContext` means fund-flow/oracle/
governance conditions fail closed in the running daemon, and call-trace
conditions only work if the RPC serves `debug_traceTransaction`; real
baseline sourcing and an in-process tracer are the next items.

---

## [2026-09-21] Fix evidence double-counting in scoring (found by the Euler replay)

**Author:** Claude Code

**What:** `detection::score` summed every matched condition across every
signature. The three shipped signatures each contain an outflow
(`fund_flow_delta`) condition, so a single large outflow scored 60 + 40 +
30 = 130 -> clamped to 100 and paused on its own; any legitimate
withdrawal above ~20% of a balance would have paused a protocol. Fix:
`ConditionKind::evidence_key` names the underlying fact (thresholds
excluded; call sequences keyed by normalised selectors); each signature
keeps its distinct evidence (highest weight per fact), and the decision
sums distinct evidence across all signatures, recording `counted_evidence`
(key, weight, source signature/condition) so a pause or near miss is
diagnosable. Hand-built matches without evidence still score (as one fact
each) rather than silently scoring zero.

**Why:** Corroboration means different facts, not one fact repeated. This
is a core promise (ARCHITECTURE.md §3.3, SECURITY.md T2) that the tests
did not actually check against the shipped signature set.

**Verified:** 9 new engine unit tests, 3 core tests, and
`crates/detection/tests/shipped_signatures.rs` against the real YAML —
the whale-withdrawal test was run against the pre-fix engine in a
throwaway worktree and fails there ("25% outflow alone scored 100 and
would pause"). Live: generic set on Euler 100.0 -> 60.0 (asserted);
incident-tuned Euler (95.0) and Beanstalk (95.0, generic 65.0) unchanged.

**Process note:** the first commit of this fix went out with the README
and WORKLOG edits silently skipped (a doc-patch script failed on an
assertion but the shell carried on to commit). Caught by re-reading the
diff; fixed in a follow-up commit. Lesson: don't chain `git commit` after
an unchecked script.

---

## [2026-09-21] Second real exploit: Euler Finance (found on-chain), and a scoring flaw it exposed

**Author:** Claude Code

**What:** Found Euler's first attack transaction on-chain instead of via
web summaries: free-tier `eth_getLogs` is capped at 10 blocks, so scanned
Aave V2 `FlashLoan` events in 10-block windows around 13 Mar 2023 for a
30,000,000 DAI loan -> tx `0xc310a0af…b111d`, block 16817996. Confirmed
on Etherscan (sender "Euler Finance Exploiter 3", recipient "Euler
Exploit Contract 1", success). My first anchor (Euler's `Liquidation`
event on the main proxy) returned nothing — Euler emits via per-market
proxies — so anchors need checking too. Added
`replay_harness::support` (skip logic, real-tx loader, ERC-20 net-outflow
from receipt logs, historical balance via `cast call`, fund-flow
`Baseline`; 7 unit tests) and `tests/euler_flash_loan_drain.rs`; replaced
the Solidity Euler placeholder with a live replay.

**Verified live:** real trace 151 frames (depth 11); Euler DAI balance
8,904,507 -> 0 (net of the repaid 30M flash loan); incident-tuned
signature (Aave callback + `donateToReserves` `0x36f022aa`, computed from
Euler's own EToken.sol, + 50% balance drain) scores 95.0 vs 80.0;
Solidity replay asserts the same drain.

**Flaw found:** the shipped generic signatures score 100.0 on Euler, but
all three matches (`flash-loan-drain` 60, `oracle-manipulation` 40,
`reentrancy-basic` 30) come from the same single outflow fact, summed
three times. Any legitimate withdrawal above ~20% of a balance would
also pause. This contradicts the corroboration rule in ARCHITECTURE.md
§3.3 / SECURITY.md T2, and no synthetic test caught it. Recorded in
PLAN.md and README.md; the test prints (does not assert) the generic
result so the flaw isn't enshrined. Fix is next, as its own PR.

---

## [2026-09-21] Fix the reentrancy false positive found on the real Beanstalk trace

**Author:** Claude Code

**What:** The generic `reentrancy-basic` condition matched the real
Beanstalk trace 36 times though it contains no classic reentrancy. Two
flaws: (1) `CallFrame` had no call kind, so read-only STATICCALLs
(`balanceOf`, `totalSupply`) counted as re-entry; (2) the "earlier call"
only had to appear earlier in the trace, not still be on the call stack,
so a call that had already returned counted as re-entered. Fix: added
`CallKind` (Call/StaticCall/DelegateCall/CallCode/Create; unknown maps to
Call, conservatively state-changing) to `CallFrame`, populated by both
trace sources (chain-adapter callTracer `type`, `cast run` `kind`; CREATE
frames no longer get initcode-as-selector); the condition now keeps a
stack of active ancestors (rebuilt from pre-order frames + depth) and
flags only a non-static call re-entering a non-static active ancestor
with the same (target, selector). 8 new detector tests, 4 core, 2
adapter, 1 cast_trace.

**Why:** Left as-is, this would fire on ordinary busy transactions; a
pause is a serious action against a live protocol.

**Verified:** Live on the real trace: matches 36 -> 1. The one remaining
match is real, not a bug: `uniswapV2Call` (0x10d1e85c) re-entered at
depth 8 while its depth-6 invocation on the attacker's contract is
active (chained flash swaps). It scores 65.0 alone, under the 80.0
threshold, because the signature needs an outflow to corroborate; the
live test asserts exactly that shape (and my first version of the
assertion expected zero matches, which running it live proved wrong).
Also fmt, clippy `-D warnings`, full test suite green.

---

## [2026-09-21] Score a real exploit trace live via `cast run` (no paid trace API)

**Author:** Claude Code

**What:** Free-tier RPC blocks trace methods, but `cast run <tx> --json`
re-executes a transaction locally at its true block position using only
state-read calls. Added `replay_harness::cast_trace` (JSON → `CallFrame`s,
walking `children` from the single root; CREATE frames get no selector;
6 unit tests) and switched the Beanstalk test to it. Live result: 349
frames, depth 16, incident-tuned signature scores 95.0 vs 80.0. Also
scored the shipped generic signatures on the same trace: 65.0
(`reentrancy-basic` only), below threshold — but that match is a
false-positive pattern: the condition counted 36 recurring (target,
selector) pairs, mostly read-only STATICCALLs (`balanceOf`,
`totalSupply`), because `CallFrame` records no call kind.

**Why:** The incident-tuned signature was built from selectors known to
be in the exploit, so passing it proves plumbing, not detection. Scoring
the generic set alongside keeps that distinction honest, and it surfaced
a real weakness no synthetic test had.

**Verified:** Live against the free-tier archive RPC (test passes,
~60s); no-key skip path; fmt, clippy `-D warnings`, 84 Rust tests green.

---

## [2026-09-21] First live RPC run: fix the Beanstalk fork test, learn the free-tier limit

**Author:** Claude Code

**What:** With an Alchemy free-tier archive key (passed via env var only,
never written to a file), ran the replay tests live for the first time.
Findings: (1) the Solidity Beanstalk test, which had only ever been
compile- and skip-path-checked, could not have worked — `vm.rpc`
returns ABI-decoded data rather than a JSON string, and the target
transaction has `to == null` (it is a contract creation whose constructor
ran the whole exploit). Rewrote it to use Foundry's transaction-aware
fork (`createSelectFork(url, txHash)` + `vm.transact`), which applies
earlier same-block transactions and preserves creation semantics, and to
assert observable effect: 4 ERC-20 transfers out of the Beanstalk
diamond across 121 logs. (2) The Rust `replay-harness` test still can't
run live: the free tier rejects `debug_traceTransaction` and
`trace_transaction`, and anvil forks proxy historical-tx traces
upstream. A local re-execution (fork at N-1, impersonate, resend
calldata) produced a 170-frame trace with both selectors but reverted
(`LibDiamondCut: _init address has no code`), so it is not faithful and
was not adopted as a fixture.

**Why:** A test that has never run against the real thing is a claim, not
evidence — the earlier version looked finished and was not.

**Verified:** Live: `FOUNDRY_PROFILE=replay forge test` passes (Beanstalk
replay real; three placeholders still skip). No-key skip path, `forge fmt
--check`, and the 19 unit tests unchanged and green.

---

## [2026-09-14] Fix a real CI-only build-order bug (sol! macro needs contracts built first)

**Author:** Claude Code

**What:** After pushing the `alloy` 1.x upgrade, CI's `fmt, clippy, build`
job still failed — a genuinely different bug from the two already fixed
this session, not a flake. `guardian-client`'s `sol!` macro invocations
(`tests/guardian_anvil.rs`) read `contracts/out/Guardian.sol/Guardian.json`
and `.../GuardedVault.sol/GuardedVault.json` at **Rust compile time** to
generate contract bindings, not only when the test actually runs. The
`lint-and-build` job never ran `forge build`, so `cargo clippy
--all-targets` (which compiles test binaries) failed with "failed to
canonicalize path." This didn't surface locally earlier only because
`contracts/out/` already existed on disk from prior `forge build` runs
in this same working directory. Reproduced locally by deleting
`contracts/out/` and re-running `cargo clippy` (confirmed the exact same
failure), then fixed by adding Foundry setup + `forge build` to the
`lint-and-build` job before the Rust steps, and documented the required
build order (contracts before Rust, always) in `CONTRIBUTING.md` and
`README.md`, since it isn't obvious.

**Why:** Order-of-operations bugs like this are exactly what CI running
on a genuinely clean checkout is for — a long-lived local working
directory papers over exactly this class of bug.

**Verified:** Reproduced the failure locally first (`rm -rf contracts/out
&& cargo clippy -p guardian-client --all-targets` fails with the same
error CI showed), then confirmed the fix resolves it (`forge build` then
`cargo clippy --workspace --all-targets --all-features -- -D warnings`
clean). Full `cargo test --workspace` still green (78 tests).

---

## [2026-09-14] Fix real CI failures: pinned deps + alloy upgrade for a real CVE

**Author:** Claude Code

**What:** Opened PR #1 for the detection-wiring work and its first CI run
surfaced two genuine bugs, not flakes: (1) `forge install` with no
arguments is a no-op when dependencies were fetched with `--no-git` (no
`.gitmodules` recorded) — every workflow and doc now runs the two
explicit pinned installs (`forge-std@v1.16.2`,
`openzeppelin-contracts@v5.7.0`) instead; (2) `cargo audit` found two
real vulnerabilities in `ruint` (RUSTSEC-2026-0220, RUSTSEC-2025-0137),
transitively pinned by `alloy` 0.9.2. Fixed by upgrading the whole
workspace from `alloy` 0.9 to 1.x (currently resolving to 1.8.3) across
`chain-adapter`, `guardian-client`, and `tripwire-daemon`, which also
let the earlier serde version pin (`=1.0.219`, worked around an
`alloy-consensus` 0.9.2 / newer-serde incompatibility) be removed
entirely. Fixed the resulting API breaks: `RootProvider`/`Provider` lost
their transport type parameter, `.on_http()` → `.connect_http()`,
`.with_recommended_fillers()` is gone (fillers on by default now, use
`.disable_recommended_fillers()` for a read-only provider),
`get_block_by_number` takes one argument now (`.full()` chained
separately), and RPC `Transaction.from` moved back under
`.inner.signer()`.

**Why:** A security product shipping with a Cargo.lock pinned to
dependencies with known CVEs would fail exactly the due-diligence
review this project is supposed to survive — upgrading was the right
call over suppressing the audit finding.

**Verified:** `cargo audit` exit code 0 (zero errors; three
warning-level unmaintained/unsound-but-inapplicable advisories remain,
documented in `SECURITY.md` §3.1). `cargo fmt --all --check`, `cargo
clippy --workspace --all-targets --all-features -- -D warnings`, `cargo
test --workspace` (78 tests), `forge fmt --check`, and `forge test` (19
tests) all clean after the upgrade — including the real end-to-end test
that deploys actual contracts to a live `anvil` node and pauses them via
`guardian-client`, which kept working unchanged through the alloy major
version bump.

---

## [2026-09-14] Wire the Beanstalk replay into the real detection engine

**Author:** Claude Code

**What:** Created `~/tripwire`'s GitHub remote (`gasthecreator/tripwire`,
public) and established `main` from the initial scaffold commit (a
repo-genesis exception to the branch+PR rule — nothing existed to review
against yet). Built `crates/replay-harness`: fetches the real Beanstalk
exploit transaction's actual decoded call trace from a real archive RPC
(via `chain-adapter`) and scores it through the real `detection` engine,
closing the gap the previous session's Solidity-only fork replay left
open (proving the transaction *replays* is not the same as proving the
*detector would have fired*). The signature used is built from two
independently-verified real selectors: `emergencyCommit(uint32)`
(`0x73015684`), computed locally from the exact function signature
quoted from Beanstalk's own public source (`GovernanceFacet.sol`,
commit `ee4720cdb449d5b6ff2b789083792c4395628674`,
github.com/BeanstalkFarms/Beanstalk), and Aave V2's standard
`executeOperation` flash-loan callback (`0x920f5c84`, a fixed public
interface, not incident-specific). Added a `replay` job to
`rust-ci.yml`, gated the same way as `foundry-ci.yml`'s replay job.

**Why:** Gideon flagged this as the highest-value remaining piece after
reviewing the initial scaffold's honest gap list — the brief's core
validation claim ("prove the system would have detected... within your
stated latency target") wasn't actually proven by a Solidity-only replay
that never touched the Rust detector.

**Verified:** `cargo build -p replay-harness --tests` and `cargo clippy
--workspace --all-targets --all-features -- -D warnings` clean.
`cargo test --workspace` green (78 tests). The new test's no-RPC-key
skip path runs and exits cleanly, matching every other network-dependent
test in this repo — but **the test has not yet executed against live
data**, since no archive-RPC key is configured yet. That's the honest
state to log here, not "done."

---

## [2026-09-14] Full first implementation pass: detection engine, guardian contracts, end-to-end wiring

**Author:** Claude Code

**What:** Built out every core component from `ARCHITECTURE.md` §3 for
real, not as stubs: `tripwire-core` (chain-agnostic types, 35 tests),
`chain-adapter`'s `EvmAdapter` on `alloy` (block/tx/log/call-trace
decoding, tested against a real locally-spawned `anvil` node), `detection`
(signature loading + 5 condition evaluators + additive confidence
scoring, 36 tests including explicit false-positive cases),
`Guardian.sol`/`GuardedVault.sol` on OpenZeppelin primitives (19 Foundry
tests: role boundaries, a live reentrancy attack simulation, a full
`TimelockController` unpause-delay test, 512-run fuzz), `guardian-client`
(signs/submits pause txs via `alloy`), and `tripwire-daemon` (polls,
evaluates, pauses). Proved the whole chain actually interoperates with an
integration test that deploys the real compiled contracts to a live
`anvil` node and pauses `GuardedVault` entirely through
`guardian_client::connect`/`submit_pause` — not a unit test in isolation.
Ran Slither against the contracts (one accepted finding, documented).
Verified one real historical exploit (Beanstalk, Apr 2022) directly
against Etherscan and replayed its actual transaction against a real
mainnet fork.

**Why:** This is the brief's core deliverable set — architecture docs
alone (already written earlier this session) don't demonstrate the
system works; only real, passing tests against real infrastructure do,
per the standing project preference for testing against real
infrastructure over mocks (carried over from Pharos/Cascade Operator).

**Verified:** `cargo test --workspace` green (77 Rust tests across 4
crates, two of which spin up real `anvil` nodes). `forge test` green (19
unit/fuzz tests). `FOUNDRY_PROFILE=replay forge test` green (4 tests,
one a real fork replay, three honest skips). `cargo clippy --workspace
--all-targets --all-features -- -D warnings` clean. `forge fmt --check`
clean. Slither clean except one documented, intentional finding.

**Deliberately incomplete, not hidden** (see `PLAN.md`'s open
questions and `README.md`'s status table for the full accounting):
three of four historical exploits lack a verified tx hash (caught a real
case of a web-search summary inventing a wrong block number for
Beanstalk — 14,895,611 instead of the actual, Etherscan-confirmed
14,602,790 — which is exactly why every number in this repo's replay
tests is either independently verified or explicitly marked as not);
the replayed fork isn't yet wired through the actual Rust detector; the
daemon's `Baseline` is a placeholder, not sourced from real chain state.

---

## [2026-09-14] Project scaffold, design docs, toolchain setup

**Author:** Claude Code

**What:** Initialized the repo (`~/tripwire`, on `feat/scaffold`). Wrote
`ARCHITECTURE.md` (system design, corrected problem statement, competitive
positioning, per-component tradeoffs), `PLAN.md` (living build checklist,
10 slices, candidate historical-exploit list), and `SECURITY.md` (threat
model for the guardian contract itself: hot-key compromise, false-positive
griefing, listener DoS, unpause-path abuse, contract-logic bugs). Pulled
portfolio conventions from `~/pharos` and `~/cascade-operator`
(`CONTRIBUTING.md`'s PLAN-first / ARCHITECTURE_PROPOSALS.md /
branch-and-PR discipline, `CODEOWNERS`, `CODE_OF_CONDUCT.md`, MIT
`LICENSE`) rather than reinventing them. Installed Rust (via `rustup`,
stable channel, clippy + rustfmt components) and Foundry (via
`foundryup`) — neither toolchain existed on this machine before this
session.

**Why:** Per the brief, no implementation code before the architecture is
confirmed and documented. Gideon confirmed: repo name Tripwire (not
"Sentry" — collides with Sentry.io branding) at `~/tripwire`; Rust over Go
for the listener/detection engine (deliberate tech diversity against
Pharos/Cascade Operator, both Go, and a real fit for the latency
requirement); demo `GuardedVault` contract plus a documented third-party
integration guide, not integration-guide-only.

**Verified:** `rustc --version` / `cargo --version` / `forge --version` /
`cast --version` / `anvil --version` all confirmed working post-install.
No application code exists yet, so no functional verification applies to
this entry.

**Open, blocking Slices 2/6:** Gideon needs to sign up for an archive-RPC
provider (Alchemy recommended) — not something this session can do on his
behalf. Everything else can proceed without it.


## Pause fee policy

Found that `submit_pause` used provider-default fees and waited indefinitely: fine on a quiet chain, unsafe when the pause competes with an attacker's transactions. Added `SubmitPolicy` with fee escalation and same-nonce replacement. Two bugs found by the anvil tests rather than by reasoning: (1) replacements failed because gas estimation runs against pending state in which the first attempt has already paused the target, so the estimate reverted with `EnforcedPause`; fixed by reusing the first attempt's gas limit. (2) a revert at estimation burned every attempt timeout before returning; a failed first send now returns immediately. Untested: real mainnet congestion and private-mempool submission.


## Liveness and metrics

Built the T3 mitigation the docs had promised. Design choice worth recording: the watchdog is a separate task from the detection loop, because the failure it must catch (a tick hung on an RPC call) is exactly the one the loop cannot report about itself. Also added a per-tick timeout for the same reason. Smoke-tested the actual binary against anvil (healthy, then chain killed: 503 plus an ALERT log). Caught a stale-binary mistake during that test (cargo test does not rebuild the bin), so the first smoke run exercised old code; rerun after an explicit build. Known gap: nothing detects a plausible-but-false RPC.
