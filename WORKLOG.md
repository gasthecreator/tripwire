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
