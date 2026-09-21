# Plan

Living document — update this as work lands, not just once. See
`ARCHITECTURE.md` for the design reasoning behind these slices;
this file tracks what's built, what's next, and what's still an open
question.

## Status snapshot (2026-09-14)

Core system is real and tested end-to-end against live local
infrastructure: detection engine, chain adapter, guardian contracts, and
the daemon wiring all pass, including a test that deploys the actual
compiled contracts to a live `anvil` node and pauses them through the
real Rust `guardian-client` code path. One historical exploit (Beanstalk,
Apr 2022) is verified against Etherscan and, as of 2026-09-21, its real
transaction has been replayed live against a real mainnet fork on the
Solidity side (`contracts/test/replay`, free-tier RPC, asserts real
token outflow from the Beanstalk diamond). Its real call trace (349 frames, from `cast run` re-executing the
transaction locally; no paid trace API needed) is scored live by the
actual `detection` engine (`crates/replay-harness`): a signature built
from two independently-verified real selectors reaches 95.0 vs an 80.0
threshold. That signature was tuned to this incident, so it validates
the pipeline, not generic detection: the shipped generic signatures
score 65.0 on the same trace, below threshold. The gaps that matter
most for anyone evaluating this beyond a portfolio context: (1) generic
detection has still only been checked against one real trace — scoring
it exposed a real false positive (the `reentrancy-basic` condition
matched 36 times: read-only STATICCALLs such as `balanceOf`, and calls
that had already returned), now fixed by recording `CallKind` on frames
and requiring a state-changing re-entry into an *active ancestor*;
one legitimate match remains (nested `uniswapV2Call` flash-swap
callbacks) and stays below threshold by design; (2) three of four planned historical exploits still lack a verified
tx hash; (3) the daemon's `Baseline` (the real chain-state context
feeding fund-flow/oracle/governance conditions) is a placeholder — the
scoring math is real and tested, but live sourcing for its inputs isn't
wired yet. All three are called out in `README.md`'s status table, not
just here.

## Build checklist, in slices

Each slice should be its own feature branch + PR (per Gideon's standing
workflow preference — branch discipline even on solo projects), tested
before merge, docs updated in the same PR as the code they describe.

- [x] **Slice 0 — Scaffold.** Repo init, `ARCHITECTURE.md`, `PLAN.md`,
      portfolio-standard meta files (`CONTRIBUTING.md`, `SECURITY.md`,
      `CODEOWNERS`, `CODE_OF_CONDUCT.md`, `LICENSE`) pulled from
      `~/pharos`/`~/cascade-operator` conventions rather than reinvented.
      Rust (via `rustup`) and Foundry (via `foundryup`) installed —
      neither existed on this machine before this project.
- [x] **Slice 1 — Core types + Rust workspace skeleton.** `tripwire-core`:
      `ChainId`, `Address`, `TxEvent`, `LogEvent`, `CallFrame`,
      `Signature`/`Condition`/`ConditionKind`, `Confidence`,
      `SignatureMatch`, `PauseDecision`. 35 unit tests, all passing.
- [x] **Slice 2 — EVM chain adapter.** `ChainAdapter` trait + `EvmAdapter`
      (built on `alloy`) against a real Ethereum-compatible RPC: block
      fetching, tx normalization, receipt log decoding, and
      `debug_traceTransaction`-based call-frame extraction with graceful
      degradation (empty call frames, not a hard failure) when a node
      doesn't expose the debug namespace. Tested against a real, locally
      spawned `anvil` node — not mocked — including a real signed
      transaction sent, mined, and decoded back correctly, and a
      block-not-found error path. **Not yet done:** mempool/pending-tx
      websocket subscription (v1 only polls confirmed blocks); this is
      an acceptable v1 simplification since the pause decision already
      gates on confirmation depth, but it does mean detection currently
      starts at 0-confirmation *mined* transactions, not truly pending ones.
- [x] **Slice 3 — Signature format + detection engine.** YAML signature
      schema (`tripwire-core::Signature`), directory loader
      (`detection::load_signatures_from_dir`), five condition evaluators
      (fund-flow delta, call sequence, oracle price deviation,
      reentrancy depth, governance proposal anomaly), additive
      confidence scoring. 36 unit tests, including explicit adversarial/
      false-positive cases (a legitimate multi-hop call trace must not
      look like reentrancy; a normal 2%-of-TVL withdrawal must not cross
      a drain threshold; ordinary market volatility must not read as
      oracle manipulation) and cases proving corroboration across
      multiple weak signals can cross a threshold that no single signal
      reaches alone.
- [x] **Slice 4 — Guardian.sol + GuardedVault.sol.** OpenZeppelin
      `AccessControl` + `Pausable` + `TimelockController` wiring exactly
      as designed in `ARCHITECTURE.md` §3.4. 19 Foundry tests: role
      boundaries (non-pauser can't pause, pauser can't unpause), a
      malicious registered target attempting to reenter `Guardian.pause`
      (blocked by role-based access control alone, no explicit
      reentrancy guard needed — proven, not just asserted), a full
      `TimelockController` unpause-delay integration test (execute
      before the delay reverts, after it succeeds), a 512-run fuzz test
      on withdrawal accounting, and a live simulated reentrant-withdrawal
      attack against `GuardedVault` (blocked by `nonReentrant` +
      checks-effects-interactions). Slither-clean except one accepted,
      inline-documented finding (`low-level-calls`, required to support
      smart-contract-wallet depositors).
- [x] **Slice 5 — Guardian client + end-to-end wiring.** `guardian-client`
      signs and submits `pause()` via `alloy`, refuses to submit a
      decision that didn't cross its own threshold before ever touching
      the network, and has no unpause method at all (that path is
      intentionally separate and timelock-gated). `tripwire-daemon` wires
      `ChainAdapter` → `detection::evaluate` → `GuardianClient` into one
      polling loop with a confirmation-depth gate, startup validation
      that its target is actually registered with the Guardian, and a
      shutdown handler. The guardian-client half is proven end-to-end by an
      integration test that deploys the real compiled `Guardian`/
      `GuardedVault` bytecode to a live local `anvil`, registers the
      vault, and pauses it through `guardian_client::connect` +
      `submit_pause`, then confirms a non-pauser key using the same code
      path fails on-chain. **Correction (2026-09-21):** the *daemon* half
      had never been exercised end-to-end and was broken: with default
      settings it could never pause anything (a transaction seen at 0
      confirmations was skipped and its block then marked processed, so
      it was never re-evaluated), it only looked at transactions whose
      `to` was the target (both real exploits replayed here were sent to
      attacker contracts), and it had no reorg handling, no idempotency
      and reprocessed blocks after a mid-loop RPC error. Rewritten as
      `tripwire_daemon::engine` (canonical-chain tracking with a reorg
      window, pending pauses re-checked every tick and cancelled if their
      block is reorged away, an `is_paused` check, retry on failure,
      bounded catch-up), with 19 in-memory state-machine tests and 3
      live-`anvil` tests including a real reorg.
- [ ] **Slice 6 — Historical exploit replay harness.** Foundry fork tests
      against real mainnet history. **Status: three of four done.**
      Beanstalk Farms (Apr 17, 2022) is verified — tx
      `0xcd314668aaa9bbfebaf1a0bd2b6553d01dd58899c508d4729fa7311dc5d33ad7`,
      block 14602790, confirmed directly against Etherscan on
      2026-09-14 — and, verified live 2026-09-21, replays against a real
      mainnet fork (`contracts/test/replay/HistoricalExploits.t.sol`).
      That transaction is a **contract creation** (`to` is null; the
      exploit ran in a constructor), so the test uses Foundry's
      transaction-aware fork (`createSelectFork(url, txHash)` +
      `vm.transact`), which applies earlier same-block transactions and
      preserves creation semantics; it asserts real ERC-20 outflows from
      the Beanstalk diamond (4 observed), not merely a non-revert. An
      earlier `vm.rpc`-based version of this test could never have
      worked (wrong return format, and no handling of a null `to`); it
      only looked fine because it had never run against a real RPC. **Second case verified 2026-09-21: Euler Finance
      (Mar 13, 2023)** — tx `0xc310a0af…b111d`, block 16817996, found
      on-chain (Aave V2 `FlashLoan` event for exactly 30,000,000 DAI)
      rather than from a web summary, then confirmed on Etherscan (sender
      "Euler Finance Exploiter 3", recipient "Euler Exploit Contract 1").
      Solidity replay asserts Euler's DAI balance 8,904,507 -> 0; Rust
      replay (`tests/euler_flash_loan_drain.rs`, real 151-frame trace,
      real fund-flow `Baseline` from archive balance + receipt logs)
      scores an incident-tuned signature at 95.0 vs 80.0. **Third case
      verified 2026-09-21: Warp Finance (Dec 17, 2020), the oracle-
      manipulation slot** — tx `0x8bb8dc5c…95090`, block 11473330. Etherscan
      gives it no label and the write-ups omit the hash, so it was found by
      block timestamp (exactly 22:24:41 UTC, Warp's published attack time)
      and the Uniswap V2 DAI/WETH pair's `Sync` events (a 341,217 WETH
      swap), then corroborated by matching the published figures against the
      receipt (94,349.3 LP minted, 3.86M DAI and 3.92M USDC borrowed from
      two `WarpVaultSC` contracts). **Generic detection result on all three
      real exploits:** the *shipped, un-tuned* signatures pause on
      Beanstalk (100), Euler (85) and Warp (100), configured with only each
      protocol's own asset list, and adversarial variants (a lone drain, a
      price move alone, call patterns alone) stay below threshold. The
      remaining signature-diversity slot (reentrancy — candidate dForce
      Apr 2020 or Fei/Rari Apr 2022) is still an explicitly-skipped
      placeholder test rather than filled with an unverified hash. **Scoring flaw found on Euler, now fixed:** the shipped generic
      signatures scored 100.0 on it, but only because a single fact (the
      large outflow) satisfied a condition in three different signatures
      and was summed three times — so any legitimate withdrawal above
      ~20% of a balance would also have reached the pause threshold,
      contradicting ARCHITECTURE.md §3.3 / SECURITY.md T2. Confidence now
      sums *distinct evidence* (each fact once, at its highest weight),
      with the counted evidence recorded on the decision; the generic set
      now scores 60.0 on Euler (below threshold, as it should absent
      corroboration) and a regression test against the shipped YAML
      proves a lone outflow of 10-100% never pauses (verified to fail on
      the pre-fix engine). **Cross-language detection wiring is now done for
      this one case:** `crates/replay-harness/tests/beanstalk_governance_exploit.rs`
      fetches the real transaction's actual decoded call trace (via
      `chain-adapter`, from a real archive RPC) and runs it through the
      real `detection` engine, using a signature built from two
      independently-verified real selectors — `emergencyCommit(uint32)`
      (`0x73015684`, computed from the exact function signature quoted
      from Beanstalk's own public source, `GovernanceFacet.sol` at
      commit `ee4720cdb449d5b6ff2b789083792c4395628674`) and Aave V2's
      standard flash-loan callback (`0x920f5c84`, a fixed public
      interface, not incident-specific). The test asserts both
      selectors are actually present in the real trace and that the
      resulting confidence crosses threshold. **Now run live (2026-09-21):** the Alchemy free tier rejects
      `debug_traceTransaction`/`trace_transaction` and anvil forks proxy
      historical traces upstream, but `cast run <tx> --json` re-executes
      the transaction locally at its true block position using only
      free-tier state calls. `replay-harness` (`src/cast_trace.rs`, 6
      unit tests) converts that trace to call frames; the live test
      finds 349 frames (depth 16), both selectors, confidence 95.0. A
      naive local re-execution (fork at N-1, impersonate, resend calldata)
      had produced a reverted, unfaithful trace — same-block state
      matters. `rust-ci.yml`'s `replay` job runs it in CI once
      `ETH_RPC_URL`/`RUN_REPLAY_TESTS` are configured.
- [ ] **Slice 7 — False-positive validation.** Not started at the
      historical-replay level (same archive-RPC dependency as Slice 6's
      remaining work). Interim signal exists in `detection`'s own unit
      tests (`small_legitimate_withdrawal_does_not_fire_high_threshold`,
      `oracle_deviation_does_not_fire_on_normal_market_move`,
      `nested_legitimate_calls_do_not_look_like_reentrancy`,
      `governance_anomaly_does_not_fire_on_normal_delegation`,
      `benign_transaction_produces_zero_confidence`) but these are
      synthetic fixtures, not real historical high-volume traffic —
      don't conflate the two when citing a false-positive rate.
- [x] **Slice 8 — Real baseline sourcing (mostly).** New
      `tripwire-context` crate, wired into the daemon
      (`TRIPWIRE_WATCHED_TOKENS`, `TRIPWIRE_EXTRA_HOLDERS`,
      `TRIPWIRE_WATCH_NATIVE`, `TRIPWIRE_TRACK_AMM_PRICES`,
      `TRIPWIRE_TRACE_FALLBACK`): **fund flow** = the worst single-asset
      drain (fraction of the balance that left), from ERC-20 `Transfer`
      logs net of inflows (so a repaid flash loan nets out) against the
      holder's balance at the *previous block*, plus native ETH from the
      call trace; **price movement** = the largest relative spot-price move
      of any Uniswap-V2-style pool in the transaction, from `Sync` events
      against `getReserves` at the previous block; **call traces** from the
      node when it serves them, else optionally `cast run` (slow but works
      on any archive RPC). Everything fails closed (a value that can't be
      read is left unset, never guessed). Pure arithmetic is unit-tested
      (23 tests); the RPC layer is tested on a live `anvil` with mock
      contracts (9 tests: real historical `eth_call`s, ERC-20 and native
      outflow, price move, fail-closed paths); and it runs on three real
      exploits (below). **Not done:** governance voting-power sourcing
      (`GovernanceProposalAnomaly` still has no baseline source);
      non-Uniswap-V2 price oracles (Curve, Uniswap V3, Chainlink) — note
      the Harvest Finance (Curve) exploit moved swap execution prices only
      0.03-0.05%, so a price-deviation percentage cannot catch that class
      and it needs a different signal; the `cast run` fallback is too slow
      for a latency-critical path (use a trace-capable or local node).
- [ ] **Slice 9 — Observability.** Structured logging exists (every
      signature match, every decision, tracing spans in the daemon) but
      metrics export and alerting hooks (SECURITY.md T3: the listener's
      own liveness needs to be a first-class monitored signal) aren't
      built yet.
- [x] **Slice 10 — CI pipeline.** `.github/workflows/rust-ci.yml`
      (fmt/clippy/build/test — the real-anvil integration tests run in
      CI, not skipped), `foundry-ci.yml` (unit tests always; a separate
      `replay` job gated behind a `RUN_REPLAY_TESTS` repo variable and an
      `ETH_RPC_URL` secret, since it needs archive-RPC access CI doesn't
      have by default), `codeql.yml` (Rust), `security-scans.yml`
      (`cargo audit` + Slither, `fail-on: high`).
- [x] **Slice 11 — Docs pass.** `SECURITY.md`, `docs/INTEGRATION.md`,
      `README.md` written for a security-conscious protocol engineering
      lead evaluating trust, not a portfolio-piece pitch — the README's
      status table states the two real gaps (Slice 6/7 completeness,
      Slice 8) as plainly as the parts that are done.
- [x] **Guardian hardening.** `registerTarget` rejects non-contracts and
      contracts without `paused()`; `script/DeployGuardian.sol` deploys with
      role separation and re-verifies the resulting on-chain state (14 tests);
      stateful invariant suite (mutation-checked); gas figures in
      `docs/GAS.md`. Slither not run locally (not installed); CI runs it.

## Open questions

- **Archive RPC access:** Gideon needs to sign up for Alchemy (or
  Infura/QuickNode) — not something this session could do on his
  behalf. Blocks completing Slice 6/7 and running `foundry-ci.yml`'s
  replay job in CI. Everything else is unblocked and already green.
- **Confirm the remaining two historical exploits' exact transaction
  hashes** (an oracle-manipulation case, a reentrancy case) against Etherscan directly before writing their replay tests —
  do not reuse a web-search-summarized hash without independently
  fetching and confirming it against the block explorer itself; this
  session caught one real instance of a search-summary tool inventing a
  plausible-but-wrong block number (14,895,611 instead of the actual
  14,602,790 for the Beanstalk transaction) that only surfaced because
  the actual Etherscan page was fetched directly afterward.
- **GitHub remote:** not yet created. Propose
  `github.com/gasthecreator/tripwire` (matching the other two portfolio
  repos' naming pattern) once Gideon confirms public vs. private
  visibility.
- Wire Slice 6's replayed fork call-trace through the real `detection`
  crate (see Slice 6 above) — this is the highest-value remaining piece
  for the brief's core "prove detection would have fired" claim.
