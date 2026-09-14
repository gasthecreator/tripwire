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
Apr 2022) is verified against Etherscan, replays against a real mainnet
fork on the Solidity side, and — as of this update — has its real
decoded call trace scored by the actual `detection` engine on the Rust
side too (`crates/replay-harness`), using two independently-verified
real function selectors. The gaps that matter most for anyone evaluating
this beyond a portfolio context: (1) none of this replay/detection
validation has actually *executed* against live data yet — it's real,
compiling, tested-for-the-skip-path code blocked on an archive-RPC key;
(2) three of four planned historical exploits still lack a verified
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
      shutdown handler. **Proven end-to-end**, not just unit-tested in
      isolation: an integration test deploys the real compiled
      `Guardian`/`GuardedVault` bytecode to a live local `anvil`,
      registers the vault, and pauses it entirely through
      `guardian_client::connect` + `submit_pause` — then confirms a
      non-pauser key using the same code path fails on-chain.
- [ ] **Slice 6 — Historical exploit replay harness.** Foundry fork tests
      against real mainnet history. **Status: one of four done.**
      Beanstalk Farms (Apr 17, 2022) is verified — tx
      `0xcd314668aaa9bbfebaf1a0bd2b6553d01dd58899c508d4729fa7311dc5d33ad7`,
      block 14602790, confirmed directly against Etherscan on
      2026-09-14 — and replays successfully against a real fork
      (`contracts/test/replay/HistoricalExploits.t.sol`) by fetching the
      real transaction live via `vm.rpc`/`eth_getTransactionByHash`
      rather than hardcoding calldata. The other three signature-
      diversity slots (flash-loan/fund-flow — candidate Euler Finance
      Mar 2023; oracle manipulation — candidate Cream Finance Oct 2021
      or Mango Markets Oct 2022; reentrancy — candidate dForce Feb 2020
      or a Curve LP incident Jul 2023) are stubbed as explicitly-skipped
      placeholder tests rather than filled with unverified hashes — web
      searches during this session confirmed dates and mechanisms for
      Euler and Cream but not a specific first-attack transaction hash
      with enough confidence to assert as fact in a security product's
      own test suite. **Cross-language detection wiring is now done for
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
      resulting confidence crosses threshold. **Still blocked on the
      archive-RPC key to actually execute** — the code compiles and its
      no-RPC skip path is verified, but it hasn't run against live data
      in this session; `rust-ci.yml`'s `replay` job runs it in CI once
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
- [ ] **Slice 8 — Real baseline sourcing.** Not started. The daemon's
      `Baseline` (balance history, reference price/TWAP, governance
      voting-power lookups) is currently `Baseline::default()` —
      detection and scoring are fully real, but this input isn't sourced
      from live chain state yet. Needs to be scoped per-protocol
      (`docs/INTEGRATION.md`'s "Signature customization" section already
      flags this) rather than solved generically.
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

## Open questions

- **Archive RPC access:** Gideon needs to sign up for Alchemy (or
  Infura/QuickNode) — not something this session could do on his
  behalf. Blocks completing Slice 6/7 and running `foundry-ci.yml`'s
  replay job in CI. Everything else is unblocked and already green.
- **Confirm the remaining three historical exploits' exact transaction
  hashes** (Euler Finance, an oracle-manipulation case, a reentrancy
  case) against Etherscan directly before writing their replay tests —
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
