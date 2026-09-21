# Tripwire

Automated, no-human-in-the-loop pause for DeFi protocols under active
exploit — the response step that today's detection tools (Forta,
Tenderly, OpenZeppelin Defender, Hypernative, Blockaid) all leave to a
human.

**Read this before anything else: what this system does and does not do.**

## The honest value proposition

A single-transaction exploit — a flash-loan attack, an atomic oracle
manipulation, most reentrancy drains — executes and finalizes within one
block. By the time any on-chain event fires, the transaction is already
mined and the funds are already gone. **No system that reacts to on-chain
events can prevent that first loss, including this one.** If a security
product's pitch implies otherwise, it's either confused about EVM
execution semantics or misrepresenting what it does.

What Tripwire actually does: pause the protocol automatically, within
seconds of detecting the first exploit transaction, without waiting for a
human to see an alert and act on it. Real incidents are rarely one
transaction and then silence — the attacker, or copycats once the exploit
is visible, frequently return for a second, third, and further drain
while a team is still being paged. The March 2026 Resolv USR exploit is
the public reference case: the protocol was paused "within minutes" of
detection, and that pause stopped continued draining — it did not undo
the initial loss. Collapsing that response time from human-mediated
minutes to automated seconds, so the second transaction never lands, is
the actual, bounded claim this project makes. See `ARCHITECTURE.md` §1
for the full reasoning.

## What's real right now vs. what isn't

This is a portfolio-stage security engineering project, not an audited
production deployment. Read this table before trusting anything else in
this README:

| Component | Status |
|---|---|
| Detection engine (signature matching + confidence scoring) | Real, fully implemented; 69 tests including adversarial cases and tests that run against the *shipped* signature YAML (not fixtures), e.g. that no supporting evidence without a harm fact can reach the pause threshold |
| Chain adapter (EVM, block/tx normalization, call-trace decoding) | Real, tested against a live local `anvil` node (not mocked) |
| Guardian contract + demo target (`Guardian.sol`, `GuardedVault.sol`) | Real, OpenZeppelin-based; 37 Foundry tests including fuzzing, a live reentrancy attack simulation, a deploy script with post-deployment verification (14 tests), and a 7-invariant stateful fuzz suite that was mutation-checked (deliberately broken contracts fail it). Slither runs in CI (one accepted, documented finding); not audited |
| End-to-end wiring (listener → detection → on-chain pause) | Real and tested at three levels: an in-memory chain that can reorg, fail RPC calls and change mid-read (19 state-machine tests), a live `anvil` node with the real compiled contracts, real adapter and real guardian client (including a **real reorg** via snapshot/revert, which cancels a pending pause), and the guardian-client end-to-end test. The first shipped daemon had never been exercised end-to-end and was broken (see `WORKLOG.md`): with default settings it could never pause anything, it filtered on `tx.to == target` (which would have missed both real exploits, sent to attacker contracts), and it had no reorg handling. All fixed. Measured detect → pause latency on a local chain: ~265 ms on a local chain with one confirmation required (the block interval on mainnet, ~12 s, dominates real-world latency) |
| Historical exploit replay (the brief's core validation requirement) | **Four real cases, all run live: Beanstalk (Apr 2022, governance), Euler Finance (Mar 2023, flash-loan/donation drain), Warp Finance (Dec 2020, oracle manipulation), Rari/Fei Fuse (Apr 2022, cross-contract reentrancy).** Hashes verified (Euler and Warp were found on-chain first — Euler via Aave `FlashLoan` events, Warp by block timestamp and `Sync` events — then corroborated: Etherscan labels, and Warp's published amounts matched against the receipt). Each replays on a real mainnet fork in Solidity (Beanstalk/Euler), and its real call trace (`cast run` re-executes it locally — no paid trace API) and real fund flow / price movement are scored by the actual Rust engine through the same production context code the daemon uses. **The shipped generic signatures pause on all four** (Beanstalk 100, Euler 85, Warp 100, Rari 95; each lost ~100% of what it custodied), configured with only each protocol's own asset list; a lone drain, a price move alone, and call patterns alone all stay under the threshold. Replaying these found and fixed four real detector bugs synthetic tests missed (reentrancy false positive; one outflow summed three times; call-pattern evidence able to pause on its own; the daemon never pausing at all) — see `PLAN.md`/`WORKLOG.md`. The Rari case exposed that cross-contract callback re-entry was invisible to the reentrancy signature; a `ProtocolCallbackReentry` fact now covers it. The Solidity-side reentrancy placeholder is still unfilled. **Caveat:** four exploits are four data points, not a recall estimate; without the flash-loan fact, several of these would sit exactly at or below the threshold |
| Baseline computation (real balance/price context feeding the detection conditions) | **Real for funds and AMM prices; not for governance.** `tripwire-context`: fund flow as net *value* lost across the protocol's watched assets when a valuer is configured (a swap or a collateral-backed borrow is not a drain; prices from the block before the transaction; falls back to the strict per-asset rule if an asset has no price), otherwise the worst single-asset outflow; Uniswap-V2 spot-price movement from `Sync` events; an optional `cast run` trace fallback; everything fails closed. Tested on a live `anvil` and on four real exploits. Governance voting-power sourcing and non-Uniswap-V2 oracles (Curve, V3, Chainlink) are not implemented |
| False-positive rate against real legitimate traffic | **Measured, on three protocols, with caveats.** 1,855 sampled outflow transactions (Aave V2, Compound V2, Curve 3pool, blocks 17.0M-20.5M) scored with the shipped signatures. The first run would have **paused 8 legitimate transactions**; that exposed two real flaws (fund flow measured one asset at a time; a shared 5% threshold), now fixed. After the fixes: **0 would-pause, every candidate traced, 95% upper bound about 1 false pause/day per protocol.** That result is *in-sample* (the fixes were made after seeing those transactions); a different-seed holdout (`docs/FALSE_POSITIVES_HOLDOUT.md`, 1,771 fresh transactions, every candidate traced) also found **0 would-pause**; it tests overfitting to the sample, not other protocols or eras. Not covered: native-ETH flows, non-Uniswap-V2 price movement, other protocol types. Details and method: `docs/FALSE_POSITIVES.md` |

If you're evaluating this for anything beyond a portfolio/demonstration
context, these are the gaps to press on: the false-positive result covers
three protocols in one block range (a holdout run with fresh windows agrees, but it is the same protocols and era);
four exploits are not a recall estimate; governance voting power and
non-Uniswap-V2 oracles are not sourced; the replay jobs need an archive-RPC
secret to run in CI (they do not run there today); and none of this has been
audited or run against a live network.

## Competitive positioning

| | Detects | Automates the pause |
|---|---|---|
| Forta / Tenderly / OpenZeppelin Defender / Hypernative / Blockaid | Yes | No — alert only, human triggers the pause |
| Tripwire | Yes (same signature categories the industry already watches) | **Yes** |

See `ARCHITECTURE.md` §2 for the full positioning, including why this
project isn't trying to out-detect any of them.

## Architecture, at a glance

```
Chain → ChainAdapter (EVM) → Detection engine (YAML signatures, confidence scoring)
                                          │
                              score ≥ threshold?
                                          ▼
                          Guardian client → Guardian.sol → target.pause()
```

Full reasoning, every major tradeoff (reorg handling, confirmation-depth
gating, the gas-cost/speed tradeoff on the guardian contract, why scoring
is additive not max-based), and the multi-chain design boundary are in
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## Repository layout

```
crates/
  tripwire-core/     chain-agnostic types (TxEvent, Signature, Confidence, PauseDecision)
  chain-adapter/     ChainAdapter trait + the EVM implementation
  detection/         signature loading, condition evaluation, confidence scoring
  guardian-client/   signs and submits pause transactions
  tripwire-daemon/   the binary that wires the above together
  replay-harness/    fetches real historical transactions and scores their
                      real call traces through the real detection engine
contracts/
  src/Guardian.sol         on-chain pause authority
  src/GuardedVault.sol     demo pausable target
  test/unit/               Foundry unit + fuzz tests
  test/replay/             historical-exploit fork tests (needs ETH_RPC_URL)
signatures/          exploit signatures as data (YAML), not code
docs/INTEGRATION.md  what a real protocol needs to do to adopt this
```

## Running it

Prerequisites: Rust (via [rustup](https://rustup.rs)), [Foundry](https://getfoundry.sh).

```bash
# Contracts -- build these FIRST: guardian-client's sol! macro reads
# contracts/out/*.json at Rust compile time, not just at test runtime.
cd contracts
forge install foundry-rs/forge-std@v1.16.2 --no-git
forge install OpenZeppelin/openzeppelin-contracts@v5.7.0 --no-git
                                 # (contracts/lib/ is gitignored -- pinned versions, see CONTRIBUTING.md)
forge build
forge test -vvv                 # unit tests only, no network required
cd ..

# Rust workspace
cargo build --workspace
cargo test --workspace          # spawns real local anvil nodes for integration tests

# Historical exploit replay (needs an archive-RPC URL, e.g. Alchemy free tier)
cd contracts
ETH_RPC_URL=<your-archive-rpc-url> FOUNDRY_PROFILE=replay forge test -vvv
```

To run the daemon against a real chain, copy `.env.example` to `.env` and
fill in an RPC URL, a deployed `Guardian` address, the contract you want
watched, and a dedicated hot-wallet private key holding only `PAUSER_ROLE`
on that Guardian — see [`docs/INTEGRATION.md`](docs/INTEGRATION.md) for
the full deployment checklist and why the pause and unpause roles must
never be the same address.

## Documentation map

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — system design, the corrected
  problem statement, competitive positioning, every major tradeoff argued
  through with reasoning.
- [`SECURITY.md`](SECURITY.md) — threat model for the guardian contract
  itself (it's a new attack surface, not just a defense), false-positive/
  false-negative handling philosophy, the unpause recovery path, and the
  Slither static-analysis results.
- [`PLAN.md`](PLAN.md) — the living build checklist and current status,
  including every open question honestly listed (not swept into this
  README's happy-path summary).
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — for a protocol team
  evaluating adoption: the interface you need, the deployment checklist,
  and the one requirement (separate pause/unpause roles) that isn't
  optional.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — engineering workflow: branch
  discipline, the `ARCHITECTURE_PROPOSALS.md` process for design
  deviations, `WORKLOG.md` for session-by-session history.

## License

MIT — see [`LICENSE`](LICENSE).
