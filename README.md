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
| Detection engine (signature matching + confidence scoring) | Real, fully implemented, 36 unit tests including adversarial/false-positive cases |
| Chain adapter (EVM, block/tx normalization, call-trace decoding) | Real, tested against a live local `anvil` node (not mocked) |
| Guardian contract + demo target (`Guardian.sol`, `GuardedVault.sol`) | Real, OpenZeppelin-based, 19 tests incl. fuzzing and a live reentrancy attack simulation, Slither-clean (one accepted, documented finding) |
| End-to-end wiring (listener → detection → on-chain pause) | Real and tested at three levels: an in-memory chain that can reorg, fail RPC calls and change mid-read (19 state-machine tests), a live `anvil` node with the real compiled contracts, real adapter and real guardian client (including a **real reorg** via snapshot/revert, which cancels a pending pause), and the guardian-client end-to-end test. The first shipped daemon had never been exercised end-to-end and was broken (see `WORKLOG.md`): with default settings it could never pause anything, it filtered on `tx.to == target` (which would have missed both real exploits, sent to attacker contracts), and it had no reorg handling. All fixed. Measured detect → pause latency on a local chain: ~265 ms on a local chain with one confirmation required (the block interval on mainnet, ~12 s, dominates real-world latency) |
| Historical exploit replay (the brief's core validation requirement) | **Three of four real cases, all run live: Beanstalk (Apr 2022, governance), Euler Finance (Mar 2023, flash-loan/donation drain), Warp Finance (Dec 2020, oracle manipulation).** Hashes verified (Euler and Warp were found on-chain first — Euler via Aave `FlashLoan` events, Warp by block timestamp and `Sync` events — then corroborated: Etherscan labels, and Warp's published amounts matched against the receipt). Each replays on a real mainnet fork in Solidity (Beanstalk/Euler), and its real call trace (`cast run` re-executes it locally — no paid trace API) and real fund flow / price movement are scored by the actual Rust engine through the same production context code the daemon uses. **The shipped, un-tuned generic signatures pause on all three** (Beanstalk 100, Euler 85, Warp 100), configured with only each protocol's own asset list; a lone drain, a price move alone, and call patterns alone all stay under the threshold. Replaying these found and fixed four real detector bugs synthetic tests missed (reentrancy false positive; one outflow summed three times; call-pattern evidence able to pause on its own; the daemon never pausing at all) — see `PLAN.md`/`WORKLOG.md`. One case (reentrancy) is scaffolded but explicitly left unverified rather than filled with an unconfirmed hash. **Caveat:** three exploits are three data points; the false-positive rate on legitimate traffic is not yet measured |
| Baseline computation (real balance/price context feeding the detection conditions) | **Real for funds and AMM prices; not for governance.** `tripwire-context`: worst-asset outflow vs the holder's balance at the previous block (ERC-20 logs net of inflows; native ETH from the trace), Uniswap-V2 spot-price movement from `Sync` events, and an optional `cast run` trace fallback; everything fails closed. Tested on a live `anvil` and on three real exploits. Governance voting-power sourcing and non-Uniswap-V2 oracles (Curve, V3, Chainlink) are not implemented |
| False-positive rate against real legitimate traffic | **Not yet measured** at the historical-replay level (blocked on the same archive-RPC access as the exploit replays); the detection engine's own unit tests include several explicit "this should NOT fire" cases as an interim signal |

If you're evaluating this for anything beyond a portfolio/demonstration
context, the two "not yet" rows above are exactly the gaps to press on.

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
