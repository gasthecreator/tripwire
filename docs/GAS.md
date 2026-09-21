# Gas costs

Measured with `forge test --gas-report` (optimizer on, 200 runs, solc 0.8.26)
over the unit suite. Figures are gas *used by the call*, not price; a pause
transaction also pays the 21,000 base cost and calldata.

| Call | Min | Median | Max | Notes |
|---|---:|---:|---:|---|
| `Guardian.pause` | 25,047 | 58,361 | 59,111 | Varies with the target's own `pause()` (storage write vs. already paused) and the length of the `reason` string. |
| `Guardian.unpause` | 24,219 | 24,219 | 34,804 | Reached through the timelock in a real deployment, so the timelock's own execute overhead is additional. |
| `Guardian.registerTarget` | 24,218 | 53,127 | 53,127 | Includes the `code.length` and `paused()` checks added for deploy-time safety; setup-time only. |
| `Guardian` deployment | 618,170 | | | 2,799 bytes. |

## What this means for speed

A pause is roughly 60k gas. That is cheap in gas terms, so **gas is not the
bottleneck to containment**: detection latency and *inclusion* latency are.
Whether a pause lands in the very next block depends on the priority fee the
hot wallet bids, which is a bidding decision, not a contract-design one. The
guardian contract deliberately spends a few thousand extra gas on the
role check and the event (audit trail) rather than optimising them away;
that is the trade recorded in `ARCHITECTURE.md` §3.4.

These numbers come from a test EVM, not mainnet. They are stable for the
contract logic but exclude L1 calldata costs on rollups.
