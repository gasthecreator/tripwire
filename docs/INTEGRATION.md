# Integrating a real protocol with Tripwire

This document is for a protocol team evaluating whether adopting Tripwire
means rewriting their contracts. It doesn't. `contracts/src/GuardedVault.sol`
is a demo target built for this repo's own tests — this document describes
the narrow surface a real, already-deployed protocol needs to expose
instead.

## What your contract needs

Exactly the interface in `contracts/src/interfaces/IPausable.sol`:

```solidity
interface IPausable {
    function pause() external;
    function unpause() external;
    function paused() external view returns (bool);
}
```

Most mature protocols already have something extremely close to this —
OpenZeppelin's `Pausable` is the de facto standard, and if your contract
already inherits it, you likely only need to:

1. Gate `pause()` behind a role your team can grant to a deployed
   `Guardian` contract's address (`AccessControl`'s `onlyRole`, or an
   equivalent custom modifier).
2. Make sure every fund-moving external function you care about
   protecting actually checks `whenNotPaused` (or your equivalent) — a
   pause that doesn't actually block withdrawals isn't a pause.
3. Never gate `unpause()` behind the same role as step 1. See
   "Why the roles must differ" below — this is the one requirement that
   isn't just "reuse what you already have."

If your protocol doesn't use OpenZeppelin's `Pausable`, you're
implementing a state flag and a modifier — this is normally under 20
lines of Solidity, not a rewrite.

## Deployment checklist

1. Deploy (or reuse) an OpenZeppelin `TimelockController` with your
   existing multisig as both proposer and executor. **Do not** use an
   EOA or the hot wallet described below as the timelock's proposer.
2. Deploy `Guardian.sol` with the `TimelockController`'s address as the
   constructor's `admin` argument. This is what makes `DEFAULT_ADMIN_ROLE`
   — and therefore `unpause` — timelock-gated instead of instant.
3. Generate a dedicated hot wallet for the off-chain detection service.
   This key does one thing for the rest of its life: sign pause
   transactions. Never reuse a key that holds any other role, anywhere.
4. Through the timelock (i.e., queue + execute a proposal, don't call
   these directly with an EOA even once during setup): call
   `guardian.grantRole(guardian.PAUSER_ROLE(), hotWalletAddress)` and
   `guardian.registerTarget(yourContractAddress)`.
5. On your own contract, grant whatever role gates your `pause()`/`unpause()`
   functions to the deployed `Guardian` contract's address — not to the
   hot wallet directly. The hot wallet talks to `Guardian`; `Guardian`
   talks to your contract. This indirection is what makes SECURITY.md's
   blast-radius argument (T1) hold: compromising the hot wallet only ever
   lets an attacker ask `Guardian` to pause a registered target, never
   bypass `Guardian` entirely.
6. Configure the off-chain daemon (`crates/tripwire-daemon`) with your
   contract's address, the `Guardian` address, an RPC endpoint, and your
   chosen `pause_threshold`. See `.env.example`.
7. **Before going live:** run the daemon against your contract on a
   testnet or a mainnet fork for at least a few days, watching the
   confidence scores it logs for real, legitimate traffic. See
   "Choosing a threshold" below — do not deploy with the default
   threshold unexamined.

## Why the roles must differ

The single most important property of this whole design, repeated here
because it's the one integration mistake that would quietly defeat the
entire point: **the address that can call `pause()` must never be the
same address that can call `unpause()`.** If it were, a compromised hot
wallet could pause your protocol and then immediately unpause it after
draining funds through some other path, or — more mundanely — a bug in
the off-chain detection service could flap your protocol's paused state
with no human ever in the loop at all. `Guardian.sol` enforces this
in code (`PAUSER_ROLE` for pause, `DEFAULT_ADMIN_ROLE` for unpause,
never the same role) — an integration only defeats this protection by
granting both roles to the same address, which nothing in Solidity can
stop you from doing to yourself. Don't.

## Configuring detection for your protocol

Detection needs to know what your protocol holds and what belongs to it. None
of this is inferred from the transaction being judged.

- `TRIPWIRE_WATCHED_TOKENS`, `TRIPWIRE_EXTRA_HOLDERS`, `TRIPWIRE_WATCH_NATIVE`:
  the assets and the contracts that custody them. Without these no fund-flow
  evidence exists and the daemon can essentially never pause.
- **Asset values** (recommended for anything that trades or lends): set
  `TRIPWIRE_TOKEN_VALUES` (pegged assets), `TRIPWIRE_NATIVE_VALUE`, and/or
  `TRIPWIRE_AAVE_V2_POOL`. With values, a swap or a borrow against fresh
  collateral is not read as a drain. **Without them each asset is judged
  alone, and value-neutral trades look like large outflows.** In the study
  this produced false pauses on ordinary Curve and Aave activity; see
  `docs/FALSE_POSITIVES.md`.
- `TRIPWIRE_PROTOCOL_CONTRACTS`: your comptroller / router / registry, so a
  callback out of the protocol and back in is recognised.

## Choosing a threshold

`pause_threshold` is not a value this project can responsibly recommend
as a universal default — see ARCHITECTURE.md §3.3 and SECURITY.md §3.
What we can tell you: run the daemon in log-only mode (comment out the
`submit_pause` call, or simply don't grant `PAUSER_ROLE` to it yet)
against your real, live traffic for a representative period first, and
look at what confidence scores real user activity produces. If your
largest legitimate single-transaction withdrawal already scores close to
your candidate threshold, that threshold is too low for your protocol's
actual usage pattern — raise it, or add signature conditions specific to
your contract's normal behavior before trusting the automated pause path.

## Signature customization

The four signatures in `signatures/` use placeholder function selectors
for flash-loan entrypoints and governance propose/execute calls (see
`signatures/README.md`). Before relying on `flash-loan-drain.yaml` or
`governance-takeover.yaml` for your protocol, replace those selectors
with your actual contract's real ABI-derived selectors — a signature
built against the wrong selectors will never fire, which is a silent
failure mode, not a loud one. Verify this by intentionally triggering the
matching legitimate code path in a test environment and confirming the
`call_sequence` condition actually matches in the daemon's logs.

## What this document does not cover

Multi-chain deployments, oracle/price-feed wiring for
`oracle-manipulation.yaml`'s reference price, and governance
voting-power lookups for `governance-takeover.yaml` are protocol-specific
integration work beyond what a generic guide can specify — reach out
(see `SECURITY.md`'s contact) if you're integrating and hit one of
these; they're exactly the kind of gap this document should grow to
cover once a real integration surfaces the specifics.
