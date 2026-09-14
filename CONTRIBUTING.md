# Contributing

This is a solo-maintained project, but it's built with the same discipline as
a real engineering team — this file documents that discipline so it's legible
to anyone reading the repo, not just followed implicitly.

## Before touching code

Read [`PLAN.md`](PLAN.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md) first.
`ARCHITECTURE.md` is the design reasoning — what was decided and why, with
tradeoffs argued through rather than asserted. `PLAN.md` is the living
build checklist and current status. If something in the codebase seems to
contradict either doc, that's a bug in the code or the doc — flag it, don't
silently reconcile it.

## Branching and PRs

- All work happens on a feature branch (`feat/`, `fix/`, `docs/`, `chore/`),
  never committed straight to `main`.
- Every change goes through a PR before merging, reviewed against
  `ARCHITECTURE.md`'s stated design and `PLAN.md`'s current slice.
- PRs don't merge themselves — merging is a deliberate, explicit step.

## Proposing an architecture change

`ARCHITECTURE.md` isn't edited directly to match new code that deviates from
it. If building something surfaces a reason to change course, write the
proposal into [`ARCHITECTURE_PROPOSALS.md`](ARCHITECTURE_PROPOSALS.md)
instead — with the actual reasoning (what was run into, what alternatives
were considered, why this one wins), not just the conclusion. That gets
reviewed and either folded into `ARCHITECTURE.md`/`PLAN.md` as
`Resolved: Approved`, or left as `Resolved: Rejected` with reasoning.
Implementation happens after that review, not before it. This matters more
here than in most projects: this is a security product, and an
undocumented, unreasoned deviation from the threat model in `SECURITY.md`
is itself a security regression.

## Logging the work

Every implementation session — what was built, why, how, what was tested —
gets an entry in [`WORKLOG.md`](WORKLOG.md). Treat it like an engineering log
at an actual job: if it's not logged there, it didn't happen. Entries are
dated and left in permanently, including ones that documented backtracking —
that's the record of real engineering judgment, not something to clean up.

## First-time setup

`contracts/lib/` (forge-std, OpenZeppelin Contracts) is gitignored rather
than committed or vendored as git submodules — fetch it once with:

```bash
cd contracts
forge install foundry-rs/forge-std@v1.16.2 --no-git
forge install OpenZeppelin/openzeppelin-contracts@v5.7.0 --no-git
```

Pinned tags, not bare `forge install`: these repos were fetched with
`--no-git` (no `.gitmodules` entry is recorded), so a bare `forge
install` with no arguments has nothing to reinstall from and silently
does nothing — every CI workflow in `.github/workflows/` runs the two
explicit commands above for exactly this reason; don't simplify them
back to a bare `forge install` without also either committing
`.gitmodules` or otherwise recording what to fetch. If `forge
build`/`forge test` behavior ever seems to disagree with what's
documented here, checking installed
versions against the two above is the first thing to rule out.

Then build the contracts **before** touching the Rust workspace at all:

```bash
cd contracts && forge build
```

This isn't optional ordering — `guardian-client`'s `sol!` macro
invocations read the compiled artifacts under `contracts/out/*.json` at
Rust *compile time* to generate contract bindings, not just when its
tests run. `cargo build`/`cargo clippy`/`cargo test` on the Rust
workspace will fail with a "failed to canonicalize path" error if
`contracts/out/` doesn't exist yet — this bit CI once already (see
`WORKLOG.md`) before every relevant workflow job ran `forge build`
first.

## Before opening a PR

Rust (event listener / detection engine):

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --workspace
cargo test --workspace
```

Solidity (guardian / target contracts, under `contracts/`):

```bash
cd contracts
forge fmt --check
forge build
forge test -vvv
```

Fork-based replay tests (`contracts/test/replay/`) additionally require
`ETH_RPC_URL` (an archive-node endpoint) set in the environment — see
`.env.example`. They're excluded from the default `forge test` run via a
dedicated profile (`FOUNDRY_PROFILE=replay forge test`) since they hit a
real external RPC and shouldn't block a plain local test run or silently
skip in CI if the secret isn't configured.

CI runs the same checks — see `.github/workflows/`. A green run there is the
bar, not "it worked on my machine once."

## What "done" means for a slice

A slice isn't done when it compiles or the design looks right on paper — for
the detection engine and guardian contract specifically, it's done when it's
verified against real forked-mainnet transaction data (an actual historical
exploit, or a real sample of legitimate high-volume activity for the
false-positive check), not synthetic fixtures alone. See `PLAN.md`'s
Slice 6/7 for what that verification looks like and why both the detection
rate and the false-positive rate get reported together, not separately.
