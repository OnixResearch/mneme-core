# Working on Mneme Core

## Workspace overview

`OnixResearch/mneme-core` is the standalone public Rust library workspace for
Mneme's typed memory engine, peer-to-peer sync library, and formally verified
decision kernel. It contains **12 library crates** and `proofs/kernel` (no
application binaries):

- `mneme-kernel` — pure `no_std` decision functions translated to Lean 4 and
  verified by `proofs/kernel` (no I/O, no allocation, no clock, no panics).
- `mneme-core` — Preserves typed records, identifiers, digests, schema registry,
  and canonical binary/JSON transport encodings.
- `mneme-store` — SQLite manifest ledger, content-addressed blob/chunk storage,
  transactions, publication, recovery, portability, and verification.
- `mneme-memory` — attributed evidence, assertion lifecycle, independent support
  graphs, recognition runs, and bounded explanations.
- `mneme-retention` — scoped retention barriers, dependency-aware withdrawal,
  replay suppression, and accountable cleanup.
- `mneme-doc` — source-first AsciiDoc and Markdown parsing, anchors, bounded
  includes, images, and safe previews.
- `mneme-datalog` — bounded, explainable relational projections (Free Join
  sorted-trie evaluator, DBSP Z-set incremental maintenance, epistemic
  provenance semiring, and Why-Not explanations).
- `mneme-recall` — scoped lexical, structured, and local-vector recall.
- `mneme-consolidation` — evidence-preserving proposals and resumable jobs.
- `mneme-prolog` — optional bounded Scryer Prolog capability contracts.
- `mneme-api` — transport-neutral local memory and federation commands/queries.
- `mneme-sync` — Iroh peer-to-peer verified BLAKE3 blob/bundle replication,
  RBSR set reconciliation, and head-revision gossip.

## Kernel and proof rules

- **Pure kernel authority.** Every decision owned by `crates/mneme-kernel` must
  be called by imperative shells rather than re-derived inline. Keep
  `mneme-kernel` `no_std`, total, panic-free, and free of I/O or ambient state.
- **Proof regeneration.** Any edit to `crates/mneme-kernel` is incomplete until
  the Lean 4 extraction is regenerated and verified from the pinned `x86_64-linux`
  dev shell:

```sh
nix develop --no-update-lock-file --command bash -euo pipefail -c '
  cargo fetch --locked
  node scripts/verify-kernel-proofs.mjs --update
  just proofs
'
```

- **No `sorry` or non-standard axioms.** All theorems in `proofs/kernel` must
  compile cleanly with zero warnings and only standard Lean axioms.
- **Mutation audits.** Use `just audit-kernel-spec` (Layer A, 100% Lean kill
  rate on `mneme-kernel`) and `just audit-mutants` (Layer B, `>= 90%` kill rate
  on shell↔kernel adapter files) when modifying kernel boundaries.

## Verification gates

Enter the pinned development shell (`nix develop`) for Rust 1.99.1, `just`,
`cargo-octet`, `scryer-prolog`, and (on `x86_64-linux`) Charon/Aeneas/Lean:

```sh
just rust-check       # cargo fmt --check, clippy -D warnings, tests, doctests
just octet            # Tier 1 strict required profile (dylint.toml, 0 findings)
just octet-all        # Tier 2 per-crate sharded ratchet (Nix sandbox check)
just octet-advisory   # Tier 3 opt-in advisory heuristics (warn-only)
just proofs           # Charon/Aeneas/Lean proof gate
```

### 3-Tier Sharded Octet policy

1. **Tier 1 (`dylint.toml`, `just octet`):** PR-blocking `deny` safety lints
   with zero baseline and `core_source_scopes` over `mneme-kernel`,
   `mneme-core`, `mneme-datalog`, and `mneme-memory`. Must stay at 0 findings.
2. **Tier 2 (`dylint-all.toml` + `octet-baseline/<crate>.json`, `just octet-all`):**
   Per-crate sharded ratchet verified in Nix (`checks.<system>.octet-all`).
   CI enforces `new_count <= base_count` for every crate via
   `node scripts/octet-sharded.mjs check-monotonic --base origin/<base_ref>`.
   Never silently expand a crate's baseline shard; fix or refactor new findings
   instead. When burning down debt, regenerate shards with
   `just octet-write-baselines`.
3. **Tier 3 (`dylint-advisory.toml`, `just octet-advisory`):** Opt-in advisory
   report for noisy heuristic lints (`assertion_density`, `ambiguous_params`,
   `numeric_units`).

### Workspace lint & safety invariants

- `unsafe_code = "forbid"` across the entire workspace.
- `clippy::panic = "deny"`, `clippy::unwrap_used = "deny"`, and
  `clippy::expect_used = "deny"` in non-test code.
- `[profile.release] overflow-checks = true` — integer overflow aborts rather
  than silently wrapping.
- All flake inputs use public HTTPS URLs (`verify.yml` refuses `ssh://` in
  `flake.lock`).

## Downstream consumption

`OnixResearch/mneme` consumes `mneme-core` by pinning one exact commit SHA over
public HTTPS across 5 files (`Cargo.toml`, `Cargo.lock`,
`crates/mneme-android/Cargo.lock`, `flake.nix`, `flake.lock`) via
`just pin-core <rev>`.
