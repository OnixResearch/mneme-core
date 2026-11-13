# Mneme Core

Mneme Core is the standalone Rust library workspace for Mneme's typed memory engine and its independently checked decision kernel. This public repository contains eleven libraries and the kernel's preserved Lean proof sources; it does not contain an application binary.

## Crate roles

- **`mneme-kernel`** — small decision functions for bounded arithmetic, identity, scope isolation, publication, cleanup, and related policy; its Rust source is translated and checked by the Lean gate.
- **`mneme-core`** — shared domain types, identifiers, typed records, transport encodings, and schema/version handling.
- **`mneme-store`** — durable workspace history, SQLite ledger, immutable source blobs, and publication/recovery operations.
- **`mneme-memory`** — attributed evidence, assertion lifecycle, support, and bounded explanations over stored snapshots.
- **`mneme-retention`** — scoped retention barriers, dependency-aware withdrawal, and accountable cleanup.
- **`mneme-doc`** — source-first AsciiDoc handling, bounded includes, images, and safe previews.
- **`mneme-datalog`** — bounded, explainable relational projections over committed snapshots.
- **`mneme-recall`** — scoped lexical, structured, and local-vector recall.
- **`mneme-consolidation`** — evidence-preserving proposal generation and resumable workspace jobs.
- **`mneme-prolog`** — optional bounded Prolog capability contracts and isolated engine execution.
- **`mneme-api`** — transport-neutral local memory commands and queries.

The workspace keeps the original crate names, public Rust APIs, Rust 1.99.1 toolchain pin, lint policy, and release overflow checks. No schema or runtime behavior is changed by this extraction.

## Provenance and preserved history

The source is **`OnixResearch/mneme` at commit `b77325d65aa2904f45234d1d9029081988a9b981`**, titled “Add retained images and verify weighted retrieval fusion.” The repository was filtered from that source history into a core-only history; the filtered starting revision is `7c8fcb894a827baeee75d29cf9f49ba5e31b6ae7`, with 75 source commits preserved. The 11 crate trees and `proofs/kernel` retain their source paths, Git blobs, and file modes from the cited source commit. Root build and developer tooling are adapted for the standalone library workspace.

The kernel proof owner is this repository: `crates/mneme-kernel` and `proofs/kernel` are kept together. Consumers should pin one exact `mneme-core` revision and run that revision's `scripts/verify-kernel-proofs.mjs`; the verifier locates its Rust kernel, proof sources, and lockfile relative to its own checkout.

## Development and verification

The source can be cloned without authentication. The pinned Nix environment
still fetches private OnixResearch verification tooling (Octet and its
dependencies), so those Nix commands require authorized SSH access. The Cargo
library workspace itself uses only local crates and crates.io dependencies.

Enter the pinned development shell to obtain Rust 1.99.1, the pinned Octet runner, the real Scryer Prolog test engine, and—on `x86_64-linux`—the matching Charon/Aeneas/Lean tools:

```sh
nix develop
```

From the repository root:

```sh
just rust-format-check
just rust-lint
just rust-test
just rust-doctest
just rust-check
just octet
just octet-all
just proofs
```

Equivalent Cargo commands are:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --workspace --doc --all-features
```

`just octet` runs the strict required profile in `dylint.toml`, without a baseline. `just octet-all` runs the full-catalog profile from `dylint-all.toml` in an isolated Nix source copy and compares findings with `octet-baseline.json`, keeping the strict profile untouched. Baseline debt does not suppress strict findings.

The extracted all-lint baseline contains 1,228 accepted finding identities,
exactly the engine-owned subset of the original repository's baseline. New
or stale identities require review and regeneration with the pinned runner;
an accepted baseline is recorded debt, not an all-lint-clean claim. The strict
profile must remain clean without a baseline.

`just proofs` runs the preserved source-to-Lean translation and audits all 128 inventoried kernel theorems against the Rust kernel, checked-in translation, and allowed Lean axioms. It is intentionally a developer/consumer workflow, not a sandboxed Nix check: Lake may fetch proof dependencies. Run it from the pinned development shell on `x86_64-linux`; the shell selects the Charon-matched extraction toolchain. The consumer-side completion gate should execute the verifier from the exact Git revision it compiles.

`nix flake check` provides the standalone Nix Rust build, Rust formatting check, and both Octet profiles. The flake and development shell require no desktop, GUI toolkit, or sibling application checkout.

## Repository status and licensing

This repository is publicly readable. No `LICENSE` or `NOTICE` file existed at the cited source commit, and this extraction adds neither. **Public visibility does not add a license grant.**
