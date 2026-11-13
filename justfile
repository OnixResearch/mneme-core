set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# The extracted workspace has no application binaries; keep formatting scoped to
# the eleven published libraries.
rust_packages := "-p mneme-kernel -p mneme-core -p mneme-store -p mneme-memory -p mneme-consolidation -p mneme-prolog -p mneme-retention -p mneme-doc -p mneme-datalog -p mneme-recall -p mneme-api"

default:
    @just --list

rust-format-check:
    cargo fmt {{rust_packages}} -- --check

rust-format:
    cargo fmt {{rust_packages}}

rust-lint:
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

rust-test:
    cargo test --locked --workspace --all-targets --all-features

rust-doctest:
    cargo test --locked --workspace --doc --all-features

# Rust formatting, Clippy, every target's unit/integration tests, and doctests.
rust-check: rust-format-check rust-lint rust-test rust-doctest

octet:
    cargo-octet check --workspace -- --all-targets --all-features --ignore-rust-version

# The all-lint check uses an isolated Nix source copy to select dylint-all.toml
# without replacing the developer's strict dylint.toml.
octet-all:
    nix build ".#checks.$(nix eval --raw --impure --expr builtins.currentSystem).octet-all"

# The pinned development shell supplies Charon, Aeneas, Lean, Lake and the
# matching Charon extraction toolchain. Lake may fetch its proof dependencies,
# so run this gate in the developer shell rather than a sandboxed derivation.
proofs:
    node scripts/verify-kernel-proofs.mjs

fmt-nix:
    nixfmt flake.nix
