set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Every workspace member, named explicitly. `--all` would follow the `vendor/rats`
# symlink and format the external Rats checkout, so formatting is scoped here.
rust_packages := "-p mneme-kernel -p mneme-core -p mneme-store -p mneme-memory -p mneme-consolidation -p mneme-prolog -p mneme-retention -p mneme-doc -p mneme-datalog -p mneme-recall -p mneme-api -p mneme-desktop -p mneme-eval -p mneme-cli"

default:
    @just --list

# Install only the pinned OpenSpec development tooling.
setup:
    npm ci --ignore-scripts --no-audit --no-fund

# Planning checks plus Rust formatting and lint checks.
check: planning rust-lint

planning:
    npm run check

rust-lint:
    cargo fmt {{rust_packages}} -- --check
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

rust-test:
    cargo test --locked --workspace --all-targets --all-features
    cargo test --locked --workspace --doc --all-features

fmt:
    cargo fmt {{rust_packages}}

# Kernel decision proofs; the script owns the pinned Lean toolchain invocation.
proofs:
    node scripts/verify-kernel-proofs.mjs

# Real behavioral acceptance: every required suite must pass and no required
# capability may remain unimplemented.
acceptance:
    cargo run --locked -q -p mneme-cli -- eval run --fixtures fixtures/evaluation --required acceptance/required-capabilities.json --report target/acceptance/report.json

# Development run: tolerates unimplemented or skipped suites so a partial slice
# can be inspected; any failed case still fails the run.
acceptance-dev:
    cargo run --locked -q -p mneme-cli -- eval run --fixtures fixtures/evaluation --required acceptance/required-capabilities.json --report target/acceptance/report.json --allow-incomplete

specs:
    npm run spec:list

status:
    npm run spec:status

fmt-nix:
    nixfmt flake.nix

# Run every completion gate and record the result in the loop state.
loop-verify:
    node scripts/loop-state.mjs verify

# Clear an explicit blocker before starting or resuming the loop.
loop-resume:
    node scripts/loop-state.mjs resume
