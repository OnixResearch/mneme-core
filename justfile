set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

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
    cargo fmt --all -- --check
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

rust-test:
    cargo test --locked --workspace --all-targets --all-features
    cargo test --locked --workspace --doc --all-features

fmt:
    cargo fmt --all

# Real behavioral acceptance: every required suite must pass and no required
# capability may remain unimplemented. It intentionally fails until the full
# plan is implemented and every required suite is registered.
acceptance:
    cargo run --locked -q -p mneme-cli -- eval run --fixtures fixtures/evaluation --required acceptance/required-capabilities.json --report target/acceptance/report.json

# Development run: prints failures, skips, and unimplemented capabilities but
# exits successfully so a partial slice can be inspected.
acceptance-dev:
    cargo run --locked -q -p mneme-cli -- eval run --fixtures fixtures/evaluation --required acceptance/required-capabilities.json --report target/acceptance/report.json --allow-incomplete

specs:
    npm run spec:list

status:
    npm run spec:status

fmt-nix:
    nixfmt flake.nix

# This intentionally cannot pass before the application is implemented.
loop-verify:
    node scripts/loop-state.mjs verify

# Clear an explicit blocker before starting or resuming the loop.
loop-resume:
    node scripts/loop-state.mjs resume
