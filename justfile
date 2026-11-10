set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

# Install only the pinned OpenSpec development tooling.
setup:
    npm ci --ignore-scripts --no-audit --no-fund

# Planning and loop-control checks today; extend with real Rust checks as built.
check:
    npm run check

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
