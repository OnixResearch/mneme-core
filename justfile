set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# The extracted workspace has no application binaries; keep formatting scoped to
# the eleven published libraries.
rust_packages := "-p mneme-kernel -p mneme-core -p mneme-store -p mneme-memory -p mneme-consolidation -p mneme-prolog -p mneme-retention -p mneme-doc -p mneme-datalog -p mneme-recall -p mneme-api -p mneme-sync"

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

# Layer A: mutate crates/mneme-kernel/src/*.rs and require 100% Lean kill rate.
audit-kernel-spec *args:
    node scripts/audit-kernel-spec-strength.mjs {{args}}

# Layer B: scoped cargo-mutants audit of the ~16 shell<->kernel adapter files
# configured in .cargo/mutants.toml, enforcing a >=90% non-equivalent kill rate.
audit-mutants *args:
    #!/usr/bin/env bash
    set -euo pipefail
    out_dir="${MNEME_MUTANTS_OUT:-mutants.out}"
    min_rate="${MNEME_MUTANTS_MIN_KILL_RATE:-0.90}"
    status=0
    cargo mutants --output "$out_dir" {{args}} || status=$?
    # cargo-mutants exits 2 when any mutant survives; evaluate the kill-rate ratchet.
    if [[ "$status" -ne 0 && "$status" -ne 2 ]]; then
        exit "$status"
    fi
    node -e '
      const fs = require("node:fs");
      const path = require("node:path");
      const outDir = process.argv[1];
      const minRate = Number.parseFloat(process.argv[2]);
      const data = JSON.parse(fs.readFileSync(path.join(outDir, "outcomes.json"), "utf8"));
      let caught = 0, missed = 0, timeout = 0, unviable = 0;
      for (const entry of data.outcomes ?? []) {
        if (!entry.scenario || entry.scenario === "Baseline") continue;
        const summary = entry.summary;
        if (summary === "CaughtMutant") caught += 1;
        else if (summary === "MissedMutant") missed += 1;
        else if (summary === "Timeout") timeout += 1;
        else if (summary === "Unviable") unviable += 1;
      }
      const killed = caught + timeout;
      const denom = killed + missed;
      const rate = denom === 0 ? 1.0 : killed / denom;
      console.log(
        `SHELL-MUTANTS: ${killed}/${denom} killed (${(rate * 100).toFixed(2)}%) ` +
        `[caught=${caught}, timeout=${timeout}, missed=${missed}, unviable=${unviable}] ` +
        `(threshold >= ${(minRate * 100).toFixed(1)}%)`
      );
      if (rate < minRate) {
        console.error(`kill rate ${(rate * 100).toFixed(2)}% is below required ${(minRate * 100).toFixed(1)}%`);
        process.exit(1);
      }
    ' "$out_dir" "$min_rate"

fmt-nix:
    nixfmt flake.nix
