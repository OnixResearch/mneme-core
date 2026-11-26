# Mneme Core TLA+ Protocol Specifications & Trace Validation

This directory contains executable TLA+ specifications model-checked with TLC for
the multi-step imperative shell protocols in `mneme-store` and `mneme-sync` that
sit above the Lean-verified pure decision kernel (`crates/mneme-kernel`):

- `WorkspaceLifecycle.tla` / `WorkspaceLifecycle.cfg` — CAS commits
  (`shared_commit_lock` vs `exclusive_sweep_lock`), `eligibility_generation`
  barriers and pinning, `FaultPoint` crashes and startup recovery, quarantine
  working-file publication races, retention purge + FastCDC chunk GC (closing
  audit bug `S1`), and `SharedRecordCache` generation invalidation.
- `RestoreBarrier.tla` / `RestoreBarrier.cfg` — `META_RESTORE_PENDING`
  fail-closed barrier, workspace genesis binding, suppression ledger
  monotonicity, and pending publication suppression on restore.
- `SyncConvergence.tla` / `SyncConvergence.cfg` — multi-peer RBSR delta pull
  with retention barrier propagation, Ed25519-signed `PushHead` monotonic
  high-water marks, `RevocationSet` G-Set CRDT merge, capability expiry under
  clock skew, cross-scope isolation, and `CalmSeal` monotonicity.
- `TraceSpec.tla` / `TraceSpec.cfg` / `TraceData.tla` — model-based trace
  validation specification (Davis et al., PVLDB 2020) checking NDJSON
  state-transition traces emitted under `#[cfg(feature = "trace-spec")]` in
  `mneme-store` and `mneme-sync`.

## Running

```sh
node scripts/verify-tla.mjs
# Validate a live NDJSON trace emitted by Rust tests:
node scripts/verify-tla.mjs --trace-ndjson path/to/trace.ndjson
```
