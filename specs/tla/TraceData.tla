----------------------------- MODULE TraceData -----------------------------
(***************************************************************************)
(* Default reference execution trace matching the NDJSON schema emitted by *)
(* `#[cfg(feature = "trace-spec")]` in `mneme-store` and `mneme-sync`.     *)
(* `scripts/verify-tla.mjs` overwrites a temporary copy of this module     *)
(* when validating live Rust NDJSON traces with TLC.                       *)
(***************************************************************************)
EXTENDS Sequences

Trace == <<
    [domain |-> "workspace", action |-> "CommitWritten", seq |-> 1, gen |-> 0, pinnedGen |-> 0, blob |-> "b1", chunks |-> {"c1", "c2"}, isRetention |-> FALSE],
    [domain |-> "workspace", action |-> "PublishIntent", intentSeq |-> 1, intentGen |-> 0, outcome |-> "published"],
    [domain |-> "workspace", action |-> "CommitWritten", seq |-> 2, gen |-> 1, pinnedGen |-> 0, blob |-> "b1", chunks |-> {}, isRetention |-> TRUE],
    [domain |-> "workspace", action |-> "PurgeBlob", blob |-> "b1", outcome |-> "purged", leakedChunks |-> 0, cacheInvalidated |-> TRUE],
    [domain |-> "restore",   action |-> "RestorePendingSet", gen |-> 0],
    [domain |-> "restore",   action |-> "ServeDenied"],
    [domain |-> "restore",   action |-> "LedgerRejected", reason |-> "stale"],
    [domain |-> "restore",   action |-> "LedgerApplied", oldGen |-> 0, newGen |-> 2, sameWorkspace |-> TRUE],
    [domain |-> "sync",      action |-> "PushHeadAccepted", scope |-> "s1", origin |-> "p1", seq |-> 1],
    [domain |-> "sync",      action |-> "PushHeadAccepted", scope |-> "s1", origin |-> "p1", seq |-> 2],
    [domain |-> "sync",      action |-> "PushHeadRejected", scope |-> "s1", origin |-> "p1", seq |-> 1],
    [domain |-> "sync",      action |-> "RevocationMerged", token |-> "t1"],
    [domain |-> "sync",      action |-> "CapabilityRejected", token |-> "t1", reason |-> "revoked"],
    [domain |-> "sync",      action |-> "RbsrPullCompleted", scope |-> "s1", generation |-> 2, resurrected |-> FALSE, crossScope |-> FALSE]
>>

=============================================================================
