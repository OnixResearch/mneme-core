----------------------------- MODULE TraceSpec -----------------------------
(***************************************************************************)
(* Model-based trace validation specification (Davis et al., PVLDB 2020)   *)
(* checking NDJSON state-transition traces emitted by `mneme-store` and    *)
(* `mneme-sync` under `#[cfg(feature = "trace-spec")]` against the formal  *)
(* safety invariants of WorkspaceLifecycle, RestoreBarrier, and            *)
(* SyncConvergence.                                                        *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC, TraceData

VARIABLES
    idx,                \* Current 1-based step index into Trace (1..Len(Trace)+1)
    wsSeq,              \* Workspace committed sequence
    wsGen,              \* Workspace eligibility_generation
    liveBlobs,          \* Live blobs in ledger
    diskBlobs,          \* Blobs physically on disk
    forgottenBlobs,     \* Forgotten blobs
    restorePending,     \* META_RESTORE_PENDING state
    pushHighWater,      \* Map from <<scope, origin>> -> high-water seq
    revokedTokens,      \* G-Set of merged revoked token IDs
    violation           \* "none" if valid, otherwise diagnostic string

vars == <<
    idx, wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs,
    restorePending, pushHighWater, revokedTokens, violation
>>

Init ==
    /\ idx = 1
    /\ wsSeq = 0
    /\ wsGen = 0
    /\ liveBlobs = {}
    /\ diskBlobs = {}
    /\ forgottenBlobs = {}
    /\ restorePending = FALSE
    /\ pushHighWater = [k \in {} |-> 0]
    /\ revokedTokens = {}
    /\ violation = "none"

LookupHW(m, k) == IF k \in DOMAIN m THEN m[k] ELSE 0

PutHW(m, k, v) == [x \in (DOMAIN m \cup {k}) |-> IF x = k THEN v ELSE m[x]]

StepWorkspace(ev) ==
    CASE ev.action = "CommitWritten" ->
            IF restorePending THEN
                /\ violation' = "commit_while_restore_pending"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE IF ev.seq <= wsSeq THEN
                /\ violation' = "non_monotonic_commit_sequence"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE IF ~ev.isRetention /\ ev.pinnedGen # wsGen THEN
                /\ violation' = "dropped_eligibility_generation_pinning"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE IF ev.isRetention /\ ev.gen <= wsGen THEN
                /\ violation' = "retention_did_not_advance_generation"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE IF ~ev.isRetention /\ ev.blob \in forgottenBlobs THEN
                /\ violation' = "resurrected_forgotten_blob"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE
                /\ wsSeq' = ev.seq
                /\ wsGen' = ev.gen
                /\ liveBlobs' = IF ev.isRetention THEN liveBlobs \ {ev.blob} ELSE liveBlobs \cup {ev.blob}
                /\ diskBlobs' = IF ev.isRetention THEN diskBlobs ELSE diskBlobs \cup {ev.blob}
                /\ forgottenBlobs' = IF ev.isRetention THEN forgottenBlobs \cup {ev.blob} ELSE forgottenBlobs
                /\ violation' = "none"
                /\ UNCHANGED <<restorePending, pushHighWater, revokedTokens>>
      [] ev.action = "PublishIntent" ->
            IF restorePending THEN
                /\ violation' = "publish_while_restore_pending"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE IF ev.outcome = "published" /\ (ev.intentSeq # wsSeq \/ ev.intentGen # wsGen) THEN
                /\ violation' = "stale_intent_published"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE
                /\ violation' = "none"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
      [] ev.action = "PurgeBlob" ->
            IF ev.outcome = "purged" /\ ev.leakedChunks > 0 THEN
                /\ violation' = "s1_unpurged_fastcdc_chunks"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE IF ev.outcome = "purged" /\ ~ev.cacheInvalidated THEN
                /\ violation' = "purged_blob_not_invalidated_in_cache"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE IF ev.outcome = "purged" /\ ev.blob \in liveBlobs THEN
                /\ violation' = "purged_live_required_blob"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE
                /\ diskBlobs' = IF ev.outcome = "purged" THEN diskBlobs \ {ev.blob} ELSE diskBlobs
                /\ violation' = "none"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
      [] ev.action = "CommitFault" ->
            /\ violation' = "none"
            /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
      [] ev.action = "Recover" ->
            /\ diskBlobs' = liveBlobs
            /\ violation' = "none"
            /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
      [] OTHER ->
            /\ violation' = "unknown_workspace_action"
            /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>

StepRestore(ev) ==
    CASE ev.action = "RestorePendingSet" ->
            /\ restorePending' = TRUE
            /\ wsGen' = ev.gen
            /\ violation' = "none"
            /\ UNCHANGED <<wsSeq, liveBlobs, diskBlobs, forgottenBlobs, pushHighWater, revokedTokens>>
      [] ev.action = "ServeDenied" ->
            /\ violation' = "none"
            /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
      [] ev.action = "ServeAllowed" ->
            /\ violation' = IF restorePending THEN "served_while_restore_pending" ELSE "none"
            /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
      [] ev.action = "LedgerRejected" ->
            /\ violation' = "none"
            /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
      [] ev.action = "LedgerApplied" ->
            IF ~restorePending THEN
                /\ violation' = "ledger_applied_when_not_pending"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE IF ~ev.sameWorkspace THEN
                /\ violation' = "foreign_workspace_ledger_applied"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE IF ev.newGen <= ev.oldGen THEN
                /\ violation' = "restore_generation_did_not_advance"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE
                /\ restorePending' = FALSE
                /\ wsGen' = ev.newGen
                /\ violation' = "none"
                /\ UNCHANGED <<wsSeq, liveBlobs, diskBlobs, forgottenBlobs, pushHighWater, revokedTokens>>
      [] OTHER ->
            /\ violation' = "unknown_restore_action"
            /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>

StepSync(ev) ==
    CASE ev.action = "PushHeadAccepted" ->
            LET k == <<ev.scope, ev.origin>>
                prev == LookupHW(pushHighWater, k)
            IN IF ev.seq <= prev THEN
                   /\ violation' = "stale_or_rollback_push_head_accepted"
                   /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
               ELSE
                   /\ pushHighWater' = PutHW(pushHighWater, k, ev.seq)
                   /\ violation' = "none"
                   /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, revokedTokens>>
      [] ev.action = "PushHeadRejected" ->
            /\ violation' = "none"
            /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
      [] ev.action = "RevocationMerged" ->
            /\ revokedTokens' = revokedTokens \cup {ev.token}
            /\ violation' = "none"
            /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater>>
      [] ev.action = "CapabilityAccepted" ->
            IF ev.token \in revokedTokens THEN
                /\ violation' = "revoked_capability_accepted_after_merge"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE
                /\ violation' = "none"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
      [] ev.action = "CapabilityRejected" ->
            /\ violation' = "none"
            /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
      [] ev.action = "ScopeDenied" ->
            /\ violation' = "none"
            /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
      [] ev.action = "RbsrPullCompleted" ->
            IF ev.resurrected THEN
                /\ violation' = "rbsr_resurrected_forgotten_record"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE IF ev.crossScope THEN
                /\ violation' = "rbsr_cross_scope_leakage"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
            ELSE
                /\ violation' = "none"
                /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
      [] OTHER ->
            /\ violation' = "unknown_sync_action"
            /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>

Step ==
    /\ idx <= Len(Trace)
    /\ LET ev == Trace[idx]
       IN /\ CASE ev.domain = "workspace" -> StepWorkspace(ev)
               [] ev.domain = "restore"   -> StepRestore(ev)
               [] ev.domain = "sync"      -> StepSync(ev)
               [] OTHER                   -> /\ violation' = "unknown_domain"
                                             /\ UNCHANGED <<wsSeq, wsGen, liveBlobs, diskBlobs, forgottenBlobs, restorePending, pushHighWater, revokedTokens>>
          /\ idx' = idx + 1

Done ==
    /\ idx > Len(Trace)
    /\ UNCHANGED vars

Next == Step \/ Done

Spec == Init /\ [][Next]_vars /\ WF_vars(Step)

TraceValid == violation = "none"

TraceCompleted == <>(idx > Len(Trace))

=============================================================================
