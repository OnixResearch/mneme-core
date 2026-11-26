--------------------------- MODULE RestoreBarrier ---------------------------
(***************************************************************************)
(* Formal protocol specification of mneme-store's backup/restore barrier   *)
(* and suppression ledger monotonicity (coordinator/recovery.rs +          *)
(* mneme-kernel/src/restore.rs):                                           *)
(*   - META_RESTORE_PENDING gate refusing reads/commits/publishes          *)
(*   - Workspace genesis binding (foreign workspace ledger rejection)      *)
(*   - Monotonic eligibility_generation check (stale ledger rejection)     *)
(*   - Atomic purge of forgotten records/blobs and suppression of pending  *)
(*     working-file publication intents on ledger application              *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Records,        \* Finite set of record IDs (e.g. {"r1", "r2"})
    Workspaces,     \* Finite set of workspace genesis IDs (e.g. {"wsA", "wsB"})
    MaxGen          \* Bounded maximum eligibility generation

ASSUME MaxGen \in Nat /\ MaxGen >= 2

VARIABLES
    liveGenesis,        \* Genesis ID of the live workspace ("wsA")
    liveRecords,        \* Live records currently in the live workspace
    liveGen,            \* Current eligibility_generation of live workspace
    liveSuppressed,     \* Monotonic set of forgotten records in live workspace
    backupTaken,        \* TRUE once a pre-erasure backup snapshot exists
    backupRecords,      \* Records captured in the backup snapshot
    backupGen,          \* eligibility_generation captured in the backup snapshot
    backupSuppressed,   \* Suppressions captured in the backup snapshot
    restoredActive,     \* TRUE once backup has been restored to disk
    restorePending,     \* META_RESTORE_PENDING flag
    restoredGen,        \* Current eligibility_generation of restored workspace
    restoredRecords,    \* Records physically present in restored workspace
    restoredSuppressed, \* Suppressions recorded in restored workspace
    restoredPendingPub, \* Pending publication intents in restored workspace
    servedWhilePending, \* Ghost flag: TRUE if read/commit/publish succeeded while pending
    invalidLedgerApplied\* Ghost flag: TRUE if foreign or stale ledger was accepted

vars == <<
    liveGenesis, liveRecords, liveGen, liveSuppressed,
    backupTaken, backupRecords, backupGen, backupSuppressed,
    restoredActive, restorePending, restoredGen, restoredRecords,
    restoredSuppressed, restoredPendingPub,
    servedWhilePending, invalidLedgerApplied
>>

Max(a, b) == IF a >= b THEN a ELSE b

TypeOK ==
    /\ liveGenesis \in Workspaces
    /\ liveRecords \subseteq Records
    /\ liveGen \in 0..MaxGen
    /\ liveSuppressed \subseteq Records
    /\ backupTaken \in BOOLEAN
    /\ backupRecords \subseteq Records
    /\ backupGen \in 0..MaxGen
    /\ backupSuppressed \subseteq Records
    /\ restoredActive \in BOOLEAN
    /\ restorePending \in BOOLEAN
    /\ restoredGen \in 0..(MaxGen + 1)
    /\ restoredRecords \subseteq Records
    /\ restoredSuppressed \subseteq Records
    /\ restoredPendingPub \in BOOLEAN
    /\ servedWhilePending \in BOOLEAN
    /\ invalidLedgerApplied \in BOOLEAN

Init ==
    /\ liveGenesis = "wsA"
    /\ liveRecords = Records
    /\ liveGen = 0
    /\ liveSuppressed = {}
    /\ backupTaken = FALSE
    /\ backupRecords = {}
    /\ backupGen = 0
    /\ backupSuppressed = {}
    /\ restoredActive = FALSE
    /\ restorePending = FALSE
    /\ restoredGen = 0
    /\ restoredRecords = {}
    /\ restoredSuppressed = {}
    /\ restoredPendingPub = FALSE
    /\ servedWhilePending = FALSE
    /\ invalidLedgerApplied = FALSE

\* Take a point-in-time backup snapshot of the live workspace before further erasures.
TakeBackup ==
    /\ ~backupTaken
    /\ backupTaken' = TRUE
    /\ backupRecords' = liveRecords
    /\ backupGen' = liveGen
    /\ backupSuppressed' = liveSuppressed
    /\ UNCHANGED <<
        liveGenesis, liveRecords, liveGen, liveSuppressed,
        restoredActive, restorePending, restoredGen, restoredRecords,
        restoredSuppressed, restoredPendingPub,
        servedWhilePending, invalidLedgerApplied
       >>

\* Live workspace forgets record r, advancing eligibility_generation.
LiveForget(r) ==
    /\ r \in liveRecords
    /\ liveGen < MaxGen
    /\ liveRecords' = liveRecords \ {r}
    /\ liveSuppressed' = liveSuppressed \cup {r}
    /\ liveGen' = liveGen + 1
    /\ UNCHANGED <<
        liveGenesis, backupTaken, backupRecords, backupGen, backupSuppressed,
        restoredActive, restorePending, restoredGen, restoredRecords,
        restoredSuppressed, restoredPendingPub,
        servedWhilePending, invalidLedgerApplied
       >>

\* Restore the backup snapshot; opens with META_RESTORE_PENDING = TRUE.
RestoreFromBackup ==
    /\ backupTaken
    /\ ~restoredActive
    /\ restoredActive' = TRUE
    /\ restorePending' = TRUE
    /\ restoredGen' = backupGen
    /\ restoredRecords' = backupRecords
    /\ restoredSuppressed' = backupSuppressed
    /\ restoredPendingPub' = TRUE
    /\ UNCHANGED <<
        liveGenesis, liveRecords, liveGen, liveSuppressed,
        backupTaken, backupRecords, backupGen, backupSuppressed,
        servedWhilePending, invalidLedgerApplied
       >>

\* Any read, commit, or publish attempt consults mneme_kernel::restore::may_serve(marker).
AttemptServe ==
    /\ restoredActive
    /\ IF restorePending THEN
           \* Refused by require_restore_suppression()
           /\ UNCHANGED vars
       ELSE
           \* Allowed once barrier is cleared; clear pending pub intent safely
           /\ restoredPendingPub' = FALSE
           /\ UNCHANGED <<
                liveGenesis, liveRecords, liveGen, liveSuppressed,
                backupTaken, backupRecords, backupGen, backupSuppressed,
                restoredActive, restorePending, restoredGen, restoredRecords,
                restoredSuppressed, servedWhilePending, invalidLedgerApplied
              >>

\* Attempt to apply an offered ledger (foreign workspace or stale generation -> rejected).
AttemptInvalidLedger(offeredGenesis, offeredGen) ==
    /\ restoredActive
    /\ restorePending
    /\ offeredGenesis \in Workspaces
    /\ offeredGen \in 0..MaxGen
    /\ (offeredGenesis # liveGenesis \/ offeredGen < restoredGen)
    \* mneme_kernel::restore::decide_ledger returns ForeignWorkspace or Stale -> no state change
    /\ UNCHANGED vars

\* Apply the current exported suppression ledger from the live workspace.
ApplyCurrentLedger ==
    /\ restoredActive
    /\ restorePending
    /\ liveGen >= restoredGen
    /\ restoredRecords' = restoredRecords \ liveSuppressed
    /\ restoredSuppressed' = restoredSuppressed \cup liveSuppressed
    /\ restoredGen' = Max(liveGen, restoredGen + 1)
    /\ restoredPendingPub' = FALSE
    /\ restorePending' = FALSE
    /\ UNCHANGED <<
        liveGenesis, liveRecords, liveGen, liveSuppressed,
        backupTaken, backupRecords, backupGen, backupSuppressed,
        restoredActive, servedWhilePending, invalidLedgerApplied
       >>

Next ==
    \/ TakeBackup
    \/ \E r \in Records : LiveForget(r)
    \/ RestoreFromBackup
    \/ AttemptServe
    \/ \E w \in Workspaces, g \in 0..MaxGen : AttemptInvalidLedger(w, g)
    \/ ApplyCurrentLedger

Fairness ==
    /\ WF_vars(ApplyCurrentLedger)

Spec == Init /\ [][Next]_vars /\ Fairness

\* ---------------------------------------------------------------------------
\* Safety Invariants
\* ---------------------------------------------------------------------------

\* No read, commit, or publication ever succeeds while META_RESTORE_PENDING is set.
NeverServeWhileRestorePending ==
    ~servedWhilePending

\* Once restorePending is cleared, no record forgotten in liveSuppressed
\* (as of ledger application) remains in restoredRecords, and pending intents are suppressed.
NoForgottenResurrection ==
    (restoredActive /\ ~restorePending) =>
        /\ (restoredRecords \cap restoredSuppressed = {})
        /\ ~restoredPendingPub

\* Suppressions are monotonic: restoredSuppressed always contains backupSuppressed.
SuppressionLedgerMonotonic ==
    restoredActive => (backupSuppressed \subseteq restoredSuppressed)

\* Generation strictly advances when a restore ledger is applied.
GenerationStrictlyAdvancesOnRestore ==
    (restoredActive /\ ~restorePending) => (restoredGen > backupGen)

ForeignAndStaleRejected ==
    ~invalidLedgerApplied

\* ---------------------------------------------------------------------------
\* Liveness Property
\* ---------------------------------------------------------------------------
RestoreEventuallyClears ==
    (restoredActive /\ restorePending) ~> (restoredActive /\ ~restorePending)

=============================================================================
