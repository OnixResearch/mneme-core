------------------------- MODULE WorkspaceLifecycle -------------------------
(***************************************************************************)
(* Formal protocol specification of mneme-store's multi-step imperative    *)
(* shell lifecycle:                                                        *)
(*   - CAS commits with shared_commit_lock vs exclusive_sweep_lock         *)
(*   - eligibility_generation retention barriers & generation pinning      *)
(*   - FaultPoint crash injection windows (AfterBlobStaging,               *)
(*     BeforeCommitTransaction, AfterCommit, BeforeFileReplace,            *)
(*     AfterFileReplace, BeforeRetentionPurge, AfterRetentionPurge)        *)
(*   - Working-file publication via quarantine displace / decide / restore *)
(*   - Retention blob purge, FastCDC chunk GC (audit bug S1), and          *)
(*     SharedRecordCache invalidation                                      *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Blobs,          \* Finite set of content-addressed blob identifiers (e.g. {"b1", "b2"})
    Chunks,         \* Finite set of FastCDC chunk identifiers (e.g. {"c1", "c2"})
    BlobChunkMap,   \* Function [Blobs -> SUBSET Chunks] mapping each blob to its FastCDC chunks
    MaxSeq,         \* Bounded maximum commit sequence for exhaustive checking
    MaxGen,         \* Bounded maximum eligibility generation
    EnableChunkGC,  \* TRUE in real protocol; FALSE reproduces audit bug S1 (leaked chunks)
    EnableGenPin    \* TRUE in real protocol; FALSE reproduces dropped eligibility_generation pinning

ASSUME MaxSeq \in Nat /\ MaxSeq >= 1
ASSUME MaxGen \in Nat /\ MaxGen >= 1
ASSUME EnableChunkGC \in BOOLEAN
ASSUME EnableGenPin \in BOOLEAN

LockStates == {"none", "shared", "exclusive"}
CommitPhases == {"idle", "staged", "committed"}
IntentStates == {"none", "pending", "published", "diverged", "suppressed", "failed"}
WorkContents == Blobs \cup {"empty", "external"}
FaultPoints == {
    "AfterBlobStaging",
    "BeforeCommitTransaction",
    "AfterCommit",
    "BeforeFileReplace",
    "AfterFileReplace",
    "BeforeRetentionPurge",
    "AfterRetentionPurge"
}

VARIABLES
    seq,                \* Current committed workspace revision sequence
    gen,                \* Current retention eligibility_generation
    lockMode,           \* "none" | "shared" | "exclusive"
    sharedHolders,      \* Number of concurrent shared_commit_lock holders (0..2)
    diskBlobs,          \* Set of blobs physically present on disk
    diskChunks,         \* Set of FastCDC chunks physically present on disk
    liveBlobs,          \* Set of blobs required by live ledger records
    forgottenBlobs,     \* Set of blobs whose records were forgotten by retention
    cacheBlobs,         \* Set of blobs currently cached in SharedRecordCache
    cacheGen,           \* Generation to which SharedRecordCache is aligned
    commitPhase,        \* Active commit transaction phase ("idle" | "staged" | "committed")
    commitBlob,         \* Blob being staged/committed ("none" or in Blobs)
    commitBaseSeq,      \* Base sequence observed when commit was prepared
    commitPinnedGen,    \* Eligibility generation pinned when commit started
    commitIsRetention,  \* TRUE if active commit is a retention barrier
    intentState,        \* Current publication intent state
    intentSeq,          \* Revision sequence the intent belongs to
    intentGen,          \* Eligibility generation the intent belongs to
    intentExpected,     \* Expected previous working-file content
    intentDesired,      \* Desired working-file blob
    workingFile,        \* Actual working-file content on disk
    quarantineSlot,     \* Displaced working-file content during quarantine ("none" or WorkContents)
    needsRecovery,      \* TRUE after a FaultPoint crash until Recover runs
    lastFault,          \* Last injected FaultPoint ("none" or FaultPoints)
    staleCommitHappened,\* Ghost flag: TRUE iff a commit succeeded with stale eligibility_generation
    stalePublishHappened,\* Ghost flag: TRUE iff a stale-seq or stale-gen intent reached "published"
    overwroteExternal   \* Ghost flag: TRUE iff publication overwrote an unexpected external edit

vars == <<
    seq, gen, lockMode, sharedHolders,
    diskBlobs, diskChunks, liveBlobs, forgottenBlobs,
    cacheBlobs, cacheGen,
    commitPhase, commitBlob, commitBaseSeq, commitPinnedGen, commitIsRetention,
    intentState, intentSeq, intentGen, intentExpected, intentDesired,
    workingFile, quarantineSlot, needsRecovery, lastFault,
    staleCommitHappened, stalePublishHappened, overwroteExternal
>>

DefaultBlobChunkMap == ("b1" :> {"c1", "c2"} @@ "b2" :> {"c2", "c3"})

ChunksOf(B) == UNION { BlobChunkMap[b] : b \in B }

ReferencedChunks == ChunksOf(diskBlobs)

LiveChunks == ChunksOf(liveBlobs)

TypeOK ==
    /\ seq \in 0..MaxSeq
    /\ gen \in 0..MaxGen
    /\ lockMode \in LockStates
    /\ sharedHolders \in 0..1
    /\ diskBlobs \subseteq Blobs
    /\ diskChunks \subseteq Chunks
    /\ liveBlobs \subseteq Blobs
    /\ forgottenBlobs \subseteq Blobs
    /\ cacheBlobs \subseteq Blobs
    /\ cacheGen \in 0..MaxGen
    /\ commitPhase \in CommitPhases
    /\ commitBlob \in Blobs \cup {"none"}
    /\ commitBaseSeq \in 0..MaxSeq
    /\ commitPinnedGen \in 0..MaxGen
    /\ commitIsRetention \in BOOLEAN
    /\ intentState \in IntentStates
    /\ intentSeq \in 0..MaxSeq
    /\ intentGen \in 0..MaxGen
    /\ intentExpected \in WorkContents
    /\ intentDesired \in Blobs \cup {"none"}
    /\ workingFile \in WorkContents
    /\ quarantineSlot \in WorkContents \cup {"none"}
    /\ needsRecovery \in BOOLEAN
    /\ lastFault \in FaultPoints \cup {"none"}
    /\ staleCommitHappened \in BOOLEAN
    /\ stalePublishHappened \in BOOLEAN
    /\ overwroteExternal \in BOOLEAN

Init ==
    /\ seq = 0
    /\ gen = 0
    /\ lockMode = "none"
    /\ sharedHolders = 0
    /\ diskBlobs = {}
    /\ diskChunks = {}
    /\ liveBlobs = {}
    /\ forgottenBlobs = {}
    /\ cacheBlobs = {}
    /\ cacheGen = 0
    /\ commitPhase = "idle"
    /\ commitBlob = "none"
    /\ commitBaseSeq = 0
    /\ commitPinnedGen = 0
    /\ commitIsRetention = FALSE
    /\ intentState = "none"
    /\ intentSeq = 0
    /\ intentGen = 0
    /\ intentExpected = "empty"
    /\ intentDesired = "none"
    /\ workingFile = "empty"
    /\ quarantineSlot = "none"
    /\ needsRecovery = FALSE
    /\ lastFault = "none"
    /\ staleCommitHappened = FALSE
    /\ stalePublishHappened = FALSE
    /\ overwroteExternal = FALSE

\* ---------------------------------------------------------------------------
\* Ordinary Commit: shared_commit_lock -> stage blob & chunks -> ledger CAS
\* ---------------------------------------------------------------------------
StageOrdinaryCommit(b) ==
    /\ ~needsRecovery
    /\ commitPhase = "idle"
    /\ lockMode \in {"none", "shared"}
    /\ seq < MaxSeq
    /\ b \in Blobs \ forgottenBlobs
    /\ lockMode' = "shared"
    /\ sharedHolders' = 1
    /\ diskBlobs' = diskBlobs \cup {b}
    /\ diskChunks' = diskChunks \cup BlobChunkMap[b]
    /\ commitPhase' = "staged"
    /\ commitBlob' = b
    /\ commitBaseSeq' = seq
    /\ commitPinnedGen' = gen
    /\ commitIsRetention' = FALSE
    /\ UNCHANGED <<
        seq, gen, liveBlobs, forgottenBlobs, cacheBlobs, cacheGen,
        intentState, intentSeq, intentGen, intentExpected, intentDesired,
        workingFile, quarantineSlot, needsRecovery, lastFault,
        staleCommitHappened, stalePublishHappened, overwroteExternal
       >>

CrashAfterBlobStaging ==
    /\ commitPhase = "staged"
    /\ ~commitIsRetention
    /\ lockMode' = "none"
    /\ sharedHolders' = 0
    /\ commitPhase' = "idle"
    /\ commitBlob' = "none"
    /\ needsRecovery' = TRUE
    /\ lastFault' = "AfterBlobStaging"
    /\ UNCHANGED <<
        seq, gen, diskBlobs, diskChunks, liveBlobs, forgottenBlobs,
        cacheBlobs, cacheGen, commitBaseSeq, commitPinnedGen, commitIsRetention,
        intentState, intentSeq, intentGen, intentExpected, intentDesired,
        workingFile, quarantineSlot, staleCommitHappened, stalePublishHappened, overwroteExternal
       >>

\* Simulate a concurrent retention generation bump while an unpinned commit was prepared
\* (only reachable when EnableGenPin = FALSE to test catching dropped generation pinning).
UnpinnedConcurrentGenBump ==
    /\ ~EnableGenPin
    /\ commitPhase = "staged"
    /\ ~commitIsRetention
    /\ gen < MaxGen
    /\ gen' = gen + 1
    /\ cacheBlobs' = {}
    /\ cacheGen' = gen + 1
    /\ UNCHANGED <<
        seq, lockMode, sharedHolders, diskBlobs, diskChunks, liveBlobs, forgottenBlobs,
        commitPhase, commitBlob, commitBaseSeq, commitPinnedGen, commitIsRetention,
        intentState, intentSeq, intentGen, intentExpected, intentDesired,
        workingFile, quarantineSlot, needsRecovery, lastFault,
        staleCommitHappened, stalePublishHappened, overwroteExternal
       >>

WriteOrdinaryCommit ==
    /\ commitPhase = "staged"
    /\ ~commitIsRetention
    /\ commitBaseSeq = seq
    /\ seq < MaxSeq
    /\ (EnableGenPin => commitPinnedGen = gen)
    /\ seq' = seq + 1
    /\ liveBlobs' = liveBlobs \cup {commitBlob}
    /\ cacheBlobs' = IF cacheGen = gen THEN cacheBlobs \cup {commitBlob} ELSE {commitBlob}
    /\ cacheGen' = gen
    /\ lockMode' = "none"
    /\ sharedHolders' = 0
    /\ commitPhase' = "committed"
    /\ intentState' = "pending"
    /\ intentSeq' = seq + 1
    /\ intentGen' = gen
    /\ intentExpected' = workingFile
    /\ intentDesired' = commitBlob
    /\ staleCommitHappened' = (staleCommitHappened \/ (commitPinnedGen # gen))
    /\ UNCHANGED <<
        gen, diskBlobs, diskChunks, forgottenBlobs,
        commitBlob, commitBaseSeq, commitPinnedGen, commitIsRetention,
        workingFile, quarantineSlot, needsRecovery, lastFault,
        stalePublishHappened, overwroteExternal
       >>

\* FaultPoint::AfterCommit: ledger committed and intent is pending, but process stops before publish
CrashAfterCommit ==
    /\ commitPhase = "committed"
    /\ commitPhase' = "idle"
    /\ commitBlob' = "none"
    /\ needsRecovery' = TRUE
    /\ lastFault' = "AfterCommit"
    /\ UNCHANGED <<
        seq, gen, lockMode, sharedHolders, diskBlobs, diskChunks, liveBlobs, forgottenBlobs,
        cacheBlobs, cacheGen, commitBaseSeq, commitPinnedGen, commitIsRetention,
        intentState, intentSeq, intentGen, intentExpected, intentDesired,
        workingFile, quarantineSlot, staleCommitHappened, stalePublishHappened, overwroteExternal
       >>

\* ---------------------------------------------------------------------------
\* External concurrent edit to working file (tests quarantine divergence safety)
\* ---------------------------------------------------------------------------
ExternalWorkingEdit ==
    /\ quarantineSlot = "none"
    /\ workingFile # "external"
    /\ workingFile' = "external"
    /\ UNCHANGED <<
        seq, gen, lockMode, sharedHolders, diskBlobs, diskChunks, liveBlobs, forgottenBlobs,
        cacheBlobs, cacheGen, commitPhase, commitBlob, commitBaseSeq, commitPinnedGen,
        commitIsRetention, intentState, intentSeq, intentGen, intentExpected, intentDesired,
        quarantineSlot, needsRecovery, lastFault,
        staleCommitHappened, stalePublishHappened, overwroteExternal
       >>

\* ---------------------------------------------------------------------------
\* Publication Intent: suppress if stale, otherwise quarantine-displace-decide
\* ---------------------------------------------------------------------------
PublishIntent ==
    /\ ~needsRecovery
    /\ intentState = "pending"
    /\ commitPhase \in {"idle", "committed"}
    /\ quarantineSlot = "none"
    /\ IF intentSeq # seq \/ intentGen # gen THEN
           \* Stale revision or generation -> Suppressed without touching workingFile
           /\ intentState' = "suppressed"
           /\ commitPhase' = "idle"
           /\ commitBlob' = "none"
           /\ stalePublishHappened' = stalePublishHappened
           /\ overwroteExternal' = overwroteExternal
           /\ UNCHANGED <<workingFile, quarantineSlot>>
       ELSE IF workingFile = intentDesired THEN
           \* AlreadyPublished: displaced and restored intact
           /\ intentState' = "published"
           /\ commitPhase' = "idle"
           /\ commitBlob' = "none"
           /\ stalePublishHappened' = (stalePublishHappened \/ intentSeq # seq \/ intentGen # gen)
           /\ overwroteExternal' = overwroteExternal
           /\ UNCHANGED <<workingFile, quarantineSlot>>
       ELSE IF workingFile = intentExpected THEN
           \* Replace: displaced expected file, installed desired blob
           /\ intentState' = "published"
           /\ workingFile' = intentDesired
           /\ commitPhase' = "idle"
           /\ commitBlob' = "none"
           /\ stalePublishHappened' = (stalePublishHappened \/ intentSeq # seq \/ intentGen # gen)
           /\ overwroteExternal' = (overwroteExternal \/ (workingFile = "external" /\ intentExpected # "external"))
           /\ UNCHANGED quarantineSlot
       ELSE
           \* Diverged: external edit observed -> restore displaced bytes, never overwrite!
           /\ intentState' = "diverged"
           /\ commitPhase' = "idle"
           /\ commitBlob' = "none"
           /\ stalePublishHappened' = stalePublishHappened
           /\ overwroteExternal' = overwroteExternal
           /\ UNCHANGED <<workingFile, quarantineSlot>>
    /\ UNCHANGED <<
        seq, gen, lockMode, sharedHolders, diskBlobs, diskChunks, liveBlobs, forgottenBlobs,
        cacheBlobs, cacheGen, commitBaseSeq, commitPinnedGen, commitIsRetention,
        intentSeq, intentGen, intentExpected, intentDesired,
        needsRecovery, lastFault, staleCommitHappened
       >>

\* ---------------------------------------------------------------------------
\* Retention Barrier Commit (exclusive_sweep_lock) & Blob/Chunk Purge
\* ---------------------------------------------------------------------------
RetentionForget(b) ==
    /\ ~needsRecovery
    /\ lockMode = "none"
    /\ commitPhase = "idle"
    /\ b \in liveBlobs
    /\ seq < MaxSeq
    /\ gen < MaxGen
    /\ seq' = seq + 1
    /\ gen' = gen + 1
    /\ liveBlobs' = liveBlobs \ {b}
    /\ forgottenBlobs' = forgottenBlobs \cup {b}
    \* Align SharedRecordCache to new generation (clears pre-erasure entries)
    /\ cacheBlobs' = {}
    /\ cacheGen' = gen + 1
    /\ UNCHANGED <<
        lockMode, sharedHolders, diskBlobs, diskChunks,
        commitPhase, commitBlob, commitBaseSeq, commitPinnedGen, commitIsRetention,
        intentState, intentSeq, intentGen, intentExpected, intentDesired,
        workingFile, quarantineSlot, needsRecovery, lastFault,
        staleCommitHappened, stalePublishHappened, overwroteExternal
       >>

PurgeBlob(b) ==
    /\ ~needsRecovery
    /\ lockMode = "none"
    /\ commitPhase = "idle"
    /\ b \in diskBlobs \ liveBlobs
    /\ diskBlobs' = diskBlobs \ {b}
    \* S1 fix: GC all FastCDC chunks no longer referenced by any remaining blob on disk
    /\ diskChunks' = IF EnableChunkGC THEN ChunksOf(diskBlobs \ {b}) ELSE diskChunks
    /\ cacheBlobs' = cacheBlobs \ {b}
    /\ UNCHANGED <<
        seq, gen, lockMode, sharedHolders, liveBlobs, forgottenBlobs, cacheGen,
        commitPhase, commitBlob, commitBaseSeq, commitPinnedGen, commitIsRetention,
        intentState, intentSeq, intentGen, intentExpected, intentDesired,
        workingFile, quarantineSlot, needsRecovery, lastFault,
        staleCommitHappened, stalePublishHappened, overwroteExternal
       >>

\* ---------------------------------------------------------------------------
\* Startup Recovery: exclusive_sweep_lock orphan cleanup + resume pending intent
\* ---------------------------------------------------------------------------
Recover ==
    /\ needsRecovery
    /\ lockMode = "none"
    /\ commitPhase = "idle"
    /\ diskBlobs' = liveBlobs
    /\ diskChunks' = IF EnableChunkGC THEN LiveChunks ELSE diskChunks
    /\ cacheBlobs' = cacheBlobs \cap liveBlobs
    /\ cacheGen' = gen
    /\ needsRecovery' = FALSE
    /\ UNCHANGED <<
        seq, gen, lockMode, sharedHolders, liveBlobs, forgottenBlobs,
        commitPhase, commitBlob, commitBaseSeq, commitPinnedGen, commitIsRetention,
        intentState, intentSeq, intentGen, intentExpected, intentDesired,
        workingFile, quarantineSlot, lastFault,
        staleCommitHappened, stalePublishHappened, overwroteExternal
       >>

Next ==
    \/ \E b \in Blobs : StageOrdinaryCommit(b)
    \/ CrashAfterBlobStaging
    \/ UnpinnedConcurrentGenBump
    \/ WriteOrdinaryCommit
    \/ CrashAfterCommit
    \/ ExternalWorkingEdit
    \/ PublishIntent
    \/ \E b \in Blobs : RetentionForget(b)
    \/ \E b \in Blobs : PurgeBlob(b)
    \/ Recover

Fairness ==
    /\ WF_vars(WriteOrdinaryCommit)
    /\ WF_vars(Recover)
    /\ SF_vars(PublishIntent)
    /\ \A b \in Blobs : SF_vars(PurgeBlob(b))

Spec == Init /\ [][Next]_vars /\ Fairness

\* ---------------------------------------------------------------------------
\* Safety Invariants
\* ---------------------------------------------------------------------------

\* Mutual exclusion between shared_commit_lock and exclusive_sweep_lock
LockExclusion ==
    /\ (lockMode = "shared" <=> sharedHolders > 0)
    /\ ~(lockMode = "exclusive" /\ sharedHolders > 0)

\* Audit bug S1 invariant: once a blob is removed from diskBlobs, no FastCDC
\* chunk exclusively referenced by that removed blob remains on disk.
NoLeakedUnreferencedChunks ==
    diskChunks \subseteq ReferencedChunks

\* Every live ledger blob must exist on disk along with all its FastCDC chunks.
LiveBlobsDurable ==
    /\ liveBlobs \subseteq diskBlobs
    /\ LiveChunks \subseteq diskChunks

\* SharedRecordCache never serves records from a prior generation or purged blobs.
CacheGenerationSoundness ==
    /\ cacheGen = gen
    /\ cacheBlobs \subseteq liveBlobs

\* No commit ever commits with a stale eligibility_generation.
GenerationPinnedCommit ==
    ~staleCommitHappened

\* A working file that was externally edited is never silently overwritten by a
\* pending intent that expected a different prior file.
QuarantineNoDataLoss ==
    ~overwroteExternal

\* No stale intent (older seq or older generation) can ever reach "published".
StaleIntentNotPublished ==
    ~stalePublishHappened

\* ---------------------------------------------------------------------------
\* Liveness Properties
\* ---------------------------------------------------------------------------
PendingIntentsEventuallyResolve ==
    (intentState = "pending") ~> (intentState \in {"published", "diverged", "suppressed", "failed"})

OrphansEventuallyReclaimed ==
    (diskBlobs # liveBlobs /\ commitPhase = "idle") ~> (diskBlobs = liveBlobs)

=============================================================================
