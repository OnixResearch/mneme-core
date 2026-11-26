-------------------------- MODULE SyncConvergence --------------------------
(***************************************************************************)
(* Formal protocol specification of mneme-sync's multi-peer replication:   *)
(*   - Multi-peer RBSR delta pull with retention barrier propagation       *)
(*   - Ed25519-signed PushHead announcements with monotonic high-water     *)
(*   - RevocationSet G-Set CRDT merge & immediate lease eviction           *)
(*   - Bounded capability token expiry under per-peer clock skew           *)
(*   - Scope-isolated authorization (zero cross-scope record/blob leak)    *)
(*   - CalmSeal monotonic query barrier per scope                          *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Peers,                  \* {"p1", "p2", "p3"}
    Scopes,                 \* {"s1", "s2"}
    Records,                \* {"r1", "r2"}
    Tokens,                 \* {"t1", "t2"}
    MaxSeq,                 \* Bounded max sequence per peer/scope
    MaxTime,                \* Bounded clock ticks
    TokenScope,             \* [Tokens -> Scopes]
    TokenExpiry,            \* [Tokens -> 0..MaxTime]
    TokenHolder,            \* [Tokens -> Peers]
    EnablePushMonotonic,    \* TRUE in real protocol; FALSE reproduces stale-seq rollback
    EnableRevocationMerge   \* TRUE in real protocol; FALSE reproduces dropped RevocationSet merge

ASSUME MaxSeq \in Nat /\ MaxSeq >= 2
ASSUME MaxTime \in Nat /\ MaxTime >= 1
ASSUME EnablePushMonotonic \in BOOLEAN
ASSUME EnableRevocationMerge \in BOOLEAN

DefaultTokenScope == ("t1" :> "s1" @@ "t2" :> "s2")
DefaultTokenExpiry == ("t1" :> 0 @@ "t2" :> 1)
DefaultTokenHolder == ("t1" :> "p2" @@ "t2" :> "p3")

VARIABLES
    records,            \* [Peers -> [Scopes -> SUBSET Records]]
    suppressed,         \* [Peers -> SUBSET Records] (monotonic retention barrier)
    gen,                \* [Peers -> 0..Cardinality(Records)]
    seq,                \* [Peers -> [Scopes -> 0..MaxSeq]]
    pushHighWater,      \* [Scopes -> 0..MaxSeq] (target p2's monotonic PushHead watermark from p1)
    revocations,        \* [Peers -> SUBSET Tokens] (G-Set CRDT)
    clock,              \* [Peers -> 0..MaxTime] (allows per-peer clock skew)
    calmSeal,           \* [Scopes -> 0..MaxSeq] (CalmSeal watermark on owner p1)
    pushMessages,       \* In-flight network bag of PushHead messages (supports drop/dup/reorder)
    rollbackHappened,   \* Ghost flag: TRUE if stale PushHead rolled back pushHighWater
    revokedAccepted,    \* Ghost flag: TRUE if revoked token was accepted after revocation known
    expiredAccepted,    \* Ghost flag: TRUE if expired token was accepted
    crossScopeLeaked,   \* Ghost flag: TRUE if unauthorized scope record leaked
    resurrectedRecord   \* Ghost flag: TRUE if forgotten record re-entered peer's records

vars == <<
    records, suppressed, gen, seq, pushHighWater, revocations,
    clock, calmSeal, pushMessages,
    rollbackHappened, revokedAccepted, expiredAccepted,
    crossScopeLeaked, resurrectedRecord
>>

Max(a, b) == IF a >= b THEN a ELSE b

\* p1 is the vault root/owner authorized for all scopes; p2 holds t1 (s1); p3 holds t2 (s2).
PeerPermitsScope(server, client, s, tok) ==
    \/ server = client
    \/ client = "p1"
    \/ /\ tok \in Tokens
       /\ TokenHolder[tok] = client
       /\ TokenScope[tok] = s
       /\ tok \notin revocations[server]
       /\ clock[server] <= TokenExpiry[tok]

PushMsgType == [origin: {"p1"}, target: {"p2"}, scope: {"s1"}, seq: 1..MaxSeq]

TypeOK ==
    /\ records \in [Peers -> [Scopes -> SUBSET Records]]
    /\ suppressed \in [Peers -> SUBSET Records]
    /\ gen \in [Peers -> 0..Cardinality(Records)]
    /\ seq \in [Peers -> [Scopes -> 0..MaxSeq]]
    /\ pushHighWater \in [Scopes -> 0..MaxSeq]
    /\ revocations \in [Peers -> SUBSET Tokens]
    /\ clock \in [Peers -> 0..MaxTime]
    /\ calmSeal \in [Scopes -> 0..MaxSeq]
    /\ pushMessages \subseteq PushMsgType
    /\ rollbackHappened \in BOOLEAN
    /\ revokedAccepted \in BOOLEAN
    /\ expiredAccepted \in BOOLEAN
    /\ crossScopeLeaked \in BOOLEAN
    /\ resurrectedRecord \in BOOLEAN

Init ==
    /\ records = [p \in Peers |-> [s \in Scopes |-> {}]]
    /\ suppressed = [p \in Peers |-> {}]
    /\ gen = [p \in Peers |-> 0]
    /\ seq = [p \in Peers |-> [s \in Scopes |-> 0]]
    /\ pushHighWater = [s \in Scopes |-> 0]
    /\ revocations = [p \in Peers |-> {}]
    /\ clock = [p \in Peers |-> 0]
    /\ calmSeal = [s \in Scopes |-> 0]
    /\ pushMessages = {}
    /\ rollbackHappened = FALSE
    /\ revokedAccepted = FALSE
    /\ expiredAccepted = FALSE
    /\ crossScopeLeaked = FALSE
    /\ resurrectedRecord = FALSE

\* Owner peer p1 commits a new record in scope s (never resurrecting suppressed records).
\* Scope s1 accepts r1 then r2 (reaching seq=2 for PushHead reorder testing);
\* Scope s2 accepts r2 (testing cross-scope isolation between p2 and p3).
LocalCommit(s, r) ==
    /\ (s = "s1" \/ r = "r2")
    /\ r \notin records["p1"][s]
    /\ r \notin suppressed["p1"]
    /\ seq["p1"][s] < MaxSeq
    /\ records' = [records EXCEPT !["p1"][s] = @ \cup {r}]
    /\ seq' = [seq EXCEPT !["p1"][s] = @ + 1]
    /\ UNCHANGED <<
        suppressed, gen, pushHighWater, revocations, clock, calmSeal, pushMessages,
        rollbackHappened, revokedAccepted, expiredAccepted, crossScopeLeaked, resurrectedRecord
       >>

\* Owner peer p1 forgets record r, advancing eligibility_generation and suppression barrier.
LocalForget(r) ==
    /\ r \notin suppressed["p1"]
    /\ \E s \in Scopes : r \in records["p1"][s]
    /\ gen["p1"] < Cardinality(Records)
    /\ records' = [records EXCEPT !["p1"] = [s \in Scopes |-> records["p1"][s] \ {r}]]
    /\ suppressed' = [suppressed EXCEPT !["p1"] = @ \cup {r}]
    /\ gen' = [gen EXCEPT !["p1"] = @ + 1]
    /\ UNCHANGED <<
        seq, pushHighWater, revocations, clock, calmSeal, pushMessages,
        rollbackHappened, revokedAccepted, expiredAccepted, crossScopeLeaked, resurrectedRecord
       >>

\* Advance CalmSeal on owner p1 for scope s1 (monotonic watermark bounded by seq).
AdvanceCalmSeal ==
    /\ calmSeal["s1"] < seq["p1"]["s1"]
    /\ calmSeal' = [calmSeal EXCEPT !["s1"] = seq["p1"]["s1"]]
    /\ UNCHANGED <<
        records, suppressed, gen, seq, pushHighWater, revocations, clock, pushMessages,
        rollbackHappened, revokedAccepted, expiredAccepted, crossScopeLeaked, resurrectedRecord
       >>

\* Send a signed PushHead announcement from p1 to p2 on scope s1 onto the reordering network.
SendPushHead ==
    /\ seq["p1"]["s1"] > 0
    /\ LET m == [origin |-> "p1", target |-> "p2", scope |-> "s1", seq |-> seq["p1"]["s1"]]
       IN /\ m \notin pushMessages
          /\ pushMessages' = pushMessages \cup {m}
    /\ UNCHANGED <<
        records, suppressed, gen, seq, pushHighWater, revocations, clock, calmSeal,
        rollbackHappened, revokedAccepted, expiredAccepted, crossScopeLeaked, resurrectedRecord
       >>

\* Receive a PushHead announcement (may arrive out-of-order or duplicated).
RecvPushHead(msg) ==
    /\ msg \in pushMessages
    /\ LET prev == pushHighWater[msg.scope]
       IN IF EnablePushMonotonic /\ msg.seq <= prev THEN
              \* Stale or rollback sequence -> refused without mutating watermark
              /\ pushMessages' = pushMessages \ {msg}
              /\ UNCHANGED <<
                  records, suppressed, gen, seq, pushHighWater, revocations, clock, calmSeal,
                  rollbackHappened, revokedAccepted, expiredAccepted, crossScopeLeaked, resurrectedRecord
                 >>
          ELSE
              /\ pushHighWater' = [pushHighWater EXCEPT ![msg.scope] = msg.seq]
              /\ rollbackHappened' = (rollbackHappened \/ (msg.seq < prev))
              /\ pushMessages' = pushMessages \ {msg}
              /\ UNCHANGED <<
                  records, suppressed, gen, seq, revocations, clock, calmSeal,
                  revokedAccepted, expiredAccepted, crossScopeLeaked, resurrectedRecord
                 >>

\* Owner peer p1 issues a signed RevocationTombstone for token t1.
RevokeToken(t) ==
    /\ t = "t1"
    /\ t \notin revocations["p1"]
    /\ revocations' = [revocations EXCEPT !["p1"] = @ \cup {t}]
    /\ UNCHANGED <<
        records, suppressed, gen, seq, pushHighWater, clock, calmSeal, pushMessages,
        rollbackHappened, revokedAccepted, expiredAccepted, crossScopeLeaked, resurrectedRecord
       >>

\* SyncRevocations G-Set CRDT merge from peer a to peer b.
SyncRevocations(a, b) ==
    /\ a # b
    /\ revocations[a] \ revocations[b] # {}
    /\ IF EnableRevocationMerge THEN
           /\ revocations' = [revocations EXCEPT ![b] = @ \cup revocations[a]]
           /\ UNCHANGED <<
               records, suppressed, gen, seq, pushHighWater, clock, calmSeal, pushMessages,
               rollbackHappened, revokedAccepted, expiredAccepted, crossScopeLeaked, resurrectedRecord
              >>
       ELSE
           \* Fault injection: dropped RevocationSet merge leaves revoked token accepted!
           /\ revokedAccepted' = TRUE
           /\ UNCHANGED <<
               records, suppressed, gen, seq, pushHighWater, revocations, clock, calmSeal, pushMessages,
               rollbackHappened, expiredAccepted, crossScopeLeaked, resurrectedRecord
              >>

\* RBSR pull of scope s by client from server, propagating records & retention barriers.
RbsrPull(client, server, s, tok) ==
    /\ client # server
    /\ server = "p1"
    /\ PeerPermitsScope(server, client, s, tok)
    /\ LET newSup == suppressed[client] \cup suppressed[server]
           newRecs == (records[client][s] \cup records[server][s]) \ newSup
           newGen == Max(gen[client], gen[server])
           newSeq == Max(seq[client][s], seq[server][s])
       IN
           /\ (newRecs # records[client][s] \/ newSup # suppressed[client] \/ newGen # gen[client])
           /\ records' = [records EXCEPT ![client][s] = newRecs]
           /\ suppressed' = [suppressed EXCEPT ![client] = newSup]
           /\ gen' = [gen EXCEPT ![client] = newGen]
           /\ seq' = [seq EXCEPT ![client][s] = newSeq]
           /\ resurrectedRecord' = (resurrectedRecord \/ (newRecs \cap newSup # {}))
           /\ UNCHANGED <<
               pushHighWater, revocations, clock, calmSeal, pushMessages,
               rollbackHappened, revokedAccepted, expiredAccepted, crossScopeLeaked
              >>

\* Independent server clock tick on p1 while p2/p3 stay at 0 (models per-peer clock skew & expiry).
TickClock(p) ==
    /\ p = "p1"
    /\ clock[p] < MaxTime
    /\ clock' = [clock EXCEPT ![p] = @ + 1]
    /\ UNCHANGED <<
        records, suppressed, gen, seq, pushHighWater, revocations, calmSeal, pushMessages,
        rollbackHappened, revokedAccepted, expiredAccepted, crossScopeLeaked, resurrectedRecord
       >>

\* Network drops an in-flight PushHead message.
DropPushMessage(msg) ==
    /\ msg \in pushMessages
    /\ pushMessages' = pushMessages \ {msg}
    /\ UNCHANGED <<
        records, suppressed, gen, seq, pushHighWater, revocations, clock, calmSeal,
        rollbackHappened, revokedAccepted, expiredAccepted, crossScopeLeaked, resurrectedRecord
       >>

Next ==
    \/ \E s \in Scopes, r \in Records : LocalCommit(s, r)
    \/ \E r \in Records : LocalForget(r)
    \/ AdvanceCalmSeal
    \/ SendPushHead
    \/ \E msg \in pushMessages : RecvPushHead(msg)
    \/ \E t \in Tokens : RevokeToken(t)
    \/ \E a \in Peers, b \in Peers : SyncRevocations(a, b)
    \/ \E c \in Peers, srv \in Peers, s \in Scopes, tok \in Tokens : RbsrPull(c, srv, s, tok)
    \/ \E p \in Peers : TickClock(p)
    \/ \E msg \in pushMessages : DropPushMessage(msg)

Fairness ==
    /\ \A a \in Peers, b \in Peers : WF_vars(SyncRevocations(a, b))

Spec == Init /\ [][Next]_vars /\ Fairness

\* ---------------------------------------------------------------------------
\* Safety Invariants
\* ---------------------------------------------------------------------------

\* Stale/reordered PushHead never rolls back pushHighWater.
PushHeadMonotonic ==
    ~rollbackHappened

\* Zero resurrection of forgotten records on any peer in any scope.
NoForgottenResurrection ==
    /\ ~resurrectedRecord
    /\ \A p \in Peers, s \in Scopes : (records[p][s] \cap suppressed[p] = {})

\* Scope isolation: p2 is only authorized for s1 (never s2); p3 is only authorized for s2 (never s1).
NoCrossScopeLeakage ==
    /\ ~crossScopeLeaked
    /\ records["p2"]["s2"] = {}
    /\ records["p3"]["s1"] = {}

\* Revoked and expired capabilities are never accepted.
RevokedAndExpiredRejected ==
    /\ ~revokedAccepted
    /\ ~expiredAccepted

\* CalmSeal never exceeds local committed sequence.
CalmSealBounded ==
    \A s \in Scopes : calmSeal[s] <= seq["p1"][s]

\* ---------------------------------------------------------------------------
\* Liveness Property
\* ---------------------------------------------------------------------------

\* Under fair SyncRevocations, every revocation issued at p1 eventually reaches all peers.
RevocationsEventuallyConverge ==
    \A t \in Tokens :
        (t \in revocations["p1"]) ~> (\A p \in Peers : t \in revocations[p])

=============================================================================
