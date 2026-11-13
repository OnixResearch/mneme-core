import MnemeKernel
open Aeneas Aeneas.Std Result

namespace mneme_kernel.admission

/-- Local restatement of the digest comparison: it always returns, and it
    returns `true` exactly when the two digests are the same value. -/
private theorem digest_eq_spec (a b : hashing.Digest) :
    ∃ r : Bool, hashing.digest_eq a b = ok r ∧ (r = true ↔ a = b) := by
  obtain ⟨ahi, alo⟩ := a
  obtain ⟨bhi, blo⟩ := b
  unfold hashing.digest_eq
  by_cases h : ahi = bhi
  · exact ⟨decide (alo = blo), by simp [h], by simp [h]⟩
  · exact ⟨false, by simp [h], by simp [h]⟩

/-- `same_request` always returns. When both fingerprints are present they
    decide; otherwise the command digests decide. -/
private theorem same_request_spec (s : StoredCommand) (command : hashing.Digest)
    (fingerprint : Option hashing.Digest) :
    ∃ r : Bool, same_request s command fingerprint = ok r ∧
      (r = true ↔
        (∃ k, s.fingerprint = some k ∧ fingerprint = some k) ∨
        ((s.fingerprint = none ∨ fingerprint = none) ∧ s.command = command)) := by
  obtain ⟨stored_command, kept⟩ := s
  unfold same_request
  cases kept with
  | none =>
    obtain ⟨r, hr, hiff⟩ := digest_eq_spec stored_command command
    exact ⟨r, hr, by simp [hiff]⟩
  | some kept =>
    cases fingerprint with
    | none =>
      obtain ⟨r, hr, hiff⟩ := digest_eq_spec stored_command command
      exact ⟨r, hr, by simp [hiff]⟩
    | some offered =>
      obtain ⟨r, hr, hiff⟩ := digest_eq_spec kept offered
      exact ⟨r, hr, by simp [hiff, eq_comm]⟩

/-- With a stored command the decision is `Replay` or `IdempotencyConflict`,
    and it is `Replay` exactly when the stored row is the same request. -/
private theorem decide_commit_of_stored (facts : CommitFacts) (s : StoredCommand)
    (h : facts.stored = some s) :
    ∃ d, decide_commit facts = ok d ∧
      (d = CommitDecision.Replay ∨ d = CommitDecision.IdempotencyConflict) ∧
      (d = CommitDecision.Replay ↔
        (∃ k, s.fingerprint = some k ∧ facts.fingerprint = some k) ∨
        ((s.fingerprint = none ∨ facts.fingerprint = none) ∧
          s.command = facts.command)) := by
  obtain ⟨r, hr, hiff⟩ := same_request_spec s facts.command facts.fingerprint
  unfold decide_commit
  rw [h]
  cases r with
  | false =>
    refine ⟨CommitDecision.IdempotencyConflict, by simp [hr], Or.inr rfl, ?_⟩
    simpa using hiff
  | true =>
    refine ⟨CommitDecision.Replay, by simp [hr], Or.inl rfl, ?_⟩
    simpa using hiff

/-- Without a stored command the base revision is checked first, then the
    erasure barrier. -/
theorem decide_commit_fresh (facts : CommitFacts) (h : facts.stored = none) :
    decide_commit facts = ok
      (if facts.base_is_current = false then CommitDecision.StaleBase
       else if facts.generation_is_pinned = false then CommitDecision.BarrierAdvanced
       else CommitDecision.Proceed) := by
  unfold decide_commit
  rw [h]
  cases facts.base_is_current <;> cases facts.generation_is_pinned <;> simp

/-- `decide_commit` never fails and never diverges. -/
theorem decide_commit_total (facts : CommitFacts) :
    ∃ d : CommitDecision, decide_commit facts = ok d := by
  cases h : facts.stored with
  | none => exact ⟨_, decide_commit_fresh facts h⟩
  | some s =>
    obtain ⟨d, hd, _⟩ := decide_commit_of_stored facts s h
    exact ⟨d, hd⟩

/-- A new revision is written only when no command is stored under the key,
    the base revision is current and the erasure generation is still pinned. -/
theorem decide_commit_proceed (facts : CommitFacts) :
    ∃ d, decide_commit facts = ok d ∧
      (d = CommitDecision.Proceed →
        facts.stored = none ∧ facts.base_is_current = true ∧
          facts.generation_is_pinned = true) := by
  cases h : facts.stored with
  | none =>
    refine ⟨_, decide_commit_fresh facts h, ?_⟩
    cases facts.base_is_current <;> cases facts.generation_is_pinned <;> simp
  | some s =>
    obtain ⟨d, hd, hor, _⟩ := decide_commit_of_stored facts s h
    refine ⟨d, hd, ?_⟩
    rcases hor with rfl | rfl <;> simp

/-- A stored command is consulted before the base revision and the barrier:
    the decision is then `Replay` or `IdempotencyConflict`, whatever the base
    and generation facts are. -/
theorem decide_commit_stored (facts : CommitFacts) (s : StoredCommand)
    (h : facts.stored = some s) :
    ∃ d, decide_commit facts = ok d ∧
      (d = CommitDecision.Replay ∨ d = CommitDecision.IdempotencyConflict) := by
  obtain ⟨d, hd, hor, _⟩ := decide_commit_of_stored facts s h
  exact ⟨d, hd, hor⟩

/-- A replay is decided only for a stored command that is the same request:
    equal fingerprints when both are present, otherwise equal command digests. -/
theorem decide_commit_replay (facts : CommitFacts) :
    ∃ d, decide_commit facts = ok d ∧
      (d = CommitDecision.Replay →
        ∃ s, facts.stored = some s ∧
          ((∃ k, s.fingerprint = some k ∧ facts.fingerprint = some k) ∨
           ((s.fingerprint = none ∨ facts.fingerprint = none) ∧
             s.command = facts.command))) := by
  cases h : facts.stored with
  | none =>
    refine ⟨_, decide_commit_fresh facts h, ?_⟩
    cases facts.base_is_current <;> cases facts.generation_is_pinned <;> simp
  | some s =>
    obtain ⟨d, hd, _, hiff⟩ := decide_commit_of_stored facts s h
    exact ⟨d, hd, fun hd' => ⟨s, rfl, hiff.mp hd'⟩⟩

/-- Two present, distinct fingerprints conflict even when the command digests
    are equal. -/
theorem decide_commit_conflict_of_distinct_fingerprints (facts : CommitFacts)
    (s : StoredCommand) (k o : hashing.Digest)
    (hs : facts.stored = some s) (hk : s.fingerprint = some k)
    (ho : facts.fingerprint = some o) (hne : k ≠ o) :
    decide_commit facts = ok CommitDecision.IdempotencyConflict := by
  obtain ⟨d, hd, hor, hiff⟩ := decide_commit_of_stored facts s hs
  rcases hor with rfl | rfl
  · exfalso
    rcases hiff.mp rfl with ⟨k', hk', ho'⟩ | ⟨hnone, _⟩
    · rw [hk] at hk'
      rw [ho] at ho'
      exact hne ((Option.some.inj hk').trans (Option.some.inj ho').symm)
    · rcases hnone with hnone | hnone
      · rw [hk] at hnone
        exact Option.some_ne_none k hnone
      · rw [ho] at hnone
        exact Option.some_ne_none o hnone
  · exact hd

/-- `decide_replay` always returns, and it returns `Fresh` exactly when no
    command is stored under the key. -/
theorem decide_replay_fresh_iff (stored : Option StoredCommand) (fp : hashing.Digest) :
    ∃ d, decide_replay stored fp = ok d ∧
      (d = ReplayDecision.Fresh ↔ stored = none) := by
  unfold decide_replay
  cases stored with
  | none => exact ⟨ReplayDecision.Fresh, rfl, by simp⟩
  | some row =>
    obtain ⟨row_command, kept⟩ := row
    cases kept with
    | none => exact ⟨ReplayDecision.Conflict, rfl, by simp⟩
    | some kept =>
      obtain ⟨r, hr, _⟩ := digest_eq_spec kept fp
      cases r with
      | false => exact ⟨ReplayDecision.Conflict, by simp [hr], by simp⟩
      | true => exact ⟨ReplayDecision.Replay, by simp [hr], by simp⟩

/-- `decide_replay` always returns, and it returns `Replay` exactly when a
    command is stored under the key with this request fingerprint. -/
theorem decide_replay_replay_iff (stored : Option StoredCommand) (fp : hashing.Digest) :
    ∃ d, decide_replay stored fp = ok d ∧
      (d = ReplayDecision.Replay ↔
        ∃ s, stored = some s ∧ s.fingerprint = some fp) := by
  unfold decide_replay
  cases stored with
  | none => exact ⟨ReplayDecision.Fresh, rfl, by simp⟩
  | some row =>
    obtain ⟨row_command, kept⟩ := row
    cases kept with
    | none => exact ⟨ReplayDecision.Conflict, rfl, by simp⟩
    | some kept =>
      obtain ⟨r, hr, hiff⟩ := digest_eq_spec kept fp
      cases r with
      | false =>
        refine ⟨ReplayDecision.Conflict, by simp [hr], ?_⟩
        simpa using hiff
      | true =>
        refine ⟨ReplayDecision.Replay, by simp [hr], ?_⟩
        simpa using hiff

end mneme_kernel.admission
