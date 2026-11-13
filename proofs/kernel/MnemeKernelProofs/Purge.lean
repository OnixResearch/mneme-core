import MnemeKernel
open Aeneas Aeneas.Std Result

namespace mneme_kernel.purge

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

/-- The complete decision table of `decide_working`. -/
private theorem decide_working_spec (facts : WorkingFacts) :
    ∃ d, decide_working facts = ok d ∧
      (d = WorkingDecision.Purge ↔
        facts.kind = EntryKind.Regular ∧ facts.observed = some facts.planned) ∧
      (d = WorkingDecision.AlreadyAbsent ↔ facts.kind = EntryKind.Absent) ∧
      (d = WorkingDecision.ExternalEdit ↔
        facts.kind = EntryKind.Regular ∧
          ∃ found, facts.observed = some found ∧ found ≠ facts.planned) := by
  obtain ⟨kind, observed, planned⟩ := facts
  unfold decide_working
  cases kind with
  | Absent =>
    exact ⟨WorkingDecision.AlreadyAbsent, rfl, by simp, by simp, by simp⟩
  | Other =>
    exact ⟨WorkingDecision.Unsupported, rfl, by simp, by simp, by simp⟩
  | Regular =>
    cases observed with
    | none =>
      exact ⟨WorkingDecision.Unsupported, rfl, by simp, by simp, by simp⟩
    | some found =>
      obtain ⟨r, hr, hiff⟩ := digest_eq_spec found planned
      cases r with
      | false =>
        exact ⟨WorkingDecision.ExternalEdit, by simp [hr], by simpa using hiff,
          by simp, by simpa using hiff⟩
      | true =>
        exact ⟨WorkingDecision.Purge, by simp [hr], by simpa using hiff,
          by simp, by simpa using hiff⟩

/-- `decide_working` never fails and never diverges. -/
theorem decide_working_total (facts : WorkingFacts) :
    ∃ d : WorkingDecision, decide_working facts = ok d := by
  obtain ⟨d, hd, _⟩ := decide_working_spec facts
  exact ⟨d, hd⟩

/-- A working file is purged exactly when it is a regular file holding the
    planned bytes. -/
theorem decide_working_purge_iff (facts : WorkingFacts) :
    ∃ d, decide_working facts = ok d ∧
      (d = WorkingDecision.Purge ↔
        facts.kind = EntryKind.Regular ∧ facts.observed = some facts.planned) := by
  obtain ⟨d, hd, h, _⟩ := decide_working_spec facts
  exact ⟨d, hd, h⟩

/-- The decision is `AlreadyAbsent` exactly when nothing sits at the path. -/
theorem decide_working_absent_iff (facts : WorkingFacts) :
    ∃ d, decide_working facts = ok d ∧
      (d = WorkingDecision.AlreadyAbsent ↔ facts.kind = EntryKind.Absent) := by
  obtain ⟨d, hd, _, h, _⟩ := decide_working_spec facts
  exact ⟨d, hd, h⟩

/-- The decision is `ExternalEdit` exactly when a regular file was read and it
    holds bytes other than the planned ones. -/
theorem decide_working_external_edit_iff (facts : WorkingFacts) :
    ∃ d, decide_working facts = ok d ∧
      (d = WorkingDecision.ExternalEdit ↔
        facts.kind = EntryKind.Regular ∧
          ∃ found, facts.observed = some found ∧ found ≠ facts.planned) := by
  obtain ⟨d, hd, _, _, h⟩ := decide_working_spec facts
  exact ⟨d, hd, h⟩

/-- The complete decision table of `decide_blob`. -/
private theorem decide_blob_spec (facts : BlobFacts) :
    decide_blob facts = ok
      (if facts.required = true then BlobDecision.RetainShared
       else if facts.present = true then BlobDecision.Purge
       else BlobDecision.AlreadyAbsent) := by
  obtain ⟨required, present⟩ := facts
  unfold decide_blob
  cases required <;> cases present <;> rfl

/-- `decide_blob` never fails and never diverges. -/
theorem decide_blob_total (facts : BlobFacts) :
    ∃ d : BlobDecision, decide_blob facts = ok d :=
  ⟨_, decide_blob_spec facts⟩

/-- A blob is purged exactly when no retained owner needs it and it is
    present. -/
theorem decide_blob_purge_iff (facts : BlobFacts) :
    ∃ d, decide_blob facts = ok d ∧
      (d = BlobDecision.Purge ↔ facts.required = false ∧ facts.present = true) := by
  refine ⟨_, decide_blob_spec facts, ?_⟩
  cases facts.required <;> cases facts.present <;> simp

/-- A blob that a retained owner still needs is kept, present or not. -/
theorem decide_blob_required (facts : BlobFacts) (h : facts.required = true) :
    decide_blob facts = ok BlobDecision.RetainShared := by
  rw [decide_blob_spec facts, h]
  rfl

end mneme_kernel.purge
