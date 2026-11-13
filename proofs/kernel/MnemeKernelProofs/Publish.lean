import MnemeKernel
open Aeneas Aeneas.Std Result

namespace mneme_kernel.publish

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

/-- Local restatement of the optional digest comparison: it always returns,
    and it returns `true` exactly when both sides are absent or both hold the
    same digest. -/
private theorem optional_digest_eq_spec (a b : Option hashing.Digest) :
    ∃ r : Bool, hashing.optional_digest_eq a b = ok r ∧ (r = true ↔ a = b) := by
  unfold hashing.optional_digest_eq
  cases a with
  | none =>
    cases b with
    | none => exact ⟨true, rfl, by simp⟩
    | some wanted => exact ⟨false, rfl, by simp⟩
  | some found =>
    cases b with
    | none => exact ⟨false, rfl, by simp⟩
    | some wanted =>
      obtain ⟨r, hr, hiff⟩ := digest_eq_spec found wanted
      exact ⟨r, hr, by simp [hiff]⟩

/-- The complete decision table of `decide_publication`. -/
private theorem decide_publication_spec (facts : PublicationFacts) :
    ∃ d, decide_publication facts = ok d ∧
      (d = PublicationDecision.AlreadyPublished ↔
        facts.observed = some facts.desired) ∧
      (d = PublicationDecision.Replace ↔
        facts.observed = facts.expected ∧ facts.observed ≠ some facts.desired) ∧
      (d = PublicationDecision.Diverged ↔
        facts.observed ≠ facts.expected ∧ facts.observed ≠ some facts.desired) := by
  obtain ⟨observed, expected, desired⟩ := facts
  obtain ⟨r, hr, hriff⟩ := optional_digest_eq_spec observed expected
  unfold decide_publication
  cases observed with
  | none =>
    cases r with
    | false =>
      exact ⟨PublicationDecision.Diverged, by simp [hr], by simp,
        by simpa using hriff, by simpa using hriff⟩
    | true =>
      exact ⟨PublicationDecision.Replace, by simp [hr], by simp,
        by simpa using hriff, by simpa using hriff⟩
  | some found =>
    obtain ⟨p, hp, hpiff⟩ := digest_eq_spec found desired
    cases p with
    | true =>
      obtain rfl : found = desired := hpiff.mp rfl
      exact ⟨PublicationDecision.AlreadyPublished, by simp [hp],
        by simp, by simp, by simp⟩
    | false =>
      have hne : found ≠ desired := fun h => Bool.false_ne_true (hpiff.mpr h)
      cases r with
      | false =>
        have hne' : some found ≠ expected :=
          fun h => Bool.false_ne_true (hriff.mpr h)
        exact ⟨PublicationDecision.Diverged, by simp [hp, hr],
          by simp [hne], by simp [hne'], by simp [hne, hne']⟩
      | true =>
        obtain rfl : some found = expected := hriff.mp rfl
        exact ⟨PublicationDecision.Replace, by simp [hp, hr],
          by simp [hne], by simp [hne], by simp⟩

/-- `decide_publication` never fails and never diverges. -/
theorem decide_publication_total (facts : PublicationFacts) :
    ∃ d : PublicationDecision, decide_publication facts = ok d := by
  obtain ⟨d, hd, _⟩ := decide_publication_spec facts
  exact ⟨d, hd⟩

/-- The decision is `AlreadyPublished` exactly when the working file already
    holds the desired bytes. -/
theorem decide_publication_already_iff (facts : PublicationFacts) :
    ∃ d, decide_publication facts = ok d ∧
      (d = PublicationDecision.AlreadyPublished ↔
        facts.observed = some facts.desired) := by
  obtain ⟨d, hd, h, _⟩ := decide_publication_spec facts
  exact ⟨d, hd, h⟩

/-- The decision is `Replace` exactly when the working file is what the
    committer expected and does not already hold the desired bytes: content
    the committer did not expect is never replaced. -/
theorem decide_publication_replace_iff (facts : PublicationFacts) :
    ∃ d, decide_publication facts = ok d ∧
      (d = PublicationDecision.Replace ↔
        facts.observed = facts.expected ∧ facts.observed ≠ some facts.desired) := by
  obtain ⟨d, hd, _, h, _⟩ := decide_publication_spec facts
  exact ⟨d, hd, h⟩

/-- The decision is `Diverged` exactly when the working file is neither what
    the committer expected nor the desired bytes. -/
theorem decide_publication_diverged_iff (facts : PublicationFacts) :
    ∃ d, decide_publication facts = ok d ∧
      (d = PublicationDecision.Diverged ↔
        facts.observed ≠ facts.expected ∧ facts.observed ≠ some facts.desired) := by
  obtain ⟨d, hd, _, _, h⟩ := decide_publication_spec facts
  exact ⟨d, hd, h⟩

/-- `should_attempt` always returns, and it returns `true` exactly for the
    `Pending` and `Failed` phases. -/
theorem should_attempt_iff (p : PublicationPhase) :
    ∃ r : Bool, should_attempt p = ok r ∧
      (r = true ↔ p = PublicationPhase.Pending ∨ p = PublicationPhase.Failed) := by
  unfold should_attempt
  cases p
  · exact ⟨true, rfl, by simp⟩
  · exact ⟨false, rfl, by simp⟩
  · exact ⟨false, rfl, by simp⟩
  · exact ⟨false, rfl, by simp⟩
  · exact ⟨true, rfl, by simp⟩

end mneme_kernel.publish
