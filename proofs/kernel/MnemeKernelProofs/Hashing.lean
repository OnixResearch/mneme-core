import MnemeKernel
open Aeneas Aeneas.Std Result

namespace mneme_kernel.hashing

/-- `digest_eq` always returns, and it returns `true` exactly when the two
    digests are the same value. -/
theorem digest_eq_iff (a b : Digest) :
    ∃ r : Bool, digest_eq a b = ok r ∧ (r = true ↔ a = b) := by
  obtain ⟨ahi, alo⟩ := a
  obtain ⟨bhi, blo⟩ := b
  unfold digest_eq
  by_cases h : ahi = bhi
  · exact ⟨decide (alo = blo), by simp [h], by simp [h]⟩
  · exact ⟨false, by simp [h], by simp [h]⟩

/-- `optional_digest_eq` always returns, and it returns `true` exactly when
    both sides are absent or both hold the same digest. -/
theorem optional_digest_eq_iff (a b : Option Digest) :
    ∃ r : Bool, optional_digest_eq a b = ok r ∧ (r = true ↔ a = b) := by
  unfold optional_digest_eq
  cases a with
  | none =>
    cases b with
    | none => exact ⟨true, rfl, by simp⟩
    | some w => exact ⟨false, rfl, by simp⟩
  | some f =>
    cases b with
    | none => exact ⟨false, rfl, by simp⟩
    | some w =>
      obtain ⟨r, hr, hiff⟩ := digest_eq_iff f w
      exact ⟨r, hr, by simp [hiff]⟩

end mneme_kernel.hashing
