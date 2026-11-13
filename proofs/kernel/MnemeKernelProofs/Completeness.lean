import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Completeness and absence

Theorems about the generated translation of
`crates/mneme-kernel/src/completeness.rs`. The three rules of the module are
total: each returns `ok` for every input (the `*_total` theorems), so each
`= ok true ↔ …` statement also determines when the rule returns `ok false`.
-/

namespace mneme_kernel.completeness

/-! ## `answer_complete` -/

/-- `answer_complete` never fails or diverges. -/
theorem answer_complete_total (facts : AnswerFacts) :
    ∃ complete, answer_complete facts = ok complete := by
  obtain ⟨rows, exhaustive, coverage, limit, valid, current⟩ := facts
  cases exhaustive <;> cases coverage <;> cases limit <;> cases valid <;>
    simp [answer_complete]

/-- An answer is complete exactly when the evaluation was exhaustive over
complete, correctly declared inputs, no limit was reached, and the erasure
generation is still current. -/
theorem answer_complete_iff (facts : AnswerFacts) :
    answer_complete facts = ok true ↔
      facts.exhaustive = true ∧
        facts.coverage = Coverage.Complete ∧
        facts.limit_reached = false ∧
        facts.declaration_valid = true ∧
        facts.generation_current = true := by
  obtain ⟨rows, exhaustive, coverage, limit, valid, current⟩ := facts
  cases exhaustive <;> cases coverage <;> cases limit <;> cases valid <;>
    simp [answer_complete]

/-! ## `absence_established` -/

/-- `absence_established` never fails or diverges. -/
theorem absence_established_total (facts : AnswerFacts) :
    ∃ established, absence_established facts = ok established := by
  by_cases hrows : facts.rows = 0#u64
  · simpa [absence_established, hrows] using answer_complete_total facts
  · simp [absence_established, hrows]

/-- An answer establishes absence exactly when it has no rows and is
complete. -/
theorem absence_established_iff (facts : AnswerFacts) :
    absence_established facts = ok true ↔
      facts.rows.val = 0 ∧
        facts.exhaustive = true ∧
        facts.coverage = Coverage.Complete ∧
        facts.limit_reached = false ∧
        facts.declaration_valid = true ∧
        facts.generation_current = true := by
  have hzero : facts.rows = 0#u64 ↔ facts.rows.val = 0 := by
    rw [UScalar.eq_equiv]; simp
  by_cases hrows : facts.rows = 0#u64
  · simp [absence_established, hrows, answer_complete_iff]
  · have hval : ¬ facts.rows.val = 0 := fun h => hrows (hzero.mpr h)
    simp [absence_established, hrows, hval]

/-- An answer that establishes absence is complete. -/
theorem absence_implies_complete (facts : AnswerFacts)
    (h : absence_established facts = ok true) :
    answer_complete facts = ok true := by
  by_cases hrows : facts.rows = 0#u64
  · simpa [absence_established, hrows] using h
  · simp [absence_established, hrows] at h

/-! ## `combine_coverage` -/

/-- `combine_coverage` never fails or diverges. -/
theorem combine_coverage_total (left right : Coverage) :
    ∃ combined, combine_coverage left right = ok combined := by
  cases left <;> cases right <;> simp [combine_coverage]

/-- `combine_coverage` is commutative: both orders return the same coverage. -/
theorem combine_coverage_comm (left right : Coverage) :
    ∃ combined,
      combine_coverage left right = ok combined ∧
        combine_coverage right left = ok combined := by
  cases left <;> cases right <;> simp [combine_coverage]

/-- `combine_coverage` is associative: both groupings return the same
coverage, and every intermediate call returns. -/
theorem combine_coverage_assoc (first second third : Coverage) :
    ∃ left right combined,
      combine_coverage first second = ok left ∧
        combine_coverage second third = ok right ∧
        combine_coverage left third = ok combined ∧
        combine_coverage first right = ok combined := by
  cases first <;> cases second <;> cases third <;> simp [combine_coverage]

/-- The combination is complete exactly when both sides are complete. -/
theorem combine_coverage_complete_iff (left right : Coverage) :
    combine_coverage left right = ok Coverage.Complete ↔
      left = Coverage.Complete ∧ right = Coverage.Complete := by
  cases left <;> cases right <;> simp [combine_coverage]

/-- Unknown coverage on either side makes the combination unknown. -/
theorem combine_coverage_unknown_absorbs (left right : Coverage)
    (h : left = Coverage.Unknown ∨ right = Coverage.Unknown) :
    combine_coverage left right = ok Coverage.Unknown := by
  rcases h with rfl | rfl
  · simp [combine_coverage]
  · cases left <;> simp [combine_coverage]

end mneme_kernel.completeness
