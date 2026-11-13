import MnemeKernel
open Aeneas Aeneas.Std Result

namespace mneme_kernel.restore

/-- `may_serve` always returns, and it returns `true` exactly when no restore
    is pending. -/
theorem may_serve_iff (marker : Marker) :
    ∃ r : Bool, may_serve marker = ok r ∧
      (r = true ↔ marker = Marker.Clear) := by
  unfold may_serve
  cases marker
  · exact ⟨true, by simp, by simp⟩
  · exact ⟨false, by simp, by simp⟩

/-- The complete decision table of `decide_ledger`. -/
private theorem decide_ledger_spec (facts : LedgerFacts) :
    ∃ d, decide_ledger facts = ok d ∧
      (d = LedgerDecision.Apply ↔
        facts.same_workspace = true ∧
          facts.restored_generation.val ≤ facts.ledger_generation.val) ∧
      (d = LedgerDecision.ForeignWorkspace ↔ facts.same_workspace = false) := by
  obtain ⟨same_workspace, ledger_generation, restored_generation⟩ := facts
  unfold decide_ledger
  cases same_workspace with
  | false =>
    exact ⟨LedgerDecision.ForeignWorkspace, by simp, by simp, by simp⟩
  | true =>
    by_cases h : ledger_generation.val < restored_generation.val
    · exact ⟨LedgerDecision.Stale, by simp [h], by simpa using h, by simp⟩
    · exact ⟨LedgerDecision.Apply, by simp [h], by simpa using h, by simp⟩

/-- `decide_ledger` never fails and never diverges. -/
theorem decide_ledger_total (facts : LedgerFacts) :
    ∃ d : LedgerDecision, decide_ledger facts = ok d := by
  obtain ⟨d, hd, _⟩ := decide_ledger_spec facts
  exact ⟨d, hd⟩

/-- A ledger is applied exactly when it names this workspace and is not older
    than the restored copy's own suppression state. -/
theorem decide_ledger_apply_iff (facts : LedgerFacts) :
    ∃ d, decide_ledger facts = ok d ∧
      (d = LedgerDecision.Apply ↔
        facts.same_workspace = true ∧
          facts.restored_generation.val ≤ facts.ledger_generation.val) := by
  obtain ⟨d, hd, h, _⟩ := decide_ledger_spec facts
  exact ⟨d, hd, h⟩

/-- The decision is `ForeignWorkspace` exactly when the ledger belongs to
    another workspace. -/
theorem decide_ledger_foreign_iff (facts : LedgerFacts) :
    ∃ d, decide_ledger facts = ok d ∧
      (d = LedgerDecision.ForeignWorkspace ↔ facts.same_workspace = false) := by
  obtain ⟨d, hd, _, h⟩ := decide_ledger_spec facts
  exact ⟨d, hd, h⟩

end mneme_kernel.restore
