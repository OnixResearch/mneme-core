import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Acceptance status algebra

Theorems about the Aeneas translation of `crates/mneme-kernel/src/verdict.rs`:
the generated definitions `mneme_kernel.verdict.*` in `MnemeKernel.lean`,
including the generated loop `aggregate_loop` and its body.

Every statement shows that the function returns `ok`, so it neither fails nor
diverges. Slice arguments are described through their element list `s.val`.
-/

namespace mneme_kernel.verdict

/-- A specification that holds yields the returned value. -/
private theorem ok_of_spec {α : Type} {m : Result α} {P : α → Prop} (h : m ⦃ P ⦄) :
    ∃ v, m = ok v ∧ P v := by
  cases m with
  | ret v => exact ⟨v, rfl, by simpa using h⟩
  | vis e k => simp at h
  | div => simp at h

/-! ## `merge` -/

/-- `merge` always returns a status. -/
theorem merge_total (a b : Status) : ∃ r, merge a b = ok r := by
  cases a <;> cases b <;> simp [merge, severity]

/-- `merge` is commutative. -/
theorem merge_comm (a b : Status) : ∃ r, merge a b = ok r ∧ merge b a = ok r := by
  cases a <;> cases b <;> simp [merge, severity]

/-- `merge` is associative. -/
theorem merge_assoc (a b c : Status) :
    ∃ ab bc r, merge a b = ok ab ∧ merge b c = ok bc ∧
      merge ab c = ok r ∧ merge a bc = ok r := by
  cases a <;> cases b <;> cases c <;> simp [merge, severity]

/-- `merge` is idempotent. -/
theorem merge_idem (a : Status) : merge a a = ok a := by
  cases a <;> simp [merge, severity]

/-- `Passed` is the identity of `merge`. -/
theorem merge_passed_identity (a : Status) :
    merge Status.Passed a = ok a ∧ merge a Status.Passed = ok a := by
  cases a <;> simp [merge, severity]

/-- `Failed` absorbs every status under `merge`. -/
theorem merge_failed_absorbs (a : Status) :
    merge Status.Failed a = ok Status.Failed ∧ merge a Status.Failed = ok Status.Failed := by
  cases a <;> simp [merge, severity]

/-- A merge is `Passed` exactly when both operands are `Passed`. -/
theorem merge_eq_passed_iff (a b : Status) :
    (∃ r, merge a b = ok r) ∧
      (merge a b = ok Status.Passed ↔ a = Status.Passed ∧ b = Status.Passed) := by
  cases a <;> cases b <;> simp [merge, severity]

/-- A merge is `Failed` exactly when one of its operands is `Failed`. -/
private theorem merge_eq_failed_iff (a b : Status) :
    merge a b = ok Status.Failed ↔ a = Status.Failed ∨ b = Status.Failed := by
  cases a <;> cases b <;> simp [merge, severity]

/-! ## `case_status` -/

/-- A declared skip never hides a failure. -/
theorem case_status_failed (declaration : SkipDeclaration) :
    case_status declaration Status.Failed = ok Status.Failed := by
  cases declaration <;> simp [case_status]

/-- A case is `Passed` exactly when it was not declared skipped and was observed `Passed`. -/
theorem case_status_passed_iff (declaration : SkipDeclaration) (observed : Status) :
    (∃ r, case_status declaration observed = ok r) ∧
      (case_status declaration observed = ok Status.Passed ↔
        declaration = SkipDeclaration.NotDeclared ∧ observed = Status.Passed) := by
  cases declaration <;> cases observed <;> simp [case_status]

/-! ## `aggregate` -/

/-- The generated loop of `aggregate`, started as `aggregate` starts it.

The invariant relates the accumulator to the prefix `s.val.take index`; the
measure is `s.length - index`. -/
private theorem aggregate_loop_spec (s : Slice Status) :
    aggregate_loop s Status.Passed 0#usize ⦃ r =>
      (r = Status.Passed ↔ ∀ x ∈ s.val, x = Status.Passed) ∧
      (r = Status.Failed ↔ Status.Failed ∈ s.val) ⦄ := by
  unfold aggregate_loop
  apply loop.spec_decr_nat
    (fun (p : Status × Usize) => s.length - p.2.val)
    (fun (p : Status × Usize) =>
      p.2.val ≤ s.length ∧
      (p.1 = Status.Passed ↔ ∀ x ∈ s.val.take p.2.val, x = Status.Passed) ∧
      (p.1 = Status.Failed ↔ Status.Failed ∈ s.val.take p.2.val))
  · rintro ⟨combined, index⟩ ⟨hle, hp, hf⟩
    simp only at hle hp hf ⊢
    unfold aggregate_loop.body
    by_cases hlt : index < Slice.len s
    · have hlt' : index.val < s.length := by scalar_tac
      obtain ⟨x, hx, hxv⟩ := ok_of_spec (Slice.index_usize_spec s index hlt')
      obtain ⟨c, hc⟩ := merge_total combined x
      obtain ⟨i1, hi1, hi1v⟩ :=
        ok_of_spec (Usize.add_spec (x := index) (y := 1#usize) (by scalar_tac))
      have hi1' : i1.val = index.val + 1 := by scalar_tac
      have hcp : c = Status.Passed ↔ combined = Status.Passed ∧ x = Status.Passed := by
        have h := (merge_eq_passed_iff combined x).2
        rw [hc] at h
        simpa using h
      have hcf : c = Status.Failed ↔ combined = Status.Failed ∨ x = Status.Failed := by
        have h := merge_eq_failed_iff combined x
        rw [hc] at h
        simpa using h
      have htake : s.val.take i1.val = s.val.take index.val ++ [x] := by
        rw [hi1', hxv]
        exact List.take_succ_eq_append_getElem hlt'
      simp only [hlt, ite_true, hx, bind_ok, hc, hi1, WP.spec_ok]
      refine ⟨⟨by omega, ?_, ?_⟩, by omega⟩
      · rw [hcp, hp, htake]
        simp [or_imp, forall_and]
      · rw [hcf, hf, htake, List.mem_append, List.mem_singleton,
          eq_comm (a := Status.Failed) (b := x)]
    · simp only [hlt, ite_false, WP.spec_ok]
      have hge : s.val.length ≤ index.val := by scalar_tac
      rw [List.take_of_length_le hge] at hp hf
      exact ⟨hp, hf⟩
  · simp

/-- The characterization of `aggregate` behind the public theorems. -/
private theorem aggregate_spec (s : Slice Status) :
    ∃ r, aggregate s = ok r ∧
      (s.val = [] → r = Status.Unimplemented) ∧
      (r = Status.Passed ↔ s.val ≠ [] ∧ ∀ x ∈ s.val, x = Status.Passed) ∧
      (r = Status.Failed ↔ Status.Failed ∈ s.val) := by
  unfold aggregate
  simp only [core.slice.Slice.is_empty, bind_ok]
  by_cases hnil : s.val = []
  · simp [hnil]
  · obtain ⟨r, hr, hp, hf⟩ := ok_of_spec (aggregate_loop_spec s)
    simp [hnil, hr, hp, hf]

/-- `aggregate` returns a status for every slice. -/
theorem aggregate_total (s : Slice Status) : ∃ r, aggregate s = ok r := by
  obtain ⟨r, hr, _⟩ := aggregate_spec s
  exact ⟨r, hr⟩

/-- An empty set aggregates to `Unimplemented`. -/
theorem aggregate_empty (s : Slice Status) (h : s.val = []) :
    aggregate s = ok Status.Unimplemented := by
  obtain ⟨r, hr, hnil, _⟩ := aggregate_spec s
  rw [hr, hnil h]

/-- A set aggregates to `Passed` exactly when it is non-empty and every element is `Passed`. -/
theorem aggregate_passed_iff (s : Slice Status) :
    (∃ r, aggregate s = ok r) ∧
      (aggregate s = ok Status.Passed ↔
        s.val ≠ [] ∧ ∀ x ∈ s.val, x = Status.Passed) := by
  obtain ⟨r, hr, _, hp, _⟩ := aggregate_spec s
  refine ⟨⟨r, hr⟩, ?_⟩
  rw [hr, Result.ok.injEq]
  exact hp

/-- A set aggregates to `Failed` exactly when it contains `Failed`. -/
theorem aggregate_failed_iff (s : Slice Status) :
    (∃ r, aggregate s = ok r) ∧
      (aggregate s = ok Status.Failed ↔ Status.Failed ∈ s.val) := by
  obtain ⟨r, hr, _, _, hf⟩ := aggregate_spec s
  refine ⟨⟨r, hr⟩, ?_⟩
  rw [hr, Result.ok.injEq]
  exact hf

/-! ## `acceptance_satisfied` -/

/-- The strict gate always answers, and it is satisfied exactly when at least one
capability is required and every capability is `Passed`. -/
theorem acceptance_satisfied_iff (s : Slice Status) :
    (∃ b, acceptance_satisfied s = ok b) ∧
      (acceptance_satisfied s = ok true ↔
        s.val ≠ [] ∧ ∀ x ∈ s.val, x = Status.Passed) := by
  obtain ⟨r, hr, _, hp, _⟩ := aggregate_spec s
  unfold acceptance_satisfied
  rw [hr]
  simp only [bind_ok]
  rw [← hp]
  cases r <;> simp

/-- An empty requirement list never satisfies the strict gate. -/
theorem acceptance_not_satisfied_when_empty (s : Slice Status) (h : s.val = []) :
    acceptance_satisfied s = ok false := by
  unfold acceptance_satisfied
  rw [aggregate_empty s h]
  simp

end mneme_kernel.verdict
