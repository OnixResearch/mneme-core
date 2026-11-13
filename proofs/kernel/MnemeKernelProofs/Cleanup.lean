import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Retention cleanup accounting

Theorems about the Aeneas translation of `crates/mneme-kernel/src/cleanup.rs`:
the generated definitions `mneme_kernel.cleanup.*` in `MnemeKernel.lean`,
including the generated loops `physically_complete_loop` and
`summarize_loop` and their bodies.

Every statement shows that the function returns `ok`, so it neither fails nor
diverges. Slice arguments are described through their element list `s.val`.
-/

namespace mneme_kernel.cleanup

/-- A specification that holds yields the returned value. -/
private theorem ok_of_spec {α : Type} {m : Result α} {P : α → Prop} (h : m ⦃ P ⦄) :
    ∃ v, m = ok v ∧ P v := by
  cases m with
  | ret v => exact ⟨v, rfl, by simpa using h⟩
  | vis e k => simp at h
  | div => simp at h

/-- Membership in a prefix that grows by one element. -/
private theorem mem_take_succ {α : Type} (l : List α) (i : Nat) (h : i < l.length) (a : α) :
    a ∈ l.take (i + 1) ↔ a ∈ l.take i ∨ l[i] = a := by
  rw [List.take_succ_eq_append_getElem h, List.mem_append, List.mem_singleton, eq_comm]

/-- Regrouping of the disjunction maintained for the partial flag of `summarize`. -/
private theorem or_regroup {a b c d e : Prop} :
    ((a ∨ b ∨ c) ∨ d ∨ e) ↔ (a ∨ (b ∨ d) ∨ (c ∨ e)) := by
  constructor
  · rintro ((h | h | h) | h | h)
    · exact Or.inl h
    · exact Or.inr (Or.inl (Or.inl h))
    · exact Or.inr (Or.inr (Or.inl h))
    · exact Or.inr (Or.inl (Or.inr h))
    · exact Or.inr (Or.inr (Or.inr h))
  · rintro (h | (h | h) | (h | h))
    · exact Or.inl (Or.inl h)
    · exact Or.inl (Or.inr (Or.inl h))
    · exact Or.inr (Or.inl h)
    · exact Or.inl (Or.inr (Or.inr h))
    · exact Or.inr (Or.inr h)

/-! ## `is_settled` and `needs_attempt` -/

/-- `is_settled` always answers, and answers `true` exactly for purged, absent and
verified locations. -/
theorem is_settled_iff (st : LocationState) :
    (∃ b, is_settled st = ok b) ∧
      (is_settled st = ok true ↔
        st = LocationState.Purged ∨ st = LocationState.Absent ∨
          st = LocationState.Verified) := by
  cases st <;> simp [is_settled]

/-- `needs_attempt` always answers, and answers `true` exactly for pending, failed,
shared and unavailable locations. -/
theorem needs_attempt_iff (st : LocationState) :
    (∃ b, needs_attempt st = ok b) ∧
      (needs_attempt st = ok true ↔
        st = LocationState.Pending ∨ st = LocationState.Failed ∨
          st = LocationState.RetainedShared ∨ st = LocationState.Unavailable) := by
  cases st <;> simp [needs_attempt]

/-- Both functions answer for every state, and exactly one of them answers `true`:
a location is either settled or must be attempted again, never both. -/
theorem settled_or_needs_attempt (st : LocationState) :
    (∃ a, is_settled st = ok a) ∧ (∃ b, needs_attempt st = ok b) ∧
      (is_settled st = ok true ∨ needs_attempt st = ok true) ∧
      ¬ (is_settled st = ok true ∧ needs_attempt st = ok true) := by
  cases st <;> simp [is_settled, needs_attempt]

/-! ## `physically_complete` -/

/-- The generated loop of `physically_complete`, started at index 0 with a
flag that says whether the inventory is non-empty.

The invariant relates the flag to the prefix `s.val.take index`; the measure is
`s.length - index`. -/
private theorem physically_complete_loop_spec (s : Slice LocationState) (settled : Bool)
    (hinit : settled = true ↔ s.val ≠ []) :
    physically_complete_loop s settled 0#usize ⦃ r =>
      r = true ↔ s.val ≠ [] ∧ ∀ x ∈ s.val,
        x = LocationState.Purged ∨ x = LocationState.Absent ∨
          x = LocationState.Verified ⦄ := by
  unfold physically_complete_loop
  apply loop.spec_decr_nat
    (fun (p : Bool × Usize) => s.length - p.2.val)
    (fun (p : Bool × Usize) =>
      p.2.val ≤ s.length ∧
      (p.1 = true ↔ s.val ≠ [] ∧ ∀ x ∈ s.val.take p.2.val,
        x = LocationState.Purged ∨ x = LocationState.Absent ∨
          x = LocationState.Verified))
  · rintro ⟨flag, index⟩ ⟨hle, hs⟩
    simp only at hle hs ⊢
    unfold physically_complete_loop.body
    by_cases hlt : index < Slice.len s
    · have hlt' : index.val < s.length := by scalar_tac
      cases flag with
      | false =>
        simp only [hlt, ite_true, Bool.false_eq_true, ite_false, WP.spec_ok]
        refine ⟨False.elim, fun ⟨hne, hall⟩ => ?_⟩
        exact Bool.false_ne_true
          (hs.mpr ⟨hne, fun x hx => hall x (List.mem_of_mem_take hx)⟩)
      | true =>
        obtain ⟨x, hx, hxv⟩ := ok_of_spec (Slice.index_usize_spec s index hlt')
        obtain ⟨b, hb⟩ := (is_settled_iff x).1
        have hbi := (is_settled_iff x).2
        rw [hb, Result.ok.injEq] at hbi
        obtain ⟨i1, hi1, hi1v⟩ :=
          ok_of_spec (Usize.add_spec (x := index) (y := 1#usize) (by scalar_tac))
        have hi1' : i1.val = index.val + 1 := by scalar_tac
        obtain ⟨hne, hall⟩ := hs.mp rfl
        simp only [hlt, ite_true, hx, bind_ok, hb, hi1, WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        rw [hbi, hi1']
        constructor
        · intro hsx
          refine ⟨hne, fun y hy => ?_⟩
          rcases (mem_take_succ s.val index.val hlt' y).mp hy with hy | hy
          · exact hall y hy
          · rw [← hy, ← hxv]
            exact hsx
        · rintro ⟨_, hall'⟩
          rw [hxv]
          exact hall' _ ((mem_take_succ s.val index.val hlt' _).mpr (Or.inr rfl))
    · simp only [hlt, ite_false, WP.spec_ok]
      have hge : s.val.length ≤ index.val := by scalar_tac
      rw [List.take_of_length_le hge] at hs
      exact hs
  · simp [hinit]

/-- The characterization of `physically_complete` behind the public theorems. -/
private theorem physically_complete_spec (s : Slice LocationState) :
    ∃ b, physically_complete s = ok b ∧
      (b = true ↔ s.val ≠ [] ∧ ∀ x ∈ s.val,
        x = LocationState.Purged ∨ x = LocationState.Absent ∨
          x = LocationState.Verified) := by
  unfold physically_complete
  simp only [core.slice.Slice.is_empty, bind_ok]
  exact ok_of_spec (physically_complete_loop_spec s _ (by simp))

/-- `physically_complete` answers for every slice. -/
theorem physically_complete_total (s : Slice LocationState) :
    ∃ b, physically_complete s = ok b := by
  obtain ⟨b, hb, _⟩ := physically_complete_spec s
  exact ⟨b, hb⟩

/-- A cleanup is physically complete exactly when the inventory is non-empty and
every location is purged, absent or verified. -/
theorem physically_complete_iff (s : Slice LocationState) :
    (∃ b, physically_complete s = ok b) ∧
      (physically_complete s = ok true ↔
        s.val ≠ [] ∧ ∀ x ∈ s.val,
          x = LocationState.Purged ∨ x = LocationState.Absent ∨
            x = LocationState.Verified) := by
  obtain ⟨b, hb, hiff⟩ := physically_complete_spec s
  refine ⟨⟨b, hb⟩, ?_⟩
  rw [hb, Result.ok.injEq]
  exact hiff

/-- An empty inventory is never complete. -/
theorem physical_cleanup_incomplete_when_empty (s : Slice LocationState) (h : s.val = []) :
    physically_complete s = ok false := by
  obtain ⟨b, hb, hiff⟩ := physically_complete_spec s
  rw [hb]
  cases b with
  | false => rfl
  | true => exact absurd h (hiff.mp rfl).1

/-! ## `summarize` -/

/-- One iteration of the generated `summarize` loop body below the slice length:
it continues with the next index and with each flag raised exactly when it was
already raised or the element at the index raises it. -/
private theorem summarize_loop_body_cont (s : Slice LocationState)
    (pending failed part : Bool) (index : Usize) (hlt : index.val < s.length) :
    ∃ p1 f1 q1 i1,
      summarize_loop.body s pending failed part index =
        ok (ControlFlow.cont (p1, f1, q1, i1)) ∧
      i1.val = index.val + 1 ∧
      (p1 = true ↔ pending = true ∨ s.val[index.val] = LocationState.Pending) ∧
      (f1 = true ↔ failed = true ∨ s.val[index.val] = LocationState.Failed) ∧
      (q1 = true ↔ part = true ∨ s.val[index.val] = LocationState.RetainedShared ∨
        s.val[index.val] = LocationState.Unavailable) := by
  obtain ⟨x, hx, hxv⟩ := ok_of_spec (Slice.index_usize_spec s index hlt)
  obtain ⟨i1, hi1, hi1v⟩ :=
    ok_of_spec (Usize.add_spec (x := index) (y := 1#usize) (by scalar_tac))
  have hi1' : i1.val = index.val + 1 := by scalar_tac
  have hlt' : index < Slice.len s := by scalar_tac
  unfold summarize_loop.body
  simp only [hlt', ite_true, hx, bind_ok, hi1]
  rw [← hxv]
  cases pending <;> cases failed <;> cases part <;> cases x <;> simp [hi1']

/-- The generated loop of `summarize`, started at index 0 with the pending and
failed flags lowered and a partial flag that says whether the inventory is empty.

The invariant relates the three flags to the prefix `s.val.take index`; the
measure is `s.length - index`. -/
private theorem summarize_loop_spec (s : Slice LocationState) (part : Bool)
    (hinit : part = true ↔ s.val = []) :
    summarize_loop s false false part 0#usize ⦃ r =>
      (r.1 = true ↔ LocationState.Pending ∈ s.val) ∧
      (r.2.1 = true ↔ LocationState.Failed ∈ s.val) ∧
      (r.2.2 = true ↔ s.val = [] ∨ LocationState.RetainedShared ∈ s.val ∨
        LocationState.Unavailable ∈ s.val) ⦄ := by
  unfold summarize_loop
  apply loop.spec_decr_nat
    (fun (p : Bool × Bool × Bool × Usize) => s.length - p.2.2.2.val)
    (fun (p : Bool × Bool × Bool × Usize) =>
      p.2.2.2.val ≤ s.length ∧
      (p.1 = true ↔ LocationState.Pending ∈ s.val.take p.2.2.2.val) ∧
      (p.2.1 = true ↔ LocationState.Failed ∈ s.val.take p.2.2.2.val) ∧
      (p.2.2.1 = true ↔ s.val = [] ∨
        LocationState.RetainedShared ∈ s.val.take p.2.2.2.val ∨
        LocationState.Unavailable ∈ s.val.take p.2.2.2.val))
  · rintro ⟨pending, failed, flag, index⟩ ⟨hle, hp, hf, hq⟩
    simp only at hle hp hf hq ⊢
    by_cases hlt : index.val < s.length
    · obtain ⟨p1, f1, q1, i1, hbody, hi1, hp1, hf1, hq1⟩ :=
        summarize_loop_body_cont s pending failed flag index hlt
      rw [hbody]
      simp only [WP.spec_ok]
      refine ⟨⟨by omega, ?_, ?_, ?_⟩, by omega⟩
      · rw [hp1, hp, hi1, mem_take_succ _ _ hlt]
      · rw [hf1, hf, hi1, mem_take_succ _ _ hlt]
      · rw [hq1, hq, hi1, mem_take_succ _ _ hlt, mem_take_succ _ _ hlt]
        exact or_regroup
    · have hge : s.val.length ≤ index.val := Nat.le_of_not_lt hlt
      have hnlt : ¬ index < Slice.len s := by scalar_tac
      unfold summarize_loop.body
      simp only [hnlt, ite_false, WP.spec_ok]
      rw [List.take_of_length_le hge] at hp hf hq
      exact ⟨hp, hf, hq⟩
  · simp [hinit]

/-- Every element is settled exactly when no unsettled state occurs. -/
private theorem all_settled_iff (l : List LocationState) :
    (∀ x ∈ l, x = LocationState.Purged ∨ x = LocationState.Absent ∨
        x = LocationState.Verified) ↔
      LocationState.Pending ∉ l ∧ LocationState.Failed ∉ l ∧
        LocationState.RetainedShared ∉ l ∧ LocationState.Unavailable ∉ l := by
  constructor
  · intro h
    refine ⟨?_, ?_, ?_, ?_⟩ <;> intro hm <;> simpa using h _ hm
  · rintro ⟨hp, hf, hr, hu⟩ x hx
    cases x <;> simp_all

/-- The characterization of `summarize` behind the public theorems. -/
private theorem summarize_spec (s : Slice LocationState) :
    ∃ r, summarize s = ok r ∧
      (r = JobSummary.Pending ↔ LocationState.Pending ∈ s.val) ∧
      (r = JobSummary.Failed ↔
        LocationState.Failed ∈ s.val ∧ LocationState.Pending ∉ s.val) ∧
      (r = JobSummary.Partial ↔
        LocationState.Pending ∉ s.val ∧ LocationState.Failed ∉ s.val ∧
          (s.val = [] ∨ LocationState.RetainedShared ∈ s.val ∨
            LocationState.Unavailable ∈ s.val)) ∧
      (r = JobSummary.Complete ↔
        LocationState.Pending ∉ s.val ∧ LocationState.Failed ∉ s.val ∧
          ¬ (s.val = [] ∨ LocationState.RetainedShared ∈ s.val ∨
            LocationState.Unavailable ∈ s.val)) := by
  unfold summarize
  simp only [core.slice.Slice.is_empty, bind_ok]
  obtain ⟨⟨pending, failed, flag⟩, hloop, hp, hf, hq⟩ :=
    ok_of_spec (summarize_loop_spec s (decide (s.length = 0)) (by simp))
  simp only at hp hf hq
  rw [hloop]
  simp only [bind_ok, uncurry_apply_pair]
  cases pending <;> cases failed <;> cases flag <;> simp_all

/-- `summarize` returns a summary for every slice. -/
theorem summarize_total (s : Slice LocationState) : ∃ r, summarize s = ok r := by
  obtain ⟨r, hr, _⟩ := summarize_spec s
  exact ⟨r, hr⟩

/-- A job is summarized as `Complete` exactly when its cleanup is physically complete. -/
theorem summarize_complete_iff (s : Slice LocationState) :
    (∃ r, summarize s = ok r) ∧ (∃ b, physically_complete s = ok b) ∧
      (summarize s = ok JobSummary.Complete ↔
        physically_complete s = ok true) := by
  obtain ⟨r, hr, _, _, _, hc⟩ := summarize_spec s
  obtain ⟨b, hb, hiff⟩ := physically_complete_spec s
  refine ⟨⟨r, hr⟩, ⟨b, hb⟩, ?_⟩
  rw [hr, hb, Result.ok.injEq, Result.ok.injEq, hc, hiff, all_settled_iff]
  constructor
  · rintro ⟨hp, hf, hn⟩
    exact ⟨fun h => hn (Or.inl h), hp, hf, fun h => hn (Or.inr (Or.inl h)),
      fun h => hn (Or.inr (Or.inr h))⟩
  · rintro ⟨hne, hp, hf, hrs, hu⟩
    exact ⟨hp, hf, fun h => h.elim hne (fun h => h.elim hrs hu)⟩

/-- A job is summarized as `Pending` exactly when some location is pending. -/
theorem summarize_pending_iff (s : Slice LocationState) :
    (∃ r, summarize s = ok r) ∧
      (summarize s = ok JobSummary.Pending ↔ LocationState.Pending ∈ s.val) := by
  obtain ⟨r, hr, hp, _⟩ := summarize_spec s
  refine ⟨⟨r, hr⟩, ?_⟩
  rw [hr, Result.ok.injEq]
  exact hp

/-- A job is summarized as `Failed` exactly when some location failed and none is
pending. -/
theorem summarize_failed_iff (s : Slice LocationState) :
    (∃ r, summarize s = ok r) ∧
      (summarize s = ok JobSummary.Failed ↔
        LocationState.Failed ∈ s.val ∧ LocationState.Pending ∉ s.val) := by
  obtain ⟨r, hr, _, hf, _⟩ := summarize_spec s
  refine ⟨⟨r, hr⟩, ?_⟩
  rw [hr, Result.ok.injEq]
  exact hf

/-- A job is summarized as `Partial` exactly when no location is pending or failed
and the inventory is empty or holds a shared or unavailable location. -/
theorem summarize_partial_iff (s : Slice LocationState) :
    (∃ r, summarize s = ok r) ∧
      (summarize s = ok JobSummary.Partial ↔
        LocationState.Pending ∉ s.val ∧ LocationState.Failed ∉ s.val ∧
          (s.val = [] ∨ LocationState.RetainedShared ∈ s.val ∨
            LocationState.Unavailable ∈ s.val)) := by
  obtain ⟨r, hr, _, _, hq, _⟩ := summarize_spec s
  refine ⟨⟨r, hr⟩, ?_⟩
  rw [hr, Result.ok.injEq]
  exact hq

end mneme_kernel.cleanup
