import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Hybrid Logical Clock (HLC) transition rules and drift guards

Theorems about the generated translation of `crates/mneme-kernel/src/hlc.rs`.
Proves total execution, strict lexicographic ordering, causal monotonicity of
`tick_local` and `receive` (`e → f ⟹ hlc(e) < hlc(f)`), bounded physical drift
(`pt ≤ next.physical_ns ≤ pt + max_skew`), and fail-closed Byzantine clock-skew
rejection (`|remote.physical_ns - pt| > max_skew ⟹ Err(ClockSkewExceeded)`).
-/

namespace mneme_kernel.hlc

private theorem ok_bind {α β : Type} (x : α) (f : α → Result β) :
    (do let y ← ok x; f y) = f x := by
  simp

private theorem spec_imp_exists {α : Type} {m : Result α} {p : α → Prop}
    (h : WP.spec m p) : ∃ v, m = ok v ∧ p v := by
  cases m with
  | ret r => exact ⟨r, rfl, by simpa using h⟩
  | vis i k => simp at h
  | div => simp at h

private theorem i64_sub_eq {a b : I64}
    (hmin : I64.min ≤ a.val - b.val) (hmax : a.val - b.val ≤ I64.max) :
    ∃ r, a - b = ok r ∧ r.val = a.val - b.val :=
  spec_imp_exists (I64.sub_spec hmin hmax)

private theorem i64_add_eq {a b : I64}
    (hmin : I64.min ≤ a.val + b.val) (hmax : a.val + b.val ≤ I64.max) :
    ∃ r, a + b = ok r ∧ r.val = a.val + b.val :=
  spec_imp_exists (I64.add_spec hmin hmax)

private theorem u32_add_one_eq {a : U32} (h : a.val < U32.max) :
    ∃ r, a + 1#u32 = ok r ∧ r.val = a.val + 1 := by
  have hbound : a.val + (1#u32).val ≤ U32.max := by scalar_tac
  obtain ⟨r, hr, hv⟩ := spec_imp_exists (U32.add_spec hbound)
  exact ⟨r, hr, by simpa using hv⟩

private theorem i64_max_val : core.num.I64.MAX.val = I64.max := by
  simp [core.num.I64.MAX, I64.max, I64.rMax, I64.numBits]

private theorem u32_max_val : core.num.U32.MAX.val = U32.max := by
  simp [core.num.U32.MAX, U32.max, U32.rMax, U32.numBits]

private theorem u32_lt_max_of_ne {x : U32} (hne : x ≠ core.num.U32.MAX) :
    x.val < U32.max := by
  have hval_ne : x.val ≠ U32.max := by
    intro heq
    apply hne
    rw [UScalar.eq_equiv, u32_max_val]
    exact heq
  scalar_tac

/-! ## `compare`, `is_before`, and `is_at_or_before` -/

/-- `compare` never fails or diverges. -/
theorem compare_total (left right : HybridTimestamp) :
    ∃ ord, compare left right = ok ord := by
  unfold compare
  split_ifs <;> exact ⟨_, rfl⟩

/-- `compare` returns `Equal` iff both components are equal. -/
theorem compare_eq_iff (left right : HybridTimestamp) :
    compare left right = ok ClockOrder.Equal ↔ left = right := by
  obtain ⟨lp, ll⟩ := left
  obtain ⟨rp, rl⟩ := right
  unfold compare
  dsimp only
  split_ifs with h1 h2 h3 h4
  · rw [Result.ok.injEq]; constructor
    · intro h; cases h
    · intro h; injection h with hp _; subst hp; exfalso; scalar_tac
  · rw [Result.ok.injEq]; constructor
    · intro h; cases h
    · intro h; injection h with hp _; subst hp; exfalso; scalar_tac
  · rw [Result.ok.injEq]; constructor
    · intro h; cases h
    · intro h; injection h with _ hl; subst hl; exfalso; scalar_tac
  · rw [Result.ok.injEq]; constructor
    · intro h; cases h
    · intro h; injection h with _ hl; subst hl; exfalso; scalar_tac
  · rw [Result.ok.injEq]; constructor
    · intro _
      have hp : lp = rp := by rw [IScalar.eq_equiv]; scalar_tac
      have hl : ll = rl := by rw [UScalar.eq_equiv]; scalar_tac
      subst hp; subst hl; rfl
    · intro _; rfl

/-- `is_before` never fails or diverges. -/
theorem is_before_total (left right : HybridTimestamp) :
    ∃ b, is_before left right = ok b := by
  obtain ⟨ord, hord⟩ := compare_total left right
  cases ord
  · exact ⟨true, by simp [is_before, hord]⟩
  · exact ⟨false, by simp [is_before, hord]⟩
  · exact ⟨false, by simp [is_before, hord]⟩

/-- `is_before` holds exactly for strict lexicographic order `(physical_ns, logical)`. -/
theorem is_before_iff (left right : HybridTimestamp) :
    is_before left right = ok true ↔
      left.physical_ns.val < right.physical_ns.val ∨
        (left.physical_ns.val = right.physical_ns.val ∧ left.logical.val < right.logical.val) := by
  unfold is_before compare
  split_ifs with h1 h2 h3 h4
  · simp; left; scalar_tac
  · simp; scalar_tac
  · simp; right; exact ⟨by scalar_tac, by scalar_tac⟩
  · simp; scalar_tac
  · simp; scalar_tac

/-- `is_before` is irreflexive. -/
theorem is_before_irrefl (ts : HybridTimestamp) :
    is_before ts ts = ok false := by
  unfold is_before compare
  simp

/-- `is_before` is transitive. -/
theorem is_before_trans (a b c : HybridTimestamp)
    (hab : is_before a b = ok true) (hbc : is_before b c = ok true) :
    is_before a c = ok true := by
  rw [is_before_iff] at hab hbc ⊢
  omega

/-- `is_at_or_before` never fails or diverges. -/
theorem is_at_or_before_total (left right : HybridTimestamp) :
    ∃ b, is_at_or_before left right = ok b := by
  obtain ⟨ord, hord⟩ := compare_total left right
  cases ord
  · exact ⟨true, by simp [is_at_or_before, hord]⟩
  · exact ⟨true, by simp [is_at_or_before, hord]⟩
  · exact ⟨false, by simp [is_at_or_before, hord]⟩

/-- `is_at_or_before` holds exactly for non-strict lexicographic order. -/
theorem is_at_or_before_iff (left right : HybridTimestamp) :
    is_at_or_before left right = ok true ↔
      left.physical_ns.val < right.physical_ns.val ∨
        (left.physical_ns.val = right.physical_ns.val ∧ left.logical.val ≤ right.logical.val) := by
  unfold is_at_or_before compare
  split_ifs with h1 h2 h3 h4
  · simp; left; scalar_tac
  · simp; scalar_tac
  · simp; right; exact ⟨by scalar_tac, by scalar_tac⟩
  · simp; scalar_tac
  · simp; right; exact ⟨by scalar_tac, by scalar_tac⟩

/-! ## `within_skew` -/

private theorem within_skew_eval (sample_ns reference_ns max_skew_ns : I64) :
    within_skew sample_ns reference_ns max_skew_ns =
      ok (decide (0 ≤ max_skew_ns.val ∧
        sample_ns.val - reference_ns.val ≤ max_skew_ns.val ∧
        reference_ns.val - sample_ns.val ≤ max_skew_ns.val)) := by
  unfold within_skew
  by_cases hneg : max_skew_ns < 0#i64
  · have hneg' : max_skew_ns.val < 0 := by scalar_tac
    have hfalse : ¬ (0 ≤ max_skew_ns.val ∧
        sample_ns.val - reference_ns.val ≤ max_skew_ns.val ∧
        reference_ns.val - sample_ns.val ≤ max_skew_ns.val) := by omega
    rw [decide_eq_false hfalse]
    simp [hneg]
  · have hnonneg : 0 ≤ max_skew_ns.val := by scalar_tac
    have hmax_eq := i64_max_val
    have hc_min : I64.min ≤ core.num.I64.MAX.val - max_skew_ns.val := by scalar_tac
    have hc_max : core.num.I64.MAX.val - max_skew_ns.val ≤ I64.max := by scalar_tac
    obtain ⟨ceiling, hceil, hceil_val⟩ := i64_sub_eq hc_min hc_max
    simp only [hneg, ite_false]
    rw [hceil, ok_bind]
    by_cases hrc : reference_ns ≤ ceiling
    · have hadd_min : I64.min ≤ reference_ns.val + max_skew_ns.val := by scalar_tac
      have hadd_max : reference_ns.val + max_skew_ns.val ≤ I64.max := by scalar_tac
      obtain ⟨upper, hupper, hupper_val⟩ := i64_add_eq hadd_min hadd_max
      simp only [hrc, ite_true]
      rw [hupper, ok_bind]
      by_cases hsu : sample_ns > upper
      · have hnot : ¬ (0 ≤ max_skew_ns.val ∧
            sample_ns.val - reference_ns.val ≤ max_skew_ns.val ∧
            reference_ns.val - sample_ns.val ≤ max_skew_ns.val) := by scalar_tac
        rw [decide_eq_false hnot]
        simp [hsu]
      · have hok1 : sample_ns.val - reference_ns.val ≤ max_skew_ns.val := by scalar_tac
        simp only [hsu, ite_false]
        by_cases hsc : sample_ns ≤ ceiling
        · have hadd2_min : I64.min ≤ sample_ns.val + max_skew_ns.val := by scalar_tac
          have hadd2_max : sample_ns.val + max_skew_ns.val ≤ I64.max := by scalar_tac
          obtain ⟨lower, hlower, hlower_val⟩ := i64_add_eq hadd2_min hadd2_max
          simp only [hsc, ite_true]
          rw [hlower, ok_bind]
          by_cases hrl : reference_ns > lower
          · have hnot : ¬ (0 ≤ max_skew_ns.val ∧
                sample_ns.val - reference_ns.val ≤ max_skew_ns.val ∧
                reference_ns.val - sample_ns.val ≤ max_skew_ns.val) := by scalar_tac
            rw [decide_eq_false hnot]
            simp [hrl]
          · have hok2 : reference_ns.val - sample_ns.val ≤ max_skew_ns.val := by scalar_tac
            have hall : 0 ≤ max_skew_ns.val ∧
                sample_ns.val - reference_ns.val ≤ max_skew_ns.val ∧
                reference_ns.val - sample_ns.val ≤ max_skew_ns.val := ⟨hnonneg, hok1, hok2⟩
            rw [decide_eq_true hall]
            simp [hrl]
        · have hok2 : reference_ns.val - sample_ns.val ≤ max_skew_ns.val := by scalar_tac
          have hall : 0 ≤ max_skew_ns.val ∧
              sample_ns.val - reference_ns.val ≤ max_skew_ns.val ∧
              reference_ns.val - sample_ns.val ≤ max_skew_ns.val := ⟨hnonneg, hok1, hok2⟩
          rw [decide_eq_true hall]
          simp [hsc]
    · have hok1 : sample_ns.val - reference_ns.val ≤ max_skew_ns.val := by scalar_tac
      simp only [hrc, ite_false]
      by_cases hsc : sample_ns ≤ ceiling
      · have hadd2_min : I64.min ≤ sample_ns.val + max_skew_ns.val := by scalar_tac
        have hadd2_max : sample_ns.val + max_skew_ns.val ≤ I64.max := by scalar_tac
        obtain ⟨lower, hlower, hlower_val⟩ := i64_add_eq hadd2_min hadd2_max
        simp only [hsc, ite_true]
        rw [hlower, ok_bind]
        by_cases hrl : reference_ns > lower
        · have hnot : ¬ (0 ≤ max_skew_ns.val ∧
              sample_ns.val - reference_ns.val ≤ max_skew_ns.val ∧
              reference_ns.val - sample_ns.val ≤ max_skew_ns.val) := by scalar_tac
          rw [decide_eq_false hnot]
          simp [hrl]
        · have hok2 : reference_ns.val - sample_ns.val ≤ max_skew_ns.val := by scalar_tac
          have hall : 0 ≤ max_skew_ns.val ∧
              sample_ns.val - reference_ns.val ≤ max_skew_ns.val ∧
              reference_ns.val - sample_ns.val ≤ max_skew_ns.val := ⟨hnonneg, hok1, hok2⟩
          rw [decide_eq_true hall]
          simp [hrl]
      · have hok2 : reference_ns.val - sample_ns.val ≤ max_skew_ns.val := by scalar_tac
        have hall : 0 ≤ max_skew_ns.val ∧
            sample_ns.val - reference_ns.val ≤ max_skew_ns.val ∧
            reference_ns.val - sample_ns.val ≤ max_skew_ns.val := ⟨hnonneg, hok1, hok2⟩
        rw [decide_eq_true hall]
        simp [hsc]

/-- `within_skew` never fails or diverges. -/
theorem within_skew_total (sample_ns reference_ns max_skew_ns : I64) :
    ∃ ok_skew, within_skew sample_ns reference_ns max_skew_ns = ok ok_skew :=
  ⟨_, within_skew_eval sample_ns reference_ns max_skew_ns⟩

/-- `within_skew` holds iff `max_skew_ns ≥ 0` and `|sample_ns - reference_ns| ≤ max_skew_ns`. -/
theorem within_skew_iff (sample_ns reference_ns max_skew_ns : I64) :
    within_skew sample_ns reference_ns max_skew_ns = ok true ↔
      0 ≤ max_skew_ns.val ∧
        sample_ns.val - reference_ns.val ≤ max_skew_ns.val ∧
        reference_ns.val - sample_ns.val ≤ max_skew_ns.val := by
  rw [within_skew_eval]
  simp

/-- `within_skew` is symmetric in `sample_ns` and `reference_ns`. -/
theorem within_skew_symm (a b max_skew_ns : I64) :
    within_skew a b max_skew_ns = within_skew b a max_skew_ns := by
  rw [within_skew_eval, within_skew_eval]
  congr 1
  by_cases h0 : 0 ≤ max_skew_ns.val <;>
    by_cases h1 : a.val - b.val ≤ max_skew_ns.val <;>
    by_cases h2 : b.val - a.val ≤ max_skew_ns.val <;>
    simp [h0, h1, h2]

/-! ## `tick_local` -/

/-- `tick_local` never fails or diverges. -/
theorem tick_local_total (last : HybridTimestamp) (physical_ns max_skew_ns : I64) :
    ∃ res, tick_local last physical_ns max_skew_ns = ok res := by
  unfold tick_local
  by_cases hneg : max_skew_ns < 0#i64
  · exact ⟨core.result.Result.Err HlcError.InvalidMaxSkew, by simp [hneg]⟩
  · by_cases hgt : physical_ns > last.physical_ns
    · exact ⟨core.result.Result.Ok { physical_ns, logical := 0#u32 }, by simp [hneg, hgt]⟩
    · obtain ⟨b, hb⟩ := within_skew_total last.physical_ns physical_ns max_skew_ns
      cases b
      · exact ⟨core.result.Result.Err HlcError.ClockSkewExceeded, by simp [hneg, hgt, hb]⟩
      · by_cases hmax : last.logical = core.num.U32.MAX
        · exact ⟨core.result.Result.Err HlcError.LogicalOverflow, by simp [hneg, hgt, hb, hmax]⟩
        · obtain ⟨inc, hinc, _⟩ := u32_add_one_eq (u32_lt_max_of_ne hmax)
          exact ⟨core.result.Result.Ok { last with logical := inc },
            by simp [hneg, hgt, hb, hmax, hinc]⟩

/-- Causal monotonicity of `tick_local`: every accepted local tick strictly advances the HLC. -/
theorem tick_local_causal_monotonic
    (last next : HybridTimestamp) (physical_ns max_skew_ns : I64)
    (h : tick_local last physical_ns max_skew_ns = ok (core.result.Result.Ok next)) :
    is_before last next = ok true := by
  unfold tick_local at h
  by_cases hneg : max_skew_ns < 0#i64
  · simp [hneg] at h
  · by_cases hgt : physical_ns > last.physical_ns
    · simp [hneg, hgt] at h
      subst h
      rw [is_before_iff]
      left
      scalar_tac
    · obtain ⟨b, hb⟩ := within_skew_total last.physical_ns physical_ns max_skew_ns
      cases b
      · simp [hneg, hgt, hb] at h
      · by_cases hmax : last.logical = core.num.U32.MAX
        · simp [hneg, hgt, hb, hmax] at h
        · obtain ⟨inc, hinc, hinc_val⟩ := u32_add_one_eq (u32_lt_max_of_ne hmax)
          simp [hneg, hgt, hb, hmax, hinc] at h
          subst h
          rw [is_before_iff]
          right
          exact ⟨rfl, by simp [hinc_val]⟩

/-- Bounded physical drift of `tick_local`: `physical_ns ≤ next.physical_ns ≤ physical_ns + max_skew_ns`. -/
theorem tick_local_bounded_drift
    (last next : HybridTimestamp) (physical_ns max_skew_ns : I64)
    (h : tick_local last physical_ns max_skew_ns = ok (core.result.Result.Ok next)) :
    physical_ns.val ≤ next.physical_ns.val ∧
      next.physical_ns.val - physical_ns.val ≤ max_skew_ns.val := by
  unfold tick_local at h
  by_cases hneg : max_skew_ns < 0#i64
  · simp [hneg] at h
  · have hnonneg : 0 ≤ max_skew_ns.val := by scalar_tac
    by_cases hgt : physical_ns > last.physical_ns
    · simp [hneg, hgt] at h
      subst h
      exact ⟨le_refl _, by simp; omega⟩
    · obtain ⟨b, hb⟩ := within_skew_total last.physical_ns physical_ns max_skew_ns
      cases b
      · simp [hneg, hgt, hb] at h
      · have hsk := (within_skew_iff last.physical_ns physical_ns max_skew_ns).mp hb
        by_cases hmax : last.logical = core.num.U32.MAX
        · simp [hneg, hgt, hb, hmax] at h
        · obtain ⟨inc, hinc, _⟩ := u32_add_one_eq (u32_lt_max_of_ne hmax)
          simp [hneg, hgt, hb, hmax, hinc] at h
          subst h
          exact ⟨by scalar_tac, hsk.2.1⟩

/-! ## `receive` -/

/-- `receive` never fails or diverges. -/
theorem receive_total (last : HybridTimestamp) (physical_ns : I64)
    (remote : HybridTimestamp) (max_skew_ns : I64) :
    ∃ res, receive last physical_ns remote max_skew_ns = ok res := by
  unfold receive
  by_cases hneg : max_skew_ns < 0#i64
  · exact ⟨core.result.Result.Err HlcError.InvalidMaxSkew, by simp [hneg]⟩
  · obtain ⟨b, hb⟩ := within_skew_total remote.physical_ns physical_ns max_skew_ns
    cases b
    · exact ⟨core.result.Result.Err HlcError.ClockSkewExceeded, by simp [hneg, hb]⟩
    · set max_lr : I64 :=
        if last.physical_ns ≥ remote.physical_ns then last.physical_ns else remote.physical_ns
      set next_p : I64 := if max_lr ≥ physical_ns then max_lr else physical_ns
      have hlr : (if last.physical_ns ≥ remote.physical_ns then ok last.physical_ns
          else ok remote.physical_ns) = ok max_lr := by
        by_cases hc : last.physical_ns ≥ remote.physical_ns <;> simp [max_lr, hc]
      have hnp : (if max_lr ≥ physical_ns then ok max_lr else ok physical_ns) = ok next_p := by
        by_cases hc : max_lr ≥ physical_ns <;> simp [next_p, hc]
      simp only [hneg, ite_false]
      rw [hb, ok_bind]
      simp only [ite_true]
      rw [hlr, ok_bind, hnp, ok_bind]
      obtain ⟨b1, hb1⟩ := within_skew_total next_p physical_ns max_skew_ns
      cases b1
      · exact ⟨core.result.Result.Err HlcError.ClockSkewExceeded, by rw [hb1, ok_bind]; rfl⟩
      · rw [hb1, ok_bind]
        simp only [ite_true]
        by_cases heq_l : next_p = last.physical_ns
        · simp only [heq_l, ite_true]
          by_cases heq_r : last.physical_ns = remote.physical_ns
          · set max_log : U32 :=
              if last.logical ≥ remote.logical then last.logical else remote.logical
            have hml : (if last.logical ≥ remote.logical then ok last.logical
                else ok remote.logical) = ok max_log := by
              by_cases hc : last.logical ≥ remote.logical <;> simp [max_log, hc]
            simp only [heq_r, ite_true]
            rw [hml, ok_bind]
            by_cases hmax : max_log = core.num.U32.MAX
            · exact ⟨core.result.Result.Err HlcError.LogicalOverflow, by simp [hmax]⟩
            · obtain ⟨inc, hinc, _⟩ := u32_add_one_eq (u32_lt_max_of_ne hmax)
              exact ⟨core.result.Result.Ok { physical_ns := remote.physical_ns, logical := inc },
                by simp [hmax, hinc]⟩
          · simp only [heq_r, ite_false]
            by_cases hmax : last.logical = core.num.U32.MAX
            · exact ⟨core.result.Result.Err HlcError.LogicalOverflow, by simp [hmax]⟩
            · obtain ⟨inc, hinc, _⟩ := u32_add_one_eq (u32_lt_max_of_ne hmax)
              exact ⟨core.result.Result.Ok { physical_ns := last.physical_ns, logical := inc },
                by simp [hmax, hinc]⟩
        · simp only [heq_l, ite_false]
          by_cases heq_r : next_p = remote.physical_ns
          · simp only [heq_r, ite_true]
            by_cases hmax : remote.logical = core.num.U32.MAX
            · exact ⟨core.result.Result.Err HlcError.LogicalOverflow, by simp [hmax]⟩
            · obtain ⟨inc, hinc, _⟩ := u32_add_one_eq (u32_lt_max_of_ne hmax)
              exact ⟨core.result.Result.Ok { physical_ns := remote.physical_ns, logical := inc },
                by simp [hmax, hinc]⟩
          · exact ⟨core.result.Result.Ok { physical_ns := next_p, logical := 0#u32 },
              by simp [heq_r]⟩

/-- Fail-closed Byzantine future/past clock-skew guard: when `max_skew_ns ≥ 0` and
`remote.physical_ns` is outside `max_skew_ns` of `physical_ns`, `receive` immediately
returns `Err(HlcError.ClockSkewExceeded)`. -/
theorem receive_rejects_excessive_skew (last : HybridTimestamp) (physical_ns : I64)
    (remote : HybridTimestamp) (max_skew_ns : I64)
    (hnonneg : 0 ≤ max_skew_ns.val)
    (hskew : within_skew remote.physical_ns physical_ns max_skew_ns = ok false) :
    receive last physical_ns remote max_skew_ns =
      ok (core.result.Result.Err HlcError.ClockSkewExceeded) := by
  have hneg : ¬ max_skew_ns < 0#i64 := by scalar_tac
  unfold receive
  simp [hneg, hskew]

/-- Causal monotonicity of `receive`: every accepted receive event strictly advances
past BOTH the local predecessor `last` and the causal sender `remote`. -/
theorem receive_causal_monotonic (last next : HybridTimestamp) (physical_ns : I64)
    (remote : HybridTimestamp) (max_skew_ns : I64)
    (h : receive last physical_ns remote max_skew_ns = ok (core.result.Result.Ok next)) :
    is_before last next = ok true ∧ is_before remote next = ok true := by
  unfold receive at h
  by_cases hneg : max_skew_ns < 0#i64
  · simp [hneg] at h
  · obtain ⟨b, hb⟩ := within_skew_total remote.physical_ns physical_ns max_skew_ns
    cases b
    · simp [hneg, hb] at h
    · set max_lr : I64 :=
        if last.physical_ns ≥ remote.physical_ns then last.physical_ns else remote.physical_ns
      set next_p : I64 := if max_lr ≥ physical_ns then max_lr else physical_ns
      have hlr : (if last.physical_ns ≥ remote.physical_ns then ok last.physical_ns
          else ok remote.physical_ns) = ok max_lr := by
        by_cases hc : last.physical_ns ≥ remote.physical_ns <;> simp [max_lr, hc]
      have hnp : (if max_lr ≥ physical_ns then ok max_lr else ok physical_ns) = ok next_p := by
        by_cases hc : max_lr ≥ physical_ns <;> simp [next_p, hc]
      have hge_last : last.physical_ns.val ≤ next_p.val := by
        dsimp [next_p, max_lr]; split_ifs <;> scalar_tac
      have hge_rem : remote.physical_ns.val ≤ next_p.val := by
        dsimp [next_p, max_lr]; split_ifs <;> scalar_tac
      simp only [hneg, ite_false] at h
      rw [hb, ok_bind] at h
      simp only [ite_true] at h
      rw [hlr, ok_bind, hnp, ok_bind] at h
      obtain ⟨b1, hb1⟩ := within_skew_total next_p physical_ns max_skew_ns
      cases b1
      · rw [hb1, ok_bind] at h; simp at h
      · rw [hb1, ok_bind] at h
        simp only [ite_true] at h
        by_cases heq_l : next_p = last.physical_ns
        · simp only [heq_l, ite_true] at h
          by_cases heq_r : last.physical_ns = remote.physical_ns
          · set max_log : U32 :=
              if last.logical ≥ remote.logical then last.logical else remote.logical
            have hml : (if last.logical ≥ remote.logical then ok last.logical
                else ok remote.logical) = ok max_log := by
              by_cases hc : last.logical ≥ remote.logical <;> simp [max_log, hc]
            have hml_l : last.logical.val ≤ max_log.val := by
              dsimp [max_log]; split_ifs <;> scalar_tac
            have hml_r : remote.logical.val ≤ max_log.val := by
              dsimp [max_log]; split_ifs <;> scalar_tac
            simp only [heq_r, ite_true] at h
            rw [hml, ok_bind] at h
            by_cases hmax : max_log = core.num.U32.MAX
            · simp [hmax] at h
            · obtain ⟨inc, hinc, hinc_val⟩ := u32_add_one_eq (u32_lt_max_of_ne hmax)
              simp [hmax, hinc] at h
              subst h
              rw [is_before_iff, is_before_iff]
              exact ⟨Or.inr ⟨by rw [heq_r], by dsimp only; omega⟩, Or.inr ⟨rfl, by dsimp only; omega⟩⟩
          · simp only [heq_r, ite_false] at h
            by_cases hmax : last.logical = core.num.U32.MAX
            · simp [hmax] at h
            · obtain ⟨inc, hinc, hinc_val⟩ := u32_add_one_eq (u32_lt_max_of_ne hmax)
              simp [hmax, hinc] at h
              subst h
              have hlt_r : remote.physical_ns.val < last.physical_ns.val := by
                have hne : last.physical_ns.val ≠ remote.physical_ns.val := fun heq =>
                  heq_r ((IScalar.eq_equiv _ _).mpr heq)
                rw [heq_l] at hge_rem
                omega
              rw [is_before_iff, is_before_iff]
              exact ⟨Or.inr ⟨rfl, by dsimp only; omega⟩, Or.inl hlt_r⟩
        · simp only [heq_l, ite_false] at h
          by_cases heq_r : next_p = remote.physical_ns
          · simp only [heq_r, ite_true] at h
            by_cases hmax : remote.logical = core.num.U32.MAX
            · simp [hmax] at h
            · obtain ⟨inc, hinc, hinc_val⟩ := u32_add_one_eq (u32_lt_max_of_ne hmax)
              simp [hmax, hinc] at h
              subst h
              have hlt_l : last.physical_ns.val < remote.physical_ns.val := by
                have hne : next_p.val ≠ last.physical_ns.val := fun heq =>
                  heq_l ((IScalar.eq_equiv _ _).mpr heq)
                rw [heq_r] at hge_last hne
                omega
              rw [is_before_iff, is_before_iff]
              exact ⟨Or.inl hlt_l, Or.inr ⟨rfl, by dsimp only; omega⟩⟩
          · simp [heq_r] at h
            subst h
            have hlt_l : last.physical_ns.val < next_p.val := by
              have hne : next_p.val ≠ last.physical_ns.val := fun heq =>
                heq_l ((IScalar.eq_equiv _ _).mpr heq)
              omega
            have hlt_r : remote.physical_ns.val < next_p.val := by
              have hne : next_p.val ≠ remote.physical_ns.val := fun heq =>
                heq_r ((IScalar.eq_equiv _ _).mpr heq)
              omega
            rw [is_before_iff, is_before_iff]
            exact ⟨Or.inl hlt_l, Or.inl hlt_r⟩

/-- Bounded physical drift of `receive`: `physical_ns ≤ next.physical_ns ≤ physical_ns + max_skew_ns`. -/
theorem receive_bounded_drift (last next : HybridTimestamp) (physical_ns : I64)
    (remote : HybridTimestamp) (max_skew_ns : I64)
    (h : receive last physical_ns remote max_skew_ns = ok (core.result.Result.Ok next)) :
    physical_ns.val ≤ next.physical_ns.val ∧
      next.physical_ns.val - physical_ns.val ≤ max_skew_ns.val := by
  unfold receive at h
  by_cases hneg : max_skew_ns < 0#i64
  · simp [hneg] at h
  · obtain ⟨b, hb⟩ := within_skew_total remote.physical_ns physical_ns max_skew_ns
    cases b
    · simp [hneg, hb] at h
    · set max_lr : I64 :=
        if last.physical_ns ≥ remote.physical_ns then last.physical_ns else remote.physical_ns
      set next_p : I64 := if max_lr ≥ physical_ns then max_lr else physical_ns
      have hlr : (if last.physical_ns ≥ remote.physical_ns then ok last.physical_ns
          else ok remote.physical_ns) = ok max_lr := by
        by_cases hc : last.physical_ns ≥ remote.physical_ns <;> simp [max_lr, hc]
      have hnp : (if max_lr ≥ physical_ns then ok max_lr else ok physical_ns) = ok next_p := by
        by_cases hc : max_lr ≥ physical_ns <;> simp [next_p, hc]
      have hge_pt : physical_ns.val ≤ next_p.val := by
        dsimp [next_p]; split_ifs <;> scalar_tac
      simp only [hneg, ite_false] at h
      rw [hb, ok_bind] at h
      simp only [ite_true] at h
      rw [hlr, ok_bind, hnp, ok_bind] at h
      obtain ⟨b1, hb1⟩ := within_skew_total next_p physical_ns max_skew_ns
      cases b1
      · rw [hb1, ok_bind] at h; simp at h
      · have hsk2 := (within_skew_iff next_p physical_ns max_skew_ns).mp hb1
        rw [hb1, ok_bind] at h
        simp only [ite_true] at h
        have hp_eq : next.physical_ns = next_p := by
          by_cases heq_l : next_p = last.physical_ns
          · simp only [heq_l, ite_true] at h
            by_cases heq_r : last.physical_ns = remote.physical_ns
            · set max_log : U32 :=
                if last.logical ≥ remote.logical then last.logical else remote.logical
              have hml : (if last.logical ≥ remote.logical then ok last.logical
                  else ok remote.logical) = ok max_log := by
                by_cases hc : last.logical ≥ remote.logical <;> simp [max_log, hc]
              simp only [heq_r, ite_true] at h
              rw [hml, ok_bind] at h
              by_cases hmax : max_log = core.num.U32.MAX
              · simp [hmax] at h
              · obtain ⟨inc, hinc, _⟩ := u32_add_one_eq (u32_lt_max_of_ne hmax)
                simp [hmax, hinc] at h
                subst h; exact heq_r.symm.trans heq_l.symm
            · simp only [heq_r, ite_false] at h
              by_cases hmax : last.logical = core.num.U32.MAX
              · simp [hmax] at h
              · obtain ⟨inc, hinc, _⟩ := u32_add_one_eq (u32_lt_max_of_ne hmax)
                simp [hmax, hinc] at h
                subst h; exact heq_l.symm
          · simp only [heq_l, ite_false] at h
            by_cases heq_r : next_p = remote.physical_ns
            · simp only [heq_r, ite_true] at h
              by_cases hmax : remote.logical = core.num.U32.MAX
              · simp [hmax] at h
              · obtain ⟨inc, hinc, _⟩ := u32_add_one_eq (u32_lt_max_of_ne hmax)
                simp [hmax, hinc] at h
                subst h; exact heq_r.symm
            · simp [heq_r] at h
              subst h; rfl
        rw [hp_eq]
        exact ⟨hge_pt, hsk2.2.1⟩

end mneme_kernel.hlc
