import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Hansson Kernel Contraction & Well-Founded Groundedness

Theorems about the Aeneas translation of `crates/mneme-kernel/src/contraction.rs`:
- Deterministic epistemic-entrenchment strict total order (`origin_rank`, `less_entrenched`)
- Finite-base Hansson kernel contraction (`select_incision`, `is_incised`,
  `survives_incision`, `any_proof_survives`):
  - **Inclusion**: `B ÷_σ φ ⊆ B`
  - **Success**: no valid non-empty minimal kernel survives in `B ÷_σ φ`
  - **Core-Retainment**: every removed element of `B` belongs to some minimal kernel
  - **Uniformity**: equal kernel families yield identical contractions
- Well-founded groundedness reachability (`edge_is_grounded`, `node_next_grounded`):
  - **Monotonicity**: grounded nodes remain grounded
  - **Cycle-free groundedness**: unfounded self-supporting sets (including
    mutual cycles `A ↔ B`) disjoint from surviving roots remain ungrounded
-/

namespace mneme_kernel.contraction

/-- A specification that holds yields the returned value. -/
private theorem ok_of_spec {α : Type} {m : Result α} {P : α → Prop} (h : m ⦃ P ⦄) :
    ∃ v, m = ok v ∧ P v := by
  cases m with
  | ret v => exact ⟨v, rfl, by simpa using h⟩
  | vis e k => simp at h
  | div => simp at h

/-- When `x < Usize.max`, `saturating_add x 1#usize` is exact addition by 1. -/
private theorem usize_saturating_add_one_val (x : Usize) (h : x.val < Usize.max) :
    (core.num.Usize.saturating_add x 1#usize).val = x.val + 1 := by
  have h1_val : (1#usize).val = 1 := by scalar_tac
  have h1 : (1#usize).bv.toNat = 1 := h1_val
  have hmax_def : UScalar.max UScalarTy.Usize = 2 ^ UScalarTy.Usize.numBits - 1 := by
    simp [UScalar.max]
  have hmax_eq : Usize.max = UScalar.max UScalarTy.Usize := by
    simp [Usize.max, UScalar.max, Usize.numBits, UScalarTy.numBits]
  have hpos : 0 < 2 ^ UScalarTy.Usize.numBits := Nat.two_pow_pos _
  have hx : x.bv.toNat = x.val := rfl
  have hlt_pow : x.bv.toNat + 1 < 2 ^ UScalarTy.Usize.numBits := by omega
  have hmin : min (UScalar.max UScalarTy.Usize) (x.bv.toNat + 1) = x.bv.toNat + 1 := by omega
  simp only [core.num.Usize.saturating_add, UScalar.saturating_add, UScalar.val,
    BitVec.toNat_ofNat]
  rw [h1, hmin, Nat.mod_eq_of_lt hlt_pow]

/-- Pure numeric rank of an `OriginTier` used in proof specifications. -/
private def originRankNat : OriginTier → Nat
  | OriginTier.ModelExtraction => 0
  | OriginTier.Imported => 1
  | OriginTier.Authored => 2

/-- Pure strict lexicographic entrenchment order on `EntrenchmentKey`. -/
private def ltKey (a b : EntrenchmentKey) : Prop :=
  originRankNat a.origin < originRankNat b.origin ∨
    (originRankNat a.origin = originRankNat b.origin ∧ a.root_count.val < b.root_count.val) ∨
    (originRankNat a.origin = originRankNat b.origin ∧ a.root_count.val = b.root_count.val ∧
      a.record_id.val < b.record_id.val)

private theorem originRankNat_inj {a b : OriginTier} (h : originRankNat a = originRankNat b) :
    a = b := by
  cases a <;> cases b <;> simp [originRankNat] at h ⊢

private theorem entrenchmentKey_eq_of_fields {a b : EntrenchmentKey}
    (ho : a.origin = b.origin) (hr : a.root_count.val = b.root_count.val)
    (hi : a.record_id.val = b.record_id.val) : a = b := by
  cases a; cases b
  simp only at ho hr hi
  have hr' : _ = _ := (UScalar.eq_equiv _ _).mpr hr
  have hi' : _ = _ := (UScalar.eq_equiv _ _).mpr hi
  subst ho; subst hr'; subst hi'; rfl

private theorem ltKey_irrefl (a : EntrenchmentKey) : ¬ ltKey a a := by
  unfold ltKey
  omega

private theorem ltKey_asym {a b : EntrenchmentKey} (h : ltKey a b) : ¬ ltKey b a := by
  unfold ltKey at h ⊢
  omega

private theorem ltKey_trans {a b c : EntrenchmentKey} (hab : ltKey a b) (hbc : ltKey b c) :
    ltKey a c := by
  unfold ltKey at hab hbc ⊢
  omega

private theorem ltKey_trichotomy (a b : EntrenchmentKey) :
    ltKey a b ∨ a = b ∨ ltKey b a := by
  by_cases ho : originRankNat a.origin = originRankNat b.origin
  · by_cases hr : a.root_count.val = b.root_count.val
    · by_cases hi : a.record_id.val = b.record_id.val
      · exact Or.inr (Or.inl (entrenchmentKey_eq_of_fields (originRankNat_inj ho) hr hi))
      · rcases Nat.lt_or_gt_of_ne hi with hlt | hgt
        · exact Or.inl (Or.inr (Or.inr ⟨ho, hr, hlt⟩))
        · exact Or.inr (Or.inr (Or.inr (Or.inr ⟨ho.symm, hr.symm, hgt⟩)))
    · rcases Nat.lt_or_gt_of_ne hr with hlt | hgt
      · exact Or.inl (Or.inr (Or.inl ⟨ho, hlt⟩))
      · exact Or.inr (Or.inr (Or.inr (Or.inl ⟨ho.symm, hgt⟩)))
  · rcases Nat.lt_or_gt_of_ne ho with hlt | hgt
    · exact Or.inl (Or.inl hlt)
    · exact Or.inr (Or.inr (Or.inl hgt))

/-! ## `origin_rank` -/

/-- `origin_rank` never fails or diverges. -/
theorem origin_rank_total (tier : OriginTier) :
    ∃ r, origin_rank tier = ok r := by
  cases tier <;> simp [origin_rank, RANK_MODEL_EXTRACTION, RANK_IMPORTED, RANK_AUTHORED]

/-- `origin_rank` assigns the strict order `ModelExtraction (0) < Imported (1) < Authored (2)`. -/
theorem origin_rank_order :
    origin_rank OriginTier.ModelExtraction = ok 0#u8 ∧
      origin_rank OriginTier.Imported = ok 1#u8 ∧
      origin_rank OriginTier.Authored = ok 2#u8 := by
  simp [origin_rank, RANK_MODEL_EXTRACTION, RANK_IMPORTED, RANK_AUTHORED]

private theorem origin_rank_val (tier : OriginTier) :
    ∃ r, origin_rank tier = ok r ∧ r.val = originRankNat tier := by
  cases tier <;> simp [origin_rank, RANK_MODEL_EXTRACTION, RANK_IMPORTED, RANK_AUTHORED,
    originRankNat]

/-! ## `less_entrenched` -/

private theorem less_entrenched_spec (a b : EntrenchmentKey) :
    ∃ res, less_entrenched a b = ok res ∧ (res = true ↔ ltKey a b) := by
  obtain ⟨ra, hra, hrav⟩ := origin_rank_val a.origin
  obtain ⟨rb, hrb, hrbv⟩ := origin_rank_val b.origin
  unfold less_entrenched
  rw [hra, bind_ok, hrb, bind_ok]
  by_cases hneq : ra != rb
  · have hne : ra.val ≠ rb.val := by
      intro heq
      have : ra = rb := (UScalar.eq_equiv ra rb).mpr heq
      subst this
      simp at hneq
    refine ⟨decide (ra < rb), by simp [hneq], ?_⟩
    simp only [decide_eq_true_eq, ltKey]
    have hlt : (ra < rb) ↔ ra.val < rb.val := by scalar_tac
    rw [hlt]
    omega
  · have heq : ra.val = rb.val := by simpa using hneq
    by_cases hrneq : a.root_count != b.root_count
    · have hrne : a.root_count.val ≠ b.root_count.val := by
        intro h
        have : a.root_count = b.root_count := (UScalar.eq_equiv _ _).mpr h
        rw [this] at hrneq
        simp at hrneq
      refine ⟨decide (a.root_count < b.root_count), by simp [hneq, hrneq], ?_⟩
      simp only [decide_eq_true_eq, ltKey]
      have hlt : (a.root_count < b.root_count) ↔ a.root_count.val < b.root_count.val := by
        scalar_tac
      rw [hlt]
      omega
    · have hreq : a.root_count.val = b.root_count.val := by simpa using hrneq
      refine ⟨decide (a.record_id < b.record_id), by simp [hneq, hrneq], ?_⟩
      simp only [decide_eq_true_eq, ltKey]
      have hlt : (a.record_id < b.record_id) ↔ a.record_id.val < b.record_id.val := by
        scalar_tac
      rw [hlt]
      omega

/-- `less_entrenched` never fails or diverges. -/
theorem less_entrenched_total (a b : EntrenchmentKey) :
    ∃ r, less_entrenched a b = ok r := by
  obtain ⟨r, hr, -⟩ := less_entrenched_spec a b
  exact ⟨r, hr⟩

/-- `less_entrenched` is irreflexive. -/
theorem less_entrenched_irrefl (a : EntrenchmentKey) :
    less_entrenched a a = ok false := by
  obtain ⟨r, hr, hiff⟩ := less_entrenched_spec a a
  cases r with
  | false => exact hr
  | true => exact False.elim (ltKey_irrefl a (hiff.mp rfl))

/-- `less_entrenched` is asymmetric. -/
theorem less_entrenched_asym (a b : EntrenchmentKey)
    (h : less_entrenched a b = ok true) :
    less_entrenched b a = ok false := by
  obtain ⟨r1, hr1, hiff1⟩ := less_entrenched_spec a b
  obtain ⟨r2, hr2, hiff2⟩ := less_entrenched_spec b a
  rw [h, Result.ok.injEq] at hr1
  have hab : ltKey a b := hiff1.mp hr1.symm
  cases r2 with
  | false => exact hr2
  | true => exact False.elim (ltKey_asym hab (hiff2.mp rfl))

/-- `less_entrenched` is transitive. -/
theorem less_entrenched_trans (a b c : EntrenchmentKey)
    (hab : less_entrenched a b = ok true)
    (hbc : less_entrenched b c = ok true) :
    less_entrenched a c = ok true := by
  obtain ⟨r1, hr1, hiff1⟩ := less_entrenched_spec a b
  obtain ⟨r2, hr2, hiff2⟩ := less_entrenched_spec b c
  obtain ⟨r3, hr3, hiff3⟩ := less_entrenched_spec a c
  rw [hab, Result.ok.injEq] at hr1
  rw [hbc, Result.ok.injEq] at hr2
  have hac : ltKey a c := ltKey_trans (hiff1.mp hr1.symm) (hiff2.mp hr2.symm)
  cases r3 with
  | true => exact hr3
  | false => exact False.elim (Bool.false_ne_true (hiff3.mpr hac))

/-- `less_entrenched` is a strict total order on distinct keys. -/
theorem less_entrenched_trichotomy (a b : EntrenchmentKey) (hne : a ≠ b) :
    less_entrenched a b = ok true ∨ less_entrenched b a = ok true := by
  obtain ⟨r1, hr1, hiff1⟩ := less_entrenched_spec a b
  obtain ⟨r2, hr2, hiff2⟩ := less_entrenched_spec b a
  rcases ltKey_trichotomy a b with hlt | heq | hgt
  · exact Or.inl (by rw [hr1, hiff1.mpr hlt])
  · exact False.elim (hne heq)
  · exact Or.inr (by rw [hr2, hiff2.mpr hgt])

/-! ## `span_stop` helper -/

private theorem span_stop_cases (span : RangeSpan) (limit : Usize) :
    (0 < span.len.val ∧ span.start.val + span.len.val ≤ limit.val ∧
        ∃ stop, span_stop span limit = ok (some stop) ∧
          stop.val = span.start.val + span.len.val) ∨
      ((span.len.val = 0 ∨ limit.val < span.start.val + span.len.val) ∧
        span_stop span limit = ok none) := by
  unfold span_stop
  by_cases hzero : span.len = 0#usize
  · have hz : span.len.val = 0 := by
      rw [hzero]; scalar_tac
    exact Or.inr ⟨Or.inl hz, by simp [hzero]⟩
  · have hpos : 0 < span.len.val := by
      have : span.len.val ≠ 0 := by
        intro h
        apply hzero
        exact (UScalar.eq_equiv _ _).mpr (by simpa using h)
      omega
    have hspec := Usize.checked_add_bv_spec span.start span.len
    cases hsum : Usize.checked_add span.start span.len with
    | none =>
      rw [hsum] at hspec
      replace hspec : Usize.max < span.start.val + span.len.val := hspec
      exact Or.inr ⟨Or.inr (by scalar_tac), by simp [hzero, lift]⟩
    | some stop =>
      rw [hsum] at hspec
      obtain ⟨-, hval, -⟩ := hspec
      by_cases hle : stop ≤ limit
      · have hle' : stop.val ≤ limit.val := by scalar_tac
        exact Or.inl ⟨hpos, by omega, stop, by simp [hzero, lift, hle'], hval⟩
      · have hgt' : limit.val < stop.val := by scalar_tac
        have hnle' : ¬ stop.val ≤ limit.val := by omega
        exact Or.inr ⟨Or.inr (by omega), by simp [hzero, lift, hnle']⟩

/-! ## `select_incision` -/

private theorem select_incision_loop_spec
    (members : Slice EntrenchmentKey) (span : RangeSpan) (stop : Usize)
    (init_chosen : EntrenchmentKey) (init_cursor : Usize)
    (hstop : stop.val = span.start.val + span.len.val)
    (hstop_le : stop.val ≤ members.length)
    (hcur_lo : span.start.val < init_cursor.val)
    (hcur_hi : init_cursor.val ≤ stop.val)
    (hinit_mem : ∃ j, span.start.val ≤ j ∧ j < init_cursor.val ∧
      members.val[j]? = some init_chosen)
    (hinit_min : ∀ j, span.start.val ≤ j → j < init_cursor.val →
      ∀ x, members.val[j]? = some x → ¬ ltKey x init_chosen) :
    select_incision_loop members stop init_chosen init_cursor ⦃ chosen =>
      (∃ j, span.start.val ≤ j ∧ j < stop.val ∧ members.val[j]? = some chosen) ∧
      (∀ j, span.start.val ≤ j → j < stop.val →
        ∀ x, members.val[j]? = some x → ¬ ltKey x chosen) ⦄ := by
  unfold select_incision_loop
  apply loop.spec_decr_nat
    (fun (p : EntrenchmentKey × Usize) => stop.val - p.2.val)
    (fun (p : EntrenchmentKey × Usize) =>
      span.start.val < p.2.val ∧ p.2.val ≤ stop.val ∧
      (∃ j, span.start.val ≤ j ∧ j < p.2.val ∧ members.val[j]? = some p.1) ∧
      (∀ j, span.start.val ≤ j → j < p.2.val →
        ∀ x, members.val[j]? = some x → ¬ ltKey x p.1))
  · rintro ⟨chosen, cursor⟩ ⟨hlo, hhi, hmem, hmin⟩
    simp only at hlo hhi hmem hmin ⊢
    unfold select_incision_loop.body
    by_cases hlt : cursor < stop
    · have hlt' : cursor.val < stop.val := by scalar_tac
      have hidx : cursor.val < members.length := by omega
      obtain ⟨cand, hcand, hcandv⟩ := ok_of_spec (Slice.index_usize_spec members cursor hidx)
      have hcand_get : members.val[cursor.val]? = some cand := by
        rw [List.getElem?_eq_getElem hidx, hcandv]
      obtain ⟨b, hb, hbiff⟩ := less_entrenched_spec cand chosen
      have hcur_max : cursor.val < Usize.max := by scalar_tac
      have hnext_val : (core.num.Usize.saturating_add cursor 1#usize).val = cursor.val + 1 :=
        usize_saturating_add_one_val cursor hcur_max
      cases b with
      | true =>
        have hlt_cc : ltKey cand chosen := hbiff.mp rfl
        simp only [hlt, ite_true, hcand, bind_ok, hb, lift, WP.spec_ok]
        refine ⟨⟨by omega, by omega, ⟨cursor.val, by omega, by omega, hcand_get⟩, ?_⟩, by omega⟩
        intro j hjlo hjhi x hx
        by_cases hj : j = cursor.val
        · subst hj
          rw [hcand_get, Option.some.injEq] at hx
          subst hx
          exact ltKey_irrefl cand
        · have hjlt : j < cursor.val := by omega
          intro hxlt
          exact hmin j hjlo hjlt x hx (ltKey_trans hxlt hlt_cc)
      | false =>
        have hnlt_cc : ¬ ltKey cand chosen := by
          intro hlt_cc
          exact Bool.false_ne_true (hbiff.mpr hlt_cc)
        simp only [hlt, ite_true, hcand, bind_ok, hb, Bool.false_eq_true, ite_false, lift, WP.spec_ok]
        obtain ⟨jm, hjm1, hjm2, hjm3⟩ := hmem
        refine ⟨⟨by omega, by omega, ⟨jm, hjm1, by omega, hjm3⟩, ?_⟩, by omega⟩
        intro j hjlo hjhi x hx
        by_cases hj : j = cursor.val
        · subst hj
          rw [hcand_get, Option.some.injEq] at hx
          subst hx
          exact hnlt_cc
        · exact hmin j hjlo (by omega) x hx
    · have hge : stop.val ≤ cursor.val := by scalar_tac
      have heq : cursor.val = stop.val := by omega
      simp only [hlt, ite_false, WP.spec_ok]
      rw [heq] at hmem hmin
      exact ⟨hmem, hmin⟩
  · exact ⟨hcur_lo, hcur_hi, hinit_mem, hinit_min⟩

private theorem select_incision_spec (members : Slice EntrenchmentKey) (span : RangeSpan) :
    (0 < span.len.val ∧ span.start.val + span.len.val ≤ members.length ∧
      ∃ chosen, select_incision members span = ok (some chosen) ∧
        (∃ j, span.start.val ≤ j ∧ j < span.start.val + span.len.val ∧
          members.val[j]? = some chosen) ∧
        (∀ j, span.start.val ≤ j → j < span.start.val + span.len.val →
          ∀ x, members.val[j]? = some x → ¬ ltKey x chosen)) ∨
    ((span.len.val = 0 ∨ members.length < span.start.val + span.len.val) ∧
      select_incision members span = ok none) := by
  unfold select_incision
  rcases span_stop_cases span (Slice.len members) with ⟨hpos, hle, stop, hstop_eq, hstop_val⟩ |
    ⟨hbad, hnone⟩
  · have hlen_val : (Slice.len members).val = members.length := by scalar_tac
    have hstop_le : stop.val ≤ members.length := by omega
    have hstart_lt : span.start.val < members.length := by omega
    obtain ⟨first, hfirst, hfirstv⟩ := ok_of_spec (Slice.index_usize_spec members span.start hstart_lt)
    have hfirst_get : members.val[span.start.val]? = some first := by
      rw [List.getElem?_eq_getElem hstart_lt, hfirstv]
    have hstart_max : span.start.val < Usize.max := by scalar_tac
    have hcur_val : (core.num.Usize.saturating_add span.start 1#usize).val = span.start.val + 1 :=
      usize_saturating_add_one_val span.start hstart_max
    have hloop := select_incision_loop_spec members span stop first
      (core.num.Usize.saturating_add span.start 1#usize)
      hstop_val hstop_le (by omega) (by omega)
      ⟨span.start.val, le_refl _, by omega, hfirst_get⟩
      (by
        intro j hj1 hj2 x hx
        have hjeq : j = span.start.val := by omega
        subst hjeq
        rw [hfirst_get, Option.some.injEq] at hx
        subst hx
        exact ltKey_irrefl first)
    obtain ⟨chosen, hchosen, hmem, hmin⟩ := ok_of_spec hloop
    rw [hstop_val] at hmem hmin
    refine Or.inl ⟨hpos, by omega, chosen, ?_, hmem, hmin⟩
    simp only [hstop_eq, bind_ok, hfirst, lift, hchosen]
  · have hlen_val : (Slice.len members).val = members.length := by scalar_tac
    rw [hlen_val] at hbad
    exact Or.inr ⟨hbad, by simp [hnone]⟩

/-- `select_incision` never fails or diverges. -/
theorem select_incision_total (members : Slice EntrenchmentKey) (span : RangeSpan) :
    ∃ r, select_incision members span = ok r := by
  rcases select_incision_spec members span with ⟨-, -, chosen, h, -, -⟩ | ⟨-, h⟩
  · exact ⟨some chosen, h⟩
  · exact ⟨none, h⟩

/-- `select_incision` returns `none` on empty or out-of-bounds spans. -/
theorem select_incision_none_of_invalid (members : Slice EntrenchmentKey) (span : RangeSpan)
    (hbad : span.len.val = 0 ∨ members.length < span.start.val + span.len.val) :
    select_incision members span = ok none := by
  rcases select_incision_spec members span with ⟨hpos, hle, -, -, -, -⟩ | ⟨-, h⟩
  · omega
  · exact h

/-- On every valid non-empty kernel span, `select_incision` returns a member of
that span that is minimal under `less_entrenched`. -/
theorem select_incision_mem_and_min (members : Slice EntrenchmentKey) (span : RangeSpan)
    (hpos : 0 < span.len.val)
    (hle : span.start.val + span.len.val ≤ members.length) :
    ∃ chosen, select_incision members span = ok (some chosen) ∧
      (∃ j, span.start.val ≤ j ∧ j < span.start.val + span.len.val ∧
        members.val[j]? = some chosen) ∧
      (∀ j, span.start.val ≤ j → j < span.start.val + span.len.val →
        ∀ x, members.val[j]? = some x → less_entrenched x chosen = ok false) := by
  rcases select_incision_spec members span with ⟨-, -, chosen, h, hmem, hmin⟩ | ⟨hbad, -⟩
  · refine ⟨chosen, h, hmem, ?_⟩
    intro j hj1 hj2 x hx
    obtain ⟨r, hr, hiff⟩ := less_entrenched_spec x chosen
    cases r with
    | false => exact hr
    | true => exact False.elim (hmin j hj1 hj2 x hx (hiff.mp rfl))
  · omega

/-- Two valid non-empty kernel spans with identical sets of `EntrenchmentKey`s
select the exact same incised key (order- and duplicate-invariance). -/
theorem select_incision_uniform
    (members1 members2 : Slice EntrenchmentKey) (span1 span2 : RangeSpan)
    (hpos1 : 0 < span1.len.val) (hle1 : span1.start.val + span1.len.val ≤ members1.length)
    (hpos2 : 0 < span2.len.val) (hle2 : span2.start.val + span2.len.val ≤ members2.length)
    (hsame : ∀ x,
      (∃ j, span1.start.val ≤ j ∧ j < span1.start.val + span1.len.val ∧
        members1.val[j]? = some x) ↔
      (∃ j, span2.start.val ≤ j ∧ j < span2.start.val + span2.len.val ∧
        members2.val[j]? = some x)) :
    select_incision members1 span1 = select_incision members2 span2 := by
  rcases select_incision_spec members1 span1 with ⟨-, -, c1, hc1, hmem1, hmin1⟩ | ⟨hbad1, -⟩
  · rcases select_incision_spec members2 span2 with ⟨-, -, c2, hc2, hmem2, hmin2⟩ | ⟨hbad2, -⟩
    · obtain ⟨j2, hj2a, hj2b, hj2c⟩ := (hsame c1).mp hmem1
      obtain ⟨j1, hj1a, hj1b, hj1c⟩ := (hsame c2).mpr hmem2
      have hn1 : ¬ ltKey c1 c2 := hmin2 j2 hj2a hj2b c1 hj2c
      have hn2 : ¬ ltKey c2 c1 := hmin1 j1 hj1a hj1b c2 hj1c
      rcases ltKey_trichotomy c1 c2 with hlt | heq | hgt
      · exact False.elim (hn1 hlt)
      · rw [hc1, hc2, heq]
      · exact False.elim (hn2 hgt)
    · omega
  · omega

/-! ## `is_incised` -/

private theorem mem_take_succ {α : Type} (l : List α) (i : Nat) (h : i < l.length) (a : α) :
    a ∈ l.take (i + 1) ↔ a ∈ l.take i ∨ l[i] = a := by
  rw [List.take_succ_eq_append_getElem h, List.mem_append, List.mem_singleton, eq_comm]

private theorem is_incised_loop_spec
    (record_id : U128) (members : Slice EntrenchmentKey) (spans : Slice RangeSpan) :
    is_incised_loop record_id members spans false 0#usize ⦃ cut =>
      cut = true ↔ ∃ s ∈ spans.val, ∃ chosen,
        select_incision members s = ok (some chosen) ∧ chosen.record_id = record_id ⦄ := by
  unfold is_incised_loop
  apply loop.spec_decr_nat
    (fun (p : Bool × Usize) => spans.length - p.2.val)
    (fun (p : Bool × Usize) =>
      p.2.val ≤ spans.length ∧
      (p.1 = true ↔ ∃ s ∈ spans.val.take p.2.val, ∃ chosen,
        select_incision members s = ok (some chosen) ∧ chosen.record_id = record_id))
  · rintro ⟨flag, index⟩ ⟨hle, hs⟩
    simp only at hle hs ⊢
    unfold is_incised_loop.body
    by_cases hlt : index < Slice.len spans
    · have hlt' : index.val < spans.length := by scalar_tac
      cases flag with
      | true =>
        simp only [hlt, ite_true, WP.spec_ok]
        refine ⟨fun _ => ?_, fun _ => trivial⟩
        obtain ⟨s, hsmem, chosen, hsel, hid⟩ := hs.mp rfl
        exact ⟨s, List.mem_of_mem_take hsmem, chosen, hsel, hid⟩
      | false =>
        obtain ⟨rs, hrs, hrsv⟩ := ok_of_spec (Slice.index_usize_spec spans index hlt')
        obtain ⟨opt, hopt⟩ := select_incision_total members rs
        have hidx_max : index.val < Usize.max := by scalar_tac
        have hnext_val : (core.num.Usize.saturating_add index 1#usize).val = index.val + 1 :=
          usize_saturating_add_one_val index hidx_max
        cases opt with
        | none =>
          simp only [hlt, ite_true, Bool.false_eq_true, ite_false, hrs, bind_ok, hopt, lift,
            WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          rw [hnext_val]
          constructor
          · exact False.elim
          · rintro ⟨s, hsmem, chosen, hsel, hid⟩
            rcases (mem_take_succ spans.val index.val hlt' s).mp hsmem with hprev | hcurr
            · exact Bool.false_ne_true (hs.mpr ⟨s, hprev, chosen, hsel, hid⟩)
            · rw [← hcurr, ← hrsv, hopt, Result.ok.injEq] at hsel
              cases hsel
        | some chosen =>
          simp only [hlt, ite_true, Bool.false_eq_true, ite_false, hrs, bind_ok, hopt, lift,
            WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          rw [hnext_val]
          constructor
          · intro heq
            have hid : chosen.record_id = record_id := by simpa using heq
            refine ⟨rs, (mem_take_succ spans.val index.val hlt' rs).mpr (Or.inr hrsv.symm),
              chosen, hopt, hid⟩
          · rintro ⟨s, hsmem, c, hsel, hid⟩
            rcases (mem_take_succ spans.val index.val hlt' s).mp hsmem with hprev | hcurr
            · exact False.elim (Bool.false_ne_true (hs.mpr ⟨s, hprev, c, hsel, hid⟩))
            · rw [← hcurr, ← hrsv, hopt, Result.ok.injEq, Option.some.injEq] at hsel
              subst hsel
              simp [hid]
    · have hge : spans.val.length ≤ index.val := by scalar_tac
      simp only [hlt, ite_false, WP.spec_ok]
      rw [List.take_of_length_le hge] at hs
      exact hs
  · simp

private theorem is_incised_spec
    (record_id : U128) (members : Slice EntrenchmentKey) (spans : Slice RangeSpan) :
    ∃ cut, is_incised record_id members spans = ok cut ∧
      (cut = true ↔ ∃ s ∈ spans.val, ∃ chosen,
        select_incision members s = ok (some chosen) ∧ chosen.record_id = record_id) := by
  exact ok_of_spec (is_incised_loop_spec record_id members spans)

/-- `is_incised` never fails or diverges. -/
theorem is_incised_total
    (record_id : U128) (members : Slice EntrenchmentKey) (spans : Slice RangeSpan) :
    ∃ r, is_incised record_id members spans = ok r := by
  obtain ⟨r, hr, -⟩ := is_incised_spec record_id members spans
  exact ⟨r, hr⟩

/-- `is_incised` is true iff some kernel span selects an element with `record_id`. -/
theorem is_incised_iff
    (record_id : U128) (members : Slice EntrenchmentKey) (spans : Slice RangeSpan) :
    is_incised record_id members spans = ok true ↔
      ∃ s ∈ spans.val, ∃ chosen,
        select_incision members s = ok (some chosen) ∧ chosen.record_id = record_id := by
  obtain ⟨r, hr, hiff⟩ := is_incised_spec record_id members spans
  rw [hr, Result.ok.injEq]
  exact hiff

/-! ## `in_base` and `survives_incision` (Inclusion, Core-Retainment, Uniformity) -/

private theorem in_base_loop_spec (record_id : U128) (base : Slice U128) :
    in_base_loop record_id base false 0#usize ⦃ mem =>
      mem = true ↔ record_id ∈ base.val ⦄ := by
  unfold in_base_loop
  apply loop.spec_decr_nat
    (fun (p : Bool × Usize) => base.length - p.2.val)
    (fun (p : Bool × Usize) =>
      p.2.val ≤ base.length ∧ (p.1 = true ↔ record_id ∈ base.val.take p.2.val))
  · rintro ⟨flag, index⟩ ⟨hle, hs⟩
    simp only at hle hs ⊢
    unfold in_base_loop.body
    by_cases hlt : index < Slice.len base
    · have hlt' : index.val < base.length := by scalar_tac
      cases flag with
      | true =>
        simp only [hlt, ite_true, WP.spec_ok]
        exact ⟨fun _ => List.mem_of_mem_take (hs.mp rfl), fun _ => trivial⟩
      | false =>
        obtain ⟨x, hx, hxv⟩ := ok_of_spec (Slice.index_usize_spec base index hlt')
        have hidx_max : index.val < Usize.max := by scalar_tac
        have hnext_val : (core.num.Usize.saturating_add index 1#usize).val = index.val + 1 :=
          usize_saturating_add_one_val index hidx_max
        by_cases heq : x = record_id
        · simp only [hlt, ite_true, Bool.false_eq_true, ite_false, hx, bind_ok, heq, lift,
            WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          rw [hnext_val]
          exact ⟨fun _ => (mem_take_succ base.val index.val hlt' record_id).mpr
            (Or.inr (hxv.symm.trans heq)), fun _ => trivial⟩
        · simp only [hlt, ite_true, Bool.false_eq_true, ite_false, hx, bind_ok, heq, lift,
            WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          rw [hnext_val]
          constructor
          · exact False.elim
          · intro hmem
            rcases (mem_take_succ base.val index.val hlt' record_id).mp hmem with hprev | hcurr
            · exact Bool.false_ne_true (hs.mpr hprev)
            · exact False.elim (heq (hxv.trans hcurr))
    · have hge : base.val.length ≤ index.val := by scalar_tac
      simp only [hlt, ite_false, WP.spec_ok]
      rw [List.take_of_length_le hge] at hs
      exact hs
  · simp

private theorem survives_incision_spec
    (record_id : U128) (base : Slice U128)
    (members : Slice EntrenchmentKey) (spans : Slice RangeSpan) :
    ∃ r, survives_incision record_id base members spans = ok r ∧
      (r = true ↔ record_id ∈ base.val ∧
        ¬ ∃ s ∈ spans.val, ∃ chosen,
          select_incision members s = ok (some chosen) ∧ chosen.record_id = record_id) := by
  obtain ⟨inb, hinb, hinb_iff⟩ := ok_of_spec (in_base_loop_spec record_id base)
  obtain ⟨cut, hcut, hcut_iff⟩ := is_incised_spec record_id members spans
  unfold survives_incision
  have hinb' : in_base record_id base = ok inb := hinb
  rw [hinb', bind_ok]
  cases inb with
  | false =>
    refine ⟨false, by simp, ?_⟩
    constructor
    · exact False.elim ∘ Bool.false_ne_true
    · rintro ⟨hmem, -⟩
      exact hinb_iff.mpr hmem
  | true =>
    simp only [ite_true, hcut, bind_ok]
    refine ⟨!cut, rfl, ?_⟩
    cases cut with
    | true =>
      simp only [Bool.not_true, Bool.false_eq_true, false_iff]
      rintro ⟨-, hncut⟩
      exact hncut (hcut_iff.mp rfl)
    | false =>
      simp only [Bool.not_false, true_iff]
      refine ⟨hinb_iff.mp rfl, ?_⟩
      intro hex
      exact Bool.false_ne_true (hcut_iff.mpr hex)

/-- `survives_incision` never fails or diverges. -/
theorem survives_incision_total
    (record_id : U128) (base : Slice U128)
    (members : Slice EntrenchmentKey) (spans : Slice RangeSpan) :
    ∃ r, survives_incision record_id base members spans = ok r := by
  obtain ⟨r, hr, -⟩ := survives_incision_spec record_id base members spans
  exact ⟨r, hr⟩

/-- **Hansson Inclusion (`B ÷_σ φ ⊆ B`)**: every record surviving contraction
already belonged to the base `B`. -/
theorem survives_incision_inclusion
    (record_id : U128) (base : Slice U128)
    (members : Slice EntrenchmentKey) (spans : Slice RangeSpan)
    (h : survives_incision record_id base members spans = ok true) :
    record_id ∈ base.val := by
  obtain ⟨r, hr, hiff⟩ := survives_incision_spec record_id base members spans
  rw [h, Result.ok.injEq] at hr
  exact (hiff.mp hr.symm).1

/-- **Hansson Core-Retainment**: every base record removed by `B ÷_σ φ` belongs
to at least one valid minimal kernel in `B ⊥ φ`. -/
theorem survives_incision_core_retainment
    (record_id : U128) (base : Slice U128)
    (members : Slice EntrenchmentKey) (spans : Slice RangeSpan)
    (hin : record_id ∈ base.val)
    (hremoved : survives_incision record_id base members spans = ok false) :
    ∃ s ∈ spans.val,
      0 < s.len.val ∧ s.start.val + s.len.val ≤ members.length ∧
      ∃ j, s.start.val ≤ j ∧ j < s.start.val + s.len.val ∧
        ∃ k, members.val[j]? = some k ∧ k.record_id = record_id := by
  obtain ⟨r, hr, hiff⟩ := survives_incision_spec record_id base members spans
  rw [hremoved, Result.ok.injEq] at hr
  have hcut : ∃ s ∈ spans.val, ∃ chosen,
      select_incision members s = ok (some chosen) ∧ chosen.record_id = record_id := by
    by_contra hncut
    exact Bool.false_ne_true (hr ▸ hiff.mpr ⟨hin, hncut⟩)
  obtain ⟨s, hsmem, chosen, hsel, hid⟩ := hcut
  rcases select_incision_spec members s with ⟨hpos, hle, c, hc, hcmem, -⟩ | ⟨-, hnone⟩
  · rw [hsel, Result.ok.injEq, Option.some.injEq] at hc
    subst hc
    obtain ⟨j, hj1, hj2, hj3⟩ := hcmem
    exact ⟨s, hsmem, hpos, hle, j, hj1, hj2, chosen, hj3, hid⟩
  · rw [hsel, Result.ok.injEq] at hnone
    cases hnone

/-- **Hansson Uniformity**: if two kernel families `(members1, spans1)` and
`(members2, spans2)` represent the exact same collection of valid minimal kernel
sets, then `survives_incision` produces identical results for every record. -/
theorem survives_incision_uniformity
    (record_id : U128) (base : Slice U128)
    (members1 members2 : Slice EntrenchmentKey)
    (spans1 spans2 : Slice RangeSpan)
    (h12 : ∀ s1 ∈ spans1.val,
      0 < s1.len.val → s1.start.val + s1.len.val ≤ members1.length →
      ∃ s2 ∈ spans2.val,
        0 < s2.len.val ∧ s2.start.val + s2.len.val ≤ members2.length ∧
        ∀ x,
          (∃ j, s1.start.val ≤ j ∧ j < s1.start.val + s1.len.val ∧
            members1.val[j]? = some x) ↔
          (∃ j, s2.start.val ≤ j ∧ j < s2.start.val + s2.len.val ∧
            members2.val[j]? = some x))
    (h21 : ∀ s2 ∈ spans2.val,
      0 < s2.len.val → s2.start.val + s2.len.val ≤ members2.length →
      ∃ s1 ∈ spans1.val,
        0 < s1.len.val ∧ s1.start.val + s1.len.val ≤ members1.length ∧
        ∀ x,
          (∃ j, s1.start.val ≤ j ∧ j < s1.start.val + s1.len.val ∧
            members1.val[j]? = some x) ↔
          (∃ j, s2.start.val ≤ j ∧ j < s2.start.val + s2.len.val ∧
            members2.val[j]? = some x)) :
    survives_incision record_id base members1 spans1 =
      survives_incision record_id base members2 spans2 := by
  obtain ⟨r1, hr1, hiff1⟩ := survives_incision_spec record_id base members1 spans1
  obtain ⟨r2, hr2, hiff2⟩ := survives_incision_spec record_id base members2 spans2
  have hequiv :
      (∃ s ∈ spans1.val, ∃ c, select_incision members1 s = ok (some c) ∧ c.record_id = record_id) ↔
      (∃ s ∈ spans2.val, ∃ c, select_incision members2 s = ok (some c) ∧ c.record_id = record_id) := by
    constructor
    · rintro ⟨s1, hs1, c, hsel1, hid⟩
      rcases select_incision_spec members1 s1 with ⟨hpos1, hle1, -, -, -, -⟩ | ⟨-, hnone⟩
      · obtain ⟨s2, hs2, hpos2, hle2, hsame⟩ := h12 s1 hs1 hpos1 hle1
        have heq := select_incision_uniform members1 members2 s1 s2 hpos1 hle1 hpos2 hle2 hsame
        exact ⟨s2, hs2, c, heq.symm.trans hsel1, hid⟩
      · rw [hsel1, Result.ok.injEq] at hnone; cases hnone
    · rintro ⟨s2, hs2, c, hsel2, hid⟩
      rcases select_incision_spec members2 s2 with ⟨hpos2, hle2, -, -, -, -⟩ | ⟨-, hnone⟩
      · obtain ⟨s1, hs1, hpos1, hle1, hsame⟩ := h21 s2 hs2 hpos2 hle2
        have heq := select_incision_uniform members1 members2 s1 s2 hpos1 hle1 hpos2 hle2 hsame
        exact ⟨s1, hs1, c, heq.trans hsel2, hid⟩
      · rw [hsel2, Result.ok.injEq] at hnone; cases hnone
  rw [hr1, hr2]
  cases r1 <;> cases r2
  · rfl
  · exfalso
    obtain ⟨hin, hncut2⟩ := hiff2.mp rfl
    exact Bool.false_ne_true (hiff1.mpr ⟨hin, fun h1 => hncut2 (hequiv.mp h1)⟩)
  · exfalso
    obtain ⟨hin, hncut1⟩ := hiff1.mp rfl
    exact Bool.false_ne_true (hiff2.mpr ⟨hin, fun h2 => hncut1 (hequiv.mpr h2)⟩)
  · rfl

/-! ## `any_proof_survives` (Hansson Success) -/

private theorem span_all_survive_loop_false_of_witness
    (base : Slice U128) (members : Slice EntrenchmentKey)
    (all_spans : Slice RangeSpan) (stop : Usize) (start : Usize)
    (hstop_le : stop.val ≤ members.length)
    (hstart_le : start.val ≤ stop.val)
    (jw : Nat) (hjw1 : start.val ≤ jw) (hjw2 : jw < stop.val)
    (kw : EntrenchmentKey) (hkw : members.val[jw]? = some kw)
    (hdead : survives_incision kw.record_id base members all_spans = ok false) :
    span_all_survive_loop base members all_spans stop true start ⦃ res => res = false ⦄ := by
  unfold span_all_survive_loop
  apply loop.spec_decr_nat
    (fun (p : Bool × Usize) => stop.val - p.2.val)
    (fun (p : Bool × Usize) =>
      p.2.val ≤ stop.val ∧ (p.1 = true → p.2.val ≤ jw))
  · rintro ⟨flag, cursor⟩ ⟨hle, hguard⟩
    simp only at hle hguard ⊢
    unfold span_all_survive_loop.body
    by_cases hlt : cursor < stop
    · have hlt' : cursor.val < stop.val := by scalar_tac
      cases flag with
      | false =>
        simp only [hlt, ite_true, Bool.false_eq_true, ite_false, WP.spec_ok]
      | true =>
        have hcur_le_jw : cursor.val ≤ jw := hguard rfl
        have hidx : cursor.val < members.length := by omega
        obtain ⟨ek, hek, hekv⟩ := ok_of_spec (Slice.index_usize_spec members cursor hidx)
        obtain ⟨surv, hsurv⟩ := survives_incision_total ek.record_id base members all_spans
        have hcur_max : cursor.val < Usize.max := by scalar_tac
        have hnext_val : (core.num.Usize.saturating_add cursor 1#usize).val = cursor.val + 1 :=
          usize_saturating_add_one_val cursor hcur_max
        simp only [hlt, ite_true, hek, bind_ok, hsurv, lift, WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        intro hst
        by_cases hcur_eq : cursor.val = jw
        · subst hcur_eq
          have hek_get : members.val[cursor.val]? = some ek := by
            rw [List.getElem?_eq_getElem hidx, hekv]
          rw [hek_get, Option.some.injEq] at hkw
          subst hkw
          rw [hdead, Result.ok.injEq] at hsurv
          exact False.elim (Bool.false_ne_true (hsurv.trans hst))
        · omega
    · have hge : stop.val ≤ cursor.val := by scalar_tac
      simp only [hlt, ite_false, WP.spec_ok]
      cases flag with
      | false => rfl
      | true =>
        have := hguard rfl
        omega
  · exact ⟨hstart_le, fun _ => hjw1⟩

private theorem span_all_survive_false_of_mem
    (base : Slice U128) (members : Slice EntrenchmentKey)
    (span : RangeSpan) (all_spans : Slice RangeSpan)
    (hmem : span ∈ all_spans.val) :
    span_all_survive base members span all_spans = ok false := by
  unfold span_all_survive
  rcases span_stop_cases span (Slice.len members) with ⟨hpos, hle, stop, hstop_eq, hstop_val⟩ |
    ⟨-, hnone⟩
  · have hlen_val : (Slice.len members).val = members.length := by scalar_tac
    have hstop_le : stop.val ≤ members.length := by omega
    obtain ⟨chosen, hsel, ⟨jw, hjw1, hjw2, hkw⟩, -⟩ :=
      select_incision_mem_and_min members span hpos (by omega)
    have hinc : is_incised chosen.record_id members all_spans = ok true :=
      (is_incised_iff chosen.record_id members all_spans).mpr ⟨span, hmem, chosen, hsel, rfl⟩
    obtain ⟨sr, hsr, hsr_iff⟩ := survives_incision_spec chosen.record_id base members all_spans
    have hdead : survives_incision chosen.record_id base members all_spans = ok false := by
      cases sr with
      | false => exact hsr
      | true =>
        exact False.elim ((hsr_iff.mp rfl).2 ⟨span, hmem, chosen, hsel, rfl⟩)
    have hloop := span_all_survive_loop_false_of_witness base members all_spans stop span.start
      hstop_le (by omega) jw hjw1 (by omega) chosen hkw hdead
    obtain ⟨res, hres, hres_eq⟩ := ok_of_spec hloop
    subst hres_eq
    simp only [hstop_eq, bind_ok, hres]
  · simp [hnone]

private theorem any_proof_survives_loop_false
    (base : Slice U128) (members : Slice EntrenchmentKey) (spans : Slice RangeSpan) :
    any_proof_survives_loop base members spans false 0#usize ⦃ res => res = false ⦄ := by
  unfold any_proof_survives_loop
  apply loop.spec_decr_nat
    (fun (p : Bool × Usize) => spans.length - p.2.val)
    (fun (p : Bool × Usize) => p.2.val ≤ spans.length ∧ p.1 = false)
  · rintro ⟨flag, index⟩ ⟨hle, hflag⟩
    simp only at hle hflag ⊢
    subst hflag
    unfold any_proof_survives_loop.body
    by_cases hlt : index < Slice.len spans
    · have hlt' : index.val < spans.length := by scalar_tac
      obtain ⟨rs, hrs, hrsv⟩ := ok_of_spec (Slice.index_usize_spec spans index hlt')
      have hrs_mem : rs ∈ spans.val := by
        rw [hrsv]
        exact List.getElem_mem hlt'
      have hfalse := span_all_survive_false_of_mem base members rs spans hrs_mem
      have hidx_max : index.val < Usize.max := by scalar_tac
      have hnext_val : (core.num.Usize.saturating_add index 1#usize).val = index.val + 1 :=
        usize_saturating_add_one_val index hidx_max
      simp only [hlt, ite_true, Bool.false_eq_true, ite_false, hrs, bind_ok, hfalse, lift,
        WP.spec_ok]
      exact ⟨⟨by omega, trivial⟩, by omega⟩
    · simp only [hlt, ite_false, WP.spec_ok]
  · simp

/-- `any_proof_survives` never fails or diverges. -/
theorem any_proof_survives_total
    (base : Slice U128) (members : Slice EntrenchmentKey) (spans : Slice RangeSpan) :
    ∃ r, any_proof_survives base members spans = ok r := by
  obtain ⟨r, hr, -⟩ := ok_of_spec (any_proof_survives_loop_false base members spans)
  exact ⟨r, hr⟩

/-- **Hansson Success (`φ ∉ Cn(B ÷_σ φ)`)**: after applying epistemic-entrenchment
incision `σ(B ⊥ φ)`, no valid non-empty minimal kernel in `B ⊥ φ` survives
intact inside `B ÷_σ φ`. -/
theorem any_proof_survives_false
    (base : Slice U128) (members : Slice EntrenchmentKey) (spans : Slice RangeSpan) :
    any_proof_survives base members spans = ok false := by
  obtain ⟨r, hr, hfalse⟩ := ok_of_spec (any_proof_survives_loop_false base members spans)
  subst hfalse
  exact hr

/-! ## `edge_is_grounded` and `node_next_grounded` (Cycle-Free Groundedness) -/

private theorem edge_is_grounded_loop_spec
    (premises : Slice Usize) (grounded : Slice Bool) (start stop : Usize)
    (hstop_le : stop.val ≤ premises.length) (hstart_le : start.val ≤ stop.val) :
    edge_is_grounded_loop premises grounded stop true start ⦃ res =>
      res = true ↔ ∀ j, start.val ≤ j → j < stop.val →
        ∀ p, premises.val[j]? = some p →
          p.val < grounded.length ∧ grounded.val[p.val]? = some true ⦄ := by
  unfold edge_is_grounded_loop
  apply loop.spec_decr_nat
    (fun (p : Bool × Usize) => stop.val - p.2.val)
    (fun (p : Bool × Usize) =>
      start.val ≤ p.2.val ∧ p.2.val ≤ stop.val ∧
      (p.1 = true ↔ ∀ j, start.val ≤ j → j < p.2.val →
        ∀ q, premises.val[j]? = some q →
          q.val < grounded.length ∧ grounded.val[q.val]? = some true))
  · rintro ⟨flag, cursor⟩ ⟨hlo, hhi, hs⟩
    simp only at hlo hhi hs ⊢
    unfold edge_is_grounded_loop.body
    by_cases hlt : cursor < stop
    · have hlt' : cursor.val < stop.val := by scalar_tac
      cases flag with
      | false =>
        simp only [hlt, ite_true, Bool.false_eq_true, ite_false, WP.spec_ok]
        refine ⟨False.elim, fun hall => ?_⟩
        exact Bool.false_ne_true (hs.mpr (fun j hj1 hj2 q hq => hall j hj1 (by omega) q hq))
      | true =>
        have hidx : cursor.val < premises.length := by omega
        obtain ⟨prem, hprem, hpremv⟩ := ok_of_spec (Slice.index_usize_spec premises cursor hidx)
        have hprem_get : premises.val[cursor.val]? = some prem := by
          rw [List.getElem?_eq_getElem hidx, hpremv]
        have hcur_max : cursor.val < Usize.max := by scalar_tac
        have hnext_val : (core.num.Usize.saturating_add cursor 1#usize).val = cursor.val + 1 :=
          usize_saturating_add_one_val cursor hcur_max
        have hall_prev := hs.mp rfl
        by_cases hp : prem < Slice.len grounded
        · have hp' : prem.val < grounded.length := by scalar_tac
          obtain ⟨gval, hgval, hgvalv⟩ := ok_of_spec (Slice.index_usize_spec grounded prem hp')
          have hg_get : grounded.val[prem.val]? = some gval := by
            rw [List.getElem?_eq_getElem hp', hgvalv]
          simp only [hlt, ite_true, hprem, bind_ok, hp, hgval, lift, WP.spec_ok]
          refine ⟨⟨by omega, by omega, ?_⟩, by omega⟩
          rw [hnext_val]
          constructor
          · intro hgt j hj1 hj2 q hq
            by_cases hj : j = cursor.val
            · subst hj
              rw [hprem_get, Option.some.injEq] at hq
              subst hq
              exact ⟨hp', by rw [hg_get, hgt]⟩
            · exact hall_prev j hj1 (by omega) q hq
          · intro hall_next
            obtain ⟨-, hgtrue⟩ := hall_next cursor.val hlo (by omega) prem hprem_get
            rw [hg_get, Option.some.injEq] at hgtrue
            exact hgtrue
        · have hp_ge : grounded.length ≤ prem.val := by scalar_tac
          simp only [hlt, ite_true, hprem, bind_ok, hp, ite_false, lift, WP.spec_ok]
          refine ⟨⟨by omega, by omega, ?_⟩, by omega⟩
          rw [hnext_val]
          constructor
          · exact False.elim ∘ Bool.false_ne_true
          · intro hall_next
            obtain ⟨hplt, -⟩ := hall_next cursor.val hlo (by omega) prem hprem_get
            omega
    · have hge : stop.val ≤ cursor.val := by scalar_tac
      have heq : cursor.val = stop.val := by omega
      simp only [hlt, ite_false, WP.spec_ok]
      rw [heq] at hs
      exact hs
  · refine ⟨le_refl _, hstart_le, ?_⟩
    simp only [true_iff]
    intro j hj1 hj2
    omega

private theorem edge_is_grounded_spec
    (edge : SupportEdge) (premises : Slice Usize) (grounded : Slice Bool) :
    ∃ r, edge_is_grounded edge premises grounded = ok r ∧
      (r = true ↔
        edge.target.val < grounded.length ∧
        0 < edge.premises.len.val ∧
        edge.premises.start.val + edge.premises.len.val ≤ premises.length ∧
        ∀ j, edge.premises.start.val ≤ j → j < edge.premises.start.val + edge.premises.len.val →
          ∀ p, premises.val[j]? = some p →
            p.val < grounded.length ∧ grounded.val[p.val]? = some true) := by
  unfold edge_is_grounded
  by_cases hge : edge.target >= Slice.len grounded
  · have hge' : grounded.length ≤ edge.target.val := by scalar_tac
    refine ⟨false, by simp [hge], ?_⟩
    constructor
    · exact False.elim ∘ Bool.false_ne_true
    · rintro ⟨hlt, -⟩; omega
  · have hlt_t : edge.target.val < grounded.length := by scalar_tac
    rcases span_stop_cases edge.premises (Slice.len premises) with
      ⟨hpos, hle, stop, hstop_eq, hstop_val⟩ | ⟨hbad, hnone⟩
    · have hlen_p : (Slice.len premises).val = premises.length := by scalar_tac
      have hstop_le : stop.val ≤ premises.length := by omega
      obtain ⟨res, hres, hres_iff⟩ := ok_of_spec
        (edge_is_grounded_loop_spec premises grounded edge.premises.start stop hstop_le (by omega))
      rw [hstop_val] at hres_iff
      refine ⟨res, by simp [hge, hstop_eq, hres], ?_⟩
      constructor
      · intro htr
        exact ⟨hlt_t, hpos, by omega, hres_iff.mp htr⟩
      · rintro ⟨-, -, -, hall⟩
        exact hres_iff.mpr hall
    · have hlen_p : (Slice.len premises).val = premises.length := by scalar_tac
      rw [hlen_p] at hbad
      refine ⟨false, by simp [hge, hnone], ?_⟩
      constructor
      · exact False.elim ∘ Bool.false_ne_true
      · rintro ⟨-, hpos, hle, -⟩; omega

/-- `edge_is_grounded` never fails or diverges. -/
theorem edge_is_grounded_total
    (edge : SupportEdge) (premises : Slice Usize) (grounded : Slice Bool) :
    ∃ r, edge_is_grounded edge premises grounded = ok r := by
  obtain ⟨r, hr, -⟩ := edge_is_grounded_spec edge premises grounded
  exact ⟨r, hr⟩

/-- `edge_is_grounded` is true iff the target is in bounds, the premise span is
valid and non-empty, and every premise node is grounded. -/
theorem edge_is_grounded_iff
    (edge : SupportEdge) (premises : Slice Usize) (grounded : Slice Bool) :
    edge_is_grounded edge premises grounded = ok true ↔
      edge.target.val < grounded.length ∧
      0 < edge.premises.len.val ∧
      edge.premises.start.val + edge.premises.len.val ≤ premises.length ∧
      ∀ j, edge.premises.start.val ≤ j → j < edge.premises.start.val + edge.premises.len.val →
        ∀ p, premises.val[j]? = some p →
          p.val < grounded.length ∧ grounded.val[p.val]? = some true := by
  obtain ⟨r, hr, hiff⟩ := edge_is_grounded_spec edge premises grounded
  rw [hr, Result.ok.injEq]
  exact hiff

private theorem node_next_grounded_loop_spec
    (node : Usize) (edges : Slice SupportEdge)
    (premises : Slice Usize) (grounded : Slice Bool) :
    node_next_grounded_loop node edges premises grounded false 0#usize ⦃ res =>
      res = true ↔ ∃ e ∈ edges.val, e.target = node ∧
        edge_is_grounded e premises grounded = ok true ⦄ := by
  unfold node_next_grounded_loop
  apply loop.spec_decr_nat
    (fun (p : Bool × Usize) => edges.length - p.2.val)
    (fun (p : Bool × Usize) =>
      p.2.val ≤ edges.length ∧
      (p.1 = true ↔ ∃ e ∈ edges.val.take p.2.val, e.target = node ∧
        edge_is_grounded e premises grounded = ok true))
  · rintro ⟨flag, index⟩ ⟨hle, hs⟩
    simp only at hle hs ⊢
    unfold node_next_grounded_loop.body
    by_cases hlt : index < Slice.len edges
    · have hlt' : index.val < edges.length := by scalar_tac
      cases flag with
      | true =>
        simp only [hlt, ite_true, WP.spec_ok]
        refine ⟨fun _ => ?_, fun _ => trivial⟩
        obtain ⟨e, hemem, ht, hg⟩ := hs.mp rfl
        exact ⟨e, List.mem_of_mem_take hemem, ht, hg⟩
      | false =>
        obtain ⟨edge, hedge, hedgev⟩ := ok_of_spec (Slice.index_usize_spec edges index hlt')
        have hidx_max : index.val < Usize.max := by scalar_tac
        have hnext_val : (core.num.Usize.saturating_add index 1#usize).val = index.val + 1 :=
          usize_saturating_add_one_val index hidx_max
        by_cases htarget : edge.target = node
        · obtain ⟨eg, heg⟩ := edge_is_grounded_total edge premises grounded
          cases eg with
          | true =>
            simp only [hlt, ite_true, Bool.false_eq_true, ite_false, hedge, bind_ok, htarget,
              heg, lift, WP.spec_ok]
            refine ⟨⟨by omega, ?_⟩, by omega⟩
            rw [hnext_val]
            exact ⟨fun _ => ⟨edge, (mem_take_succ edges.val index.val hlt' edge).mpr (Or.inr hedgev.symm),
              htarget, heg⟩, fun _ => trivial⟩
          | false =>
            simp only [hlt, ite_true, Bool.false_eq_true, ite_false, hedge, bind_ok, htarget,
              heg, lift, WP.spec_ok]
            refine ⟨⟨by omega, ?_⟩, by omega⟩
            rw [hnext_val]
            constructor
            · exact False.elim
            · rintro ⟨e, hemem, ht, hg⟩
              rcases (mem_take_succ edges.val index.val hlt' e).mp hemem with hprev | hcurr
              · exact Bool.false_ne_true (hs.mpr ⟨e, hprev, ht, hg⟩)
              · rw [← hcurr, ← hedgev, heg, Result.ok.injEq] at hg
                cases hg
        · simp only [hlt, ite_true, Bool.false_eq_true, ite_false, hedge, bind_ok, htarget,
            lift, WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          rw [hnext_val]
          constructor
          · exact False.elim
          · rintro ⟨e, hemem, ht, hg⟩
            rcases (mem_take_succ edges.val index.val hlt' e).mp hemem with hprev | hcurr
            · exact Bool.false_ne_true (hs.mpr ⟨e, hprev, ht, hg⟩)
            · rw [← hcurr, ← hedgev] at ht
              exact False.elim (htarget ht)
    · have hge : edges.val.length ≤ index.val := by scalar_tac
      simp only [hlt, ite_false, WP.spec_ok]
      rw [List.take_of_length_le hge] at hs
      exact hs
  · simp

private theorem node_next_grounded_spec
    (node : Usize) (edges : Slice SupportEdge)
    (premises : Slice Usize) (grounded : Slice Bool) :
    ∃ r, node_next_grounded node edges premises grounded = ok r ∧
      (r = true ↔
        node.val < grounded.length ∧
        (grounded.val[node.val]? = some true ∨
          ∃ e ∈ edges.val, e.target = node ∧ edge_is_grounded e premises grounded = ok true)) := by
  unfold node_next_grounded
  by_cases hge : node >= Slice.len grounded
  · have hge' : grounded.length ≤ node.val := by scalar_tac
    refine ⟨false, by simp [hge], ?_⟩
    constructor
    · exact False.elim ∘ Bool.false_ne_true
    · rintro ⟨hlt, -⟩; omega
  · have hlt : node.val < grounded.length := by scalar_tac
    obtain ⟨gval, hgval, hgvalv⟩ := ok_of_spec (Slice.index_usize_spec grounded node hlt)
    have hg_get : grounded.val[node.val]? = some gval := by
      rw [List.getElem?_eq_getElem hlt, hgvalv]
    cases gval with
    | true =>
      refine ⟨true, by simp [hge, hgval], ?_⟩
      exact ⟨fun _ => ⟨hlt, Or.inl hg_get⟩, fun _ => rfl⟩
    | false =>
      obtain ⟨res, hres, hres_iff⟩ := ok_of_spec
        (node_next_grounded_loop_spec node edges premises grounded)
      refine ⟨res, by simp [hge, hgval, hres], ?_⟩
      constructor
      · intro htr
        exact ⟨hlt, Or.inr (hres_iff.mp htr)⟩
      · rintro ⟨-, htrue | hex⟩
        · rw [hg_get, Option.some.injEq] at htrue
          cases htrue
        · exact hres_iff.mpr hex

/-- `node_next_grounded` never fails or diverges. -/
theorem node_next_grounded_total
    (node : Usize) (edges : Slice SupportEdge)
    (premises : Slice Usize) (grounded : Slice Bool) :
    ∃ r, node_next_grounded node edges premises grounded = ok r := by
  obtain ⟨r, hr, -⟩ := node_next_grounded_spec node edges premises grounded
  exact ⟨r, hr⟩

/-- Groundedness is monotone: an already grounded node stays grounded. -/
theorem node_next_grounded_monotone
    (node : Usize) (edges : Slice SupportEdge)
    (premises : Slice Usize) (grounded : Slice Bool)
    (hlt : node.val < grounded.length)
    (hg : grounded.val[node.val]? = some true) :
    node_next_grounded node edges premises grounded = ok true := by
  obtain ⟨r, hr, hiff⟩ := node_next_grounded_spec node edges premises grounded
  rw [hr, hiff.mpr ⟨hlt, Or.inl hg⟩]

/-- **Cycle-Free Groundedness (Unfounded-Set Invariance)**:
for any unfounded set `U` disjoint from the currently grounded nodes such that
every hyperedge targeting a node in `U` either is empty/out-of-bounds or
requires at least one premise in `U` (or out-of-bounds), no node in `U` becomes
grounded. By induction, `U` remains completely ungrounded at every round and
at fixpoint. -/
theorem node_next_grounded_unfounded_preserved
    (U : Nat → Prop)
    (node : Usize) (edges : Slice SupportEdge)
    (premises : Slice Usize) (grounded : Slice Bool)
    (hnode : U node.val)
    (hinit : ∀ i, i < grounded.length → U i → grounded.val[i]? = some false)
    (hedges : ∀ e ∈ edges.val, U e.target.val →
      e.premises.len.val = 0 ∨
      premises.length < e.premises.start.val + e.premises.len.val ∨
      ∃ j, e.premises.start.val ≤ j ∧ j < e.premises.start.val + e.premises.len.val ∧
        ∀ p, premises.val[j]? = some p → grounded.length ≤ p.val ∨ U p.val) :
    node_next_grounded node edges premises grounded = ok false := by
  obtain ⟨r, hr, hiff⟩ := node_next_grounded_spec node edges premises grounded
  cases r with
  | false => exact hr
  | true =>
    exfalso
    obtain ⟨hlt, hself | ⟨e, hemem, htarget, heg⟩⟩ := hiff.mp rfl
    · have hf := hinit node.val hlt hnode
      rw [hf, Option.some.injEq] at hself
      cases hself
    · have he_u : U e.target.val := by rw [htarget]; exact hnode
      obtain ⟨-, hpos, hle, hall⟩ := (edge_is_grounded_iff e premises grounded).mp heg
      rcases hedges e hemem he_u with hzero | hgt | ⟨j, hj1, hj2, hbad⟩
      · omega
      · omega
      · have hj_lt : j < premises.length := by omega
        obtain ⟨p, hp⟩ : ∃ p, premises.val[j]? = some p :=
          ⟨premises.val[j], List.getElem?_eq_getElem hj_lt⟩
        obtain ⟨hplt, hpg⟩ := hall j hj1 hj2 p hp
        rcases hbad p hp with hpge | hpu
        · omega
        · have hf := hinit p.val hplt hpu
          rw [hf, Option.some.injEq] at hpg
          cases hpg

/-- **Mutual Cycle (`A ↔ B`) Unfoundedness**: a mutually self-supporting pair
`{a, b}` with no surviving root and every incoming hyperedge requiring `a` or
`b` remains completely ungrounded. -/
theorem node_next_grounded_mutual_cycle_ungrounded
    (a b : Usize) (edges : Slice SupportEdge)
    (premises : Slice Usize) (grounded : Slice Bool)
    (ha0 : a.val < grounded.length → grounded.val[a.val]? = some false)
    (hb0 : b.val < grounded.length → grounded.val[b.val]? = some false)
    (hedges : ∀ e ∈ edges.val, e.target.val = a.val ∨ e.target.val = b.val →
      e.premises.len.val = 0 ∨
      premises.length < e.premises.start.val + e.premises.len.val ∨
      ∃ j, e.premises.start.val ≤ j ∧ j < e.premises.start.val + e.premises.len.val ∧
        ∀ p, premises.val[j]? = some p →
          grounded.length ≤ p.val ∨ p.val = a.val ∨ p.val = b.val) :
    node_next_grounded a edges premises grounded = ok false ∧
      node_next_grounded b edges premises grounded = ok false := by
  let U : Nat → Prop := fun i => i = a.val ∨ i = b.val
  have hinit : ∀ i, i < grounded.length → U i → grounded.val[i]? = some false := by
    intro i hi hu
    rcases hu with rfl | rfl
    · exact ha0 hi
    · exact hb0 hi
  exact ⟨
    node_next_grounded_unfounded_preserved U a edges premises grounded (Or.inl rfl) hinit hedges,
    node_next_grounded_unfounded_preserved U b edges premises grounded (Or.inr rfl) hinit hedges
  ⟩

end mneme_kernel.contraction
