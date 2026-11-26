import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Half-open bitemporal interval algebra, coalescing, Allen relations, and bounded DatalogMTL

Theorems about the generated translation of `crates/mneme-kernel/src/temporal.rs`.
Proves:
- Half-open `[start, stop)` membership and legacy `Instant(t) -> [t, t + 1ns)` decoding.
- Half-open expiry handoff disjointness (`expire_bounds`).
- Monoidal intersection laws: totality, commutativity, associativity, empty annihilation,
  and pointwise membership soundness.
- Coalescing soundness: pairwise and full-slice snapshot-equivalence
  (`∀ t, t ∈ ⋃ I ↔ t ∈ ⋃ coalesce(I)`), canonical strictly-separated output, and idempotence.
- Allen's 13 relations exhaustiveness on valid periods and fail-closed `Unknown`.
- Bounded DatalogMTL (`diamond_minus`, `box_minus`, `since`) totality and fail-closed `Unknown`.
-/

namespace mneme_kernel.temporal

private theorem ok_bind {α β : Type} (x : α) (f : α → Result β) :
    (do let y ← ok x; f y) = f x := by
  simp

private theorem spec_imp_exists {α : Type} {m : Result α} {p : α → Prop}
    (h : WP.spec m p) : ∃ v, m = ok v ∧ p v := by
  cases m with
  | ret r => exact ⟨r, rfl, by simpa using h⟩
  | vis i k => simp at h
  | div => simp at h

private theorem i128_add_eq {a b : I128}
    (hmin : I128.min ≤ a.val + b.val) (hmax : a.val + b.val ≤ I128.max) :
    ∃ r, a + b = ok r ∧ r.val = a.val + b.val :=
  spec_imp_exists (I128.add_spec hmin hmax)

private theorem i128_sub_eq {a b : I128}
    (hmin : I128.min ≤ a.val - b.val) (hmax : a.val - b.val ≤ I128.max) :
    ∃ r, a - b = ok r ∧ r.val = a.val - b.val :=
  spec_imp_exists (I128.sub_spec hmin hmax)

private theorem usize_add_one_eq {i : Usize} (h : i.val + 1 ≤ Usize.max) :
    ∃ j, i + 1#usize = ok j ∧ j.val = i.val + 1 := by
  have h1 : i.val + (1#usize).val ≤ Usize.max := by scalar_tac
  obtain ⟨j, hj, hv⟩ := spec_imp_exists (Usize.add_spec h1)
  exact ⟨j, hj, by scalar_tac⟩

private theorem usize_sub_one_eq {i : Usize} (h : 0 < i.val) :
    ∃ j, i - 1#usize = ok j ∧ j.val = i.val - 1 := by
  have h1 : (1#usize).val ≤ i.val := by scalar_tac
  obtain ⟨j, hj, hv, _⟩ := spec_imp_exists (Usize.sub_spec h1)
  exact ⟨j, hj, by scalar_tac⟩

private theorem index_usize_eq (s : Slice Period) (i : Usize) (h : i.val < s.val.length) :
    Slice.index_usize s i = ok (s.val[i.val]'h) := by
  obtain ⟨x, hx, hv⟩ := spec_imp_exists (Slice.index_usize_spec s i h)
  rw [hx, hv]

private theorem update_eq (s : Slice Period) (i : Usize) (v : Period) (h : i.val < s.val.length) :
    ∃ s', Slice.update s i v = ok s' ∧
      s'.val.length = s.val.length ∧
      s'.val = s.val.set i.val v := by
  have hlen : i.val < s.length := by simpa [Slice.length] using h
  obtain ⟨s', hs', hset⟩ := spec_imp_exists (Slice.update_spec s i v hlen)
  have hval : s'.val = s.val.set i.val v := by
    rw [hset]
    simp [Slice.set, Slice.setAtNat]
  exact ⟨s', hs', by rw [hval, List.length_set], hval⟩

private theorem neg_inf_val : NEG_INF.val = I128.min := by
  simp [NEG_INF, core.num.I128.MIN, I128.min, I128.rMin, I128.numBits]

private theorem pos_inf_val : POS_INF.val = I128.max := by
  simp [POS_INF, core.num.I128.MAX, I128.max, I128.rMax, I128.numBits]

private theorem one_ns_val : ONE_NS.val = 1 := by
  simp [ONE_NS]

private theorem zero_ns_val : ZERO_NS.val = 0 := by
  simp [ZERO_NS]

private theorem cast_i64_to_i128_eq (x : I64) :
    ∃ y : I128, lift (IScalar.cast .I128 x) = ok y ∧ y.val = x.val := by
  have hmin : IScalar.min .I128 ≤ x.val := by
    simp only [IScalar.min, IScalarTy.numBits]
    have hx := x.hBounds
    simp only [IScalarTy.numBits] at hx
    omega
  have hmax : x.val ≤ IScalar.max .I128 := by
    simp only [IScalar.max, IScalarTy.numBits]
    have hx := x.hBounds
    simp only [IScalarTy.numBits] at hx
    omega
  exact spec_imp_exists (IScalar.cast_inBounds_spec .I128 x ⟨hmin, hmax⟩)

private theorem shift_forward_total (endpoint delta : I128) :
    ∃ r, shift_forward endpoint delta = ok r := by
  unfold shift_forward
  by_cases h1 : endpoint = NEG_INF
  · exact ⟨NEG_INF, by simp only [h1, ite_true]⟩
  · by_cases h2 : endpoint = POS_INF
    · refine ⟨POS_INF, ?_⟩
      simp only [h1, ite_false]
      simp only [h2, ite_true]
    · by_cases h3 : delta ≤ ZERO_NS
      · refine ⟨endpoint, ?_⟩
        simp only [h1, ite_false]
        simp only [h2, ite_false]
        simp only [h3, ite_true]
      · have hpos : 0 < delta.val := by
          have hz := zero_ns_val
          scalar_tac
        have hpm := pos_inf_val
        have hsub_min : I128.min ≤ POS_INF.val - delta.val := by scalar_tac
        have hsub_max : POS_INF.val - delta.val ≤ I128.max := by scalar_tac
        obtain ⟨lim, hlim, hlim_val⟩ := i128_sub_eq hsub_min hsub_max
        simp only [h1, h2, h3, ite_false]
        rw [hlim, ok_bind]
        by_cases hgt : endpoint > lim
        · exact ⟨POS_INF, by simp only [hgt, ite_true]⟩
        · have hadd_min : I128.min ≤ endpoint.val + delta.val := by scalar_tac
          have hadd_max : endpoint.val + delta.val ≤ I128.max := by scalar_tac
          obtain ⟨r, hr, _⟩ := i128_add_eq hadd_min hadd_max
          exact ⟨r, by simp only [hgt, ite_false, hr]⟩

private theorem shift_back_one_total (endpoint : I128) :
    ∃ r, shift_back_one endpoint = ok r := by
  unfold shift_back_one
  by_cases h1 : endpoint = NEG_INF
  · exact ⟨NEG_INF, by simp only [h1, ite_true]⟩
  · by_cases h2 : endpoint = POS_INF
    · refine ⟨POS_INF, ?_⟩
      simp only [h1, ite_false]
      simp only [h2, ite_true]
    · have hne : endpoint.val ≠ I128.min := by
        intro heq
        apply h1
        rw [IScalar.eq_equiv, neg_inf_val]
        exact heq
      have h1v := one_ns_val
      have hmin : I128.min ≤ endpoint.val - ONE_NS.val := by scalar_tac
      have hmax : endpoint.val - ONE_NS.val ≤ I128.max := by scalar_tac
      obtain ⟨r, hr, _⟩ := i128_sub_eq hmin hmax
      exact ⟨r, by simp only [h1, h2, ite_false, hr]⟩

/-! ## Core Period & Validity Predicates -/

/-- `is_valid` never fails and holds iff `period.start < period.stop`. -/
theorem is_valid_iff (period : Period) :
    is_valid period = ok (decide (period.start.val < period.stop.val)) := by
  unfold is_valid
  by_cases h : period.start < period.stop
  · have h' : period.start.val < period.stop.val := by scalar_tac
    simp [h, h']
  · have h' : ¬ period.start.val < period.stop.val := by scalar_tac
    simp [h, h']

/-- `contains` never fails and enforces half-open `[start, stop)` membership. -/
theorem contains_iff (period : Period) (instant : I128) :
    contains period instant = ok (decide (period.start.val ≤ instant.val ∧ instant.val < period.stop.val)) := by
  unfold contains
  by_cases h1 : period.start ≤ instant
  · have h1' : period.start.val ≤ instant.val := by scalar_tac
    by_cases h2 : instant < period.stop
    · have h2' : instant.val < period.stop.val := by scalar_tac
      simp [h1, h2, h1', h2']
    · have h2' : ¬ instant.val < period.stop.val := by scalar_tac
      simp [h1, h2, h1', h2']
  · have h1' : ¬ period.start.val ≤ instant.val := by scalar_tac
    simp [h1, h1']

/-- `Validity.Unknown` fails closed: it contains no instant. -/
theorem validity_contains_unknown (instant : I128) :
    validity_contains Validity.Unknown instant = ok false := by
  rfl

/-- `validity_contains` on a known period delegates directly to half-open `contains`. -/
theorem validity_contains_known_iff (period : Period) (instant : I128) :
    validity_contains (Validity.Known period) instant =
      ok (decide (period.start.val ≤ instant.val ∧ instant.val < period.stop.val)) := by
  unfold validity_contains
  exact contains_iff period instant

/-! ## Legacy Bounds Decoding & Expiry Handoff -/

/-- `from_legacy_bounds` never fails or overflows for any optional 64-bit bounds. -/
theorem from_legacy_bounds_total (start stop : Option I64) :
    ∃ res, from_legacy_bounds start stop = ok res := by
  unfold from_legacy_bounds
  cases start with
  | none =>
    cases stop with
    | none => exact ⟨_, rfl⟩
    | some hi =>
      dsimp only
      obtain ⟨y, hy, _⟩ := cast_i64_to_i128_eq hi
      exact ⟨_, by rw [hy, ok_bind]⟩
  | some lo =>
    cases stop with
    | none =>
      dsimp only
      obtain ⟨y, hy, _⟩ := cast_i64_to_i128_eq lo
      exact ⟨_, by rw [hy, ok_bind]⟩
    | some hi =>
      dsimp only
      by_cases hlt : lo < hi
      · obtain ⟨y1, hy1, _⟩ := cast_i64_to_i128_eq lo
        obtain ⟨y2, hy2, _⟩ := cast_i64_to_i128_eq hi
        exact ⟨_, by simp only [hlt, ite_true]; rw [hy1, ok_bind, hy2, ok_bind]⟩
      · by_cases heq : lo = hi
        · subst heq
          obtain ⟨y, hy, hyv⟩ := cast_i64_to_i128_eq lo
          have h1v := one_ns_val
          have hmin : I128.min ≤ y.val + ONE_NS.val := by
            simp only [I128.min, I128.numBits, IScalarTy.numBits]
            have hlo := lo.hBounds
            simp only [IScalarTy.numBits] at hlo
            omega
          have hmax : y.val + ONE_NS.val ≤ I128.max := by
            simp only [I128.max, I128.numBits, IScalarTy.numBits]
            have hlo := lo.hBounds
            simp only [IScalarTy.numBits] at hlo
            omega
          obtain ⟨y1, hy1, _⟩ := i128_add_eq hmin hmax
          refine ⟨some { start := y, stop := y1 }, ?_⟩
          simp only [hlt, ite_false, ite_true]
          rw [hy, ok_bind, hy1, ok_bind]
        · exact ⟨none, by simp only [hlt, heq, ite_false]⟩

/-- Legacy point-instant bounds `(some t, some t)` decode to `[t, t + 1ns)`. -/
theorem from_legacy_bounds_instant (t : I64) :
    ∃ p, from_legacy_bounds (some t) (some t) = ok (some p) ∧
      p.start.val = t.val ∧ p.stop.val = t.val + 1 := by
  unfold from_legacy_bounds
  dsimp only
  have hnotlt : ¬ t < t := by scalar_tac
  obtain ⟨y, hy, hyv⟩ := cast_i64_to_i128_eq t
  have h1v := one_ns_val
  have hmin : I128.min ≤ y.val + ONE_NS.val := by
    simp only [I128.min, I128.numBits, IScalarTy.numBits]
    have ht := t.hBounds
    simp only [IScalarTy.numBits] at ht
    omega
  have hmax : y.val + ONE_NS.val ≤ I128.max := by
    simp only [I128.max, I128.numBits, IScalarTy.numBits]
    have ht := t.hBounds
    simp only [IScalarTy.numBits] at ht
    omega
  obtain ⟨y1, hy1, hy1v⟩ := i128_add_eq hmin hmax
  refine ⟨{ start := y, stop := y1 }, ?_, hyv, by dsimp only; omega⟩
  simp only [hnotlt, ite_false, ite_true]
  rw [hy, ok_bind, hy1, ok_bind]

/-- Inverted bounds (`stop < start`) are rejected with `none`. -/
theorem from_legacy_bounds_inverted (start stop : I64) (h : stop.val < start.val) :
    from_legacy_bounds (some start) (some stop) = ok none := by
  unfold from_legacy_bounds
  dsimp only
  have h1 : ¬ start < stop := by scalar_tac
  have h2 : ¬ start = stop := by
    intro heq; subst heq; omega
  simp only [h1, h2, ite_false]

/-- `expire_bounds` fails closed on `Validity.Unknown`. -/
theorem expire_bounds_unknown (effective : I64) :
    expire_bounds Validity.Unknown effective = ok ExpiryDecision.UnknownValidity := by
  rfl

/-- `expire_bounds` never fails or diverges. -/
theorem expire_bounds_total (validity : Validity) (effective : I64) :
    ∃ d, expire_bounds validity effective = ok d := by
  unfold expire_bounds
  cases validity with
  | Unknown => exact ⟨_, rfl⟩
  | Known p =>
    dsimp only
    rw [is_valid_iff]
    simp only [bind_ok]
    by_cases hv : p.start.val < p.stop.val
    · obtain ⟨eff, heff, _⟩ := cast_i64_to_i128_eq effective
      simp only [hv, decide_true, ite_true]
      rw [heff, ok_bind]
      split_ifs <;> exact ⟨_, rfl⟩
    · exact ⟨ExpiryDecision.UnknownValidity,
        by simp only [hv, decide_false, Bool.false_eq_true, ite_false]⟩

/-- Half-open expiry handoff: an allowed expiry at `effective` excludes `effective`
itself and preserves membership for every strictly earlier instant. -/
theorem expire_bounds_handoff_disjoint (p q : Period) (effective : I64)
    (h : expire_bounds (Validity.Known p) effective = ok (ExpiryDecision.Allowed q)) :
    q.start = p.start ∧ q.stop.val = effective.val ∧ q.start.val < q.stop.val ∧
      (∀ t : I128, t.val = effective.val → contains q t = ok false) ∧
      (∀ t : I128, t.val < effective.val → contains q t = contains p t) := by
  unfold expire_bounds at h
  dsimp only at h
  rw [is_valid_iff] at h
  simp only [bind_ok] at h
  by_cases hv : p.start.val < p.stop.val
  · obtain ⟨eff, heff, heff_val⟩ := cast_i64_to_i128_eq effective
    simp only [hv, decide_true, ite_true] at h
    rw [heff, ok_bind] at h
    split_ifs at h with h1 h2
    · simp at h
    · simp at h
    · simp only [Result.ok.injEq, ExpiryDecision.Allowed.injEq] at h
      subst h
      have hlt1 : p.start.val < eff.val := by scalar_tac
      have hlt2 : eff.val < p.stop.val := by scalar_tac
      refine ⟨rfl, heff_val, hlt1, ?_, ?_⟩
      · intro t ht
        rw [contains_iff]
        have : ¬ (p.start.val ≤ t.val ∧ t.val < eff.val) := by omega
        simp [this]
      · intro t ht
        rw [contains_iff, contains_iff]
        have hlt_e : t.val < eff.val := by omega
        have hlt_s : t.val < p.stop.val := by omega
        simp [hlt_e, hlt_s]
  · simp [hv] at h

/-! ## Monoidal Intersection Algebra -/

private theorem intersect_eval (a b : Period) :
    (¬ (a.start.val < a.stop.val ∧ b.start.val < b.stop.val ∧
        max a.start.val b.start.val < min a.stop.val b.stop.val) ∧
      intersect a b = ok none) ∨
    (a.start.val < a.stop.val ∧ b.start.val < b.stop.val ∧
      max a.start.val b.start.val < min a.stop.val b.stop.val ∧
      ∃ r, intersect a b = ok (some r) ∧
        r.start.val = max a.start.val b.start.val ∧
        r.stop.val = min a.stop.val b.stop.val) := by
  unfold intersect
  rw [is_valid_iff, is_valid_iff]
  simp only [bind_ok]
  by_cases ha : a.start.val < a.stop.val
  · by_cases hb : b.start.val < b.stop.val
    · simp only [ha, hb, decide_true, ite_true]
      set s : I128 := if a.start ≥ b.start then a.start else b.start
      set e : I128 := if a.stop ≤ b.stop then a.stop else b.stop
      have hs : (if a.start ≥ b.start then ok a.start else ok b.start) = ok s := by
        by_cases hc : a.start ≥ b.start <;> simp [s, hc]
      have he : (if a.stop ≤ b.stop then ok a.stop else ok b.stop) = ok e := by
        by_cases hc : a.stop ≤ b.stop <;> simp [e, hc]
      have hsv : s.val = max a.start.val b.start.val := by
        dsimp [s]; split_ifs <;> scalar_tac
      have hev : e.val = min a.stop.val b.stop.val := by
        dsimp [e]; split_ifs <;> scalar_tac
      rw [hs, ok_bind, he, ok_bind]
      by_cases hlt : s < e
      · have hlt' : max a.start.val b.start.val < min a.stop.val b.stop.val := by scalar_tac
        right
        exact ⟨trivial, trivial, hlt', Period.mk s e, by simp [hlt], hsv, hev⟩
      · have hnot : ¬ max a.start.val b.start.val < min a.stop.val b.stop.val := by scalar_tac
        left
        exact ⟨by omega, by simp [hlt]⟩
    · left; exact ⟨by omega, by simp [ha, hb]⟩
  · left; exact ⟨by omega, by simp [ha]⟩

/-- `intersect` never fails or diverges. -/
theorem intersect_total (left right : Period) :
    ∃ r, intersect left right = ok r := by
  rcases intersect_eval left right with ⟨_, h⟩ | ⟨_, _, _, r, h, _, _⟩
  · exact ⟨none, h⟩
  · exact ⟨some r, h⟩

/-- `intersect` is commutative. -/
theorem intersect_comm (left right : Period) :
    intersect left right = intersect right left := by
  rcases intersect_eval left right with ⟨h1, heq1⟩ | ⟨ha, hb, hlt, r1, heq1, hs1, he1⟩
  · rcases intersect_eval right left with ⟨_, heq2⟩ | ⟨hb, ha, hlt, _, _, _, _⟩
    · rw [heq1, heq2]
    · exfalso; apply h1; exact ⟨ha, hb, by omega⟩
  · rcases intersect_eval right left with ⟨h2, _⟩ | ⟨_, _, _, r2, heq2, hs2, he2⟩
    · exfalso; apply h2; exact ⟨hb, ha, by omega⟩
    · rw [heq1, heq2]
      have hstart : r1.start = r2.start := by rw [IScalar.eq_equiv]; omega
      have hstop : r1.stop = r2.stop := by rw [IScalar.eq_equiv]; omega
      cases r1; cases r2; simp at hstart hstop; subst hstart; subst hstop; rfl

/-- `intersect` satisfies pointwise set-intersection soundness. -/
theorem intersect_pointwise (left right r : Period)
    (h : intersect left right = ok (some r)) (instant : I128) :
    contains r instant = ok true ↔
      (contains left instant = ok true ∧ contains right instant = ok true) := by
  rcases intersect_eval left right with ⟨_, hnone⟩ | ⟨_, _, _, r', hsome, hs, he⟩
  · rw [hnone] at h; simp at h
  · rw [hsome] at h
    simp only [Result.ok.injEq, Option.some.injEq] at h
    subst h
    rw [contains_iff, contains_iff, contains_iff]
    simp only [Result.ok.injEq, decide_eq_true_eq]
    omega

/-- Left empty annihilation: `∅ ∩ x = ∅`. -/
theorem intersect_option_none_left (right : Option Period) :
    intersect_option none right = ok none := by
  rfl

/-- Right empty annihilation: `x ∩ ∅ = ∅`. -/
theorem intersect_option_none_right (left : Option Period) :
    intersect_option left none = ok none := by
  cases left <;> rfl

/-- `intersect_option` is commutative. -/
theorem intersect_option_comm (left right : Option Period) :
    intersect_option left right = intersect_option right left := by
  cases left with
  | none => cases right <;> rfl
  | some a =>
    cases right with
    | none => rfl
    | some b => exact intersect_comm a b

/-- `intersect_option` is associative: `(a ∩ b) ∩ c = a ∩ (b ∩ c)`. -/
theorem intersect_option_assoc (a b c : Option Period) :
    (do let ab ← intersect_option a b; intersect_option ab c) =
      (do let bc ← intersect_option b c; intersect_option a bc) := by
  cases a with
  | none =>
    cases b with
    | none => simp [intersect_option]
    | some bp =>
      cases c with
      | none => simp [intersect_option]
      | some cp =>
        obtain ⟨bc, hbc⟩ := intersect_total bp cp
        simp [intersect_option, hbc]
  | some ap =>
    cases b with
    | none => simp [intersect_option]
    | some bp =>
      cases c with
      | none =>
        obtain ⟨ab, hab⟩ := intersect_total ap bp
        cases ab <;> simp [intersect_option, hab]
      | some cp =>
        dsimp only [intersect_option]
        rcases intersect_eval ap bp with ⟨hab_not, hab⟩ | ⟨ha, hb, hlt_ab, ab, hab, hs_ab, he_ab⟩
        · simp [hab]
          rcases intersect_eval bp cp with ⟨_, hbc⟩ | ⟨hb, hc, hlt_bc, bc, hbc, hs_bc, he_bc⟩
          · simp [hbc]
          · simp [hbc]
            rcases intersect_eval ap bc with ⟨_, habc⟩ | ⟨ha, _, hlt_abc, _, _, _, _⟩
            · exact habc.symm
            · exfalso; apply hab_not; exact ⟨ha, hb, by omega⟩
        · simp [hab]
          rcases intersect_eval bp cp with ⟨hbc_not, hbc⟩ | ⟨_, hc, hlt_bc, bc, hbc, hs_bc, he_bc⟩
          · simp [hbc]
            rcases intersect_eval ab cp with ⟨_, habc⟩ | ⟨_, hc, hlt_abc, _, _, _, _⟩
            · exact habc
            · exfalso; apply hbc_not; exact ⟨hb, hc, by omega⟩
          · simp [hbc]
            rcases intersect_eval ab cp with ⟨h1_not, h1⟩ | ⟨_, _, h1_lt, r1, h1, hs1, he1⟩
            · rcases intersect_eval ap bc with ⟨_, h2⟩ | ⟨_, _, h2_lt, _, _, _, _⟩
              · rw [h1, h2]
              · exfalso; apply h1_not; exact ⟨by omega, hc, by omega⟩
            · rcases intersect_eval ap bc with ⟨h2_not, _⟩ | ⟨_, _, _, r2, h2, hs2, he2⟩
              · exfalso; apply h2_not; exact ⟨ha, by omega, by omega⟩
              · rw [h1, h2]
                have hstart : r1.start = r2.start := by rw [IScalar.eq_equiv]; omega
                have hstop : r1.stop = r2.stop := by rw [IScalar.eq_equiv]; omega
                cases r1; cases r2; simp at hstart hstop; subst hstart; subst hstop; rfl

/-! ## Pairwise and Full-Slice Coalescing -/

/-- `can_coalesce` is symmetric. -/
theorem can_coalesce_symm (left right : Period) :
    can_coalesce left right = can_coalesce right left := by
  unfold can_coalesce
  rw [is_valid_iff, is_valid_iff]
  simp only [bind_ok]
  by_cases ha : left.start.val < left.stop.val <;>
    by_cases hb : right.start.val < right.stop.val <;>
    by_cases h1 : left.start ≤ right.stop <;>
    by_cases h2 : right.start ≤ left.stop <;>
    simp [ha, hb, h1, h2]

/-- Pairwise coalescing snapshot-equivalence: `m = coalesce_pair a b` covers
exactly the union of instants covered by `a` or `b`. -/
theorem coalesce_pair_snapshot_equiv (left right merged : Period)
    (h : coalesce_pair left right = ok (some merged)) (instant : I128) :
    contains merged instant = ok true ↔
      (contains left instant = ok true ∨ contains right instant = ok true) := by
  unfold coalesce_pair can_coalesce at h
  rw [is_valid_iff, is_valid_iff] at h
  simp only [bind_ok] at h
  by_cases ha : left.start.val < left.stop.val
  · by_cases hb : right.start.val < right.stop.val
    · simp only [ha, hb, decide_true, ite_true] at h
      by_cases h1 : left.start ≤ right.stop
      · by_cases h2 : right.start ≤ left.stop
        · have h1' : left.start.val ≤ right.stop.val := by scalar_tac
          have h2' : right.start.val ≤ left.stop.val := by scalar_tac
          simp only [h1, h2, decide_true, ite_true, bind_ok] at h
          set s : I128 := if left.start ≤ right.start then left.start else right.start
          have hs : (if left.start ≤ right.start then ok left.start else ok right.start) = ok s := by
            by_cases hc : left.start ≤ right.start <;> simp [s, hc]
          have hsv : s.val = min left.start.val right.start.val := by
            dsimp [s]; split_ifs <;> scalar_tac
          rw [hs, ok_bind] at h
          by_cases hstop : left.stop ≥ right.stop
          · simp only [hstop, ite_true, Result.ok.injEq, Option.some.injEq] at h
            subst h
            have hge : right.stop.val ≤ left.stop.val := by scalar_tac
            rw [contains_iff, contains_iff, contains_iff]
            simp only [Result.ok.injEq, decide_eq_true_eq]
            omega
          · simp only [hstop, ite_false, Result.ok.injEq, Option.some.injEq] at h
            subst h
            have hlt : left.stop.val < right.stop.val := by scalar_tac
            rw [contains_iff, contains_iff, contains_iff]
            simp only [Result.ok.injEq, decide_eq_true_eq]
            omega
        · simp [h1, h2] at h
      · simp [h1] at h
    · simp [ha, hb] at h
  · simp [ha] at h

/-- Snapshot membership predicate over the first `n` entries of a slice of periods. -/
def PrefixContains (s : Slice Period) (n : Nat) (t : I128) : Prop :=
  ∃ i, i < n ∧ ∃ hlen : i < s.val.length,
    (s.val[i]'hlen).start.val ≤ t.val ∧ t.val < (s.val[i]'hlen).stop.val

/-- Canonical coalesced invariant over the first `n` entries of a slice of periods. -/
def PrefixCoalesced (s : Slice Period) (n : Nat) : Prop :=
  n ≤ s.val.length ∧
  (∀ i, i < n → ∃ hlen : i < s.val.length,
    (s.val[i]'hlen).start.val < (s.val[i]'hlen).stop.val) ∧
  (∀ i, i + 1 < n → ∃ h1 : i < s.val.length, ∃ h2 : i + 1 < s.val.length,
    (s.val[i]'h1).stop.val < (s.val[i + 1]'h2).start.val)

/-- Start-sorted precondition on a slice of periods. -/
def StartSorted (s : Slice Period) : Prop :=
  ∀ i j (hi : i < s.val.length) (hj : j < s.val.length),
    i ≤ j → (s.val[i]'hi).start.val ≤ (s.val[j]'hj).start.val

private theorem interval_set_contains_loop_spec (s : Slice Period) (t : I128) :
    interval_set_contains_loop s t false 0#usize ⦃ b =>
      b = true ↔ PrefixContains s s.val.length t ⦄ := by
  unfold interval_set_contains_loop
  apply loop.spec_decr_nat
    (fun st : Bool × Usize => s.val.length - st.2.val)
    (fun st : Bool × Usize =>
      st.2.val ≤ s.val.length ∧
      (st.1 = true ↔ PrefixContains s st.2.val t))
  · rintro ⟨is_m, idx⟩ ⟨hidx, hinv⟩
    dsimp only at *
    unfold interval_set_contains_loop.body
    by_cases hlt : idx < Slice.len s
    · have hlt' : idx.val < s.val.length := by scalar_tac
      simp only [hlt, ite_true]
      cases is_m with
      | true =>
        simp only [ite_true, WP.spec_ok]
        have hpref : PrefixContains s idx.val t := hinv.mp rfl
        rcases hpref with ⟨i, hi, hlen, h1, h2⟩
        exact ⟨fun _ => ⟨i, by omega, hlen, h1, h2⟩, fun _ => trivial⟩
      | false =>
        have hnot : ¬ PrefixContains s idx.val t := by
          intro hp; exact Bool.false_ne_true (hinv.mpr hp)
        have hinc_bound : idx.val + 1 ≤ Usize.max := by
          have := (Slice.len s).hBounds
          scalar_tac
        obtain ⟨idx1, hidx1, hidx1v⟩ := usize_add_one_eq hinc_bound
        simp only [Bool.false_eq_true, ite_false, index_usize_eq s idx hlt', bind_ok,
          contains_iff, hidx1, WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        constructor
        · intro hd
          have hmem := of_decide_eq_true hd
          exact ⟨idx.val, by omega, hlt', hmem.1, hmem.2⟩
        · rintro ⟨i, hi, hlen, h1, h2⟩
          by_cases heq : i = idx.val
          · subst heq
            exact decide_eq_true ⟨h1, h2⟩
          · exfalso
            exact hnot ⟨i, by omega, hlen, h1, h2⟩
    · have hge : s.val.length ≤ idx.val := by scalar_tac
      have heq : idx.val = s.val.length := by omega
      simp only [hlt, ite_false, WP.spec_ok]
      rwa [heq] at hinv
  · dsimp only
    refine ⟨Nat.zero_le _, ?_⟩
    constructor
    · intro h; cases h
    · rintro ⟨i, hi, _⟩
      have h0 : (0#usize).val = 0 := rfl
      omega

/-- `interval_set_contains` never fails and answers `true` iff some period in the
set contains `instant`. -/
theorem interval_set_contains_iff (set : IntervalSet) (instant : I128) :
    ∃ b, interval_set_contains set instant = ok b ∧
      (b = true ↔ PrefixContains set.periods set.periods.val.length instant) :=
  spec_imp_exists (interval_set_contains_loop_spec set.periods instant)

private theorem interval_set_is_coalesced_loop_spec (s : Slice Period) :
    interval_set_is_coalesced_loop s true 0#usize ⦃ b =>
      b = true ↔ PrefixCoalesced s s.val.length ⦄ := by
  unfold interval_set_is_coalesced_loop
  apply loop.spec_decr_nat
    (fun st : Bool × Usize => s.val.length - st.2.val)
    (fun st : Bool × Usize =>
      st.2.val ≤ s.val.length ∧
      (st.1 = true ↔ PrefixCoalesced s st.2.val))
  · rintro ⟨is_c, idx⟩ ⟨hidx, hinv⟩
    dsimp only at *
    unfold interval_set_is_coalesced_loop.body
    by_cases hlt : idx < Slice.len s
    · have hlt' : idx.val < s.val.length := by scalar_tac
      simp only [hlt, ite_true]
      cases is_c with
      | false =>
        simp only [Bool.false_eq_true, ite_false, WP.spec_ok]
        constructor
        · intro h; cases h
        · intro hfull
          have hpref : PrefixCoalesced s idx.val := by
            refine ⟨hidx, fun i hi => hfull.2.1 i (by omega), fun i hi => hfull.2.2 i (by omega)⟩
          exact Bool.false_ne_true (hinv.mpr hpref)
      | true =>
        have hpref : PrefixCoalesced s idx.val := hinv.mp rfl
        have hinc_bound : idx.val + 1 ≤ Usize.max := by
          have := (Slice.len s).hBounds
          scalar_tac
        obtain ⟨idx1, hidx1, hidx1v⟩ := usize_add_one_eq hinc_bound
        simp only [ite_true, index_usize_eq s idx hlt', bind_ok, is_valid_iff]
        by_cases hval : (s.val[idx.val]'hlt').start.val < (s.val[idx.val]'hlt').stop.val
        · simp only [hval, decide_true, ite_true]
          by_cases hpos : idx > 0#usize
          · have hpos' : 0 < idx.val := by scalar_tac
            obtain ⟨im1, him1, him1v⟩ := usize_sub_one_eq hpos'
            have him1_lt : im1.val < s.val.length := by omega
            simp only [hpos, ite_true, him1, bind_ok, index_usize_eq s im1 him1_lt]
            by_cases hge : (s.val[im1.val]'him1_lt).stop ≥ (s.val[idx.val]'hlt').start
            · have hge' : (s.val[im1.val]'him1_lt).stop.val ≥ (s.val[idx.val]'hlt').start.val := by
                scalar_tac
              simp only [hge, ite_true, bind_ok, hidx1, WP.spec_ok]
              refine ⟨⟨by omega, ?_⟩, by omega⟩
              constructor
              · intro hf; cases hf
              · intro hc
                obtain ⟨h1, h2, hlt_sep⟩ := hc.2.2 (idx.val - 1) (by omega)
                have hidx_eq : idx.val - 1 + 1 = idx.val := by omega
                have : (s.val[im1.val]'him1_lt).stop.val < (s.val[idx.val]'hlt').start.val := by
                  simpa [him1v, hidx_eq] using hlt_sep
                omega
            · have hlt_sep : (s.val[im1.val]'him1_lt).stop.val < (s.val[idx.val]'hlt').start.val := by
                scalar_tac
              simp only [hge, ite_false, bind_ok, hidx1, WP.spec_ok]
              refine ⟨⟨by omega, ?_⟩, by omega⟩
              constructor
              · intro _
                refine ⟨by omega, ?_, ?_⟩
                · intro i hi
                  by_cases heq : i = idx.val
                  · subst heq; exact ⟨hlt', hval⟩
                  · exact hpref.2.1 i (by omega)
                · intro i hi
                  by_cases heq : i + 1 = idx.val
                  · have hi_eq : i = im1.val := by omega
                    have hsucc : im1.val + 1 = idx.val := by omega
                    refine ⟨by omega, by omega, ?_⟩
                    simpa [hi_eq, hsucc] using hlt_sep
                  · exact hpref.2.2 i (by omega)
              · intro _; trivial
          · have hz : idx.val = 0 := by scalar_tac
            simp only [hpos, ite_false, bind_ok, hidx1, WP.spec_ok]
            refine ⟨⟨by omega, ?_⟩, by omega⟩
            constructor
            · intro _
              refine ⟨by omega, ?_, ?_⟩
              · intro i hi
                have hi0 : i = 0 := by omega
                subst hi0
                exact ⟨by omega, by simpa [hz] using hval⟩
              · intro i hi; omega
            · intro _; trivial
        · simp only [hval, decide_false, Bool.false_eq_true, ite_false, bind_ok, hidx1, WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          constructor
          · intro hf; cases hf
          · intro hc
            obtain ⟨_, hvalid⟩ := hc.2.1 idx.val (by omega)
            exact (hval hvalid).elim
    · have hge : s.val.length ≤ idx.val := by scalar_tac
      have heq : idx.val = s.val.length := by omega
      simp only [hlt, ite_false, WP.spec_ok]
      rwa [heq] at hinv
  · dsimp only
    refine ⟨Nat.zero_le _, ?_⟩
    have h0 : (0#usize).val = 0 := rfl
    exact ⟨fun _ => ⟨Nat.zero_le _, fun i hi => by omega, fun i hi => by omega⟩, fun _ => rfl⟩

/-- `interval_set_is_coalesced` never fails and holds iff every period is valid
and consecutive periods are strictly separated (`prev.stop < next.start`). -/
theorem interval_set_is_coalesced_iff (set : IntervalSet) :
    ∃ b, interval_set_is_coalesced set = ok b ∧
      (b = true ↔ PrefixCoalesced set.periods set.periods.val.length) :=
  spec_imp_exists (interval_set_is_coalesced_loop_spec set.periods)

private theorem coalesce_sorted_loop_total (init : Slice Period) :
    coalesce_sorted_loop init 0#usize 0#usize ⦃ res =>
      res.1.val ≤ init.val.length ∧ res.2.val.length = init.val.length ⦄ := by
  unfold coalesce_sorted_loop
  apply loop.spec_decr_nat
    (fun st : Slice Period × Usize × Usize => init.val.length - st.2.2.val)
    (fun st : Slice Period × Usize × Usize =>
      st.1.val.length = init.val.length ∧ st.2.1.val ≤ st.2.2.val ∧ st.2.2.val ≤ init.val.length)
  · rintro ⟨ps, w, r⟩ ⟨hlen, hw, hr⟩
    dsimp only at *
    unfold coalesce_sorted_loop.body
    by_cases hlt : r < Slice.len ps
    · have hlt' : r.val < ps.val.length := by scalar_tac
      have hr_inc_bound : r.val + 1 ≤ Usize.max := by
        have := (Slice.len ps).hBounds; scalar_tac
      obtain ⟨r1, hr1, hr1v⟩ := usize_add_one_eq hr_inc_bound
      simp only [hlt, ite_true, index_usize_eq ps r hlt', bind_ok, is_valid_iff]
      by_cases hval : (ps.val[r.val]'hlt').start.val < (ps.val[r.val]'hlt').stop.val
      · simp only [hval, decide_true, ite_true]
        by_cases hw0 : w = 0#usize
        · have h0lt : (0#usize).val < ps.val.length := by scalar_tac
          obtain ⟨s', hs', hs'len, _⟩ := update_eq ps 0#usize (ps.val[r.val]'hlt') h0lt
          simp only [hw0, ite_true, hs', bind_ok, hr1]
          apply (WP.spec_ok _).mpr; dsimp only
          refine ⟨⟨by omega, ?_, by omega⟩, by omega⟩
          scalar_tac
        · have hwpos : 0 < w.val := by
            have hne : w.val ≠ 0 := fun h0 => hw0 ((UScalar.eq_equiv _ _).mpr h0)
            omega
          obtain ⟨wm1, hwm1, hwm1v⟩ := usize_sub_one_eq hwpos
          have hwm1_lt : wm1.val < ps.val.length := by omega
          simp only [hw0, ite_false, hwm1, bind_ok, index_usize_eq ps wm1 hwm1_lt]
          by_cases hov : (ps.val[r.val]'hlt').start ≤ (ps.val[wm1.val]'hwm1_lt).stop
          · set ms : I128 :=
              if (ps.val[r.val]'hlt').stop ≥ (ps.val[wm1.val]'hwm1_lt).stop
              then (ps.val[r.val]'hlt').stop
              else (ps.val[wm1.val]'hwm1_lt).stop
            have hms : (if (ps.val[r.val]'hlt').stop ≥ (ps.val[wm1.val]'hwm1_lt).stop
                then ok (ps.val[r.val]'hlt').stop
                else ok (ps.val[wm1.val]'hwm1_lt).stop) = ok ms := by
              by_cases hc : (ps.val[r.val]'hlt').stop ≥ (ps.val[wm1.val]'hwm1_lt).stop <;>
                simp [ms, hc]
            obtain ⟨s', hs', hs'len, _⟩ :=
              update_eq ps wm1 { (ps.val[wm1.val]'hwm1_lt) with stop := ms } hwm1_lt
            simp only [hov, ite_true, hms, bind_ok, hs', hr1]
            apply (WP.spec_ok _).mpr; dsimp only
            exact ⟨⟨by omega, by omega, by omega⟩, by omega⟩
          · have hw_lt : w.val < ps.val.length := by omega
            have hw_inc_bound : w.val + 1 ≤ Usize.max := by
              have := (Slice.len ps).hBounds; scalar_tac
            obtain ⟨w1, hw1, hw1v⟩ := usize_add_one_eq hw_inc_bound
            obtain ⟨s', hs', hs'len, _⟩ := update_eq ps w (ps.val[r.val]'hlt') hw_lt
            simp only [hov, ite_false, hs', bind_ok, hw1, hr1]
            apply (WP.spec_ok _).mpr; dsimp only
            exact ⟨⟨by omega, by omega, by omega⟩, by omega⟩
      · simp only [hval, decide_false, Bool.false_eq_true, ite_false, bind_ok, hr1]
        apply (WP.spec_ok _).mpr; dsimp only
        exact ⟨⟨hlen, by omega, by omega⟩, by omega⟩
    · have hge : ps.val.length ≤ r.val := by scalar_tac
      simp only [hlt, ite_false, WP.spec_ok]
      exact ⟨by omega, hlen⟩
  · exact ⟨rfl, Nat.le_refl _, Nat.zero_le _⟩

/-- `coalesce_sorted` never fails or diverges on any input slice. -/
theorem coalesce_sorted_total (periods : Slice Period) :
    ∃ len out, coalesce_sorted periods = ok (len, out) ∧
      len.val ≤ periods.val.length ∧ out.val.length = periods.val.length := by
  obtain ⟨⟨len, out⟩, hres, h1, h2⟩ := spec_imp_exists (coalesce_sorted_loop_total periods)
  exact ⟨len, out, hres, h1, h2⟩

private theorem coalesce_sorted_loop_spec (init : Slice Period) (hsorted : StartSorted init) :
    coalesce_sorted_loop init 0#usize 0#usize ⦃ res =>
      res.1.val ≤ init.val.length ∧
      res.2.val.length = init.val.length ∧
      PrefixCoalesced res.2 res.1.val ∧
      (∀ t : I128, PrefixContains init init.val.length t ↔ PrefixContains res.2 res.1.val t) ⦄ := by
  unfold coalesce_sorted_loop
  apply loop.spec_decr_nat
    (fun st : Slice Period × Usize × Usize => init.val.length - st.2.2.val)
    (fun st : Slice Period × Usize × Usize =>
      st.1.val.length = init.val.length ∧
      st.2.1.val ≤ st.2.2.val ∧
      st.2.2.val ≤ init.val.length ∧
      (∀ k, st.2.2.val ≤ k → ∀ (hkl : k < init.val.length),
        ∃ hk1 : k < st.1.val.length, st.1.val[k]'hk1 = init.val[k]'hkl) ∧
      PrefixCoalesced st.1 st.2.1.val ∧
      (∀ (_hw : 0 < st.2.1.val) (hr : st.2.2.val < init.val.length),
        ∃ hlast : st.2.1.val - 1 < st.1.val.length,
          (st.1.val[st.2.1.val - 1]'hlast).start.val ≤ (init.val[st.2.2.val]'hr).start.val) ∧
      (∀ t : I128, PrefixContains init st.2.2.val t ↔ PrefixContains st.1 st.2.1.val t))
  · rintro ⟨ps, w, r⟩ ⟨hlen, hw, hr, htail, hcoal, hlast_le, hsnap⟩
    dsimp only at *
    unfold coalesce_sorted_loop.body
    by_cases hlt : r < Slice.len ps
    · have hlt' : r.val < ps.val.length := by scalar_tac
      have hlt_init : r.val < init.val.length := by omega
      have hcand_eq : ps.val[r.val]'hlt' = init.val[r.val]'hlt_init := by
        obtain ⟨_, heq⟩ := htail r.val (Nat.le_refl _) hlt_init
        exact heq
      have hr_inc_bound : r.val + 1 ≤ Usize.max := by
        have := (Slice.len ps).hBounds; scalar_tac
      obtain ⟨r1, hr1, hr1v⟩ := usize_add_one_eq hr_inc_bound
      simp only [hlt, ite_true, index_usize_eq ps r hlt', bind_ok, is_valid_iff]
      by_cases hval : (ps.val[r.val]'hlt').start.val < (ps.val[r.val]'hlt').stop.val
      · simp only [hval, decide_true, ite_true]
        by_cases hw0 : w = 0#usize
        · have hw0v : w.val = 0 := by scalar_tac
          have h0lt : (0#usize).val < ps.val.length := by scalar_tac
          obtain ⟨s', hs', hs'len, hs'set⟩ := update_eq ps 0#usize (ps.val[r.val]'hlt') h0lt
          simp only [hw0, ite_true, hs', bind_ok, hr1]
          apply (WP.spec_ok _).mpr; dsimp only
          refine ⟨⟨by omega, by scalar_tac, by omega, ?_, ?_, ?_, ?_⟩, by omega⟩
          · intro k hk hkl
            refine ⟨by omega, ?_⟩
            have hk_ne : 0 ≠ k := by omega
            have : s'.val[k]'(by omega) = ps.val[k]'(by omega) := by
              simp [hs'set, List.getElem_set_ne hk_ne]
            rw [this]
            obtain ⟨_, heq⟩ := htail k (by omega) hkl
            exact heq
          · refine ⟨by scalar_tac, ?_, ?_⟩
            · intro i hi
              have hi0 : i = 0 := by scalar_tac
              subst hi0
              refine ⟨by omega, ?_⟩
              simpa [hs'set] using hval
            · intro i hi; scalar_tac
          · intro _ hr1_lt
            have h1_val : (1#usize).val = 1 := rfl
            refine ⟨by omega, ?_⟩
            have hle_init := hsorted r.val r1.val hlt_init hr1_lt (by omega)
            have hs0 : s'.val[(1#usize).val - 1]'(by omega) = init.val[r.val]'hlt_init := by
              simp [hs'set, hcand_eq]
            rw [hs0]
            exact hle_init
          · intro t
            have hprev_empty : ¬ PrefixContains init r.val t := by
              intro hp
              have := (hsnap t).mp hp
              rcases this with ⟨i, hi, _⟩
              omega
            constructor
            · rintro ⟨i, hi, hlen_i, h1, h2⟩
              have hir : i = r.val := by
                by_contra hne
                exact hprev_empty ⟨i, by omega, hlen_i, h1, h2⟩
              subst hir
              refine ⟨0, by scalar_tac, by omega, ?_, ?_⟩
              · simpa [hs'set, hcand_eq] using h1
              · simpa [hs'set, hcand_eq] using h2
            · rintro ⟨j, hj, _, h1, h2⟩
              have hj0 : j = 0 := by scalar_tac
              subst hj0
              refine ⟨r.val, by omega, hlt_init, ?_, ?_⟩
              · simpa [hs'set, hcand_eq] using h1
              · simpa [hs'set, hcand_eq] using h2
        · have hwpos : 0 < w.val := by
            have hne : w.val ≠ 0 := fun h0 => hw0 ((UScalar.eq_equiv _ _).mpr h0)
            omega
          obtain ⟨wm1, hwm1, hwm1v⟩ := usize_sub_one_eq hwpos
          have hwm1_lt : wm1.val < ps.val.length := by omega
          have hprev_start_le :
              (ps.val[wm1.val]'hwm1_lt).start.val ≤ (ps.val[r.val]'hlt').start.val := by
            obtain ⟨_, hle⟩ := hlast_le hwpos hlt_init
            simpa [hwm1v, hcand_eq] using hle
          have hprev_valid :
              (ps.val[wm1.val]'hwm1_lt).start.val < (ps.val[wm1.val]'hwm1_lt).stop.val := by
            obtain ⟨_, hv⟩ := hcoal.2.1 wm1.val (by omega)
            exact hv
          simp only [hw0, ite_false, hwm1, bind_ok, index_usize_eq ps wm1 hwm1_lt]
          by_cases hov : (ps.val[r.val]'hlt').start ≤ (ps.val[wm1.val]'hwm1_lt).stop
          · have hov' : (ps.val[r.val]'hlt').start.val ≤ (ps.val[wm1.val]'hwm1_lt).stop.val := by
              scalar_tac
            set ms : I128 :=
              if (ps.val[r.val]'hlt').stop ≥ (ps.val[wm1.val]'hwm1_lt).stop
              then (ps.val[r.val]'hlt').stop
              else (ps.val[wm1.val]'hwm1_lt).stop
            have hms : (if (ps.val[r.val]'hlt').stop ≥ (ps.val[wm1.val]'hwm1_lt).stop
                then ok (ps.val[r.val]'hlt').stop
                else ok (ps.val[wm1.val]'hwm1_lt).stop) = ok ms := by
              by_cases hc : (ps.val[r.val]'hlt').stop ≥ (ps.val[wm1.val]'hwm1_lt).stop <;>
                simp [ms, hc]
            have hms_val :
                ms.val = max (ps.val[wm1.val]'hwm1_lt).stop.val (ps.val[r.val]'hlt').stop.val := by
              dsimp [ms]; split_ifs <;> scalar_tac
            obtain ⟨s', hs', hs'len, hs'set⟩ :=
              update_eq ps wm1 { (ps.val[wm1.val]'hwm1_lt) with stop := ms } hwm1_lt
            simp only [hov, ite_true, hms, bind_ok, hs', hr1]
            apply (WP.spec_ok _).mpr; dsimp only
            refine ⟨⟨by omega, by omega, by omega, ?_, ?_, ?_, ?_⟩, by omega⟩
            · intro k hk hkl
              refine ⟨by omega, ?_⟩
              have hne : wm1.val ≠ k := by omega
              have : s'.val[k]'(by omega) = ps.val[k]'(by omega) := by
                simp [hs'set, List.getElem_set_ne hne]
              rw [this]
              obtain ⟨_, heq⟩ := htail k (by omega) hkl
              exact heq
            · refine ⟨by omega, ?_, ?_⟩
              · intro i hi
                refine ⟨by omega, ?_⟩
                by_cases heq : i = wm1.val
                · subst heq
                  simp [hs'set]
                  omega
                · have hget : s'.val[i]'(by omega) = ps.val[i]'(by omega) := by
                    simp [hs'set, List.getElem_set_ne (Ne.symm heq)]
                  rw [hget]
                  obtain ⟨_, hv⟩ := hcoal.2.1 i hi
                  exact hv
              · intro i hi
                refine ⟨by omega, by omega, ?_⟩
                have hne1 : wm1.val ≠ i := by omega
                have hget1 : s'.val[i]'(by omega) = ps.val[i]'(by omega) := by
                  simp [hs'set, List.getElem_set_ne hne1]
                by_cases heq2 : i + 1 = wm1.val
                · have hget2 : (s'.val[i + 1]'(by omega)).start = (ps.val[wm1.val]'hwm1_lt).start := by
                    simp [heq2, hs'set]
                  rw [hget1, hget2]
                  obtain ⟨_, _, hsep⟩ := hcoal.2.2 i hi
                  simpa [heq2] using hsep
                · have hget2 : s'.val[i + 1]'(by omega) = ps.val[i + 1]'(by omega) := by
                    simp [hs'set, List.getElem_set_ne (Ne.symm heq2)]
                  rw [hget1, hget2]
                  obtain ⟨_, _, hsep⟩ := hcoal.2.2 i hi
                  exact hsep
            · intro _ hr1_lt
              refine ⟨by omega, ?_⟩
              have hle_init := hsorted r.val r1.val hlt_init hr1_lt (by omega)
              have hs_last :
                  (s'.val[w.val - 1]'(by omega)).start.val = (ps.val[wm1.val]'hwm1_lt).start.val := by
                simp [← hwm1v, hs'set]
              rw [hs_last]
              rw [hcand_eq] at hprev_start_le
              omega
            · intro t
              constructor
              · rintro ⟨i, hi, hlen_i, h1, h2⟩
                by_cases hir : i = r.val
                · subst hir
                  refine ⟨wm1.val, by omega, by omega, ?_, ?_⟩
                  · simp [hs'set]; rw [← hcand_eq] at h1; omega
                  · simp [hs'set]; rw [← hcand_eq] at h2; omega
                · obtain ⟨j, hj, hlen_j, hj1, hj2⟩ :=
                    (hsnap t).mp ⟨i, by omega, hlen_i, h1, h2⟩
                  refine ⟨j, hj, by omega, ?_, ?_⟩
                  · by_cases hjm : j = wm1.val
                    · subst hjm; simp [hs'set]; exact hj1
                    · have hget : s'.val[j]'(by omega) = ps.val[j]'(by omega) := by
                        simp [hs'set, List.getElem_set_ne (Ne.symm hjm)]
                      rw [hget]; exact hj1
                  · by_cases hjm : j = wm1.val
                    · subst hjm; simp [hs'set]; omega
                    · have hget : s'.val[j]'(by omega) = ps.val[j]'(by omega) := by
                        simp [hs'set, List.getElem_set_ne (Ne.symm hjm)]
                      rw [hget]; exact hj2
              · rintro ⟨j, hj, hlen_j, hj1, hj2⟩
                by_cases hjm : j = wm1.val
                · subst hjm
                  simp only [hs'set, List.getElem_set_self] at hj1 hj2
                  by_cases hlt_old : t.val < (ps.val[wm1.val]'hwm1_lt).stop.val
                  · obtain ⟨i, hi, hlen_i, hi1, hi2⟩ :=
                      (hsnap t).mpr ⟨wm1.val, by omega, hwm1_lt, hj1, hlt_old⟩
                    exact ⟨i, by omega, hlen_i, hi1, hi2⟩
                  · refine ⟨r.val, by omega, hlt_init, ?_, ?_⟩
                    · rw [← hcand_eq]; omega
                    · rw [← hcand_eq]; omega
                · have hget : s'.val[j]'(by omega) = ps.val[j]'(by omega) := by
                    simp [hs'set, List.getElem_set_ne (Ne.symm hjm)]
                  rw [hget] at hj1 hj2
                  obtain ⟨i, hi, hlen_i, hi1, hi2⟩ :=
                    (hsnap t).mpr ⟨j, hj, by omega, hj1, hj2⟩
                  exact ⟨i, by omega, hlen_i, hi1, hi2⟩
          · have hsep_new : (ps.val[wm1.val]'hwm1_lt).stop.val < (ps.val[r.val]'hlt').start.val := by
              scalar_tac
            have hw_lt : w.val < ps.val.length := by omega
            have hw_inc_bound : w.val + 1 ≤ Usize.max := by
              have := (Slice.len ps).hBounds; scalar_tac
            obtain ⟨w1, hw1, hw1v⟩ := usize_add_one_eq hw_inc_bound
            obtain ⟨s', hs', hs'len, hs'set⟩ := update_eq ps w (ps.val[r.val]'hlt') hw_lt
            simp only [hov, ite_false, hs', bind_ok, hw1, hr1]
            apply (WP.spec_ok _).mpr; dsimp only
            refine ⟨⟨by omega, by omega, by omega, ?_, ?_, ?_, ?_⟩, by omega⟩
            · intro k hk hkl
              refine ⟨by omega, ?_⟩
              have hne : w.val ≠ k := by omega
              have : s'.val[k]'(by omega) = ps.val[k]'(by omega) := by
                simp [hs'set, List.getElem_set_ne hne]
              rw [this]
              obtain ⟨_, heq⟩ := htail k (by omega) hkl
              exact heq
            · refine ⟨by omega, ?_, ?_⟩
              · intro i hi
                refine ⟨by omega, ?_⟩
                by_cases heq : i = w.val
                · subst heq; simp [hs'set]; exact hval
                · have hget : s'.val[i]'(by omega) = ps.val[i]'(by omega) := by
                    simp [hs'set, List.getElem_set_ne (Ne.symm heq)]
                  rw [hget]
                  obtain ⟨_, hv⟩ := hcoal.2.1 i (by omega)
                  exact hv
              · intro i hi
                refine ⟨by omega, by omega, ?_⟩
                have hne1 : w.val ≠ i := by omega
                have hget1 : s'.val[i]'(by omega) = ps.val[i]'(by omega) := by
                  simp [hs'set, List.getElem_set_ne hne1]
                by_cases heq2 : i + 1 = w.val
                · have hi_eq : i = wm1.val := by omega
                  have hget2 : s'.val[i + 1]'(by omega) = ps.val[r.val]'hlt' := by
                    simp [heq2, hs'set]
                  rw [hget1, hget2]
                  simpa [hi_eq] using hsep_new
                · have hget2 : s'.val[i + 1]'(by omega) = ps.val[i + 1]'(by omega) := by
                    simp [hs'set, List.getElem_set_ne (Ne.symm heq2)]
                  rw [hget1, hget2]
                  obtain ⟨_, _, hsep⟩ := hcoal.2.2 i (by omega)
                  exact hsep
            · intro _ hr1_lt
              refine ⟨by omega, ?_⟩
              have hle_init := hsorted r.val r1.val hlt_init hr1_lt (by omega)
              have hw1m1 : w1.val - 1 = w.val := by omega
              have hs_last : s'.val[w1.val - 1]'(by omega) = init.val[r.val]'hlt_init := by
                simp [hw1m1, hs'set, hcand_eq]
              rw [hs_last]
              exact hle_init
            · intro t
              constructor
              · rintro ⟨i, hi, hlen_i, h1, h2⟩
                by_cases hir : i = r.val
                · subst hir
                  refine ⟨w.val, by omega, by omega, ?_, ?_⟩
                  · simp [hs'set, hcand_eq]; exact h1
                  · simp [hs'set, hcand_eq]; exact h2
                · obtain ⟨j, hj, hlen_j, hj1, hj2⟩ :=
                    (hsnap t).mp ⟨i, by omega, hlen_i, h1, h2⟩
                  have hne : w.val ≠ j := by omega
                  refine ⟨j, by omega, by omega, ?_, ?_⟩
                  · simp [hs'set, List.getElem_set_ne hne]; exact hj1
                  · simp [hs'set, List.getElem_set_ne hne]; exact hj2
              · rintro ⟨j, hj, hlen_j, hj1, hj2⟩
                by_cases hjw : j = w.val
                · subst hjw
                  simp only [hs'set, List.getElem_set_self] at hj1 hj2
                  refine ⟨r.val, by omega, hlt_init, ?_, ?_⟩
                  · simpa [hcand_eq] using hj1
                  · simpa [hcand_eq] using hj2
                · have hne : w.val ≠ j := Ne.symm hjw
                  have hget : s'.val[j]'(by omega) = ps.val[j]'(by omega) := by
                    simp [hs'set, List.getElem_set_ne hne]
                  rw [hget] at hj1 hj2
                  obtain ⟨i, hi, hlen_i, hi1, hi2⟩ :=
                    (hsnap t).mpr ⟨j, by omega, by omega, hj1, hj2⟩
                  exact ⟨i, by omega, hlen_i, hi1, hi2⟩
      · simp only [hval, decide_false, Bool.false_eq_true, ite_false, bind_ok, hr1]
        apply (WP.spec_ok _).mpr; dsimp only
        refine ⟨⟨hlen, by omega, by omega, ?_, hcoal, ?_, ?_⟩, by omega⟩
        · intro k hk hkl; exact htail k (by omega) hkl
        · intro hwpos hr1_lt
          obtain ⟨hlast, h1⟩ := hlast_le hwpos hlt_init
          have h2 := hsorted r.val r1.val hlt_init hr1_lt (by omega)
          exact ⟨hlast, by omega⟩
        · intro t
          constructor
          · rintro ⟨i, hi, hlen_i, h1, h2⟩
            by_cases hir : i = r.val
            · subst hir; rw [← hcand_eq] at h1 h2; omega
            · exact (hsnap t).mp ⟨i, by omega, hlen_i, h1, h2⟩
          · intro hp
            obtain ⟨i, hi, hlen_i, h1, h2⟩ := (hsnap t).mpr hp
            exact ⟨i, by omega, hlen_i, h1, h2⟩
    · have hge : ps.val.length ≤ r.val := by scalar_tac
      have hr_eq : r.val = init.val.length := by omega
      simp only [hlt, ite_false, WP.spec_ok]
      refine ⟨by omega, hlen, hcoal, ?_⟩
      intro t
      simpa [hr_eq] using hsnap t
  · dsimp only
    have h0 : (0#usize).val = 0 := rfl
    refine ⟨rfl, Nat.le_refl _, Nat.zero_le _, fun k _ hkl => ⟨hkl, rfl⟩, ?_, fun hw => by omega, ?_⟩
    · exact ⟨Nat.zero_le _, fun i hi => by omega, fun i hi => by omega⟩
    · intro t
      exact ⟨fun ⟨i, hi, _⟩ => by omega, fun ⟨i, hi, _⟩ => by omega⟩

/-- Full-slice coalescing snapshot-equivalence and canonical output: for any
start-sorted input slice `periods`, `coalesce_sorted` returns a canonical
strictly-separated prefix `out[0..len]` covering the exact same set of instants
`t : I128` as `periods`. -/
theorem coalesce_sorted_snapshot_equiv (periods : Slice Period) (hsorted : StartSorted periods) :
    ∃ len out, coalesce_sorted periods = ok (len, out) ∧
      len.val ≤ periods.val.length ∧
      out.val.length = periods.val.length ∧
      PrefixCoalesced out len.val ∧
      (∀ t : I128, PrefixContains periods periods.val.length t ↔ PrefixContains out len.val t) := by
  obtain ⟨⟨len, out⟩, hres, h1, h2, h3, h4⟩ :=
    spec_imp_exists (coalesce_sorted_loop_spec periods hsorted)
  exact ⟨len, out, hres, h1, h2, h3, h4⟩

private theorem slice_set_self_eq (s : Slice Period) (i : Usize) (h : i.val < s.val.length) :
    Slice.update s i (s.val[i.val]'h) = ok s := by
  obtain ⟨s', hs', _, hset⟩ := update_eq s i (s.val[i.val]'h) h
  have hval : s'.val = s.val := by
    rw [hset]
    exact List.set_getElem_self h
  have heq : s' = s := (Slice.eq_iff s' s).mpr hval
  rw [heq] at hs'
  exact hs'

private theorem coalesce_sorted_loop_idempotent (init : Slice Period)
    (hcoal : PrefixCoalesced init init.val.length) :
    coalesce_sorted_loop init 0#usize 0#usize ⦃ res =>
      res.1 = Slice.len init ∧ res.2 = init ⦄ := by
  unfold coalesce_sorted_loop
  apply loop.spec_decr_nat
    (fun st : Slice Period × Usize × Usize => init.val.length - st.2.2.val)
    (fun st : Slice Period × Usize × Usize =>
      st.1 = init ∧ st.2.1 = st.2.2 ∧ st.2.2.val ≤ init.val.length)
  · rintro ⟨ps, w, r⟩ ⟨hps, hwr, hr⟩
    dsimp only at *
    subst hps
    rw [hwr] at *
    clear hwr w
    unfold coalesce_sorted_loop.body
    by_cases hlt : r < Slice.len ps
    · have hlt' : r.val < ps.val.length := by scalar_tac
      have hr_inc_bound : r.val + 1 ≤ Usize.max := by
        have := (Slice.len ps).hBounds; scalar_tac
      obtain ⟨r1, hr1, hr1v⟩ := usize_add_one_eq hr_inc_bound
      obtain ⟨_, hval⟩ := hcoal.2.1 r.val hlt'
      simp only [hlt, ite_true, index_usize_eq ps r hlt', bind_ok, is_valid_iff,
        hval, decide_true]
      by_cases hr0 : r = 0#usize
      · subst hr0
        have hupd := slice_set_self_eq ps 0#usize hlt'
        have hr1_eq : r1 = 1#usize := by rw [UScalar.eq_equiv]; scalar_tac
        simp only [ite_true, hupd, bind_ok, hr1, hr1_eq]
        apply (WP.spec_ok _).mpr; dsimp only
        have h1_val : (1#usize).val = 1 := rfl
        have h0_val : (0#usize).val = 0 := rfl
        exact ⟨⟨rfl, rfl, by omega⟩, by omega⟩
      · have hrpos : 0 < r.val := by
          have hne : r.val ≠ 0 := fun h0 => hr0 ((UScalar.eq_equiv _ _).mpr h0)
          omega
        obtain ⟨rm1, hrm1, hrm1v⟩ := usize_sub_one_eq hrpos
        have hrm1_lt : rm1.val < ps.val.length := by omega
        obtain ⟨_, _, hsep⟩ := hcoal.2.2 rm1.val (by omega)
        have hrm1_succ : rm1.val + 1 = r.val := by omega
        have hsep' : (ps.val[rm1.val]'hrm1_lt).stop.val < (ps.val[r.val]'hlt').start.val := by
          simpa [hrm1_succ] using hsep
        have hnot_ov : ¬ (ps.val[r.val]'hlt').start ≤ (ps.val[rm1.val]'hrm1_lt).stop := by
          scalar_tac
        have hupd := slice_set_self_eq ps r hlt'
        simp only [hr0, ite_false, hrm1, bind_ok, index_usize_eq ps rm1 hrm1_lt,
          hnot_ov, hupd, hr1]
        apply (WP.spec_ok _).mpr; dsimp only
        have h1_val : (1#usize).val = 1 := rfl
        have h0_val : (0#usize).val = 0 := rfl
        exact ⟨⟨rfl, rfl, by omega⟩, by omega⟩
    · have hge : ps.val.length ≤ r.val := by scalar_tac
      have hr_eq : r = Slice.len ps := by rw [UScalar.eq_equiv]; scalar_tac
      simp only [hlt, ite_false, WP.spec_ok]
      exact ⟨hr_eq, trivial⟩
  · exact ⟨rfl, rfl, Nat.zero_le _⟩

/-- Coalescing idempotence: running `coalesce_sorted` on an already-coalesced
slice returns the full length and leaves the slice unchanged. -/
theorem coalesce_sorted_idempotent (periods : Slice Period)
    (hcoal : PrefixCoalesced periods periods.val.length) :
    coalesce_sorted periods = ok (Slice.len periods, periods) := by
  obtain ⟨⟨len, out⟩, hres, hlen, hout⟩ :=
    spec_imp_exists (coalesce_sorted_loop_idempotent periods hcoal)
  dsimp only at hlen hout
  subst hlen; subst hout
  exact hres

/-! ## Allen's 13 Interval Relations -/

/-- `allen_relation` never fails and classifies every valid pair into one of
Allen's 13 mutually exclusive relations, returning `none` iff either period is invalid. -/
theorem allen_relation_some_iff (left right : Period) :
    ∃ r, allen_relation left right = ok r ∧
      (r.isSome = true ↔ left.start.val < left.stop.val ∧ right.start.val < right.stop.val) := by
  unfold allen_relation
  rw [is_valid_iff, is_valid_iff]
  simp only [bind_ok]
  by_cases ha : left.start.val < left.stop.val
  · by_cases hb : right.start.val < right.stop.val
    · simp only [ha, hb, decide_true, ite_true]
      split_ifs <;> exact ⟨_, rfl, by simp⟩
    · exact ⟨none, by simp [ha, hb], by simp [hb]⟩
  · exact ⟨none, by simp [ha], by simp [ha]⟩

/-- `allen_holds` fails closed when the left validity is `Unknown`. -/
theorem allen_holds_unknown_left (right : Validity) (relation : AllenRelation) :
    allen_holds Validity.Unknown right relation = ok false := by
  rfl

/-- `allen_holds` fails closed when the right validity is `Unknown`. -/
theorem allen_holds_unknown_right (left : Validity) (relation : AllenRelation) :
    allen_holds left Validity.Unknown relation = ok false := by
  cases left <;> rfl

/-! ## Bounded DatalogMTL Metric Operators -/

/-- `window_valid` never fails and holds iff `0 ≤ lower ≤ upper`. -/
theorem window_valid_iff (window : MetricWindow) :
    window_valid window = ok (decide (0 ≤ window.lower.val ∧ window.lower.val ≤ window.upper.val)) := by
  unfold window_valid
  have hz := zero_ns_val
  by_cases h1 : window.lower ≥ ZERO_NS
  · have h1' : 0 ≤ window.lower.val := by scalar_tac
    by_cases h2 : window.lower ≤ window.upper
    · have h2' : window.lower.val ≤ window.upper.val := by scalar_tac
      simp [h1, h2, h1', h2']
    · have h2' : ¬ window.lower.val ≤ window.upper.val := by scalar_tac
      simp [h1, h2, h1', h2']
  · have h1' : ¬ 0 ≤ window.lower.val := by scalar_tac
    simp [h1, h1']

/-- `diamond_minus` never fails or diverges. -/
theorem diamond_minus_total (validity : Validity) (window : MetricWindow) :
    ∃ r, diamond_minus validity window = ok r := by
  unfold diamond_minus
  rw [window_valid_iff]
  simp only [bind_ok]
  by_cases hw : 0 ≤ window.lower.val ∧ window.lower.val ≤ window.upper.val
  · simp only [hw, and_self, decide_true, ite_true]
    cases validity with
    | Unknown => exact ⟨none, rfl⟩
    | Known p =>
      dsimp only
      rw [is_valid_iff]
      simp only [bind_ok]
      by_cases hv : p.start.val < p.stop.val
      · obtain ⟨s, hs⟩ := shift_forward_total p.start window.lower
        obtain ⟨e, he⟩ := shift_forward_total p.stop window.upper
        simp only [hv, decide_true, ite_true, hs, he, bind_ok]
        split_ifs <;> exact ⟨_, rfl⟩
      · exact ⟨none, by simp [hv]⟩
  · exact ⟨none, by simp [hw]⟩

/-- Fail-closed `Unknown`: `♦₋_ρ(Unknown) = ∅`. -/
theorem diamond_minus_unknown (window : MetricWindow) :
    diamond_minus Validity.Unknown window = ok none := by
  unfold diamond_minus
  rw [window_valid_iff]
  simp only [bind_ok]
  split_ifs <;> rfl

/-- `box_minus` never fails or diverges. -/
theorem box_minus_total (validity : Validity) (window : MetricWindow) :
    ∃ r, box_minus validity window = ok r := by
  unfold box_minus
  rw [window_valid_iff]
  simp only [bind_ok]
  by_cases hw : 0 ≤ window.lower.val ∧ window.lower.val ≤ window.upper.val
  · simp only [hw, and_self, decide_true, ite_true]
    cases validity with
    | Unknown => exact ⟨none, rfl⟩
    | Known p =>
      dsimp only
      rw [is_valid_iff]
      simp only [bind_ok]
      by_cases hv : p.start.val < p.stop.val
      · obtain ⟨s, hs⟩ := shift_forward_total p.start window.upper
        obtain ⟨e, he⟩ := shift_forward_total p.stop window.lower
        simp only [hv, decide_true, ite_true, hs, he, bind_ok]
        split_ifs <;> exact ⟨_, rfl⟩
      · exact ⟨none, by simp [hv]⟩
  · exact ⟨none, by simp [hw]⟩

/-- Fail-closed `Unknown`: `■₋_ρ(Unknown) = ∅`. -/
theorem box_minus_unknown (window : MetricWindow) :
    box_minus Validity.Unknown window = ok none := by
  unfold box_minus
  rw [window_valid_iff]
  simp only [bind_ok]
  split_ifs <;> rfl

/-- `since` never fails or diverges. -/
theorem since_total (maintained trigger : Validity) (window : MetricWindow) :
    ∃ r, since maintained trigger window = ok r := by
  unfold since
  rw [window_valid_iff]
  simp only [bind_ok]
  by_cases hw : 0 ≤ window.lower.val ∧ window.lower.val ≤ window.upper.val
  · simp only [hw, and_self, decide_true, ite_true]
    cases maintained with
    | Unknown => exact ⟨none, rfl⟩
    | Known m =>
      cases trigger with
      | Unknown => exact ⟨none, rfl⟩
      | Known t =>
        dsimp only
        rw [is_valid_iff, is_valid_iff]
        simp only [bind_ok]
        by_cases hm : m.start.val < m.stop.val
        · by_cases ht : t.start.val < t.stop.val
          · obtain ⟨ms1, hms1⟩ := shift_back_one_total m.start
            obtain ⟨me1, hme1⟩ := shift_back_one_total m.stop
            simp only [hm, ht, decide_true, ite_true, hms1, hme1, bind_ok]
            set js : I128 := if t.start ≥ ms1 then t.start else ms1
            set je : I128 := if t.stop ≤ me1 then t.stop else me1
            set sl : I128 := if window.lower ≥ ONE_NS then window.lower else ONE_NS
            have hjs : (if t.start ≥ ms1 then ok t.start else ok ms1) = ok js := by
              by_cases hc : t.start ≥ ms1 <;> simp [js, hc]
            have hje : (if t.stop ≤ me1 then ok t.stop else ok me1) = ok je := by
              by_cases hc : t.stop ≤ me1 <;> simp [je, hc]
            have hsl : (if window.lower ≥ ONE_NS then ok window.lower else ok ONE_NS) = ok sl := by
              by_cases hc : window.lower ≥ ONE_NS <;> simp [sl, hc]
            rw [hjs, ok_bind, hje, ok_bind, hsl, ok_bind]
            set hs_bool : Bool := if js < je then decide (sl ≤ window.upper) else false
            have hhs : (if js < je then ok (decide (sl ≤ window.upper)) else ok false) = ok hs_bool := by
              by_cases hc : js < je <;> simp [hs_bool, hc]
            rw [hhs, ok_bind]
            by_cases h0 : window.lower = ZERO_NS
            · simp only [h0, ite_true]
              cases hs_bool with
              | false => exact ⟨some t, rfl⟩
              | true =>
                obtain ⟨sh, hsh⟩ := shift_forward_total je window.upper
                simp only [ite_true, hsh, bind_ok]
                set cs : I128 := if sh ≤ m.stop then sh else m.stop
                set fs : I128 := if t.stop ≥ cs then t.stop else cs
                have hcs : (if sh ≤ m.stop then ok sh else ok m.stop) = ok cs := by
                  by_cases hc : sh ≤ m.stop <;> simp [cs, hc]
                have hfs : (if t.stop ≥ cs then ok t.stop else ok cs) = ok fs := by
                  by_cases hc : t.stop ≥ cs <;> simp [fs, hc]
                rw [hcs, ok_bind, hfs, ok_bind]
                split_ifs <;> exact ⟨_, rfl⟩
            · simp only [h0, ite_false]
              cases hs_bool with
              | false => exact ⟨none, rfl⟩
              | true =>
                obtain ⟨st, hst⟩ := shift_forward_total js sl
                obtain ⟨sh, hsh⟩ := shift_forward_total je window.upper
                simp only [ite_true, hst, hsh, bind_ok]
                set sp : I128 := if sh ≤ m.stop then sh else m.stop
                have hsp : (if sh ≤ m.stop then ok sh else ok m.stop) = ok sp := by
                  by_cases hc : sh ≤ m.stop <;> simp [sp, hc]
                rw [hsp, ok_bind]
                split_ifs <;> exact ⟨_, rfl⟩
          · exact ⟨none, by simp [hm, ht]⟩
        · exact ⟨none, by simp [hm]⟩
  · exact ⟨none, by simp [hw]⟩

/-- Fail-closed `Unknown`: `Unknown S_ρ trigger = ∅`. -/
theorem since_unknown_left (trigger : Validity) (window : MetricWindow) :
    since Validity.Unknown trigger window = ok none := by
  unfold since
  rw [window_valid_iff]
  simp only [bind_ok]
  split_ifs <;> rfl

/-- Fail-closed `Unknown`: `maintained S_ρ Unknown = ∅`. -/
theorem since_unknown_right (maintained : Validity) (window : MetricWindow) :
    since maintained Validity.Unknown window = ok none := by
  unfold since
  rw [window_valid_iff]
  simp only [bind_ok]
  split_ifs
  · cases maintained <;> rfl
  · rfl

end mneme_kernel.temporal
