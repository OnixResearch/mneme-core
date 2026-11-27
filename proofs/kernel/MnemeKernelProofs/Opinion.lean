import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Exact Fixed-Point Rational Subjective Logic Opinions

Theorems about the Aeneas translation of `crates/mneme-kernel/src/opinion.rs`:
- **Simplex preservation** (`project_simplex_preservation`):
  `b_num + d_num + u_num = denom`, `denom > 0`, and `conflict_num ≤ b_num + d_num < denom`.
- **Vacuous opinion** (`vacuous_projects_exact`):
  zero evidence maps to exact `(0, 0, 1, a)` with zero conflict.
- **Anti-echo-chamber cluster averaging** (`averaging_cluster_echo_chamber_invariance`):
  any number of derivative copies sharing one `RootIdentity` keep `u = 2/3` invariant.
- **Cumulative Fusion (`⊕`)** (`cumulative_fuse_comm`, `cumulative_fuse_assoc`,
  `cumulative_fuse_vacuous_identity`): structurally commutative, associative up to exact
  rational equivalence, with vacuous identity.
- **Averaging Fusion (`◇`)** (`averaging_fuse_comm`, `averaging_fuse_idempotent`):
  commutative and idempotent up to exact rational equivalence (and identical simplex ratios).
- **Trust Discounting (`⊗`)** (`trust_discount_non_inflation`, `trust_discount_vacuous_trust`):
  preserves simplex (`D_out = D_trust * D_target`), never inflates belief (`b' ≤ b_target`,
  `b' ≤ b_trust`) or disbelief (`d' ≤ d_target`), and never decreases uncertainty (`u' ≥ u_target`).
-/

namespace mneme_kernel.opinion

/-! ## Private Arithmetic Helpers -/

private theorem u128_checked_add_cases (a b : U128) :
    (a.val + b.val ≤ U128.max ∧
      ∃ c, U128.checked_add a b = some c ∧ c.val = a.val + b.val) ∨
    (U128.max < a.val + b.val ∧ U128.checked_add a b = none) := by
  have hspec := U128.checked_add_bv_spec a b
  cases h : U128.checked_add a b with
  | none =>
    rw [h] at hspec
    exact Or.inr ⟨hspec, rfl⟩
  | some c =>
    rw [h] at hspec
    obtain ⟨hle, hval, -⟩ := hspec
    exact Or.inl ⟨hle, c, rfl, hval⟩

private theorem u128_checked_add_some_iff (a b c : U128) :
    U128.checked_add a b = some c ↔ c.val = a.val + b.val ∧ a.val + b.val ≤ U128.max := by
  rcases u128_checked_add_cases a b with ⟨hle, c', hc', hval⟩ | ⟨hgt, hnone⟩
  · rw [hc', Option.some.injEq, UScalar.eq_equiv]
    omega
  · rw [hnone]
    constructor
    · intro h; cases h
    · rintro ⟨-, hle⟩; omega

private theorem u128_checked_add_none_iff (a b : U128) :
    U128.checked_add a b = none ↔ U128.max < a.val + b.val := by
  rcases u128_checked_add_cases a b with ⟨hle, c', hc', -⟩ | ⟨hgt, hnone⟩
  · rw [hc']
    constructor
    · intro h; cases h
    · intro hgt; omega
  · rw [hnone]
    exact ⟨fun _ => hgt, fun _ => rfl⟩

private theorem u128_checked_add_comm (a b : U128) :
    U128.checked_add a b = U128.checked_add b a := by
  rcases u128_checked_add_cases a b with ⟨hle, c, hc, hval⟩ | ⟨hgt, hnone⟩
  · rw [hc]
    exact ((u128_checked_add_some_iff b a c).mpr ⟨by omega, by omega⟩).symm
  · rw [hnone]
    exact ((u128_checked_add_none_iff b a).mpr (by omega)).symm

private theorem u128_checked_mul_cases (a b : U128) :
    (a.val * b.val ≤ U128.max ∧
      ∃ c, U128.checked_mul a b = some c ∧ c.val = a.val * b.val) ∨
    (U128.max < a.val * b.val ∧ U128.checked_mul a b = none) := by
  have hspec := U128.checked_mul_bv_spec a b
  cases h : U128.checked_mul a b with
  | none =>
    rw [h] at hspec
    exact Or.inr ⟨hspec, rfl⟩
  | some c =>
    rw [h] at hspec
    obtain ⟨hle, hval, -⟩ := hspec
    exact Or.inl ⟨hle, c, rfl, hval⟩

private theorem u128_checked_mul_some_iff (a b c : U128) :
    U128.checked_mul a b = some c ↔ c.val = a.val * b.val ∧ a.val * b.val ≤ U128.max := by
  rcases u128_checked_mul_cases a b with ⟨hle, c', hc', hval⟩ | ⟨hgt, hnone⟩
  · rw [hc', Option.some.injEq, UScalar.eq_equiv]
    omega
  · rw [hnone]
    constructor
    · intro h; cases h
    · rintro ⟨-, hle⟩; omega

private theorem u128_checked_mul_none_iff (a b : U128) :
    U128.checked_mul a b = none ↔ U128.max < a.val * b.val := by
  rcases u128_checked_mul_cases a b with ⟨hle, c', hc', -⟩ | ⟨hgt, hnone⟩
  · rw [hc']
    constructor
    · intro h; cases h
    · intro hgt; omega
  · rw [hnone]
    exact ⟨fun _ => hgt, fun _ => rfl⟩

private theorem u128_checked_mul_comm (a b : U128) :
    U128.checked_mul a b = U128.checked_mul b a := by
  rcases u128_checked_mul_cases a b with ⟨hle, c, hc, hval⟩ | ⟨hgt, hnone⟩
  · rw [hc]
    exact ((u128_checked_mul_some_iff b a c).mpr
      ⟨by rw [Nat.mul_comm]; exact hval, by rw [Nat.mul_comm]; exact hle⟩).symm
  · rw [hnone]
    exact ((u128_checked_mul_none_iff b a).mpr (by rw [Nat.mul_comm]; exact hgt)).symm

private theorem u128_saturating_add_exact (a b : U128) (h : a.val + b.val ≤ U128.max) :
    (core.num.U128.saturating_add a b).val = a.val + b.val := by
  have hmax_def : UScalar.max UScalarTy.U128 = 2 ^ UScalarTy.U128.numBits - 1 := by scalar_tac
  have hmax_eq : U128.max = UScalar.max UScalarTy.U128 := by scalar_tac
  have hpos : 0 < 2 ^ UScalarTy.U128.numBits := Nat.two_pow_pos _
  have ha : a.bv.toNat = a.val := rfl
  have hb : b.bv.toNat = b.val := rfl
  have hlt_pow : a.bv.toNat + b.bv.toNat < 2 ^ UScalarTy.U128.numBits := by omega
  have hmin : min (UScalar.max UScalarTy.U128) (a.bv.toNat + b.bv.toNat) =
      a.bv.toNat + b.bv.toNat := by omega
  simp only [core.num.U128.saturating_add, UScalar.saturating_add, UScalar.val,
    BitVec.toNat_ofNat]
  rw [hmin, Nat.mod_eq_of_lt hlt_pow, ha, hb]

private theorem u64_cast_u128_val (x : U64) :
    (UScalar.cast .U128 x).val = x.val := by
  scalar_tac

private theorem clamp_base_rate_spec (a : U64) :
    ∃ r, clamp_base_rate a = ok r ∧
      r.val ≤ BASE_RATE_SCALE.val ∧
      (a.val ≤ BASE_RATE_SCALE.val → r = a) := by
  unfold clamp_base_rate
  by_cases h : a <= BASE_RATE_SCALE
  · refine ⟨a, by simp [h], ?_, fun _ => rfl⟩
    exact h
  · refine ⟨BASE_RATE_SCALE, by simp [h], Nat.le_refl _, ?_⟩
    intro hle
    exact absurd hle h

private theorem min_base_rate_spec (a b : U64) :
    ∃ r, min_base_rate a b = ok r ∧
      r.val = min a.val b.val ∧
      (a = b → r = a) := by
  unfold min_base_rate
  by_cases h : a <= b
  · refine ⟨a, by simp [h], ?_, fun _ => rfl⟩
    have hle : a.val ≤ b.val := h
    omega
  · refine ⟨b, by simp [h], ?_, fun hab => by subst hab; rfl⟩
    have hgt : b.val < a.val := by
      have : ¬ a.val ≤ b.val := h
      omega
    omega

private theorem min_base_rate_comm (a b : U64) :
    min_base_rate a b = min_base_rate b a := by
  obtain ⟨r1, h1, hv1, _⟩ := min_base_rate_spec a b
  obtain ⟨r2, h2, hv2, _⟩ := min_base_rate_spec b a
  rw [h1, h2]
  congr 1
  apply (UScalar.eq_equiv _ _).mpr
  omega

private theorem checked_denom_cases (r s w : U128) :
    (r.val + s.val + w.val ≤ U128.max ∧
      ∃ d, checked_denom r s w = ok (some d) ∧ d.val = r.val + s.val + w.val) ∨
    (U128.max < r.val + s.val + w.val ∧ checked_denom r s w = ok none) := by
  unfold checked_denom
  rcases u128_checked_add_cases r s with ⟨hrs_le, rs, hrs, hrs_val⟩ | ⟨hrs_gt, hrs_none⟩
  · rcases u128_checked_add_cases rs w with ⟨hd_le, d, hd, hd_val⟩ | ⟨hd_gt, hd_none⟩
    · exact Or.inl ⟨by omega, d, by simp [hrs, hd, lift], by omega⟩
    · exact Or.inr ⟨by omega, by simp [hrs, hd_none, lift]⟩
  · exact Or.inr ⟨by omega, by simp [hrs_none, lift]⟩

private theorem checked_denom_total (r s w : U128) :
    ∃ o, checked_denom r s w = ok o := by
  rcases checked_denom_cases r s w with ⟨-, d, hd, -⟩ | ⟨-, hnone⟩
  · exact ⟨some d, hd⟩
  · exact ⟨none, hnone⟩

private theorem checked_denom_some_iff (r s w d : U128) :
    checked_denom r s w = ok (some d) ↔ d.val = r.val + s.val + w.val ∧
      r.val + s.val + w.val ≤ U128.max := by
  rcases checked_denom_cases r s w with ⟨hle, d', hd', hval⟩ | ⟨hgt, hnone⟩
  · rw [hd', ok.injEq, Option.some.injEq, UScalar.eq_equiv]
    omega
  · rw [hnone, ok.injEq]
    constructor
    · intro h; cases h
    · rintro ⟨-, hle⟩; omega

private theorem checked_denom_none_iff (r s w : U128) :
    checked_denom r s w = ok none ↔ U128.max < r.val + s.val + w.val := by
  rcases checked_denom_cases r s w with ⟨hle, d', hd', -⟩ | ⟨hgt, hnone⟩
  · rw [hd', ok.injEq]
    constructor
    · intro h; cases h
    · intro hgt; omega
  · rw [hnone]
    exact ⟨fun _ => hgt, fun _ => rfl⟩

private theorem checked_cross_sum_cases (a b c d : U128) :
    (a.val * b.val + c.val * d.val ≤ U128.max ∧
      ∃ res, checked_cross_sum a b c d = ok (some res) ∧
        res.val = a.val * b.val + c.val * d.val) ∨
    (U128.max < a.val * b.val + c.val * d.val ∧ checked_cross_sum a b c d = ok none) := by
  unfold checked_cross_sum
  rcases u128_checked_mul_cases a b with ⟨hp1_le, p1, hp1, hp1_val⟩ | ⟨hp1_gt, hp1_none⟩
  · rcases u128_checked_mul_cases c d with ⟨hp2_le, p2, hp2, hp2_val⟩ | ⟨hp2_gt, hp2_none⟩
    · rcases u128_checked_add_cases p1 p2 with ⟨hs_le, res, hres, hres_val⟩ | ⟨hs_gt, hs_none⟩
      · exact Or.inl ⟨by omega, res, by simp [hp1, hp2, hres, lift], by omega⟩
      · exact Or.inr ⟨by omega, by simp [hp1, hp2, hs_none, lift]⟩
    · exact Or.inr ⟨by omega, by simp [hp1, hp2_none, lift]⟩
  · exact Or.inr ⟨by omega, by simp [hp1_none, lift]⟩

private theorem checked_cross_sum_total (a b c d : U128) :
    ∃ o, checked_cross_sum a b c d = ok o := by
  rcases checked_cross_sum_cases a b c d with ⟨-, res, hres, -⟩ | ⟨-, hnone⟩
  · exact ⟨some res, hres⟩
  · exact ⟨none, hnone⟩

private theorem checked_cross_sum_some_iff (a b c d res : U128) :
    checked_cross_sum a b c d = ok (some res) ↔
      res.val = a.val * b.val + c.val * d.val ∧
      a.val * b.val + c.val * d.val ≤ U128.max := by
  rcases checked_cross_sum_cases a b c d with ⟨hle, res', hres', hval⟩ | ⟨hgt, hnone⟩
  · rw [hres', ok.injEq, Option.some.injEq, UScalar.eq_equiv]
    omega
  · rw [hnone, ok.injEq]
    constructor
    · intro h; cases h
    · rintro ⟨-, hle⟩; omega

private theorem checked_cross_sum_none_iff (a b c d : U128) :
    checked_cross_sum a b c d = ok none ↔ U128.max < a.val * b.val + c.val * d.val := by
  rcases checked_cross_sum_cases a b c d with ⟨hle, res', hres', -⟩ | ⟨hgt, hnone⟩
  · rw [hres', ok.injEq]
    constructor
    · intro h; cases h
    · intro hgt; omega
  · rw [hnone]
    exact ⟨fun _ => hgt, fun _ => rfl⟩

private theorem checked_cross_sum_comm (a b c d : U128) :
    checked_cross_sum a b c d = checked_cross_sum c d a b := by
  rcases checked_cross_sum_cases a b c d with ⟨hle, res, hres, hval⟩ | ⟨hgt, hnone⟩
  · rw [hres]
    exact ((checked_cross_sum_some_iff c d a b res).mpr ⟨by omega, by omega⟩).symm
  · rw [hnone]
    exact ((checked_cross_sum_none_iff c d a b).mpr (by omega)).symm

private theorem build_valid_total (r s w : U128) (base_rate : U64) :
    ∃ o, build_valid r s w base_rate = ok o := by
  unfold build_valid
  by_cases hw : w = 0#u128
  · exact ⟨none, by simp [hw]⟩
  · by_cases ha : base_rate > BASE_RATE_SCALE
    · exact ⟨none, by simp [hw, ha]⟩
    · obtain ⟨o, ho⟩ := checked_denom_total r s w
      cases o with
      | none => exact ⟨none, by simp [hw, ha, ho]⟩
      | some _ => exact ⟨some { r, s, w, base_rate }, by simp [hw, ha, ho]⟩

private theorem build_valid_some_iff (r s w : U128) (base_rate : U64) (out : Evidence) :
    build_valid r s w base_rate = ok (some out) ↔
      out = { r, s, w, base_rate } ∧
      0 < w.val ∧ base_rate.val ≤ BASE_RATE_SCALE.val ∧
      r.val + s.val + w.val ≤ U128.max := by
  unfold build_valid
  by_cases hw : w = 0#u128
  · subst hw
    have hw0 : (0#u128).val = 0 := by scalar_tac
    simp only [↓reduceIte, ok.injEq, reduceCtorEq, false_iff]
    rintro ⟨-, hwpos, -⟩; omega
  · have hwpos : 0 < w.val := by
      by_contra h0
      have hval : w.val = (0#u128).val := by scalar_tac
      exact hw ((UScalar.eq_equiv w 0#u128).mpr hval)
    by_cases ha : base_rate > BASE_RATE_SCALE
    · have hagt : BASE_RATE_SCALE.val < base_rate.val := ha
      simp only [hw, ↓reduceIte, ha, ok.injEq, reduceCtorEq, false_iff]
      rintro ⟨-, -, hale, -⟩; omega
    · have hale : base_rate.val ≤ BASE_RATE_SCALE.val := by scalar_tac
      rcases checked_denom_cases r s w with ⟨hle, d, hd, -⟩ | ⟨hgt, hnone⟩
      · simp only [hw, ↓reduceIte, ha, hd, bind_ok, ok.injEq, Option.some.injEq]
        constructor
        · intro heq; exact ⟨heq.symm, hwpos, hale, hle⟩
        · rintro ⟨heq, _, _, _⟩; exact heq.symm
      · simp only [hw, ↓reduceIte, ha, hnone, bind_ok, ok.injEq, reduceCtorEq, false_iff]
        rintro ⟨-, -, -, hle⟩; omega

/-! ## `is_valid` -/

/-- `is_valid` never fails or diverges. -/
theorem is_valid_total (ev : Evidence) :
    ∃ b, is_valid ev = ok b := by
  unfold is_valid
  by_cases hw : ev.w = 0#u128
  · exact ⟨false, by simp [hw]⟩
  · by_cases ha : ev.base_rate > BASE_RATE_SCALE
    · exact ⟨false, by simp [hw, ha]⟩
    · obtain ⟨o, ho⟩ := checked_denom_total ev.r ev.s ev.w
      exact ⟨core.option.Option.is_some o, by simp [hw, ha, ho]⟩

/-- `is_valid ev = ok true` holds iff `w > 0`, `base_rate ≤ BASE_RATE_SCALE`, and
`r + s + w ≤ U128.max`. -/
theorem is_valid_iff (ev : Evidence) :
    is_valid ev = ok true ↔
      0 < ev.w.val ∧ ev.base_rate.val ≤ BASE_RATE_SCALE.val ∧
      ev.r.val + ev.s.val + ev.w.val ≤ U128.max := by
  unfold is_valid
  by_cases hw : ev.w = 0#u128
  · have h0 : (0#u128).val = 0 := by scalar_tac
    simp only [hw, ↓reduceIte, ok.injEq, Bool.false_eq_true, false_iff]
    rintro ⟨hwpos, -⟩; omega
  · have hwpos : 0 < ev.w.val := by
      by_contra h0
      have hval : ev.w.val = (0#u128).val := by scalar_tac
      exact hw ((UScalar.eq_equiv ev.w 0#u128).mpr hval)
    by_cases ha : ev.base_rate > BASE_RATE_SCALE
    · have hagt : BASE_RATE_SCALE.val < ev.base_rate.val := ha
      simp only [hw, ↓reduceIte, ha, ok.injEq, Bool.false_eq_true, false_iff]
      rintro ⟨-, hale, -⟩; omega
    · have hale : ev.base_rate.val ≤ BASE_RATE_SCALE.val := by scalar_tac
      rcases checked_denom_cases ev.r ev.s ev.w with ⟨hle, d, hd, -⟩ | ⟨hgt, hnone⟩
      · simp [hw, ha, hd, core.option.Option.is_some]
        exact ⟨hwpos, hale, hle⟩
      · simp only [hw, ↓reduceIte, ha, hnone, bind_ok, core.option.Option.is_some,
          Option.isSome_none, ok.injEq, Bool.false_eq_true, false_iff]
        rintro ⟨-, -, hle⟩; omega

/-! ## `vacuous` -/

/-- `vacuous` never fails or diverges. -/
theorem vacuous_total (base_rate : U64) :
    ∃ ev, vacuous base_rate = ok ev := by
  obtain ⟨r, hr, _, _⟩ := clamp_base_rate_spec base_rate
  exact ⟨{ r := 0#u128, s := 0#u128, w := PRIOR_WEIGHT, base_rate := r }, by simp [vacuous, hr]⟩

/-- `vacuous` always yields a valid opinion. -/
theorem vacuous_valid (base_rate : U64) :
    ∃ ev, vacuous base_rate = ok ev ∧ is_valid ev = ok true := by
  obtain ⟨r, hr, hle, _⟩ := clamp_base_rate_spec base_rate
  refine ⟨{ r := 0#u128, s := 0#u128, w := PRIOR_WEIGHT, base_rate := r }, by simp [vacuous, hr], ?_⟩
  rw [is_valid_iff]
  dsimp only
  have hw : PRIOR_WEIGHT.val = 2 := by simp [PRIOR_WEIGHT]
  have hr0 : (0#u128).val = 0 := by scalar_tac
  have hmax : 2 ≤ U128.max := by scalar_tac
  refine ⟨by omega, hle, by omega⟩

/-- `vacuous` projects to the exact vacuous simplex point `(b = 0, d = 0, u = 1, conflict = 0)`. -/
theorem vacuous_projects_exact (base_rate : U64) :
    ∃ ev p, vacuous base_rate = ok ev ∧ project ev = ok (some p) ∧
      p.b_num.val = 0 ∧ p.d_num.val = 0 ∧ p.u_num.val = p.denom.val ∧
      p.denom.val = 2 ∧ p.conflict_num.val = 0 := by
  obtain ⟨r, hr, hle, _⟩ := clamp_base_rate_spec base_rate
  let ev : Evidence := { r := 0#u128, s := 0#u128, w := PRIOR_WEIGHT, base_rate := r }
  have hvac : vacuous base_rate = ok ev := by simp [vacuous, hr, ev]
  have hw_ne : PRIOR_WEIGHT ≠ 0#u128 := by simp [PRIOR_WEIGHT]
  have hra : ¬ (r > BASE_RATE_SCALE) := by
    intro hgt
    have : BASE_RATE_SCALE.val < r.val := hgt
    omega
  have hd : checked_denom 0#u128 0#u128 PRIOR_WEIGHT = ok (some 2#u128) := by
    rw [checked_denom_some_iff]
    have h0 : (0#u128).val = 0 := by scalar_tac
    have h2 : (2#u128).val = 2 := by scalar_tac
    have hw : PRIOR_WEIGHT.val = 2 := by simp [PRIOR_WEIGHT]
    have hmax : 2 ≤ U128.max := by scalar_tac
    omega
  have hproj : project ev = ok (some {
      b_num := 0#u128, d_num := 0#u128, u_num := PRIOR_WEIGHT,
      denom := 2#u128, conflict_num := core.num.U128.saturating_add 0#u128 0#u128,
      base_rate := r }) := by
    simp [project, ev, hw_ne, hra, hd, lift]
  refine ⟨ev, _, hvac, hproj, ?_, ?_, ?_, ?_, ?_⟩
  · scalar_tac
  · scalar_tac
  · simp [PRIOR_WEIGHT]
  · scalar_tac
  · have hmax : (0#u128).val + (0#u128).val ≤ U128.max := by scalar_tac
    rw [u128_saturating_add_exact 0#u128 0#u128 hmax]
    scalar_tac

/-! ## `project` -/

/-- `project` never fails or diverges. -/
theorem project_total (ev : Evidence) :
    ∃ p, project ev = ok p := by
  unfold project
  by_cases hw : ev.w = 0#u128
  · exact ⟨none, by simp [hw]⟩
  · by_cases ha : ev.base_rate > BASE_RATE_SCALE
    · exact ⟨none, by simp [hw, ha]⟩
    · obtain ⟨o, ho⟩ := checked_denom_total ev.r ev.s ev.w
      cases o with
      | none => exact ⟨none, by simp [hw, ha, ho]⟩
      | some denom =>
        by_cases hrs : ev.r <= ev.s
        · exact ⟨some (Projected.mk ev.r ev.s ev.w denom
              (core.num.U128.saturating_add ev.r ev.r) ev.base_rate),
            by simp [hw, ha, ho, hrs, lift]⟩
        · exact ⟨some (Projected.mk ev.r ev.s ev.w denom
              (core.num.U128.saturating_add ev.s ev.s) ev.base_rate),
            by simp [hw, ha, ho, hrs, lift]⟩

/-- **Simplex preservation**: every projected opinion satisfies exact
`b_num + d_num + u_num = denom` with `denom > 0`, bounded dissonance
`conflict_num ≤ b_num + d_num < denom`, and `base_rate ≤ BASE_RATE_SCALE`. -/
theorem project_simplex_preservation (ev : Evidence) (p : Projected)
    (hp : project ev = ok (some p)) :
    p.b_num.val + p.d_num.val + p.u_num.val = p.denom.val ∧
      0 < p.denom.val ∧
      p.conflict_num.val = 2 * min p.b_num.val p.d_num.val ∧
      p.conflict_num.val ≤ p.b_num.val + p.d_num.val ∧
      p.conflict_num.val < p.denom.val ∧
      p.base_rate.val ≤ BASE_RATE_SCALE.val := by
  unfold project at hp
  by_cases hw : ev.w = 0#u128
  · simp [hw] at hp
  · have hwpos : 0 < ev.w.val := by
      by_contra h0
      have hval : ev.w.val = (0#u128).val := by scalar_tac
      exact hw ((UScalar.eq_equiv ev.w 0#u128).mpr hval)
    by_cases ha : ev.base_rate > BASE_RATE_SCALE
    · simp [hw, ha] at hp
    · have hale : ev.base_rate.val ≤ BASE_RATE_SCALE.val := by scalar_tac
      rcases checked_denom_cases ev.r ev.s ev.w with ⟨hle, denom, ho, hdenom⟩ | ⟨-, ho⟩
      · by_cases hrs : ev.r <= ev.s
        · have hrs_le : ev.r.val ≤ ev.s.val := hrs
          simp only [hw, ↓reduceIte, ha, ho, bind_ok, hrs, lift, ok.injEq, Option.some.injEq] at hp
          subst hp
          dsimp only
          have h2r : ev.r.val + ev.r.val ≤ U128.max := by omega
          have hconf := u128_saturating_add_exact ev.r ev.r h2r
          omega
        · have hrs_gt : ev.s.val < ev.r.val := by scalar_tac
          simp only [hw, ↓reduceIte, ha, ho, bind_ok, hrs, lift, ok.injEq, Option.some.injEq] at hp
          subst hp
          dsimp only
          have h2s : ev.s.val + ev.s.val ≤ U128.max := by omega
          have hconf := u128_saturating_add_exact ev.s ev.s h2s
          omega
      · simp [hw, ha, ho] at hp

/-- Internal dissonance is strictly positive iff both belief and disbelief are positive. -/
theorem project_conflict_pos_iff (ev : Evidence) (p : Projected)
    (hp : project ev = ok (some p)) :
    0 < p.conflict_num.val ↔ 0 < p.b_num.val ∧ 0 < p.d_num.val := by
  have ⟨_, _, hconf, _, _, _⟩ := project_simplex_preservation ev p hp
  omega

/-! ## `averaging_cluster` (Anti-Echo-Chamber Invariance) -/

/-- `averaging_cluster` never fails or diverges. -/
theorem averaging_cluster_total (supports challenges base_rate : U64) :
    ∃ ev, averaging_cluster supports challenges base_rate = ok ev := by
  obtain ⟨clamped, hc, _, _⟩ := clamp_base_rate_spec base_rate
  unfold averaging_cluster
  rw [hc]
  by_cases hs : supports = 0#u64 <;> by_cases hch : challenges = 0#u64 <;>
    simp [hs, hch, lift]

/-- `averaging_cluster` always produces a valid opinion whose uncertainty equals `2/3`
whenever at least one observation is present (`3 * u_num = 2 * denom`), preventing
derivative-copy echo-chamber inflation. -/
theorem averaging_cluster_echo_chamber_invariance (supports challenges base_rate : U64) :
    ∃ ev p, averaging_cluster supports challenges base_rate = ok ev ∧
      project ev = ok (some p) ∧
      (supports.val = 0 ∧ challenges.val = 0 →
        p.b_num.val = 0 ∧ p.d_num.val = 0 ∧ p.u_num.val = p.denom.val) ∧
      (0 < supports.val ∨ 0 < challenges.val →
        3 * p.u_num.val = 2 * p.denom.val) ∧
      (0 < supports.val ∧ challenges.val = 0 →
        ev.r.val = 1 ∧ ev.s.val = 0 ∧ ev.w.val = 2) ∧
      (supports.val = 0 ∧ 0 < challenges.val →
        ev.r.val = 0 ∧ ev.s.val = 1 ∧ ev.w.val = 2) := by
  obtain ⟨clamped, hc, hcle, _⟩ := clamp_base_rate_spec base_rate
  have hcl_not_gt : ¬ (clamped > BASE_RATE_SCALE) := by
    intro hgt; have : BASE_RATE_SCALE.val < clamped.val := hgt; omega
  have hw2_ne : PRIOR_WEIGHT ≠ 0#u128 := by simp [PRIOR_WEIGHT]
  have hw2_val : PRIOR_WEIGHT.val = 2 := by simp [PRIOR_WEIGHT]
  have h0_128 : (0#u128).val = 0 := by scalar_tac
  have h1_128 : (1#u128).val = 1 := by scalar_tac
  have hmax_big : 2 ^ 68 ≤ U128.max := by scalar_tac
  by_cases hs : supports = 0#u64
  · have hs0 : supports.val = 0 := by rw [hs]; scalar_tac
    by_cases hch : challenges = 0#u64
    · have hch0 : challenges.val = 0 := by rw [hch]; scalar_tac
      let ev : Evidence := { r := 0#u128, s := 0#u128, w := PRIOR_WEIGHT, base_rate := clamped }
      have hev : averaging_cluster supports challenges base_rate = ok ev := by
        simp [averaging_cluster, hc, hs, hch, ev]
      have hd : checked_denom ev.r ev.s ev.w = ok (some 2#u128) := by
        rw [checked_denom_some_iff]
        have h2 : (2#u128).val = 2 := by scalar_tac
        simp only [ev]; omega
      have hsome : ∃ p, project ev = ok (some p) := by
        unfold project; simp [ev, hw2_ne, hcl_not_gt, hd, lift]
      obtain ⟨p, hp⟩ := hsome
      have ⟨hsum, _, _, _, _, _⟩ := project_simplex_preservation ev p hp
      have hp_fields : p.b_num = 0#u128 ∧ p.d_num = 0#u128 ∧ p.u_num = PRIOR_WEIGHT := by
        unfold project at hp; simp [ev, hw2_ne, hcl_not_gt, hd, lift] at hp
        rw [← hp]; exact ⟨rfl, rfl, rfl⟩
      refine ⟨ev, p, hev, hp, ?_, ?_, ?_, ?_⟩
      · intro _; rw [hp_fields.1, hp_fields.2.1, hp_fields.2.2] at hsum ⊢; omega
      · intro hpos; omega
      · intro hpos; omega
      · intro hpos; omega
    · have hch_pos : 0 < challenges.val := by
        by_contra h0
        have hval : challenges.val = (0#u64).val := by scalar_tac
        exact hch ((UScalar.eq_equiv challenges 0#u64).mpr hval)
      let ev : Evidence := { r := 0#u128, s := 1#u128, w := PRIOR_WEIGHT, base_rate := clamped }
      have hev : averaging_cluster supports challenges base_rate = ok ev := by
        simp [averaging_cluster, hc, hs, hch, ev]
      have hd : checked_denom ev.r ev.s ev.w = ok (some 3#u128) := by
        rw [checked_denom_some_iff]
        have h3 : (3#u128).val = 3 := by scalar_tac
        simp only [ev]; omega
      have hsome : ∃ p, project ev = ok (some p) := by
        unfold project; simp [ev, hw2_ne, hcl_not_gt, hd, lift]
      obtain ⟨p, hp⟩ := hsome
      have ⟨hsum, _, _, _, _, _⟩ := project_simplex_preservation ev p hp
      have hp_fields : p.b_num = 0#u128 ∧ p.d_num = 1#u128 ∧ p.u_num = PRIOR_WEIGHT := by
        unfold project at hp; simp [ev, hw2_ne, hcl_not_gt, hd, lift] at hp
        rw [← hp]; exact ⟨rfl, rfl, rfl⟩
      refine ⟨ev, p, hev, hp, ?_, ?_, ?_, ?_⟩
      · intro h0; omega
      · intro _; rw [hp_fields.1, hp_fields.2.1, hp_fields.2.2] at hsum; rw [hp_fields.2.2]; omega
      · intro hpos; omega
      · intro _; simp only [ev]; exact ⟨h0_128, h1_128, hw2_val⟩
  · have hs_pos : 0 < supports.val := by
      by_contra h0
      have hval : supports.val = (0#u64).val := by scalar_tac
      exact hs ((UScalar.eq_equiv supports 0#u64).mpr hval)
    by_cases hch : challenges = 0#u64
    · have hch0 : challenges.val = 0 := by rw [hch]; scalar_tac
      let ev : Evidence := { r := 1#u128, s := 0#u128, w := PRIOR_WEIGHT, base_rate := clamped }
      have hev : averaging_cluster supports challenges base_rate = ok ev := by
        simp [averaging_cluster, hc, hs, hch, ev]
      have hd : checked_denom ev.r ev.s ev.w = ok (some 3#u128) := by
        rw [checked_denom_some_iff]
        have h3 : (3#u128).val = 3 := by scalar_tac
        simp only [ev]; omega
      have hsome : ∃ p, project ev = ok (some p) := by
        unfold project; simp [ev, hw2_ne, hcl_not_gt, hd, lift]
      obtain ⟨p, hp⟩ := hsome
      have ⟨hsum, _, _, _, _, _⟩ := project_simplex_preservation ev p hp
      have hp_fields : p.b_num = 1#u128 ∧ p.d_num = 0#u128 ∧ p.u_num = PRIOR_WEIGHT := by
        unfold project at hp; simp [ev, hw2_ne, hcl_not_gt, hd, lift] at hp
        rw [← hp]; exact ⟨rfl, rfl, rfl⟩
      refine ⟨ev, p, hev, hp, ?_, ?_, ?_, ?_⟩
      · intro h0; omega
      · intro _; rw [hp_fields.1, hp_fields.2.1, hp_fields.2.2] at hsum; rw [hp_fields.2.2]; omega
      · intro _; simp only [ev]; exact ⟨h1_128, h0_128, hw2_val⟩
      · intro hpos; omega
    · have hch_pos : 0 < challenges.val := by
        by_contra h0
        have hval : challenges.val = (0#u64).val := by scalar_tac
        exact hch ((UScalar.eq_equiv challenges 0#u64).mpr hval)
      let r : U128 := UScalar.cast .U128 supports
      let s : U128 := UScalar.cast .U128 challenges
      let total : U128 := core.num.U128.saturating_add r s
      let w : U128 := core.num.U128.saturating_add total total
      let ev : Evidence := { r, s, w, base_rate := clamped }
      have hr_val : r.val = supports.val := u64_cast_u128_val supports
      have hs_val : s.val = challenges.val := u64_cast_u128_val challenges
      have hr_bound : r.val < 2 ^ 64 := by rw [hr_val]; scalar_tac
      have hs_bound : s.val < 2 ^ 64 := by rw [hs_val]; scalar_tac
      have hpow_le : 6 * (2 ^ 64) ≤ 2 ^ 68 := by decide
      have htot_val : total.val = r.val + s.val :=
        u128_saturating_add_exact r s (by omega)
      have hw_val : w.val = 2 * (r.val + s.val) := by
        have h := u128_saturating_add_exact total total (by omega)
        change (core.num.U128.saturating_add total total).val = 2 * (r.val + s.val)
        omega
      have hw_ne : w ≠ 0#u128 := by
        intro hw0
        have hwz : w.val = 0 := by rw [hw0]; scalar_tac
        omega
      have hev : averaging_cluster supports challenges base_rate = ok ev := by
        simp [averaging_cluster, hc, hs, hch, ev, r, s, total, w, lift]
      have hdenom_le : r.val + s.val + w.val ≤ U128.max := by omega
      rcases checked_denom_cases r s w with ⟨-, d, hd, -⟩ | ⟨hgt, -⟩
      · have hsome : ∃ p, project ev = ok (some p) := by
          unfold project
          by_cases hrs : r <= s <;> simp [ev, hw_ne, hcl_not_gt, hd, hrs, lift]
        obtain ⟨p, hp⟩ := hsome
        have ⟨hsum, _, _, _, _, _⟩ := project_simplex_preservation ev p hp
        have hp_fields : p.b_num = r ∧ p.d_num = s ∧ p.u_num = w := by
          unfold project at hp
          by_cases hrs : r <= s <;> simp [ev, hw_ne, hcl_not_gt, hd, hrs, lift] at hp <;>
            rw [← hp] <;> exact ⟨rfl, rfl, rfl⟩
        refine ⟨ev, p, hev, hp, ?_, ?_, ?_, ?_⟩
        · intro h0; omega
        · intro _; rw [hp_fields.1, hp_fields.2.1, hp_fields.2.2] at hsum; rw [hp_fields.2.2]; omega
        · intro h0; omega
        · intro h0; omega
      · omega

/-! ## `cumulative_fuse` (`⊕`) -/

private theorem cumulative_fuse_equal_weight_total (a b : Evidence) (br : U64) :
    ∃ o, cumulative_fuse_equal_weight a b br = ok o := by
  unfold cumulative_fuse_equal_weight
  cases U128.checked_add a.r b.r with
  | none => exact ⟨none, by simp [lift]⟩
  | some r =>
    cases U128.checked_add a.s b.s with
    | none => exact ⟨none, by simp [lift]⟩
    | some s =>
      obtain ⟨o, ho⟩ := build_valid_total r s a.w br
      exact ⟨o, by simp [ho, lift]⟩

private theorem cumulative_fuse_general_total (a b : Evidence) (br : U64) :
    ∃ o, cumulative_fuse_general a b br = ok o := by
  unfold cumulative_fuse_general
  obtain ⟨or_, hor⟩ := checked_cross_sum_total a.r b.w b.r a.w
  cases or_ with
  | none => exact ⟨none, by simp [hor]⟩
  | some r =>
    obtain ⟨os, hos⟩ := checked_cross_sum_total a.s b.w b.s a.w
    cases os with
    | none => exact ⟨none, by simp [hor, hos]⟩
    | some s =>
      cases U128.checked_mul a.w b.w with
      | none => exact ⟨none, by simp [hor, hos, lift]⟩
      | some w =>
        obtain ⟨o, ho⟩ := build_valid_total r s w br
        exact ⟨o, by simp [hor, hos, ho, lift]⟩

/-- `cumulative_fuse` never fails or diverges. -/
theorem cumulative_fuse_total (left right : Evidence) :
    ∃ o, cumulative_fuse left right = ok o := by
  unfold cumulative_fuse
  obtain ⟨bl, hbl⟩ := is_valid_total left
  cases bl with
  | false => exact ⟨none, by simp [hbl]⟩
  | true =>
    obtain ⟨br, hbr⟩ := is_valid_total right
    cases br with
    | false => exact ⟨none, by simp [hbl, hbr]⟩
    | true =>
      obtain ⟨m, hm, _, _⟩ := min_base_rate_spec left.base_rate right.base_rate
      by_cases hw : left.w = right.w
      · obtain ⟨o, ho⟩ := cumulative_fuse_equal_weight_total left right m
        exact ⟨o, by simp [hbl, hbr, hm, hw, ho]⟩
      · obtain ⟨o, ho⟩ := cumulative_fuse_general_total left right m
        exact ⟨o, by simp [hbl, hbr, hm, hw, ho]⟩

/-- Exact rational characterization of `cumulative_fuse`: whenever `left ⊕ right = ok (some out)`,
`out` is valid and carries the exact rational evidence sum
`out.r / out.w = left.r / left.w + right.r / right.w` and
`out.s / out.w = left.s / left.w + right.s / right.w`. -/
theorem cumulative_fuse_spec (left right out : Evidence)
    (h : cumulative_fuse left right = ok (some out)) :
    is_valid left = ok true ∧
      is_valid right = ok true ∧
      is_valid out = ok true ∧
      out.r.val * (left.w.val * right.w.val) =
        (left.r.val * right.w.val + right.r.val * left.w.val) * out.w.val ∧
      out.s.val * (left.w.val * right.w.val) =
        (left.s.val * right.w.val + right.s.val * left.w.val) * out.w.val ∧
      out.base_rate.val = min left.base_rate.val right.base_rate.val := by
  unfold cumulative_fuse at h
  obtain ⟨bl, hbl⟩ := is_valid_total left
  cases bl with
  | false => simp [hbl] at h
  | true =>
    obtain ⟨br, hbr⟩ := is_valid_total right
    cases br with
    | false => simp [hbl, hbr] at h
    | true =>
      obtain ⟨m, hm, hm_val, _⟩ := min_base_rate_spec left.base_rate right.base_rate
      by_cases hw : left.w = right.w
      · simp only [hbl, hbr, bind_ok, ↓reduceIte, hm, hw] at h
        unfold cumulative_fuse_equal_weight at h
        cases hr : U128.checked_add left.r right.r with
        | none => simp [hr, lift] at h
        | some r =>
          have ⟨hr_val, _⟩ := (u128_checked_add_some_iff left.r right.r r).mp hr
          cases hs : U128.checked_add left.s right.s with
          | none => simp [hr, hs, lift] at h
          | some s =>
            have ⟨hs_val, _⟩ := (u128_checked_add_some_iff left.s right.s s).mp hs
            simp only [hr, hs, lift, bind_ok] at h
            have ⟨hout, hw_pos, hm_le, hsum_le⟩ :=
              (build_valid_some_iff r s left.w m out).mp h
            subst hout
            have hvalid_out : is_valid { r, s, w := left.w, base_rate := m } = ok true :=
              (is_valid_iff _).mpr ⟨hw_pos, hm_le, hsum_le⟩
            refine ⟨hbl, hbr, hvalid_out, ?_, ?_, hm_val⟩
            · simp only [hw, hr_val]; ring
            · simp only [hw, hs_val]; ring
      · simp only [hbl, hbr, bind_ok, ↓reduceIte, hm, hw] at h
        unfold cumulative_fuse_general at h
        obtain ⟨or_, hor⟩ := checked_cross_sum_total left.r right.w right.r left.w
        cases or_ with
        | none => simp [hor] at h
        | some r =>
          have ⟨hr_val, _⟩ :=
            (checked_cross_sum_some_iff left.r right.w right.r left.w r).mp hor
          obtain ⟨os, hos⟩ := checked_cross_sum_total left.s right.w right.s left.w
          cases os with
          | none => simp [hor, hos] at h
          | some s =>
            have ⟨hs_val, _⟩ :=
              (checked_cross_sum_some_iff left.s right.w right.s left.w s).mp hos
            cases hwm : U128.checked_mul left.w right.w with
            | none => simp [hor, hos, hwm, lift] at h
            | some w =>
              have ⟨hw_val, _⟩ := (u128_checked_mul_some_iff left.w right.w w).mp hwm
              simp only [hor, hos, hwm, lift, bind_ok] at h
              have ⟨hout, hw_pos, hm_le, hsum_le⟩ :=
                (build_valid_some_iff r s w m out).mp h
              subst hout
              have hvalid_out : is_valid { r, s, w, base_rate := m } = ok true :=
                (is_valid_iff _).mpr ⟨hw_pos, hm_le, hsum_le⟩
              refine ⟨hbl, hbr, hvalid_out, ?_, ?_, hm_val⟩
              · simp only [hr_val, hw_val]
              · simp only [hs_val, hw_val]

/-- **Cumulative Fusion Commutativity**: `left ⊕ right = right ⊕ left` structurally. -/
theorem cumulative_fuse_comm (left right : Evidence) :
    cumulative_fuse left right = cumulative_fuse right left := by
  unfold cumulative_fuse
  obtain ⟨bl, hbl⟩ := is_valid_total left
  obtain ⟨br, hbr⟩ := is_valid_total right
  cases bl <;> cases br
  · simp [hbl, hbr]
  · simp [hbl, hbr]
  · simp [hbl, hbr]
  · simp only [hbl, hbr, bind_ok, ↓reduceIte]
    have hm := min_base_rate_comm left.base_rate right.base_rate
    obtain ⟨m, hml, _, _⟩ := min_base_rate_spec left.base_rate right.base_rate
    have hmr : min_base_rate right.base_rate left.base_rate = ok m := hm.symm.trans hml
    rw [hml, hmr]
    simp only [bind_ok]
    by_cases hw : left.w = right.w
    · simp only [hw, ↓reduceIte, cumulative_fuse_equal_weight]
      rw [u128_checked_add_comm left.r right.r, u128_checked_add_comm left.s right.s]
    · have hwr : ¬ (right.w = left.w) := fun h => hw h.symm
      simp only [hw, hwr, ↓reduceIte, cumulative_fuse_general]
      rw [checked_cross_sum_comm left.r right.w right.r left.w,
        checked_cross_sum_comm left.s right.w right.s left.w,
        u128_checked_mul_comm left.w right.w]

private theorem cross_assoc_nat
    (ar br cr abr bcr lr rr aw bw cw abw bcw lw rw_ : Nat)
    (haw : 0 < aw) (hbw : 0 < bw) (hcw : 0 < cw) (habw : 0 < abw) (hbcw : 0 < bcw)
    (hab : abr * (aw * bw) = (ar * bw + br * aw) * abw)
    (hbc : bcr * (bw * cw) = (br * cw + cr * bw) * bcw)
    (hlhs : lr * (abw * cw) = (abr * cw + cr * abw) * lw)
    (hrhs : rr * (aw * bcw) = (ar * bcw + bcr * aw) * rw_) :
    lr * rw_ = rr * lw := by
  have hpos : 0 < aw * bw * cw * abw * bcw := by
    have h1 := Nat.mul_pos haw hbw
    have h2 := Nat.mul_pos h1 hcw
    have h3 := Nat.mul_pos h2 habw
    exact Nat.mul_pos h3 hbcw
  apply Nat.eq_of_mul_eq_mul_left hpos
  have hL : (aw * bw * cw * abw * bcw) * (lr * rw_) =
      (ar * bw * cw + br * aw * cw + cr * aw * bw) * (abw * bcw * lw * rw_) := by
    have s1 : lr * (abw * cw) * (aw * bw) =
        (abr * (aw * bw) * cw + cr * abw * (aw * bw)) * lw := by
      rw [hlhs]; ring
    rw [hab] at s1
    calc (aw * bw * cw * abw * bcw) * (lr * rw_)
        = lr * (abw * cw) * (aw * bw) * (bcw * rw_) := by ring
      _ = ((ar * bw + br * aw) * abw * cw + cr * abw * (aw * bw)) * lw * (bcw * rw_) := by
          rw [s1]
      _ = (ar * bw * cw + br * aw * cw + cr * aw * bw) * (abw * bcw * lw * rw_) := by ring
  have hR : (aw * bw * cw * abw * bcw) * (rr * lw) =
      (ar * bw * cw + br * aw * cw + cr * aw * bw) * (abw * bcw * lw * rw_) := by
    have s1 : rr * (aw * bcw) * (bw * cw) =
        (ar * bcw * (bw * cw) + bcr * (bw * cw) * aw) * rw_ := by
      rw [hrhs]; ring
    rw [hbc] at s1
    calc (aw * bw * cw * abw * bcw) * (rr * lw)
        = rr * (aw * bcw) * (bw * cw) * (abw * lw) := by ring
      _ = (ar * bcw * (bw * cw) + (br * cw + cr * bw) * bcw * aw) * rw_ * (abw * lw) := by
          rw [s1]
      _ = (ar * bw * cw + br * aw * cw + cr * aw * bw) * (abw * bcw * lw * rw_) := by ring
  rw [hL, hR]

/-- **Cumulative Fusion Associativity**: `(a ⊕ b) ⊕ c` and `a ⊕ (b ⊕ c)` represent the
exact same rational binomial opinion (`r_lhs / w_lhs = r_rhs / w_rhs`,
`s_lhs / w_lhs = s_rhs / w_rhs`, and equal `base_rate`). -/
theorem cumulative_fuse_assoc (a b c ab bc lhs rhs : Evidence)
    (hab : cumulative_fuse a b = ok (some ab))
    (hbc : cumulative_fuse b c = ok (some bc))
    (hlhs : cumulative_fuse ab c = ok (some lhs))
    (hrhs : cumulative_fuse a bc = ok (some rhs)) :
    lhs.r.val * rhs.w.val = rhs.r.val * lhs.w.val ∧
      lhs.s.val * rhs.w.val = rhs.s.val * lhs.w.val ∧
      lhs.base_rate = rhs.base_rate := by
  have ⟨ha_v, hb_v, hab_v, hab_r, hab_s, hab_a⟩ := cumulative_fuse_spec a b ab hab
  have ⟨_, hc_v, hbc_v, hbc_r, hbc_s, hbc_a⟩ := cumulative_fuse_spec b c bc hbc
  have ⟨_, _, _, hlhs_r, hlhs_s, hlhs_a⟩ := cumulative_fuse_spec ab c lhs hlhs
  have ⟨_, _, _, hrhs_r, hrhs_s, hrhs_a⟩ := cumulative_fuse_spec a bc rhs hrhs
  have ha_w : 0 < a.w.val := ((is_valid_iff a).mp ha_v).1
  have hb_w : 0 < b.w.val := ((is_valid_iff b).mp hb_v).1
  have hc_w : 0 < c.w.val := ((is_valid_iff c).mp hc_v).1
  have hab_w : 0 < ab.w.val := ((is_valid_iff ab).mp hab_v).1
  have hbc_w : 0 < bc.w.val := ((is_valid_iff bc).mp hbc_v).1
  refine ⟨
    cross_assoc_nat a.r.val b.r.val c.r.val ab.r.val bc.r.val lhs.r.val rhs.r.val
      a.w.val b.w.val c.w.val ab.w.val bc.w.val lhs.w.val rhs.w.val
      ha_w hb_w hc_w hab_w hbc_w hab_r hbc_r hlhs_r hrhs_r,
    cross_assoc_nat a.s.val b.s.val c.s.val ab.s.val bc.s.val lhs.s.val rhs.s.val
      a.w.val b.w.val c.w.val ab.w.val bc.w.val lhs.w.val rhs.w.val
      ha_w hb_w hc_w hab_w hbc_w hab_s hbc_s hlhs_s hrhs_s,
    (UScalar.eq_equiv _ _).mpr (by omega)
  ⟩

/-- **Vacuous Identity for Cumulative Fusion**: fusing a valid opinion with `vacuous`
preserves its exact rational evidence counts. -/
theorem cumulative_fuse_vacuous_identity (ev v out : Evidence)
    (hv : vacuous ev.base_rate = ok v)
    (hf : cumulative_fuse ev v = ok (some out)) :
    out.r.val * ev.w.val = ev.r.val * out.w.val ∧
      out.s.val * ev.w.val = ev.s.val * out.w.val ∧
      out.base_rate = ev.base_rate := by
  have ⟨hev_v, _, _, hr, hs, ha⟩ := cumulative_fuse_spec ev v out hf
  have hbr_le : ev.base_rate.val ≤ BASE_RATE_SCALE.val := ((is_valid_iff ev).mp hev_v).2.1
  obtain ⟨cl, hcl, _, hcl_eq⟩ := clamp_base_rate_spec ev.base_rate
  have hcl_same : cl = ev.base_rate := hcl_eq hbr_le
  simp only [vacuous, hcl, hcl_same, bind_ok, ok.injEq] at hv
  subst hv
  have hv_w_pos : 0 < PRIOR_WEIGHT.val := by simp [PRIOR_WEIGHT]
  have hr0 : (0#u128).val = 0 := by scalar_tac
  have hr_eq : out.r.val * ev.w.val = ev.r.val * out.w.val := by
    apply Nat.eq_of_mul_eq_mul_right hv_w_pos
    calc out.r.val * ev.w.val * PRIOR_WEIGHT.val
        = out.r.val * (ev.w.val * PRIOR_WEIGHT.val) := by rw [Nat.mul_assoc]
      _ = (ev.r.val * PRIOR_WEIGHT.val + (0#u128).val * ev.w.val) * out.w.val := hr
      _ = ev.r.val * out.w.val * PRIOR_WEIGHT.val := by
          rw [hr0, Nat.zero_mul, Nat.add_zero]
          simp only [Nat.mul_assoc, Nat.mul_comm]
  have hs_eq : out.s.val * ev.w.val = ev.s.val * out.w.val := by
    apply Nat.eq_of_mul_eq_mul_right hv_w_pos
    calc out.s.val * ev.w.val * PRIOR_WEIGHT.val
        = out.s.val * (ev.w.val * PRIOR_WEIGHT.val) := by rw [Nat.mul_assoc]
      _ = (ev.s.val * PRIOR_WEIGHT.val + (0#u128).val * ev.w.val) * out.w.val := hs
      _ = ev.s.val * out.w.val * PRIOR_WEIGHT.val := by
          rw [hr0, Nat.zero_mul, Nat.add_zero]
          simp only [Nat.mul_assoc, Nat.mul_comm]
  have ha_eq : out.base_rate = ev.base_rate := by
    apply (UScalar.eq_equiv _ _).mpr
    simp only [Nat.min_self] at ha
    exact ha
  exact ⟨hr_eq, hs_eq, ha_eq⟩

/-! ## `averaging_fuse` (`◇`) -/

private theorem averaging_fuse_equal_weight_total (a b : Evidence) (br : U64) :
    ∃ o, averaging_fuse_equal_weight a b br = ok o := by
  unfold averaging_fuse_equal_weight
  cases U128.checked_add a.r b.r with
  | none => exact ⟨none, by simp [lift]⟩
  | some r =>
    cases U128.checked_add a.s b.s with
    | none => exact ⟨none, by simp [lift]⟩
    | some s =>
      cases U128.checked_mul a.w PRIOR_WEIGHT with
      | none => exact ⟨none, by simp [lift]⟩
      | some w =>
        obtain ⟨o, ho⟩ := build_valid_total r s w br
        exact ⟨o, by simp [ho, lift]⟩

private theorem checked_double_mul_total (a b : U128) :
    ∃ o, checked_double_mul a b = ok o := by
  unfold checked_double_mul
  cases U128.checked_mul a b with
  | none => exact ⟨none, by simp [lift]⟩
  | some p => exact ⟨U128.checked_mul p PRIOR_WEIGHT, by simp [lift]⟩

private theorem checked_double_mul_comm (a b : U128) :
    checked_double_mul a b = checked_double_mul b a := by
  unfold checked_double_mul
  rw [u128_checked_mul_comm a b]

private theorem averaging_fuse_general_total (a b : Evidence) (br : U64) :
    ∃ o, averaging_fuse_general a b br = ok o := by
  unfold averaging_fuse_general
  obtain ⟨or_, hor⟩ := checked_cross_sum_total a.r b.w b.r a.w
  cases or_ with
  | none => exact ⟨none, by simp [hor]⟩
  | some r =>
    obtain ⟨os, hos⟩ := checked_cross_sum_total a.s b.w b.s a.w
    cases os with
    | none => exact ⟨none, by simp [hor, hos]⟩
    | some s =>
      obtain ⟨ow, how⟩ := checked_double_mul_total a.w b.w
      cases ow with
      | none => exact ⟨none, by simp [hor, hos, how]⟩
      | some w =>
        obtain ⟨o, ho⟩ := build_valid_total r s w br
        exact ⟨o, by simp [hor, hos, how, ho]⟩

/-- `averaging_fuse` never fails or diverges. -/
theorem averaging_fuse_total (left right : Evidence) :
    ∃ o, averaging_fuse left right = ok o := by
  unfold averaging_fuse
  obtain ⟨bl, hbl⟩ := is_valid_total left
  cases bl with
  | false => exact ⟨none, by simp [hbl]⟩
  | true =>
    obtain ⟨br, hbr⟩ := is_valid_total right
    cases br with
    | false => exact ⟨none, by simp [hbl, hbr]⟩
    | true =>
      obtain ⟨m, hm, _, _⟩ := min_base_rate_spec left.base_rate right.base_rate
      by_cases hw : left.w = right.w
      · obtain ⟨o, ho⟩ := averaging_fuse_equal_weight_total left right m
        exact ⟨o, by simp [hbl, hbr, hm, hw, ho]⟩
      · obtain ⟨o, ho⟩ := averaging_fuse_general_total left right m
        exact ⟨o, by simp [hbl, hbr, hm, hw, ho]⟩

/-- **Averaging Fusion Commutativity**: `left ◇ right = right ◇ left` structurally. -/
theorem averaging_fuse_comm (left right : Evidence) :
    averaging_fuse left right = averaging_fuse right left := by
  unfold averaging_fuse
  obtain ⟨bl, hbl⟩ := is_valid_total left
  obtain ⟨br, hbr⟩ := is_valid_total right
  cases bl <;> cases br
  · simp [hbl, hbr]
  · simp [hbl, hbr]
  · simp [hbl, hbr]
  · simp only [hbl, hbr, bind_ok, ↓reduceIte]
    have hm := min_base_rate_comm left.base_rate right.base_rate
    obtain ⟨m, hml, _, _⟩ := min_base_rate_spec left.base_rate right.base_rate
    have hmr : min_base_rate right.base_rate left.base_rate = ok m := hm.symm.trans hml
    rw [hml, hmr]
    simp only [bind_ok]
    by_cases hw : left.w = right.w
    · simp only [hw, ↓reduceIte, averaging_fuse_equal_weight]
      rw [u128_checked_add_comm left.r right.r, u128_checked_add_comm left.s right.s]
    · have hwr : ¬ (right.w = left.w) := fun h => hw h.symm
      simp only [hw, hwr, ↓reduceIte, averaging_fuse_general]
      rw [checked_cross_sum_comm left.r right.w right.r left.w,
        checked_cross_sum_comm left.s right.w right.s left.w,
        checked_double_mul_comm left.w right.w]

/-- **Averaging Fusion Idempotence**: fusing any opinion with itself yields an opinion
with identical exact rational `(b, d, u)` ratios and identical `base_rate`. -/
theorem averaging_fuse_idempotent (ev out : Evidence)
    (h : averaging_fuse ev ev = ok (some out)) :
    is_valid out = ok true ∧
      out.r.val * ev.w.val = ev.r.val * out.w.val ∧
      out.s.val * ev.w.val = ev.s.val * out.w.val ∧
      out.r.val * (ev.r.val + ev.s.val + ev.w.val) =
        ev.r.val * (out.r.val + out.s.val + out.w.val) ∧
      out.s.val * (ev.r.val + ev.s.val + ev.w.val) =
        ev.s.val * (out.r.val + out.s.val + out.w.val) ∧
      out.w.val * (ev.r.val + ev.s.val + ev.w.val) =
        ev.w.val * (out.r.val + out.s.val + out.w.val) ∧
      out.base_rate = ev.base_rate := by
  unfold averaging_fuse at h
  obtain ⟨bv, hbv⟩ := is_valid_total ev
  cases bv with
  | false => simp [hbv] at h
  | true =>
    obtain ⟨m, hm, _, hm_eq⟩ := min_base_rate_spec ev.base_rate ev.base_rate
    have hmsame : m = ev.base_rate := hm_eq rfl
    simp only [hbv, bind_ok, ↓reduceIte, hm, hmsame, averaging_fuse_equal_weight] at h
    cases hr : U128.checked_add ev.r ev.r with
    | none => simp [hr, lift] at h
    | some r =>
      have ⟨hr_val, _⟩ := (u128_checked_add_some_iff ev.r ev.r r).mp hr
      cases hs : U128.checked_add ev.s ev.s with
      | none => simp [hr, hs, lift] at h
      | some s =>
        have ⟨hs_val, _⟩ := (u128_checked_add_some_iff ev.s ev.s s).mp hs
        cases hw : U128.checked_mul ev.w PRIOR_WEIGHT with
        | none => simp [hr, hs, hw, lift] at h
        | some w =>
          have ⟨hw_val, _⟩ := (u128_checked_mul_some_iff ev.w PRIOR_WEIGHT w).mp hw
          have hpw : PRIOR_WEIGHT.val = 2 := by simp [PRIOR_WEIGHT]
          simp only [hr, hs, hw, lift, bind_ok] at h
          have ⟨hout, hw_pos, ha_le, hsum_le⟩ :=
            (build_valid_some_iff r s w ev.base_rate out).mp h
          subst hout
          have hvalid_out : is_valid { r, s, w, base_rate := ev.base_rate } = ok true :=
            (is_valid_iff _).mpr ⟨hw_pos, ha_le, hsum_le⟩
          have hr2 : r.val = 2 * ev.r.val := by omega
          have hs2 : s.val = 2 * ev.s.val := by omega
          have hw2 : w.val = 2 * ev.w.val := by rw [hw_val, hpw, Nat.mul_comm]
          refine ⟨hvalid_out, ?_, ?_, ?_, ?_, ?_, rfl⟩
          · rw [hr2, hw2]; ring
          · rw [hs2, hw2]; ring
          · rw [hr2, hs2, hw2]; ring
          · rw [hr2, hs2, hw2]; ring
          · rw [hr2, hs2, hw2]; ring

/-! ## `trust_discount` (`⊗`) -/

private theorem trust_discount_inner_total (trust target : Evidence) (td tnb : U128) :
    ∃ o, trust_discount_inner trust target td tnb = ok o := by
  unfold trust_discount_inner
  cases U128.checked_mul trust.r target.r with
  | none => exact ⟨none, by simp [lift]⟩
  | some r =>
    cases U128.checked_mul trust.r target.s with
    | none => exact ⟨none, by simp [lift]⟩
    | some s =>
      obtain ⟨ow, how⟩ := checked_cross_sum_total tnb td trust.r target.w
      cases ow with
      | none => exact ⟨none, by simp [how, lift]⟩
      | some w =>
        obtain ⟨o, ho⟩ := build_valid_total r s w target.base_rate
        exact ⟨o, by simp [how, ho, lift]⟩

/-- `trust_discount` never fails or diverges. -/
theorem trust_discount_total (trust target : Evidence) :
    ∃ o, trust_discount trust target = ok o := by
  unfold trust_discount
  obtain ⟨bt, hbt⟩ := is_valid_total trust
  cases bt with
  | false => exact ⟨none, by simp [hbt]⟩
  | true =>
    obtain ⟨bx, hbx⟩ := is_valid_total target
    cases bx with
    | false => exact ⟨none, by simp [hbt, hbx]⟩
    | true =>
      obtain ⟨od, hod⟩ := checked_denom_total target.r target.s target.w
      cases od with
      | none => exact ⟨none, by simp [hbt, hbx, hod]⟩
      | some td =>
        cases U128.checked_add trust.s trust.w with
        | none => exact ⟨none, by simp [hbt, hbx, hod, lift]⟩
        | some tnb =>
          obtain ⟨o, ho⟩ := trust_discount_inner_total trust target td tnb
          exact ⟨o, by simp [hbt, hbx, hod, ho, lift]⟩

/-- **Trust Discounting Non-Inflation**: discounting `target` by `trust` preserves the
simplex (`D_out = D_trust * D_target`), preserves `target.base_rate`, never inflates
belief (`b' ≤ b_target` and `b' ≤ b_trust`) or disbelief (`d' ≤ d_target`), and never
decreases uncertainty (`u' ≥ u_target`). -/
theorem trust_discount_non_inflation (trust target out : Evidence)
    (h : trust_discount trust target = ok (some out)) :
    let dt := trust.r.val + trust.s.val + trust.w.val
    let dx := target.r.val + target.s.val + target.w.val
    let dout := out.r.val + out.s.val + out.w.val
    is_valid out = ok true ∧
      dout = dt * dx ∧
      out.r.val * dx ≤ target.r.val * dout ∧
      out.r.val * dt ≤ trust.r.val * dout ∧
      out.s.val * dx ≤ target.s.val * dout ∧
      target.w.val * dout ≤ out.w.val * dx ∧
      out.base_rate = target.base_rate := by
  unfold trust_discount at h
  obtain ⟨bt, hbt⟩ := is_valid_total trust
  cases bt with
  | false => simp [hbt] at h
  | true =>
    obtain ⟨bx, hbx⟩ := is_valid_total target
    cases bx with
    | false => simp [hbt, hbx] at h
    | true =>
      obtain ⟨od, hod⟩ := checked_denom_total target.r target.s target.w
      cases od with
      | none => simp [hbt, hbx, hod] at h
      | some td =>
        have ⟨htd, _⟩ := (checked_denom_some_iff target.r target.s target.w td).mp hod
        cases hnb : U128.checked_add trust.s trust.w with
        | none => simp [hbt, hbx, hod, hnb, lift] at h
        | some tnb =>
          have ⟨htnb, _⟩ := (u128_checked_add_some_iff trust.s trust.w tnb).mp hnb
          simp only [hbt, hbx, hod, hnb, lift, bind_ok, ↓reduceIte, trust_discount_inner] at h
          cases hr : U128.checked_mul trust.r target.r with
          | none => simp [hr] at h
          | some r =>
            have ⟨hr_val, _⟩ := (u128_checked_mul_some_iff trust.r target.r r).mp hr
            cases hs : U128.checked_mul trust.r target.s with
            | none => simp [hr, hs] at h
            | some s =>
              have ⟨hs_val, _⟩ := (u128_checked_mul_some_iff trust.r target.s s).mp hs
              obtain ⟨ow, how⟩ := checked_cross_sum_total tnb td trust.r target.w
              cases ow with
              | none => simp [hr, hs, how] at h
              | some w =>
                have ⟨hw_val, _⟩ :=
                  (checked_cross_sum_some_iff tnb td trust.r target.w w).mp how
                simp only [hr, hs, how, bind_ok] at h
                have ⟨hout, hw_pos, ha_le, hsum_le⟩ :=
                  (build_valid_some_iff r s w target.base_rate out).mp h
                subst hout
                have hvalid_out : is_valid { r, s, w, base_rate := target.base_rate } = ok true :=
                  (is_valid_iff _).mpr ⟨hw_pos, ha_le, hsum_le⟩
                dsimp only
                have hdout : r.val + s.val + w.val =
                    (trust.r.val + trust.s.val + trust.w.val) *
                    (target.r.val + target.s.val + target.w.val) := by
                  rw [hr_val, hs_val, hw_val, htnb, htd]; ring
                refine ⟨hvalid_out, hdout, ?_, ?_, ?_, ?_, rfl⟩
                · rw [hdout, hr_val]
                  have hle : trust.r.val ≤ trust.r.val + trust.s.val + trust.w.val := by omega
                  have h1 := Nat.mul_le_mul_right (target.r.val * (target.r.val + target.s.val + target.w.val)) hle
                  calc trust.r.val * target.r.val * (target.r.val + target.s.val + target.w.val)
                      = trust.r.val * (target.r.val * (target.r.val + target.s.val + target.w.val)) := by
                        ring
                    _ ≤ (trust.r.val + trust.s.val + trust.w.val) *
                        (target.r.val * (target.r.val + target.s.val + target.w.val)) := h1
                    _ = target.r.val *
                        ((trust.r.val + trust.s.val + trust.w.val) *
                          (target.r.val + target.s.val + target.w.val)) := by ring
                · rw [hdout, hr_val]
                  have hle : target.r.val ≤ target.r.val + target.s.val + target.w.val := by omega
                  have h1 := Nat.mul_le_mul_left (trust.r.val * (trust.r.val + trust.s.val + trust.w.val)) hle
                  calc trust.r.val * target.r.val * (trust.r.val + trust.s.val + trust.w.val)
                      = trust.r.val * (trust.r.val + trust.s.val + trust.w.val) * target.r.val := by
                        ring
                    _ ≤ trust.r.val * (trust.r.val + trust.s.val + trust.w.val) *
                        (target.r.val + target.s.val + target.w.val) := h1
                    _ = trust.r.val *
                        ((trust.r.val + trust.s.val + trust.w.val) *
                          (target.r.val + target.s.val + target.w.val)) := by ring
                · rw [hdout, hs_val]
                  have hle : trust.r.val ≤ trust.r.val + trust.s.val + trust.w.val := by omega
                  have h1 := Nat.mul_le_mul_right (target.s.val * (target.r.val + target.s.val + target.w.val)) hle
                  calc trust.r.val * target.s.val * (target.r.val + target.s.val + target.w.val)
                      = trust.r.val * (target.s.val * (target.r.val + target.s.val + target.w.val)) := by
                        ring
                    _ ≤ (trust.r.val + trust.s.val + trust.w.val) *
                        (target.s.val * (target.r.val + target.s.val + target.w.val)) := h1
                    _ = target.s.val *
                        ((trust.r.val + trust.s.val + trust.w.val) *
                          (target.r.val + target.s.val + target.w.val)) := by ring
                · rw [hdout, hw_val, htnb, htd]
                  have hle : target.w.val ≤ target.r.val + target.s.val + target.w.val := by omega
                  have h1 := Nat.mul_le_mul_left (trust.s.val + trust.w.val) hle
                  have h2 : target.w.val * (trust.r.val + trust.s.val + trust.w.val) ≤
                      (trust.s.val + trust.w.val) * (target.r.val + target.s.val + target.w.val) +
                      trust.r.val * target.w.val := by
                    calc target.w.val * (trust.r.val + trust.s.val + trust.w.val)
                        = (trust.s.val + trust.w.val) * target.w.val +
                          trust.r.val * target.w.val := by ring
                      _ ≤ (trust.s.val + trust.w.val) * (target.r.val + target.s.val + target.w.val) +
                          trust.r.val * target.w.val := Nat.add_le_add_right h1 _
                  have h3 := Nat.mul_le_mul_right (target.r.val + target.s.val + target.w.val) h2
                  calc target.w.val *
                        ((trust.r.val + trust.s.val + trust.w.val) *
                          (target.r.val + target.s.val + target.w.val))
                      = target.w.val * (trust.r.val + trust.s.val + trust.w.val) *
                        (target.r.val + target.s.val + target.w.val) := by ring
                    _ ≤ ((trust.s.val + trust.w.val) * (target.r.val + target.s.val + target.w.val) +
                          trust.r.val * target.w.val) *
                        (target.r.val + target.s.val + target.w.val) := h3

/-- An untrusted source (`trust.r = 0`) discounts any opinion to exact vacuous (`r = 0, s = 0`). -/
theorem trust_discount_vacuous_trust (trust target out : Evidence)
    (h0 : trust.r.val = 0)
    (h : trust_discount trust target = ok (some out)) :
    out.r.val = 0 ∧ out.s.val = 0 := by
  unfold trust_discount at h
  obtain ⟨bt, hbt⟩ := is_valid_total trust
  cases bt with
  | false => simp [hbt] at h
  | true =>
    obtain ⟨bx, hbx⟩ := is_valid_total target
    cases bx with
    | false => simp [hbt, hbx] at h
    | true =>
      obtain ⟨od, hod⟩ := checked_denom_total target.r target.s target.w
      cases od with
      | none => simp [hbt, hbx, hod] at h
      | some td =>
        cases hnb : U128.checked_add trust.s trust.w with
        | none => simp [hbt, hbx, hod, hnb, lift] at h
        | some tnb =>
          simp only [hbt, hbx, hod, hnb, lift, bind_ok, ↓reduceIte, trust_discount_inner] at h
          cases hr : U128.checked_mul trust.r target.r with
          | none => simp [hr] at h
          | some r =>
            have ⟨hr_val, _⟩ := (u128_checked_mul_some_iff trust.r target.r r).mp hr
            cases hs : U128.checked_mul trust.r target.s with
            | none => simp [hr, hs] at h
            | some s =>
              have ⟨hs_val, _⟩ := (u128_checked_mul_some_iff trust.r target.s s).mp hs
              obtain ⟨ow, how⟩ := checked_cross_sum_total tnb td trust.r target.w
              cases ow with
              | none => simp [hr, hs, how] at h
              | some w =>
                simp only [hr, hs, how, bind_ok] at h
                have ⟨hout, _, _, _⟩ :=
                  (build_valid_some_iff r s w target.base_rate out).mp h
                subst hout
                simp only [hr_val, hs_val, h0, Nat.zero_mul, and_self]

end mneme_kernel.opinion
