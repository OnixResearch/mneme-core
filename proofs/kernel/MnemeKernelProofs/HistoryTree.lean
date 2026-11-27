import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Crosby-Wallach / RFC 6962 Merkle history tree verification proofs

Theorems about the generated translation of `crates/mneme-kernel/src/historytree.rs`
(`mneme_kernel::history_tree`).
-/

namespace mneme_kernel.history_tree

private instance : DecidableEq mneme_kernel.hashing.Digest := fun a b =>
  match a, b with
  | ⟨ahi, alo⟩, ⟨bhi, blo⟩ =>
    if h1 : ahi = bhi then
      if h2 : alo = blo then isTrue (by rw [h1, h2])
      else isFalse (fun h => h2 (by cases h; rfl))
    else isFalse (fun h => h1 (by cases h; rfl))

private theorem spec_imp_exists {α : Type} {m : Result α} {p : α → Prop}
    (h : WP.spec m p) : ∃ v, m = ok v ∧ p v := by
  cases m with
  | ret r => exact ⟨r, rfl, by simpa using h⟩
  | vis i k => simp at h
  | div => simp at h

private theorem u64_shr_one_eq (x : U64) :
    ∃ y : U64, x >>> BIT_SHIFT_ONE = ok y ∧ y.val = x.val / 2 := by
  have hshift : (BIT_SHIFT_ONE : U32).val < 64 := by
    unfold BIT_SHIFT_ONE; scalar_tac
  obtain ⟨y, hy, hval⟩ := spec_imp_exists (U64.ShiftRight_spec x BIT_SHIFT_ONE hshift)
  refine ⟨y, hy, ?_⟩
  have hb : (BIT_SHIFT_ONE : U32).val = 1 := by unfold BIT_SHIFT_ONE; scalar_tac
  have hnat : y.val = x.val >>> (BIT_SHIFT_ONE : U32).val := hval.1
  rw [hnat, hb]
  exact Nat.shiftRight_eq_div_pow x.val 1

private theorem u64_and_one_val (x : U64) :
    (x &&& BIT_MASK_LSB).val = x.val % 2 := by
  have hb : (BIT_MASK_LSB : U64).val = 1 := by unfold BIT_MASK_LSB; scalar_tac
  rw [UScalar.val_and, hb]
  exact Nat.and_one_is_mod x.val

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

private theorem u64_saturating_sub_one_val (x : U64) :
    (core.num.U64.saturating_sub x 1#u64).val = x.val - 1 := by
  have h1_val : (1#u64).val = 1 := by scalar_tac
  have h1 : (1#u64).bv.toNat = 1 := h1_val
  have hbits : UScalarTy.U64.numBits = 64 := rfl
  have hlt : x.bv.toNat - 1 < 2 ^ UScalarTy.U64.numBits := by
    rw [hbits]
    have := x.bv.isLt
    omega
  simp only [core.num.U64.saturating_sub, UScalar.saturating_sub, UScalar.val,
    BitVec.toNat_ofNat]
  rw [h1, Nat.max_eq_right (Nat.zero_le _), Nat.mod_eq_of_lt hlt]

private theorem same_digest_eq (a b : mneme_kernel.hashing.Digest) :
    same_digest a b = ok (decide (a = b)) := by
  obtain ⟨ahi, alo⟩ := a
  obtain ⟨bhi, blo⟩ := b
  unfold same_digest
  by_cases h1 : ahi = bhi
  · by_cases h2 : alo = blo
    · simp [h1, h2]
    · simp [h1, h2]
  · simp [h1]

private def isLeftSiblingSpec (c : IndexCursor) : Bool :=
  (c.fn_idx.val % 2 == 1) || (c.fn_idx == c.sn_idx)

private theorem is_left_sibling_step_eq (c : IndexCursor) :
    is_left_sibling_step c = ok (isLeftSiblingSpec c) := by
  unfold is_left_sibling_step isLeftSiblingSpec
  simp only [lift]
  have hand : (c.fn_idx &&& BIT_MASK_LSB).val = c.fn_idx.val % 2 := u64_and_one_val c.fn_idx
  have hb : (BIT_MASK_LSB : U64).val = 1 := by unfold BIT_MASK_LSB; scalar_tac
  by_cases h1 : (c.fn_idx &&& BIT_MASK_LSB) = BIT_MASK_LSB
  · have hmod : c.fn_idx.val % 2 = 1 := by rw [← hand, h1, hb]
    simp [h1, hmod]
  · have hmod : c.fn_idx.val % 2 ≠ 1 := by
      intro hm
      apply h1
      apply UScalar.eq_of_val_eq
      rw [hand, hb, hm]
    by_cases heq : c.fn_idx = c.sn_idx
    · simp [heq]
    · simp [h1, hmod, heq]

/-- Pure mathematical specification of dropping trailing zero bits from `fn_idx`. -/
def shiftZerosSpec (f s : Nat) : Nat × Nat :=
  if h : f ≠ 0 ∧ f % 2 = 0 then
    shiftZerosSpec (f / 2) (s / 2)
  else
    (f, s)
termination_by f
decreasing_by omega

/-- Pure mathematical specification of dropping trailing one bits from `fn_idx`. -/
def shiftOnesSpec (f s : Nat) : Nat × Nat :=
  if h : f % 2 = 1 then
    shiftOnesSpec (f / 2) (s / 2)
  else
    (f, s)
termination_by f
decreasing_by omega

private theorem shift_trailing_zeros_loop_spec (f s : U64) :
    shift_trailing_zeros_loop f s ⦃ r =>
      (r.1.val, r.2.val) = shiftZerosSpec f.val s.val ⦄ := by
  unfold shift_trailing_zeros_loop
  apply loop.spec_decr_nat
    (fun (x : U64 × U64) => x.1.val)
    (fun (x : U64 × U64) => shiftZerosSpec x.1.val x.2.val = shiftZerosSpec f.val s.val)
  · rintro ⟨f1, s1⟩ hinv
    simp only at hinv ⊢
    unfold shift_trailing_zeros_loop.body
    by_cases hnz : f1 != 0#u64
    · have hfnz : f1.val ≠ 0 := by
        simp only [bne_iff_ne, ne_eq] at hnz
        intro h0
        apply hnz
        apply UScalar.eq_of_val_eq
        simpa using h0
      simp only [hnz, ↓reduceIte, lift]
      have hand := u64_and_one_val f1
      by_cases heven : (f1 &&& BIT_MASK_LSB) = 0#u64
      · have hmod : f1.val % 2 = 0 := by
          rw [← hand, heven]
          scalar_tac
        obtain ⟨f2, hf2, hf2v⟩ := u64_shr_one_eq f1
        obtain ⟨s2, hs2, hs2v⟩ := u64_shr_one_eq s1
        simp only [heven, ↓reduceIte, hf2, bind_ok, hs2, WP.spec_ok]
        refine ⟨?_, by omega⟩
        rw [← hinv, hf2v, hs2v]
        conv_rhs => unfold shiftZerosSpec
        simp [hfnz, hmod]
      · have hmod : f1.val % 2 ≠ 0 := by
          intro hm
          apply heven
          apply UScalar.eq_of_val_eq
          rw [hand, hm]
          scalar_tac
        simp only [bind_ok, heven, ↓reduceIte, WP.spec_ok]
        rw [← hinv, shiftZerosSpec]
        symm
        exact dite_eq_right_iff.mpr (fun hc => absurd hc.2 hmod)
    · have hf0 : f1.val = 0 := by
        simp only [bne_iff_ne, ne_eq, Decidable.not_not] at hnz
        rw [hnz]
        scalar_tac
      simp only [hnz, Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
      rw [← hinv, shiftZerosSpec]
      symm
      exact dite_eq_right_iff.mpr (fun hc => absurd hf0 hc.1)
  · rfl

private theorem shift_trailing_zeros_spec (c : IndexCursor) :
    ∃ r : IndexCursor, shift_trailing_zeros c = ok r ∧
      (r.fn_idx.val, r.sn_idx.val) = shiftZerosSpec c.fn_idx.val c.sn_idx.val := by
  unfold shift_trailing_zeros
  obtain ⟨⟨rf, rs⟩, hloop, hval⟩ := spec_imp_exists (shift_trailing_zeros_loop_spec c.fn_idx c.sn_idx)
  exact ⟨{ fn_idx := rf, sn_idx := rs }, by rw [hloop]; simp [bind_ok], hval⟩

private theorem shift_trailing_ones_loop_spec (f s : U64) :
    shift_trailing_ones_loop f s ⦃ r =>
      (r.1.val, r.2.val) = shiftOnesSpec f.val s.val ⦄ := by
  unfold shift_trailing_ones_loop
  apply loop.spec_decr_nat
    (fun (x : U64 × U64) => x.1.val)
    (fun (x : U64 × U64) => shiftOnesSpec x.1.val x.2.val = shiftOnesSpec f.val s.val)
  · rintro ⟨f1, s1⟩ hinv
    simp only at hinv ⊢
    unfold shift_trailing_ones_loop.body
    simp only [lift]
    have hand := u64_and_one_val f1
    have hb : (BIT_MASK_LSB : U64).val = 1 := by unfold BIT_MASK_LSB; scalar_tac
    by_cases hodd : (f1 &&& BIT_MASK_LSB) = BIT_MASK_LSB
    · have hmod : f1.val % 2 = 1 := by rw [← hand, hodd, hb]
      obtain ⟨f2, hf2, hf2v⟩ := u64_shr_one_eq f1
      obtain ⟨s2, hs2, hs2v⟩ := u64_shr_one_eq s1
      simp only [hodd, ↓reduceIte, hf2, bind_ok, hs2, WP.spec_ok]
      refine ⟨?_, by omega⟩
      rw [← hinv, hf2v, hs2v]
      conv_rhs => unfold shiftOnesSpec
      simp [hmod]
    · have hmod : f1.val % 2 ≠ 1 := by
        intro hm
        apply hodd
        apply UScalar.eq_of_val_eq
        rw [hand, hb, hm]
      simp only [bind_ok, hodd, ↓reduceIte, WP.spec_ok]
      rw [← hinv, shiftOnesSpec]
      symm
      exact dite_eq_right_iff.mpr (fun hc => absurd hc hmod)
  · rfl

private theorem shift_trailing_ones_spec (c : IndexCursor) :
    ∃ r : IndexCursor, shift_trailing_ones c = ok r ∧
      (r.fn_idx.val, r.sn_idx.val) = shiftOnesSpec c.fn_idx.val c.sn_idx.val := by
  unfold shift_trailing_ones
  obtain ⟨⟨rf, rs⟩, hloop, hval⟩ := spec_imp_exists (shift_trailing_ones_loop_spec c.fn_idx c.sn_idx)
  exact ⟨{ fn_idx := rf, sn_idx := rs }, by rw [hloop]; simp [bind_ok], hval⟩

/-- Pure mathematical specification of one RFC 6962 inclusion step. -/
def inclusionStepSpec (fn_val sn_val : Nat) (current : mneme_kernel.hashing.Digest)
    (step : InclusionStep) : Option (Nat × Nat × mneme_kernel.hashing.Digest) :=
  if sn_val = 0 then none
  else if fn_val % 2 = 1 ∨ fn_val = sn_val then
    match step.side with
    | SiblingSide.Left =>
      if step.right = current then
        let (f', s') := shiftZerosSpec fn_val sn_val
        some (f' / 2, s' / 2, step.parent)
      else none
    | SiblingSide.Right => none
  else
    match step.side with
    | SiblingSide.Right =>
      if step.left = current then
        some (fn_val / 2, sn_val / 2, step.parent)
      else none
    | SiblingSide.Left => none

/-- Fold `inclusionStepSpec` over a list of inclusion proof steps. -/
def runInclusionSteps (fn_val sn_val : Nat) (current : mneme_kernel.hashing.Digest) :
    List InclusionStep → Option (Nat × Nat × mneme_kernel.hashing.Digest)
  | [] => some (fn_val, sn_val, current)
  | step :: rest =>
    match inclusionStepSpec fn_val sn_val current step with
    | none => none
    | some (f', s', cur') => runInclusionSteps f' s' cur' rest

/-- Exact specification of a valid RFC 6962 inclusion proof. -/
def InclusionProofValid (check : InclusionCheck) (steps : List InclusionStep) : Prop :=
  check.tree_size.val > 0 ∧ check.leaf_index.val < check.tree_size.val ∧
    ∃ f', runInclusionSteps check.leaf_index.val (check.tree_size.val - 1)
      check.leaf_digest steps = some (f', 0, check.expected_root)

private theorem apply_inclusion_step_spec (st : InclusionState) (step : InclusionStep) :
    ∃ r : Option InclusionState, apply_inclusion_step st step = ok r ∧
      (match r, inclusionStepSpec st.cursor.fn_idx.val st.cursor.sn_idx.val st.current step with
       | none, none => True
       | some next, some (f', s', cur') =>
           next.cursor.fn_idx.val = f' ∧ next.cursor.sn_idx.val = s' ∧ next.current = cur'
       | _, _ => False) := by
  unfold apply_inclusion_step inclusionStepSpec
  rw [same_digest_eq, same_digest_eq]
  simp only [bind_ok]
  by_cases hsn : st.cursor.sn_idx = 0#u64
  · have hsn0 : st.cursor.sn_idx.val = 0 := by rw [hsn]; scalar_tac
    exact ⟨none, by simp [hsn], by simp [hsn0]⟩
  · have hsn0 : st.cursor.sn_idx.val ≠ 0 := by
      intro h; apply hsn; apply UScalar.eq_of_val_eq; simpa using h
    simp only [hsn, ↓reduceIte, hsn0, is_left_sibling_step_eq, bind_ok]
    unfold isLeftSiblingSpec
    by_cases hleft : st.cursor.fn_idx.val % 2 = 1 ∨ st.cursor.fn_idx.val = st.cursor.sn_idx.val
    · have hb : ((st.cursor.fn_idx.val % 2 == 1) || (st.cursor.fn_idx == st.cursor.sn_idx)) = true := by
        rcases hleft with hmod | heq
        · simp [hmod]
        · have hce : st.cursor.fn_idx = st.cursor.sn_idx := UScalar.eq_of_val_eq heq
          simp [hce]
      simp only [hb, ↓reduceIte, hleft]
      cases hside : step.side with
      | Left =>
        by_cases hreq : step.right = st.current
        · obtain ⟨sh, hsh, hshv⟩ := shift_trailing_zeros_spec st.cursor
          obtain ⟨i, hi, hiv⟩ := u64_shr_one_eq sh.fn_idx
          obtain ⟨i1, hi1, hi1v⟩ := u64_shr_one_eq sh.sn_idx
          refine ⟨some { cursor := { fn_idx := i, sn_idx := i1 }, current := step.parent }, ?_, ?_⟩
          · simp [hreq, hsh, hi, hi1]
          · simp only [hreq, ↓reduceIte, ← hshv]
            exact ⟨hiv, hi1v, trivial⟩
        · exact ⟨none, by simp [hreq], by simp [hreq]⟩
      | Right =>
        exact ⟨none, by simp, by simp⟩
    · have hleft' : st.cursor.fn_idx.val % 2 ≠ 1 ∧ st.cursor.fn_idx.val ≠ st.cursor.sn_idx.val := by
        constructor <;> intro h <;> exact hleft (by tauto)
      have hne : st.cursor.fn_idx ≠ st.cursor.sn_idx := fun h => hleft'.2 (by rw [h])
      have hb : ((st.cursor.fn_idx.val % 2 == 1) || (st.cursor.fn_idx == st.cursor.sn_idx)) = false := by
        simp [hleft'.1, hne]
      simp only [hb, ↓reduceIte, hleft]
      cases hside : step.side with
      | Right =>
        by_cases hleq : step.left = st.current
        · obtain ⟨i, hi, hiv⟩ := u64_shr_one_eq st.cursor.fn_idx
          obtain ⟨i1, hi1, hi1v⟩ := u64_shr_one_eq st.cursor.sn_idx
          refine ⟨some { cursor := { fn_idx := i, sn_idx := i1 }, current := step.parent }, ?_, ?_⟩
          · simp [hleq, hi, hi1]
          · simp only [hleq, ↓reduceIte]
            exact ⟨hiv, hi1v, trivial⟩
        · exact ⟨none, by simp [hleq], by simp [hleq]⟩
      | Left =>
        exact ⟨none, by simp, by simp⟩

private theorem index_inc_step (s : Slice InclusionStep) (i : Usize) (h : i.val < s.val.length) :
    Slice.index_usize s i = ok (s.val[i.val]'h) := by
  obtain ⟨x, hx, hv⟩ := spec_imp_exists (Slice.index_usize_spec s i h)
  rw [hx, hv]

private theorem verify_inclusion_proof_loop_spec (steps : Slice InclusionStep)
    (init : InclusionState) (valid : Bool) (idx : Usize) (hidx : idx.val ≤ steps.val.length) :
    verify_inclusion_proof_loop steps init valid idx ⦃ res =>
      (match res.2, (if valid then runInclusionSteps init.cursor.fn_idx.val init.cursor.sn_idx.val
          init.current (steps.val.drop idx.val) else none) with
       | true, some (f', s', cur') =>
           res.1.cursor.fn_idx.val = f' ∧ res.1.cursor.sn_idx.val = s' ∧ res.1.current = cur'
       | false, none => True
       | _, _ => False) ⦄ := by
  unfold verify_inclusion_proof_loop
  apply loop.spec_decr_nat
    (fun (x : InclusionState × Bool × Usize) => steps.val.length - x.2.2.val)
    (fun (x : InclusionState × Bool × Usize) =>
      x.2.2.val ≤ steps.val.length ∧
      (if x.2.1 then runInclusionSteps x.1.cursor.fn_idx.val x.1.cursor.sn_idx.val x.1.current
          (steps.val.drop x.2.2.val) else none) =
      (if valid then runInclusionSteps init.cursor.fn_idx.val init.cursor.sn_idx.val init.current
          (steps.val.drop idx.val) else none))
  · rintro ⟨st, v, i⟩ ⟨hi, hinv⟩
    simp only at hi hinv ⊢
    unfold verify_inclusion_proof_loop.body
    by_cases hlt : i < Slice.len steps
    · have hlt' : i.val < steps.val.length := by scalar_tac
      have himax : i.val < Usize.max := by scalar_tac
      cases v with
      | true =>
        have hdrop : steps.val.drop i.val = (steps.val[i.val]'hlt') :: steps.val.drop (i.val + 1) :=
          List.drop_eq_getElem_cons hlt'
        obtain ⟨res, hres, hspec⟩ := apply_inclusion_step_spec st (steps.val[i.val]'hlt')
        have hsat := usize_saturating_add_one_val i himax
        cases res with
        | none =>
          simp only [hlt, ↓reduceIte, index_inc_step steps i hlt', bind_ok, hres, lift]
          simp [WP.spec_ok, hsat]
          refine ⟨by omega, ?_, by omega⟩
          intro hv
          simp only [hv, ↓reduceIte] at hinv
          rw [← hinv, hdrop]
          cases hstep : inclusionStepSpec st.cursor.fn_idx.val st.cursor.sn_idx.val st.current
              (steps.val[i.val]'hlt') with
          | none => simp [runInclusionSteps, hstep]
          | some _ => simp [hstep] at hspec
        | some next =>
          simp only [hlt, ↓reduceIte, index_inc_step steps i hlt', bind_ok, hres, lift]
          simp [WP.spec_ok, hsat]
          refine ⟨by omega, ?_, by omega⟩
          rw [← hinv, hdrop]
          cases hstep : inclusionStepSpec st.cursor.fn_idx.val st.cursor.sn_idx.val st.current
              (steps.val[i.val]'hlt') with
          | none => simp [hstep] at hspec
          | some p =>
            rcases p with ⟨f', s', cur'⟩
            simp only [hstep] at hspec
            rcases hspec with ⟨hf', hs', hcur'⟩
            simp [runInclusionSteps, hstep, hf', hs', hcur']
      | false =>
        simp only [hlt, ↓reduceIte, Bool.false_eq_true, WP.spec_ok]
        simp only [Bool.false_eq_true, ↓reduceIte] at hinv
        rw [← hinv]
        trivial
    · have heq : i.val = steps.val.length := by scalar_tac
      simp only [hlt, ↓reduceIte, WP.spec_ok]
      rw [← hinv, heq, List.drop_length]
      cases v with
      | true =>
        simp only [↓reduceIte, runInclusionSteps]
        exact ⟨trivial, trivial, trivial⟩
      | false =>
        simp
  · exact ⟨hidx, rfl⟩

/-- `verify_inclusion_proof` always terminates and returns `true` iff `InclusionProofValid` holds. -/
theorem verify_inclusion_proof_total_and_spec (check : InclusionCheck)
    (steps : Slice InclusionStep) :
    ∃ r : Bool, verify_inclusion_proof check steps = ok r ∧
      (r = true ↔ InclusionProofValid check steps.val) := by
  unfold verify_inclusion_proof InclusionProofValid
  by_cases hzero : check.tree_size = 0#u64
  · have hz : check.tree_size.val = 0 := by rw [hzero]; scalar_tac
    exact ⟨false, by simp [hzero], by simp [hz]⟩
  · have hpos : check.tree_size.val > 0 := by
      by_contra h
      apply hzero
      apply UScalar.eq_of_val_eq
      have : check.tree_size.val = 0 := by omega
      simpa using this
    by_cases hoob : check.leaf_index ≥ check.tree_size
    · have hge : check.leaf_index.val ≥ check.tree_size.val := by scalar_tac
      refine ⟨false, by simp [hzero, hoob], ?_⟩
      constructor
      · intro h; cases h
      · rintro ⟨_, hlt, _⟩; omega
    · have hlt : check.leaf_index.val < check.tree_size.val := by scalar_tac
      have hsub := u64_saturating_sub_one_val check.tree_size
      let init : InclusionState := {
        cursor := {
          fn_idx := check.leaf_index,
          sn_idx := core.num.U64.saturating_sub check.tree_size 1#u64
        },
        current := check.leaf_digest
      }
      obtain ⟨⟨st, valid⟩, hloop, hspec⟩ :=
        spec_imp_exists (verify_inclusion_proof_loop_spec steps init true 0#usize (by scalar_tac))
      simp only [hzero, ↓reduceIte, hoob, lift, bind_ok]
      rw [hloop]
      simp only [bind_ok, same_digest_eq]
      simp only [↓reduceIte, show (0#usize).val = 0 by scalar_tac, List.drop_zero,
        init, hsub] at hspec
      cases valid with
      | false =>
        refine ⟨false, by simp, ?_⟩
        cases hrun : runInclusionSteps check.leaf_index.val (check.tree_size.val - 1)
            check.leaf_digest steps.val with
        | none => simp
        | some _ => simp [hrun] at hspec
      | true =>
        cases hrun : runInclusionSteps check.leaf_index.val (check.tree_size.val - 1)
            check.leaf_digest steps.val with
        | none => simp [hrun] at hspec
        | some p =>
          rcases p with ⟨f', s', cur'⟩
          simp only [hrun] at hspec
          rcases hspec with ⟨hf', hs', hcur'⟩
          by_cases hsn0 : st.cursor.sn_idx = 0#u64
          · have hs0 : s' = 0 := by rw [← hs', hsn0]; scalar_tac
            refine ⟨decide (st.current = check.expected_root), by simp [hsn0], ?_⟩
            rw [hcur', hs0]
            simp [hpos, hlt]
          · have hsne : s' ≠ 0 := by
              intro h; apply hsn0; apply UScalar.eq_of_val_eq
              rw [hs', h]; scalar_tac
            exact ⟨false, by simp [hsn0], by simp [hsne]⟩

/-- Out-of-bounds leaf indices or empty trees are always rejected by `verify_inclusion_proof`. -/
theorem verify_inclusion_proof_rejects_out_of_bounds (check : InclusionCheck)
    (steps : Slice InclusionStep)
    (h : check.tree_size = 0#u64 ∨ check.leaf_index ≥ check.tree_size) :
    verify_inclusion_proof check steps = ok false := by
  unfold verify_inclusion_proof
  rcases h with hz | hge
  · simp [hz]
  · by_cases hz : check.tree_size = 0#u64
    · simp [hz]
    · simp [hz, hge]

/-- On a 1-leaf tree with an empty step list, inclusion holds iff leaf equals root. -/
theorem verify_inclusion_proof_singleton_iff (check : InclusionCheck)
    (steps : Slice InclusionStep)
    (hsize : check.tree_size = 1#u64) (hidx : check.leaf_index = 0#u64)
    (hempty : steps.val = []) :
    ∃ r : Bool, verify_inclusion_proof check steps = ok r ∧
      (r = true ↔ check.leaf_digest = check.expected_root) := by
  obtain ⟨r, hr, hiff⟩ := verify_inclusion_proof_total_and_spec check steps
  refine ⟨r, hr, ?_⟩
  rw [hiff]
  unfold InclusionProofValid
  have hs1 : check.tree_size.val = 1 := by rw [hsize]; scalar_tac
  have hi0 : check.leaf_index.val = 0 := by rw [hidx]; scalar_tac
  simp [hs1, hi0, hempty, runInclusionSteps]

/-- Pure mathematical specification of one RFC 6962 consistency step. -/
def consistencyStepSpec (fn_val sn_val : Nat)
    (old_acc new_acc : mneme_kernel.hashing.Digest) (step : ConsistencyStep) :
    Option (Nat × Nat × mneme_kernel.hashing.Digest × mneme_kernel.hashing.Digest) :=
  if sn_val = 0 then none
  else if fn_val % 2 = 1 ∨ fn_val = sn_val then
    match step.side with
    | SiblingSide.Left =>
      if step.old_right = old_acc ∧ step.new_child = new_acc then
        let (f', s') := shiftZerosSpec fn_val sn_val
        some (f' / 2, s' / 2, step.old_parent, step.new_parent)
      else none
    | SiblingSide.Right => none
  else
    match step.side with
    | SiblingSide.Right =>
      if step.new_child = new_acc then
        some (fn_val / 2, sn_val / 2, old_acc, step.new_parent)
      else none
    | SiblingSide.Left => none

/-- Fold `consistencyStepSpec` over a list of consistency proof steps. -/
def runConsistencySteps (fn_val sn_val : Nat)
    (old_acc new_acc : mneme_kernel.hashing.Digest) :
    List ConsistencyStep →
    Option (Nat × Nat × mneme_kernel.hashing.Digest × mneme_kernel.hashing.Digest)
  | [] => some (fn_val, sn_val, old_acc, new_acc)
  | step :: rest =>
    match consistencyStepSpec fn_val sn_val old_acc new_acc step with
    | none => none
    | some (f', s', o', n') => runConsistencySteps f' s' o' n' rest

/-- Exact specification of a valid RFC 6962 append-only consistency proof. -/
def ConsistencyProofValid (check : ConsistencyCheck) (steps : List ConsistencyStep) : Prop :=
  check.old_size.val > 0 ∧ check.old_size.val ≤ check.new_size.val ∧
    if check.old_size.val = check.new_size.val then
      steps = [] ∧ check.old_root = check.new_root
    else
      let (f0, s0) := shiftOnesSpec (check.old_size.val - 1) (check.new_size.val - 1)
      (f0 ≠ 0 ∨ check.initial_digest = check.old_root) ∧
      ∃ f', runConsistencySteps f0 s0 check.initial_digest check.initial_digest steps =
        some (f', 0, check.old_root, check.new_root)

private theorem apply_consistency_step_spec (st : ConsistencyState) (step : ConsistencyStep) :
    ∃ r : Option ConsistencyState, apply_consistency_step st step = ok r ∧
      (match r, consistencyStepSpec st.cursor.fn_idx.val st.cursor.sn_idx.val
          st.old_acc st.new_acc step with
       | none, none => True
       | some next, some (f', s', o', n') =>
           next.cursor.fn_idx.val = f' ∧ next.cursor.sn_idx.val = s' ∧
           next.old_acc = o' ∧ next.new_acc = n'
       | _, _ => False) := by
  unfold apply_consistency_step consistencyStepSpec
  rw [same_digest_eq, same_digest_eq]
  simp only [bind_ok]
  by_cases hsn : st.cursor.sn_idx = 0#u64
  · have hsn0 : st.cursor.sn_idx.val = 0 := by rw [hsn]; scalar_tac
    exact ⟨none, by simp [hsn], by simp [hsn0]⟩
  · have hsn0 : st.cursor.sn_idx.val ≠ 0 := by
      intro h; apply hsn; apply UScalar.eq_of_val_eq; simpa using h
    simp only [hsn, ↓reduceIte, hsn0, is_left_sibling_step_eq, bind_ok]
    unfold isLeftSiblingSpec
    by_cases hleft : st.cursor.fn_idx.val % 2 = 1 ∨ st.cursor.fn_idx.val = st.cursor.sn_idx.val
    · have hb : ((st.cursor.fn_idx.val % 2 == 1) || (st.cursor.fn_idx == st.cursor.sn_idx)) = true := by
        rcases hleft with hmod | heq
        · simp [hmod]
        · have hce : st.cursor.fn_idx = st.cursor.sn_idx := UScalar.eq_of_val_eq heq
          simp [hce]
      simp only [hb, ↓reduceIte, hleft]
      cases hside : step.side with
      | Left =>
        by_cases ho : step.old_right = st.old_acc
        · by_cases hn : step.new_child = st.new_acc
          · obtain ⟨sh, hsh, hshv⟩ := shift_trailing_zeros_spec st.cursor
            obtain ⟨i, hi, hiv⟩ := u64_shr_one_eq sh.fn_idx
            obtain ⟨i1, hi1, hi1v⟩ := u64_shr_one_eq sh.sn_idx
            let nextSt : ConsistencyState := {
              cursor := { fn_idx := i, sn_idx := i1 },
              old_acc := step.old_parent,
              new_acc := step.new_parent
            }
            refine ⟨some nextSt, ?_, ?_⟩
            · simp [nextSt, ho, hn, hsh, hi, hi1]
            · simp only [nextSt, ho, hn, and_self, ↓reduceIte, ← hshv]
              exact ⟨hiv, hi1v, trivial⟩
          · exact ⟨none, by simp [ho, hn], by simp [ho, hn]⟩
        · exact ⟨none, by simp [ho], by simp [ho]⟩
      | Right =>
        exact ⟨none, by simp, by simp⟩
    · have hleft' : st.cursor.fn_idx.val % 2 ≠ 1 ∧ st.cursor.fn_idx.val ≠ st.cursor.sn_idx.val := by
        constructor <;> intro h <;> exact hleft (by tauto)
      have hne : st.cursor.fn_idx ≠ st.cursor.sn_idx := fun h => hleft'.2 (by rw [h])
      have hb : ((st.cursor.fn_idx.val % 2 == 1) || (st.cursor.fn_idx == st.cursor.sn_idx)) = false := by
        simp [hleft'.1, hne]
      simp only [hb, ↓reduceIte, hleft]
      cases hside : step.side with
      | Right =>
        by_cases hn : step.new_child = st.new_acc
        · obtain ⟨i, hi, hiv⟩ := u64_shr_one_eq st.cursor.fn_idx
          obtain ⟨i1, hi1, hi1v⟩ := u64_shr_one_eq st.cursor.sn_idx
          let nextSt : ConsistencyState := {
            cursor := { fn_idx := i, sn_idx := i1 },
            old_acc := st.old_acc,
            new_acc := step.new_parent
          }
          refine ⟨some nextSt, ?_, ?_⟩
          · simp [nextSt, hn, hi, hi1]
          · simp only [nextSt, hn, ↓reduceIte]
            exact ⟨hiv, hi1v, trivial, trivial⟩
        · exact ⟨none, by simp [hn], by simp [hn]⟩
      | Left =>
        exact ⟨none, by simp, by simp⟩

private theorem index_cons_step (s : Slice ConsistencyStep) (i : Usize) (h : i.val < s.val.length) :
    Slice.index_usize s i = ok (s.val[i.val]'h) := by
  obtain ⟨x, hx, hv⟩ := spec_imp_exists (Slice.index_usize_spec s i h)
  rw [hx, hv]

private theorem verify_consistency_proof_loop_spec (steps : Slice ConsistencyStep)
    (init : ConsistencyState) (valid : Bool) (idx : Usize) (hidx : idx.val ≤ steps.val.length) :
    verify_consistency_proof_loop steps init valid idx ⦃ res =>
      (match res.2, (if valid then runConsistencySteps init.cursor.fn_idx.val init.cursor.sn_idx.val
          init.old_acc init.new_acc (steps.val.drop idx.val) else none) with
       | true, some (f', s', o', n') =>
           res.1.cursor.fn_idx.val = f' ∧ res.1.cursor.sn_idx.val = s' ∧
           res.1.old_acc = o' ∧ res.1.new_acc = n'
       | false, none => True
       | _, _ => False) ⦄ := by
  unfold verify_consistency_proof_loop
  apply loop.spec_decr_nat
    (fun (x : ConsistencyState × Bool × Usize) => steps.val.length - x.2.2.val)
    (fun (x : ConsistencyState × Bool × Usize) =>
      x.2.2.val ≤ steps.val.length ∧
      (if x.2.1 then runConsistencySteps x.1.cursor.fn_idx.val x.1.cursor.sn_idx.val
          x.1.old_acc x.1.new_acc (steps.val.drop x.2.2.val) else none) =
      (if valid then runConsistencySteps init.cursor.fn_idx.val init.cursor.sn_idx.val
          init.old_acc init.new_acc (steps.val.drop idx.val) else none))
  · rintro ⟨st, v, i⟩ ⟨hi, hinv⟩
    simp only at hi hinv ⊢
    unfold verify_consistency_proof_loop.body
    by_cases hlt : i < Slice.len steps
    · have hlt' : i.val < steps.val.length := by scalar_tac
      have himax : i.val < Usize.max := by scalar_tac
      cases v with
      | true =>
        have hdrop : steps.val.drop i.val = (steps.val[i.val]'hlt') :: steps.val.drop (i.val + 1) :=
          List.drop_eq_getElem_cons hlt'
        obtain ⟨res, hres, hspec⟩ := apply_consistency_step_spec st (steps.val[i.val]'hlt')
        have hsat := usize_saturating_add_one_val i himax
        cases res with
        | none =>
          simp only [hlt, ↓reduceIte, index_cons_step steps i hlt', bind_ok, hres, lift]
          simp [WP.spec_ok, hsat]
          refine ⟨by omega, ?_, by omega⟩
          intro hv
          simp only [hv, ↓reduceIte] at hinv
          rw [← hinv, hdrop]
          cases hstep : consistencyStepSpec st.cursor.fn_idx.val st.cursor.sn_idx.val
              st.old_acc st.new_acc (steps.val[i.val]'hlt') with
          | none => simp [runConsistencySteps, hstep]
          | some _ => simp [hstep] at hspec
        | some next =>
          simp only [hlt, ↓reduceIte, index_cons_step steps i hlt', bind_ok, hres, lift]
          simp [WP.spec_ok, hsat]
          refine ⟨by omega, ?_, by omega⟩
          rw [← hinv, hdrop]
          cases hstep : consistencyStepSpec st.cursor.fn_idx.val st.cursor.sn_idx.val
              st.old_acc st.new_acc (steps.val[i.val]'hlt') with
          | none => simp [hstep] at hspec
          | some p =>
            rcases p with ⟨f', s', o', n'⟩
            simp only [hstep] at hspec
            rcases hspec with ⟨hf', hs', ho', hn'⟩
            simp [runConsistencySteps, hstep, hf', hs', ho', hn']
      | false =>
        simp only [hlt, ↓reduceIte, Bool.false_eq_true, WP.spec_ok]
        simp only [Bool.false_eq_true, ↓reduceIte] at hinv
        rw [← hinv]
        trivial
    · have heq : i.val = steps.val.length := by scalar_tac
      simp only [hlt, ↓reduceIte, WP.spec_ok]
      rw [← hinv, heq, List.drop_length]
      cases v with
      | true =>
        simp only [↓reduceIte, runConsistencySteps]
        exact ⟨trivial, trivial, trivial, trivial⟩
      | false =>
        simp
  · exact ⟨hidx, rfl⟩

/-- `verify_consistency_proof` always terminates and returns `true` iff `ConsistencyProofValid`. -/
theorem verify_consistency_proof_total_and_spec (check : ConsistencyCheck)
    (steps : Slice ConsistencyStep) :
    ∃ r : Bool, verify_consistency_proof check steps = ok r ∧
      (r = true ↔ ConsistencyProofValid check steps.val) := by
  unfold verify_consistency_proof ConsistencyProofValid
  rw [same_digest_eq, same_digest_eq]
  simp only [bind_ok]
  by_cases hzero : check.old_size = 0#u64
  · have hz : check.old_size.val = 0 := by rw [hzero]; scalar_tac
    exact ⟨false, by simp [hzero], by simp [hz]⟩
  · have hpos : check.old_size.val > 0 := by
      by_contra h
      apply hzero
      apply UScalar.eq_of_val_eq
      have : check.old_size.val = 0 := by omega
      simpa using this
    by_cases hgt : check.old_size > check.new_size
    · have hgtv : check.old_size.val > check.new_size.val := by scalar_tac
      refine ⟨false, by simp [hzero, hgt], ?_⟩
      constructor
      · intro h; cases h
      · rintro ⟨_, hle, _⟩; omega
    · have hle : check.old_size.val ≤ check.new_size.val := by scalar_tac
      by_cases heq : check.old_size = check.new_size
      · have hnew_pos : check.new_size.val > 0 := by rw [← heq]; exact hpos
        have hnew_nz : check.new_size ≠ 0#u64 := by rw [← heq]; exact hzero
        obtain ⟨b, hb, hbiff⟩ := spec_imp_exists (core.slice.Slice.is_empty_spec steps)
        have hbe : b = true ↔ steps.val = [] := by
          rw [hbiff]
          constructor
          · intro hlen; exact List.eq_nil_of_length_eq_zero hlen
          · intro hnil; simp [hnil]
        simp only [heq, hnew_nz, ↓reduceIte, lt_self_iff_false, hb, bind_ok]
        cases b with
        | true =>
          have hnil : steps.val = [] := hbe.mp rfl
          refine ⟨decide (check.old_root = check.new_root), by simp, ?_⟩
          simp [hnew_pos, hnil]
        | false =>
          have hne : steps.val ≠ [] := fun h => by have := hbe.mpr h; contradiction
          exact ⟨false, by simp, by simp [hne]⟩
      · have hnev : check.old_size.val ≠ check.new_size.val := fun h => heq (UScalar.eq_of_val_eq h)
        have hsub1 := u64_saturating_sub_one_val check.old_size
        have hsub2 := u64_saturating_sub_one_val check.new_size
        let c0 : IndexCursor := {
          fn_idx := core.num.U64.saturating_sub check.old_size 1#u64,
          sn_idx := core.num.U64.saturating_sub check.new_size 1#u64
        }
        obtain ⟨initial, hinit, hinitv⟩ := shift_trailing_ones_spec c0
        have hinitv' : (initial.fn_idx.val, initial.sn_idx.val) =
            shiftOnesSpec (check.old_size.val - 1) (check.new_size.val - 1) := by
          simpa [c0, hsub1, hsub2] using hinitv
        let initValid : Bool := if initial.fn_idx != 0#u64 then true
          else decide (check.initial_digest = check.old_root)
        let initState : ConsistencyState := {
          cursor := initial,
          old_acc := check.initial_digest,
          new_acc := check.initial_digest
        }
        obtain ⟨⟨st, valid1⟩, hloop, hspec⟩ :=
          spec_imp_exists (verify_consistency_proof_loop_spec steps initState initValid 0#usize (by scalar_tac))
        simp only [hzero, ↓reduceIte, hgt, heq, lift, bind_ok]
        rw [hinit]
        simp only [bind_ok]
        have hif_eq : (if initial.fn_idx != 0#u64 then ok true
            else ok (decide (check.initial_digest = check.old_root))) = ok initValid := by
          dsimp [initValid]; split_ifs <;> rfl
        rw [hif_eq]
        simp only [bind_ok]
        rw [hloop]
        simp only [bind_ok, same_digest_eq]
        have hpow2 : initValid = true ↔ (initial.fn_idx.val ≠ 0 ∨ check.initial_digest = check.old_root) := by
          dsimp [initValid]
          by_cases hnz : initial.fn_idx != 0#u64
          · have hfnz : initial.fn_idx.val ≠ 0 := by
              simp only [bne_iff_ne, ne_eq] at hnz
              intro h; apply hnz; apply UScalar.eq_of_val_eq; simpa using h
            simp [hnz, hfnz]
          · have hf0 : initial.fn_idx.val = 0 := by
              simp only [bne_iff_ne, ne_eq, Decidable.not_not] at hnz
              rw [hnz]; scalar_tac
            simp [hnz, hf0]
        simp only [show (0#usize).val = 0 by scalar_tac, List.drop_zero, initState] at hspec
        cases valid1 with
        | false =>
          refine ⟨false, by simp, ?_⟩
          simp only [hpos, hle, hnev, ↓reduceIte, ← hinitv', true_and, Bool.false_eq_true, false_iff]
          rintro ⟨hp2, f', hrun⟩
          have hiv : initValid = true := hpow2.mpr hp2
          simp [hiv, hrun] at hspec
        | true =>
          have hiv : initValid = true := by
            by_contra hnv
            have hnf : initValid = false := by cases initValid <;> simp_all
            simp [hnf] at hspec
          have hp2 : initial.fn_idx.val ≠ 0 ∨ check.initial_digest = check.old_root := hpow2.mp hiv
          simp only [hiv, ↓reduceIte] at hspec
          cases hrun : runConsistencySteps initial.fn_idx.val initial.sn_idx.val
              check.initial_digest check.initial_digest steps.val with
          | none => simp [hrun] at hspec
          | some p =>
            rcases p with ⟨f', s', o', n'⟩
            simp only [hrun] at hspec
            rcases hspec with ⟨hf', hs', ho', hn'⟩
            by_cases hsn0 : st.cursor.sn_idx = 0#u64
            · have hs0 : s' = 0 := by rw [← hs', hsn0]; scalar_tac
              by_cases ho : st.old_acc = check.old_root
              · refine ⟨decide (st.new_acc = check.new_root), by simp [hsn0, ho], ?_⟩
                simp only [hpos, hle, hnev, ↓reduceIte, ← hinitv', hp2, true_and, hrun, hs0,
                  Option.some.injEq, Prod.mk.injEq, exists_eq_left']
                rw [ho', hn'] at *
                simp [ho]
              · refine ⟨false, by simp [hsn0, ho], ?_⟩
                simp only [hpos, hle, hnev, ↓reduceIte, ← hinitv', hp2, true_and, hrun, hs0,
                  Option.some.injEq, Prod.mk.injEq, exists_eq_left', Bool.false_eq_true, false_iff]
                rw [ho'] at ho
                rintro ⟨h_old, _⟩
                exact ho h_old
            · have hsne : s' ≠ 0 := by
                intro h; apply hsn0; apply UScalar.eq_of_val_eq
                rw [hs', h]; scalar_tac
              refine ⟨false, by simp [hsn0], ?_⟩
              simp only [hpos, hle, hnev, ↓reduceIte, ← hinitv', hp2, true_and, hrun,
                Option.some.injEq, Prod.mk.injEq, exists_eq_left', Bool.false_eq_true, false_iff]
              rintro ⟨h_s0, _, _⟩
              exact hsne h_s0

/-- Invalid tree sizes (`old_size = 0` or `old_size > new_size`) are always rejected. -/
theorem verify_consistency_proof_rejects_invalid_sizes (check : ConsistencyCheck)
    (steps : Slice ConsistencyStep)
    (h : check.old_size = 0#u64 ∨ check.old_size > check.new_size) :
    verify_consistency_proof check steps = ok false := by
  unfold verify_consistency_proof
  rw [same_digest_eq, same_digest_eq]
  simp only [bind_ok]
  rcases h with hz | hgt
  · simp [hz]
  · by_cases hz : check.old_size = 0#u64
    · simp [hz]
    · simp [hz, hgt]

/-- Reflexive consistency (`old_size = new_size > 0`) holds iff steps are empty and roots match. -/
theorem verify_consistency_proof_reflexive_iff (check : ConsistencyCheck)
    (steps : Slice ConsistencyStep)
    (hpos : check.old_size ≠ 0#u64) (heq : check.old_size = check.new_size) :
    ∃ r : Bool, verify_consistency_proof check steps = ok r ∧
      (r = true ↔ steps.val = [] ∧ check.old_root = check.new_root) := by
  obtain ⟨r, hr, hiff⟩ := verify_consistency_proof_total_and_spec check steps
  refine ⟨r, hr, ?_⟩
  rw [hiff]
  unfold ConsistencyProofValid
  have hposv : check.old_size.val > 0 := by
    by_contra h
    apply hpos
    apply UScalar.eq_of_val_eq
    have : check.old_size.val = 0 := by omega
    simpa using this
  have hnew_pos : check.new_size.val > 0 := by rw [← heq]; exact hposv
  simp [heq, hnew_pos]

/-- `equivocation_detected` always terminates and characterizes split-view / rewrite detection. -/
theorem equivocation_detected_iff (facts : EquivocationFacts) :
    ∃ r : Bool, equivocation_detected facts = ok r ∧
      (r = true ↔
        facts.is_both_signed_same_origin = true ∧
        facts.first_size ≠ 0#u64 ∧
        facts.second_size ≠ 0#u64 ∧
        ((facts.first_size = facts.second_size ∧ facts.first_root ≠ facts.second_root) ∨
         (facts.first_size ≠ facts.second_size ∧
           facts.consistency = ConsistencyVerdict.Inconsistent))) := by
  unfold equivocation_detected
  rw [same_digest_eq]
  simp only [bind_ok]
  cases hs : facts.is_both_signed_same_origin with
  | false => exact ⟨false, by simp, by simp⟩
  | true =>
    by_cases h1 : facts.first_size = 0#u64
    · exact ⟨false, by simp [h1], by simp [h1]⟩
    · by_cases h2 : facts.second_size = 0#u64
      · exact ⟨false, by simp [h1, h2], by simp [h1, h2]⟩
      · by_cases heq : facts.first_size = facts.second_size
        · exact ⟨!decide (facts.first_root = facts.second_root),
            by simp [h2, heq], by simp [h2, heq]⟩
        · cases hc : facts.consistency with
          | Consistent => exact ⟨false, by simp [h1, h2, heq], by simp [h1, h2, heq]⟩
          | Inconsistent => exact ⟨true, by simp [h1, h2, heq], by simp [h1, h2, heq]⟩

end mneme_kernel.history_tree
