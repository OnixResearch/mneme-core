import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# ASPIC+ Structured Argumentation & Dung Grounded Labelling

Theorems about the Aeneas translation of `crates/mneme-kernel/src/argumentation.rs`:
- **Authority preferences** (`authority_rank`, `preference_defeats`):
  strict order `Proposed (0) < Accepted (1) < ConflictResolution (2)`; ties yield
  symmetric defeat (`Undec`), higher authority defeats lower asymmetrically.
- **Alternative-argument join** (`best_label`):
  commutative, associative, idempotent join (`In > Undec > Out`) with `Out`
  identity and `In` absorber.
- **Dung characteristic operator** (`next_label`, `is_fixpoint`,
  `is_conflict_free`, `is_admissible`):
  - Totality and exact logical specification of `next_label`, `is_fixpoint`,
    `is_conflict_free`, and `is_admissible`.
  - Monotonicity in the information order (`Undec ≤ In`, `Undec ≤ Out`).
  - Permutation invariance under reordering `defeats`.
  - Every fixpoint of `next_label` is conflict-free and admissible.
  - **Termination in `≤ |Ar|` rounds**: iterating `next_label` from all-`Undec`
    reaches a fixpoint in at most `n` rounds.
  - **Uniqueness**: the grounded labelling is the unique least fixpoint of
    `next_label` (conflict-free, admissible, and permutation-invariant).
-/

namespace mneme_kernel.argumentation

/-! ## Private Helpers -/

private theorem ok_of_spec {α : Type} {m : Result α} {P : α → Prop} (h : m ⦃ P ⦄) :
    ∃ v, m = ok v ∧ P v := by
  cases m with
  | ret v => exact ⟨v, rfl, by simpa using h⟩
  | vis e k => simp at h
  | div => simp at h

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

/-- Information order on Dung labels: `Undec ≤ In`, `Undec ≤ Out`, and reflexive. -/
private def infoLe (a b : Label) : Prop :=
  a = Label.Undec ∨ a = b

private theorem infoLe_refl (a : Label) : infoLe a a := Or.inr rfl

private theorem infoLe_undec (b : Label) : infoLe Label.Undec b := Or.inl rfl

private theorem infoLe_trans {a b c : Label} (hab : infoLe a b) (hbc : infoLe b c) :
    infoLe a c := by
  rcases hab with rfl | rfl
  · exact Or.inl rfl
  · exact hbc

private theorem infoLe_antisymm {a b : Label} (hab : infoLe a b) (hba : infoLe b a) :
    a = b := by
  rcases hab with rfl | rfl
  · rcases hba with h | h <;> exact h.symm
  · rfl

/-- Pointwise information order on two label lists of equal length. -/
private def infoLeList (xs ys : List Label) : Prop :=
  xs.length = ys.length ∧ ∀ i, i < xs.length →
    ∀ a b, xs[i]? = some a → ys[i]? = some b → infoLe a b

private theorem infoLeList_refl (xs : List Label) : infoLeList xs xs := by
  refine ⟨rfl, fun i _ a b ha hb => ?_⟩
  rw [ha, Option.some.injEq] at hb
  exact Or.inr hb

private theorem infoLeList_trans {xs ys zs : List Label}
    (hxy : infoLeList xs ys) (hyz : infoLeList ys zs) : infoLeList xs zs := by
  refine ⟨hxy.1.trans hyz.1, fun i hi a c ha hc => ?_⟩
  have hiy : i < ys.length := hxy.1 ▸ hi
  obtain ⟨b, hb⟩ : ∃ b, ys[i]? = some b := ⟨ys[i], List.getElem?_eq_getElem hiy⟩
  exact infoLe_trans (hxy.2 i hi a b ha hb) (hyz.2 i hiy b c hb hc)

private theorem infoLeList_antisymm {xs ys : List Label}
    (hxy : infoLeList xs ys) (hyx : infoLeList ys xs) : xs = ys := by
  apply List.ext_getElem hxy.1
  intro i h1 h2
  have ha : xs[i]? = some xs[i] := List.getElem?_eq_getElem h1
  have hb : ys[i]? = some ys[i] := List.getElem?_eq_getElem h2
  exact infoLe_antisymm (hxy.2 i h1 _ _ ha hb) (hyx.2 i h2 _ _ hb ha)

private theorem label_ne_eq (a b : Label) :
    (a = b →
      core.cmp.PartialEq.ne.trait_default Label.Insts.CoreCmpPartialEqLabel a b = ok false) ∧
    (a ≠ b →
      core.cmp.PartialEq.ne.trait_default Label.Insts.CoreCmpPartialEqLabel a b = ok true) := by
  cases a <;> cases b <;>
    simp [core.cmp.PartialEq.ne.trait_default, core.cmp.PartialEq.ne.default,
      Label.Insts.CoreCmpPartialEqLabel.eq, Label.read_discriminant]

/-! ## `authority_rank` & `preference_defeats` -/

/-- `authority_rank` never fails or diverges. -/
theorem authority_rank_total (authority : Authority) :
    ∃ r, authority_rank authority = ok r := by
  cases authority <;>
    simp [authority_rank, RANK_PROPOSED, RANK_ACCEPTED, RANK_CONFLICT_RESOLUTION]

/-- `authority_rank` assigns `Proposed (0) < Accepted (1) < ConflictResolution (2)`. -/
theorem authority_rank_order :
    authority_rank Authority.Proposed = ok 0#u8 ∧
      authority_rank Authority.Accepted = ok 1#u8 ∧
      authority_rank Authority.ConflictResolution = ok 2#u8 := by
  simp [authority_rank, RANK_PROPOSED, RANK_ACCEPTED, RANK_CONFLICT_RESOLUTION]

/-- `preference_defeats` never fails or diverges. -/
theorem preference_defeats_total (attacker target : Authority) :
    ∃ b, preference_defeats attacker target = ok b := by
  cases attacker <;> cases target <;>
    simp [preference_defeats, authority_rank, RANK_PROPOSED, RANK_ACCEPTED,
      RANK_CONFLICT_RESOLUTION]

/-- Equal authority yields symmetric defeat (ties become `Undec`, never auto-promoting). -/
theorem preference_defeats_reflexive (a : Authority) :
    preference_defeats a a = ok true := by
  cases a <;>
    simp [preference_defeats, authority_rank, RANK_PROPOSED, RANK_ACCEPTED,
      RANK_CONFLICT_RESOLUTION]

/-- Strictly higher authority defeats lower authority asymmetrically. -/
theorem preference_defeats_strict_asymmetric (a b : Authority) (ra rb : U8)
    (ha : authority_rank a = ok ra) (hb : authority_rank b = ok rb)
    (hlt : rb.val < ra.val) :
    preference_defeats a b = ok true ∧ preference_defeats b a = ok false := by
  cases a <;> cases b <;>
    simp [authority_rank, RANK_PROPOSED, RANK_ACCEPTED, RANK_CONFLICT_RESOLUTION] at ha hb <;>
    subst ha <;> subst hb <;>
    simp [preference_defeats, authority_rank, RANK_PROPOSED, RANK_ACCEPTED,
      RANK_CONFLICT_RESOLUTION] at hlt ⊢

/-- `preference_defeats` is transitive. -/
theorem preference_defeats_transitive (a b c : Authority)
    (hab : preference_defeats a b = ok true) (hbc : preference_defeats b c = ok true) :
    preference_defeats a c = ok true := by
  cases a <;> cases b <;> cases c <;>
    simp [preference_defeats, authority_rank, RANK_PROPOSED, RANK_ACCEPTED,
      RANK_CONFLICT_RESOLUTION] at hab hbc ⊢

/-! ## `best_label` -/

/-- `best_label` never fails or diverges. -/
theorem best_label_total (left right : Label) :
    ∃ r, best_label left right = ok r := by
  cases left <;> cases right <;>
    simp [best_label, label_rank, LABEL_RANK_OUT, LABEL_RANK_UNDEC, LABEL_RANK_IN]

/-- `best_label` is commutative. -/
theorem best_label_comm (left right : Label) :
    best_label left right = best_label right left := by
  cases left <;> cases right <;>
    simp [best_label, label_rank, LABEL_RANK_OUT, LABEL_RANK_UNDEC, LABEL_RANK_IN]

/-- `best_label` is associative. -/
theorem best_label_assoc (a b c : Label) :
    ∃ ab bc r, best_label a b = ok ab ∧ best_label b c = ok bc ∧
      best_label ab c = ok r ∧ best_label a bc = ok r := by
  cases a <;> cases b <;> cases c <;>
    simp [best_label, label_rank, LABEL_RANK_OUT, LABEL_RANK_UNDEC, LABEL_RANK_IN]

/-- `best_label` is idempotent. -/
theorem best_label_idem (a : Label) :
    best_label a a = ok a := by
  cases a <;>
    simp [best_label, label_rank, LABEL_RANK_OUT, LABEL_RANK_UNDEC, LABEL_RANK_IN]

/-- `Label.In` absorbs every label and `Label.Out` is the identity of `best_label`. -/
theorem best_label_bounds (a : Label) :
    best_label Label.In a = ok Label.In ∧ best_label Label.Out a = ok a := by
  cases a <;>
    simp [best_label, label_rank, LABEL_RANK_OUT, LABEL_RANK_UNDEC, LABEL_RANK_IN]

/-! ## `next_label` (Dung Characteristic Operator $F_{AF}$) -/

private theorem next_label_loop_spec
    (node : Usize) (defeats : Slice DefeatEdge) (labels : Slice Label) :
    next_label_loop node defeats labels false false 0#usize ⦃ res =>
      (res.1 = true ↔
        ∃ j, j < defeats.length ∧ ∃ e, defeats.val[j]? = some e ∧
          e.target = node ∧ e.attacker.val < labels.length ∧
          labels.val[e.attacker.val]? = some Label.In) ∧
      (res.2 = true ↔
        ∃ j, j < defeats.length ∧ ∃ e, defeats.val[j]? = some e ∧
          e.target = node ∧ e.attacker.val < labels.length ∧
          labels.val[e.attacker.val]? ≠ some Label.Out) ⦄ := by
  unfold next_label_loop
  apply loop.spec_decr_nat
    (fun (s : Bool × Bool × Usize) => defeats.length - s.2.2.val)
    (fun (s : Bool × Bool × Usize) =>
      s.2.2.val ≤ defeats.length ∧
      (s.1 = true ↔
        ∃ j, j < s.2.2.val ∧ ∃ e, defeats.val[j]? = some e ∧
          e.target = node ∧ e.attacker.val < labels.length ∧
          labels.val[e.attacker.val]? = some Label.In) ∧
      (s.2.1 = true ↔
        ∃ j, j < s.2.2.val ∧ ∃ e, defeats.val[j]? = some e ∧
          e.target = node ∧ e.attacker.val < labels.length ∧
          labels.val[e.attacker.val]? ≠ some Label.Out))
  · rintro ⟨hasIn, hasNonOut, index⟩ ⟨hle, hIn, hNonOut⟩
    simp only at hle hIn hNonOut ⊢
    unfold next_label_loop.body
    by_cases hlt : index < Slice.len defeats
    · have hlt' : index.val < defeats.length := by scalar_tac
      obtain ⟨edge, hedge, hedgev⟩ := ok_of_spec (Slice.index_usize_spec defeats index hlt')
      have hedge_get : defeats.val[index.val]? = some edge := by
        rw [List.getElem?_eq_getElem hlt', hedgev]
      have hidx_max : index.val < Usize.max := by scalar_tac
      have hnext_val : (core.num.Usize.saturating_add index 1#usize).val = index.val + 1 :=
        usize_saturating_add_one_val index hidx_max
      by_cases ht : edge.target = node
      · by_cases ha : edge.attacker < Slice.len labels
        · have ha' : edge.attacker.val < labels.length := by scalar_tac
          obtain ⟨al, hal, halv⟩ := ok_of_spec (Slice.index_usize_spec labels edge.attacker ha')
          have hal_get : labels.val[edge.attacker.val]? = some al := by
            rw [List.getElem?_eq_getElem ha', halv]
          cases al with
          | Out =>
            simp [hlt, hedge, ht, ha', hal, lift]
            rw [hnext_val]
            refine ⟨by scalar_tac, ?_, ?_, by scalar_tac⟩
            · constructor
              · intro h1
                obtain ⟨j, hj, e, he, hte, hae, hle'⟩ := hIn.mp h1
                exact ⟨j, by omega, e, he, hte, hae, hle'⟩
              · rintro ⟨j, hj, e, he, hte, hae, hle'⟩
                by_cases hji : j = index.val
                · subst hji
                  rw [hedge_get, Option.some.injEq] at he; subst he
                  rw [hal_get] at hle'; cases hle'
                · exact hIn.mpr ⟨j, by omega, e, he, hte, hae, hle'⟩
            · constructor
              · intro h2
                obtain ⟨j, hj, e, he, hte, hae, hle'⟩ := hNonOut.mp h2
                exact ⟨j, by omega, e, he, hte, hae, hle'⟩
              · rintro ⟨j, hj, e, he, hte, hae, hle'⟩
                by_cases hji : j = index.val
                · subst hji
                  rw [hedge_get, Option.some.injEq] at he; subst he
                  exact absurd hal_get hle'
                · exact hNonOut.mpr ⟨j, by omega, e, he, hte, hae, hle'⟩
          | Undec =>
            simp [hlt, hedge, ht, ha', hal, lift]
            rw [hnext_val]
            refine ⟨by scalar_tac, ?_, ?_, by scalar_tac⟩
            · constructor
              · intro h1
                obtain ⟨j, hj, e, he, hte, hae, hle'⟩ := hIn.mp h1
                exact ⟨j, by omega, e, he, hte, hae, hle'⟩
              · rintro ⟨j, hj, e, he, hte, hae, hle'⟩
                by_cases hji : j = index.val
                · subst hji
                  rw [hedge_get, Option.some.injEq] at he; subst he
                  rw [hal_get] at hle'; cases hle'
                · exact hIn.mpr ⟨j, by omega, e, he, hte, hae, hle'⟩
            · exact ⟨index.val, by omega, edge, hedge_get, ht, ha', by rw [hal_get]; simp⟩
          | In =>
            simp [hlt, hedge, ht, ha', hal, lift]
            rw [hnext_val]
            refine ⟨by scalar_tac, ?_, ?_, by scalar_tac⟩
            · exact ⟨index.val, by omega, edge, hedge_get, ht, ha', hal_get⟩
            · exact ⟨index.val, by omega, edge, hedge_get, ht, ha', by rw [hal_get]; simp⟩
        · have ha_ge : labels.length ≤ edge.attacker.val := by scalar_tac
          have ha_not : ¬ edge.attacker.val < labels.val.length := by scalar_tac
          simp [hlt, hedge, ht, ha_not, lift]
          rw [hnext_val]
          refine ⟨by scalar_tac, ?_, ?_, by scalar_tac⟩
          · constructor
            · intro h1
              obtain ⟨j, hj, e, he, hte, hae, hle'⟩ := hIn.mp h1
              exact ⟨j, by omega, e, he, hte, hae, hle'⟩
            · rintro ⟨j, hj, e, he, hte, hae, hle'⟩
              by_cases hji : j = index.val
              · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he; omega
              · exact hIn.mpr ⟨j, by omega, e, he, hte, hae, hle'⟩
          · constructor
            · intro h2
              obtain ⟨j, hj, e, he, hte, hae, hle'⟩ := hNonOut.mp h2
              exact ⟨j, by omega, e, he, hte, hae, hle'⟩
            · rintro ⟨j, hj, e, he, hte, hae, hle'⟩
              by_cases hji : j = index.val
              · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he; omega
              · exact hNonOut.mpr ⟨j, by omega, e, he, hte, hae, hle'⟩
      · simp [hlt, hedge, ht, lift]
        rw [hnext_val]
        refine ⟨by scalar_tac, ?_, ?_, by scalar_tac⟩
        · constructor
          · intro h1
            obtain ⟨j, hj, e, he, hte, hae, hle'⟩ := hIn.mp h1
            exact ⟨j, by omega, e, he, hte, hae, hle'⟩
          · rintro ⟨j, hj, e, he, hte, hae, hle'⟩
            by_cases hji : j = index.val
            · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he; exact absurd hte ht
            · exact hIn.mpr ⟨j, by omega, e, he, hte, hae, hle'⟩
        · constructor
          · intro h2
            obtain ⟨j, hj, e, he, hte, hae, hle'⟩ := hNonOut.mp h2
            exact ⟨j, by omega, e, he, hte, hae, hle'⟩
          · rintro ⟨j, hj, e, he, hte, hae, hle'⟩
            by_cases hji : j = index.val
            · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he; exact absurd hte ht
            · exact hNonOut.mpr ⟨j, by omega, e, he, hte, hae, hle'⟩
    · have hge : defeats.length ≤ index.val := by scalar_tac
      have heq : index.val = defeats.length := by omega
      simp only [hlt, ite_false, WP.spec_ok]
      rw [← heq]
      exact ⟨hIn, hNonOut⟩
  · simp

/-- `next_label` never fails or diverges. -/
theorem next_label_total (node : Usize) (defeats : Slice DefeatEdge) (labels : Slice Label) :
    ∃ r, next_label node defeats labels = ok r := by
  unfold next_label
  by_cases hge : node >= Slice.len labels
  · exact ⟨Label.Undec, by simp [hge]⟩
  · obtain ⟨⟨hasIn, hasNonOut⟩, hloop, _⟩ := ok_of_spec (next_label_loop_spec node defeats labels)
    cases hasIn <;> cases hasNonOut <;> simp [hge, hloop]

/-- Exact characterization of `next_label`:
- `Out` iff `node < labels.length` and some in-bounds attacker of `node` is `In`.
- `In` iff `node < labels.length` and every in-bounds attacker of `node` is `Out`. -/
theorem next_label_spec (node : Usize) (defeats : Slice DefeatEdge) (labels : Slice Label) :
    ∃ r, next_label node defeats labels = ok r ∧
      (r = Label.Out ↔
        node.val < labels.length ∧
        ∃ e ∈ defeats.val, e.target = node ∧ e.attacker.val < labels.length ∧
          labels.val[e.attacker.val]? = some Label.In) ∧
      (r = Label.In ↔
        node.val < labels.length ∧
        ∀ e ∈ defeats.val, e.target = node → e.attacker.val < labels.length →
          labels.val[e.attacker.val]? = some Label.Out) := by
  unfold next_label
  by_cases hge : node >= Slice.len labels
  · have hge' : labels.length ≤ node.val := by scalar_tac
    refine ⟨Label.Undec, by simp [hge], ?_, ?_⟩
    · constructor
      · intro h; cases h
      · intro h; omega
    · constructor
      · intro h; cases h
      · intro h; omega
  · have hlt : node.val < labels.length := by scalar_tac
    obtain ⟨⟨hasIn, hasNonOut⟩, hloop, hIn, hNonOut⟩ :=
      ok_of_spec (next_label_loop_spec node defeats labels)
    have hIn_mem : hasIn = true ↔
        ∃ e ∈ defeats.val, e.target = node ∧ e.attacker.val < labels.length ∧
          labels.val[e.attacker.val]? = some Label.In := by
      rw [hIn]
      constructor
      · rintro ⟨j, hj, e, he, ht, ha, hl⟩
        have hmem : e ∈ defeats.val := by
          rw [List.getElem?_eq_getElem hj, Option.some.injEq] at he
          subst he; exact List.getElem_mem hj
        exact ⟨e, hmem, ht, ha, hl⟩
      · rintro ⟨e, hmem, ht, ha, hl⟩
        obtain ⟨j, hj, he⟩ := List.getElem_of_mem hmem
        exact ⟨j, hj, e, by rw [List.getElem?_eq_getElem hj, he], ht, ha, hl⟩
    have hNonOut_mem : hasNonOut = true ↔
        ∃ e ∈ defeats.val, e.target = node ∧ e.attacker.val < labels.length ∧
          labels.val[e.attacker.val]? ≠ some Label.Out := by
      rw [hNonOut]
      constructor
      · rintro ⟨j, hj, e, he, ht, ha, hl⟩
        have hmem : e ∈ defeats.val := by
          rw [List.getElem?_eq_getElem hj, Option.some.injEq] at he
          subst he; exact List.getElem_mem hj
        exact ⟨e, hmem, ht, ha, hl⟩
      · rintro ⟨e, hmem, ht, ha, hl⟩
        obtain ⟨j, hj, he⟩ := List.getElem_of_mem hmem
        exact ⟨j, hj, e, by rw [List.getElem?_eq_getElem hj, he], ht, ha, hl⟩
    cases hasIn with
    | true =>
      have hex := hIn_mem.mp rfl
      refine ⟨Label.Out, by simp [hge, hloop], ?_, ?_⟩
      · exact ⟨fun _ => ⟨hlt, hex⟩, fun _ => rfl⟩
      · constructor
        · intro h; cases h
        · rintro ⟨_, hall⟩
          obtain ⟨e, he, ht, ha, hin⟩ := hex
          have hout := hall e he ht ha
          rw [hin] at hout; cases hout
    | false =>
      cases hasNonOut with
      | true =>
        have hnoIn : ¬ ∃ e ∈ defeats.val, e.target = node ∧ e.attacker.val < labels.length ∧
            labels.val[e.attacker.val]? = some Label.In := fun h => Bool.false_ne_true (hIn_mem.mpr h)
        have hnonOut := hNonOut_mem.mp rfl
        refine ⟨Label.Undec, by simp [hge, hloop], ?_, ?_⟩
        · exact ⟨(fun h => by cases h), fun h => absurd h.2 hnoIn⟩
        · constructor
          · intro h; cases h
          · rintro ⟨_, hall⟩
            obtain ⟨e, he, ht, ha, hne⟩ := hnonOut
            exact absurd (hall e he ht ha) hne
      | false =>
        have hnoIn : ¬ ∃ e ∈ defeats.val, e.target = node ∧ e.attacker.val < labels.length ∧
            labels.val[e.attacker.val]? = some Label.In := fun h => Bool.false_ne_true (hIn_mem.mpr h)
        have hallOut : ∀ e ∈ defeats.val, e.target = node → e.attacker.val < labels.length →
            labels.val[e.attacker.val]? = some Label.Out := by
          intro e he ht ha
          by_contra hne
          exact Bool.false_ne_true (hNonOut_mem.mpr ⟨e, he, ht, ha, hne⟩)
        refine ⟨Label.In, by simp [hge, hloop], ?_, ?_⟩
        · exact ⟨(fun h => by cases h), fun h => absurd h.2 hnoIn⟩
        · exact ⟨fun _ => ⟨hlt, hallOut⟩, fun _ => rfl⟩

/-- **Monotonicity of $F_{AF}$**: if `labels1 ≤ labels2` in the information order
(`Undec ≤ In`, `Undec ≤ Out`), then `next_label node defeats labels1 ≤ next_label node defeats labels2`. -/
theorem next_label_monotone
    (node : Usize) (defeats : Slice DefeatEdge) (labels1 labels2 : Slice Label)
    (hlen : labels1.length = labels2.length)
    (hle : ∀ i, i < labels1.length →
      ∀ a b, labels1.val[i]? = some a → labels2.val[i]? = some b →
        a = Label.Undec ∨ a = b) :
    ∃ r1 r2, next_label node defeats labels1 = ok r1 ∧
      next_label node defeats labels2 = ok r2 ∧
      (r1 = Label.Undec ∨ r1 = r2) := by
  obtain ⟨r1, hr1, hOut1, hIn1⟩ := next_label_spec node defeats labels1
  obtain ⟨r2, hr2, hOut2, hIn2⟩ := next_label_spec node defeats labels2
  refine ⟨r1, r2, hr1, hr2, ?_⟩
  cases r1 with
  | Undec => exact Or.inl rfl
  | Out =>
    right
    obtain ⟨hn, e, he, ht, ha, hin⟩ := hOut1.mp rfl
    have ha2 : e.attacker.val < labels2.length := by omega
    obtain ⟨b, hb⟩ : ∃ b, labels2.val[e.attacker.val]? = some b :=
      ⟨labels2.val[e.attacker.val], List.getElem?_eq_getElem ha2⟩
    have hbin : b = Label.In := by
      rcases hle e.attacker.val ha Label.In b hin hb with h | h
      · cases h
      · exact h.symm
    subst hbin
    exact (hOut2.mpr ⟨by omega, e, he, ht, ha2, hb⟩).symm
  | In =>
    right
    obtain ⟨hn, hall⟩ := hIn1.mp rfl
    have hall2 : ∀ e ∈ defeats.val, e.target = node → e.attacker.val < labels2.length →
        labels2.val[e.attacker.val]? = some Label.Out := by
      intro e he ht ha2
      have ha1 : e.attacker.val < labels1.length := by omega
      have hout1 := hall e he ht ha1
      obtain ⟨b, hb⟩ : ∃ b, labels2.val[e.attacker.val]? = some b :=
        ⟨labels2.val[e.attacker.val], List.getElem?_eq_getElem ha2⟩
      have hbout : b = Label.Out := by
        rcases hle e.attacker.val ha1 Label.Out b hout1 hb with h | h
        · cases h
        · exact h.symm
      rw [hb, hbout]
    exact (hIn2.mpr ⟨by omega, hall2⟩).symm

/-- **Permutation invariance of `next_label`**: any two defeat slices with the same
edge set (in particular any permutation) produce the exact same `next_label`. -/
theorem next_label_perm_invariant
    (node : Usize) (defeats1 defeats2 : Slice DefeatEdge) (labels : Slice Label)
    (heq : ∀ e, e ∈ defeats1.val ↔ e ∈ defeats2.val) :
    next_label node defeats1 labels = next_label node defeats2 labels := by
  obtain ⟨r1, hr1, hOut1, hIn1⟩ := next_label_spec node defeats1 labels
  obtain ⟨r2, hr2, hOut2, hIn2⟩ := next_label_spec node defeats2 labels
  rw [hr1, hr2]
  congr 1
  cases r1 with
  | Out =>
    obtain ⟨hn, e, he, ht, ha, hin⟩ := hOut1.mp rfl
    exact (hOut2.mpr ⟨hn, e, (heq e).mp he, ht, ha, hin⟩).symm
  | In =>
    obtain ⟨hn, hall⟩ := hIn1.mp rfl
    exact (hIn2.mpr ⟨hn, fun e he ht ha => hall e ((heq e).mpr he) ht ha⟩).symm
  | Undec =>
    cases r2 with
    | Undec => rfl
    | Out =>
      obtain ⟨hn, e, he, ht, ha, hin⟩ := hOut2.mp rfl
      have := hOut1.mpr ⟨hn, e, (heq e).mpr he, ht, ha, hin⟩
      cases this
    | In =>
      obtain ⟨hn, hall⟩ := hIn2.mp rfl
      have := hIn1.mpr ⟨hn, fun e he ht ha => hall e ((heq e).mp he) ht ha⟩
      cases this

/-! ## `is_fixpoint` -/

private theorem is_fixpoint_loop_spec
    (defeats : Slice DefeatEdge) (labels : Slice Label) :
    is_fixpoint_loop defeats labels true 0#usize ⦃ res =>
      res = true ↔ ∀ i, i < labels.length →
        ∀ u : Usize, u.val = i →
          ∀ l, labels.val[i]? = some l → next_label u defeats labels = ok l ⦄ := by
  unfold is_fixpoint_loop
  apply loop.spec_decr_nat
    (fun (p : Bool × Usize) => labels.length - p.2.val)
    (fun (p : Bool × Usize) =>
      p.2.val ≤ labels.length ∧
      (p.1 = true ↔ ∀ i, i < p.2.val →
        ∀ u : Usize, u.val = i →
          ∀ l, labels.val[i]? = some l → next_label u defeats labels = ok l))
  · rintro ⟨flag, index⟩ ⟨hle, hinv⟩
    simp only at hle hinv ⊢
    unfold is_fixpoint_loop.body
    by_cases hlt : index < Slice.len labels
    · have hlt' : index.val < labels.length := by scalar_tac
      cases flag with
      | false =>
        simp only [hlt, ite_true, Bool.false_eq_true, ite_false, WP.spec_ok]
        refine ⟨False.elim, fun hall => ?_⟩
        exact Bool.false_ne_true (hinv.mpr (fun i hi u hu l hl => hall i (by omega) u hu l hl))
      | true =>
        obtain ⟨upd, hupd⟩ := next_label_total index defeats labels
        obtain ⟨cur, hcur, hcurv⟩ := ok_of_spec (Slice.index_usize_spec labels index hlt')
        have hcur_get : labels.val[index.val]? = some cur := by
          rw [List.getElem?_eq_getElem hlt', hcurv]
        have hidx_max : index.val < Usize.max := by scalar_tac
        have hnext_val : (core.num.Usize.saturating_add index 1#usize).val = index.val + 1 :=
          usize_saturating_add_one_val index hidx_max
        have hall_prev := hinv.mp rfl
        by_cases heq : upd = cur
        · have hne := (label_ne_eq upd cur).1 heq
          subst heq
          simp only [hlt, ↓reduceIte, hupd, hcur, hne, Bool.false_eq_true, bind_ok, lift, WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          rw [hnext_val]
          refine ⟨fun _ i hi u hu l hl => ?_, fun _ => trivial⟩
          by_cases hji : i = index.val
          · subst hji
            have hu_eq : u = index := (UScalar.eq_equiv u index).mpr hu
            subst hu_eq
            rw [hcur_get, Option.some.injEq] at hl
            subst hl
            exact hupd
          · exact hall_prev i (by omega) u hu l hl
        · have hne := (label_ne_eq upd cur).2 heq
          simp only [hlt, ↓reduceIte, hupd, hcur, hne, bind_ok, lift, WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          rw [hnext_val]
          refine ⟨(fun h => by cases h), fun hall => ?_⟩
          have hfx := hall index.val (by omega) index rfl cur hcur_get
          rw [hupd, ok.injEq] at hfx
          exact absurd hfx heq
    · have hge : labels.length ≤ index.val := by scalar_tac
      have heq : index.val = labels.length := by omega
      simp only [hlt, ite_false, WP.spec_ok]
      rw [← heq]
      exact hinv
  · simp

/-- `is_fixpoint` never fails or diverges. -/
theorem is_fixpoint_total (defeats : Slice DefeatEdge) (labels : Slice Label) :
    ∃ r, is_fixpoint defeats labels = ok r := by
  obtain ⟨r, hr, _⟩ := ok_of_spec (is_fixpoint_loop_spec defeats labels)
  exact ⟨r, hr⟩

/-- `is_fixpoint defeats labels = ok true` iff every in-bounds index `u` satisfies
`next_label u defeats labels = ok labels[u]`. -/
theorem is_fixpoint_iff (defeats : Slice DefeatEdge) (labels : Slice Label) :
    is_fixpoint defeats labels = ok true ↔
      ∀ i, i < labels.length →
        ∀ u : Usize, u.val = i →
          ∀ l, labels.val[i]? = some l → next_label u defeats labels = ok l := by
  obtain ⟨r, hr, hiff⟩ := ok_of_spec (is_fixpoint_loop_spec defeats labels)
  unfold is_fixpoint
  rw [hr]
  cases r with
  | true => simpa using hiff
  | false =>
    constructor
    · intro h; rw [ok.injEq] at h; cases h
    · intro hall; exact absurd (hiff.mpr hall) Bool.false_ne_true

/-! ## `is_conflict_free` -/

private theorem is_conflict_free_loop_spec
    (defeats : Slice DefeatEdge) (labels : Slice Label) :
    is_conflict_free_loop defeats labels true 0#usize ⦃ res =>
      res = true ↔ ∀ j, j < defeats.length →
        ∀ e, defeats.val[j]? = some e →
          e.attacker.val < labels.length → e.target.val < labels.length →
          ¬ (labels.val[e.attacker.val]? = some Label.In ∧
             labels.val[e.target.val]? = some Label.In) ⦄ := by
  unfold is_conflict_free_loop
  apply loop.spec_decr_nat
    (fun (p : Bool × Usize) => defeats.length - p.2.val)
    (fun (p : Bool × Usize) =>
      p.2.val ≤ defeats.length ∧
      (p.1 = true ↔ ∀ j, j < p.2.val →
        ∀ e, defeats.val[j]? = some e →
          e.attacker.val < labels.length → e.target.val < labels.length →
          ¬ (labels.val[e.attacker.val]? = some Label.In ∧
             labels.val[e.target.val]? = some Label.In)))
  · rintro ⟨flag, index⟩ ⟨hle, hinv⟩
    simp only at hle hinv ⊢
    unfold is_conflict_free_loop.body
    by_cases hlt : index < Slice.len defeats
    · have hlt' : index.val < defeats.length := by scalar_tac
      cases flag with
      | false =>
        simp only [hlt, ite_true, Bool.false_eq_true, ite_false, WP.spec_ok]
        refine ⟨False.elim, fun hall => ?_⟩
        exact Bool.false_ne_true (hinv.mpr (fun j hj e he ha ht => hall j (by omega) e he ha ht))
      | true =>
        obtain ⟨edge, hedge, hedgev⟩ := ok_of_spec (Slice.index_usize_spec defeats index hlt')
        have hedge_get : defeats.val[index.val]? = some edge := by
          rw [List.getElem?_eq_getElem hlt', hedgev]
        have hidx_max : index.val < Usize.max := by scalar_tac
        have hnext_val : (core.num.Usize.saturating_add index 1#usize).val = index.val + 1 :=
          usize_saturating_add_one_val index hidx_max
        have hall_prev := hinv.mp rfl
        by_cases ha : edge.attacker < Slice.len labels
        · have ha' : edge.attacker.val < labels.length := by scalar_tac
          by_cases ht : edge.target < Slice.len labels
          · have ht' : edge.target.val < labels.length := by scalar_tac
            obtain ⟨la, hla, hlav⟩ := ok_of_spec (Slice.index_usize_spec labels edge.attacker ha')
            have hla_get : labels.val[edge.attacker.val]? = some la := by
              rw [List.getElem?_eq_getElem ha', hlav]
            cases la with
            | In =>
              obtain ⟨lt_, hlt_, hltv⟩ := ok_of_spec (Slice.index_usize_spec labels edge.target ht')
              have hlt_get : labels.val[edge.target.val]? = some lt_ := by
                rw [List.getElem?_eq_getElem ht', hltv]
              cases lt_ with
              | In =>
                simp only [hlt, ↓reduceIte, hedge, bind_ok, ha, ht, hla, hlt_, lift, WP.spec_ok]
                refine ⟨⟨by omega, ?_⟩, by omega⟩
                rw [hnext_val]
                refine ⟨(fun h => by cases h), fun hall => ?_⟩
                exact False.elim (hall index.val (by omega) edge hedge_get ha' ht' ⟨hla_get, hlt_get⟩)
              | Out =>
                simp only [hlt, ↓reduceIte, hedge, bind_ok, ha, ht, hla, hlt_, Bool.false_eq_true,
                  lift, WP.spec_ok]
                refine ⟨⟨by omega, ?_⟩, by omega⟩
                rw [hnext_val]
                refine ⟨fun _ j hj e he hae hte hboth => ?_, fun _ => trivial⟩
                by_cases hji : j = index.val
                · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he
                  rw [hlt_get] at hboth; cases hboth.2
                · exact hall_prev j (by omega) e he hae hte hboth
              | Undec =>
                simp only [hlt, ↓reduceIte, hedge, bind_ok, ha, ht, hla, hlt_, Bool.false_eq_true,
                  lift, WP.spec_ok]
                refine ⟨⟨by omega, ?_⟩, by omega⟩
                rw [hnext_val]
                refine ⟨fun _ j hj e he hae hte hboth => ?_, fun _ => trivial⟩
                by_cases hji : j = index.val
                · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he
                  rw [hlt_get] at hboth; cases hboth.2
                · exact hall_prev j (by omega) e he hae hte hboth
            | Out =>
              simp only [hlt, ↓reduceIte, hedge, bind_ok, ha, ht, hla, Bool.false_eq_true,
                lift, WP.spec_ok]
              refine ⟨⟨by omega, ?_⟩, by omega⟩
              rw [hnext_val]
              refine ⟨fun _ j hj e he hae hte hboth => ?_, fun _ => trivial⟩
              by_cases hji : j = index.val
              · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he
                rw [hla_get] at hboth; cases hboth.1
              · exact hall_prev j (by omega) e he hae hte hboth
            | Undec =>
              simp only [hlt, ↓reduceIte, hedge, bind_ok, ha, ht, hla, Bool.false_eq_true,
                lift, WP.spec_ok]
              refine ⟨⟨by omega, ?_⟩, by omega⟩
              rw [hnext_val]
              refine ⟨fun _ j hj e he hae hte hboth => ?_, fun _ => trivial⟩
              by_cases hji : j = index.val
              · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he
                rw [hla_get] at hboth; cases hboth.1
              · exact hall_prev j (by omega) e he hae hte hboth
          · have ht_ge : labels.length ≤ edge.target.val := by scalar_tac
            simp only [hlt, ↓reduceIte, hedge, bind_ok, ha, ht, lift, WP.spec_ok]
            refine ⟨⟨by omega, ?_⟩, by omega⟩
            rw [hnext_val]
            refine ⟨fun _ j hj e he hae hte hboth => ?_, fun _ => trivial⟩
            by_cases hji : j = index.val
            · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he; omega
            · exact hall_prev j (by omega) e he hae hte hboth
        · have ha_ge : labels.length ≤ edge.attacker.val := by scalar_tac
          simp only [hlt, ↓reduceIte, hedge, bind_ok, ha, lift, WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          rw [hnext_val]
          refine ⟨fun _ j hj e he hae hte hboth => ?_, fun _ => trivial⟩
          by_cases hji : j = index.val
          · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he; omega
          · exact hall_prev j (by omega) e he hae hte hboth
    · have hge : defeats.length ≤ index.val := by scalar_tac
      have heq : index.val = defeats.length := by omega
      simp only [hlt, ite_false, WP.spec_ok]
      rw [← heq]
      exact hinv
  · simp

/-- `is_conflict_free` never fails or diverges. -/
theorem is_conflict_free_total (defeats : Slice DefeatEdge) (labels : Slice Label) :
    ∃ r, is_conflict_free defeats labels = ok r := by
  obtain ⟨r, hr, _⟩ := ok_of_spec (is_conflict_free_loop_spec defeats labels)
  exact ⟨r, hr⟩

/-- `is_conflict_free defeats labels = ok true` iff no in-bounds defeat edge links an `In`
attacker to an `In` target. -/
theorem is_conflict_free_iff (defeats : Slice DefeatEdge) (labels : Slice Label) :
    is_conflict_free defeats labels = ok true ↔
      ∀ e ∈ defeats.val,
        e.attacker.val < labels.length → e.target.val < labels.length →
        ¬ (labels.val[e.attacker.val]? = some Label.In ∧
           labels.val[e.target.val]? = some Label.In) := by
  obtain ⟨r, hr, hiff⟩ := ok_of_spec (is_conflict_free_loop_spec defeats labels)
  have hmem_iff :
      (∀ j, j < defeats.length → ∀ e, defeats.val[j]? = some e →
        e.attacker.val < labels.length → e.target.val < labels.length →
        ¬ (labels.val[e.attacker.val]? = some Label.In ∧
           labels.val[e.target.val]? = some Label.In)) ↔
      (∀ e ∈ defeats.val, e.attacker.val < labels.length → e.target.val < labels.length →
        ¬ (labels.val[e.attacker.val]? = some Label.In ∧
           labels.val[e.target.val]? = some Label.In)) := by
    constructor
    · intro hall e hmem ha ht
      obtain ⟨j, hj, he⟩ := List.getElem_of_mem hmem
      exact hall j hj e (by rw [List.getElem?_eq_getElem hj, he]) ha ht
    · intro hall j hj e he ha ht
      rw [List.getElem?_eq_getElem hj, Option.some.injEq] at he
      subst he
      exact hall defeats.val[j] (List.getElem_mem hj) ha ht
  unfold is_conflict_free
  rw [hr]
  cases r with
  | true => simpa using hiff.trans hmem_iff
  | false =>
    constructor
    · intro h; rw [ok.injEq] at h; cases h
    · intro hall; exact absurd (hiff.mpr (hmem_iff.mpr hall)) Bool.false_ne_true

/-! ## `is_admissible` -/

private theorem has_in_counterattacker_loop_spec
    (attacker : Usize) (defeats : Slice DefeatEdge) (labels : Slice Label) :
    has_in_counterattacker_loop attacker defeats labels false 0#usize ⦃ res =>
      res = true ↔
        ∃ e ∈ defeats.val, e.target = attacker ∧ e.attacker.val < labels.length ∧
          labels.val[e.attacker.val]? = some Label.In ⦄ := by
  unfold has_in_counterattacker_loop
  apply loop.spec_decr_nat
    (fun (p : Bool × Usize) => defeats.length - p.2.val)
    (fun (p : Bool × Usize) =>
      p.2.val ≤ defeats.length ∧
      (p.1 = true ↔
        ∃ j, j < p.2.val ∧ ∃ e, defeats.val[j]? = some e ∧
          e.target = attacker ∧ e.attacker.val < labels.length ∧
          labels.val[e.attacker.val]? = some Label.In))
  · rintro ⟨flag, index⟩ ⟨hle, hinv⟩
    simp only at hle hinv ⊢
    unfold has_in_counterattacker_loop.body
    by_cases hlt : index < Slice.len defeats
    · have hlt' : index.val < defeats.length := by scalar_tac
      cases flag with
      | true =>
        simp only [hlt, ↓reduceIte, WP.spec_ok]
        obtain ⟨j, hj, e, he, ht, ha, hin⟩ := hinv.mp rfl
        have hj_lt : j < defeats.length := by omega
        have hmem : e ∈ defeats.val := by
          rw [List.getElem?_eq_getElem hj_lt, Option.some.injEq] at he
          subst he; exact List.getElem_mem hj_lt
        exact ⟨fun _ => ⟨e, hmem, ht, ha, hin⟩, fun _ => trivial⟩
      | false =>
        obtain ⟨edge, hedge, hedgev⟩ := ok_of_spec (Slice.index_usize_spec defeats index hlt')
        have hedge_get : defeats.val[index.val]? = some edge := by
          rw [List.getElem?_eq_getElem hlt', hedgev]
        have hidx_max : index.val < Usize.max := by scalar_tac
        have hnext_val : (core.num.Usize.saturating_add index 1#usize).val = index.val + 1 :=
          usize_saturating_add_one_val index hidx_max
        have hnone_prev : ¬ ∃ j, j < index.val ∧ ∃ e, defeats.val[j]? = some e ∧
            e.target = attacker ∧ e.attacker.val < labels.length ∧
            labels.val[e.attacker.val]? = some Label.In :=
          fun h => Bool.false_ne_true (hinv.mpr h)
        by_cases ht : edge.target = attacker
        · by_cases ha : edge.attacker < Slice.len labels
          · have ha' : edge.attacker.val < labels.length := by scalar_tac
            obtain ⟨la, hla, hlav⟩ := ok_of_spec (Slice.index_usize_spec labels edge.attacker ha')
            have hla_get : labels.val[edge.attacker.val]? = some la := by
              rw [List.getElem?_eq_getElem ha', hlav]
            cases la with
            | In =>
              simp only [hlt, ↓reduceIte, Bool.false_eq_true, hedge, bind_ok, ht, ha,
                hla, lift, WP.spec_ok]
              refine ⟨⟨by omega, ?_⟩, by omega⟩
              rw [hnext_val]
              exact ⟨fun _ => ⟨index.val, by omega, edge, hedge_get, ht, ha', hla_get⟩,
                fun _ => trivial⟩
            | Out =>
              simp only [hlt, ↓reduceIte, Bool.false_eq_true, hedge, bind_ok, ht, ha,
                hla, lift, WP.spec_ok]
              refine ⟨⟨by omega, ?_⟩, by omega⟩
              rw [hnext_val]
              refine ⟨False.elim, ?_⟩
              rintro ⟨j, hj, e, he, hte, hae, hin⟩
              by_cases hji : j = index.val
              · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he
                rw [hla_get] at hin; cases hin
              · exact hnone_prev ⟨j, by omega, e, he, hte, hae, hin⟩
            | Undec =>
              simp only [hlt, ↓reduceIte, Bool.false_eq_true, hedge, bind_ok, ht, ha,
                hla, lift, WP.spec_ok]
              refine ⟨⟨by omega, ?_⟩, by omega⟩
              rw [hnext_val]
              refine ⟨False.elim, ?_⟩
              rintro ⟨j, hj, e, he, hte, hae, hin⟩
              by_cases hji : j = index.val
              · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he
                rw [hla_get] at hin; cases hin
              · exact hnone_prev ⟨j, by omega, e, he, hte, hae, hin⟩
          · have ha_ge : labels.length ≤ edge.attacker.val := by scalar_tac
            simp only [hlt, ↓reduceIte, Bool.false_eq_true, hedge, bind_ok, ht, ha,
              lift, WP.spec_ok]
            refine ⟨⟨by omega, ?_⟩, by omega⟩
            rw [hnext_val]
            refine ⟨False.elim, ?_⟩
            rintro ⟨j, hj, e, he, hte, hae, hin⟩
            by_cases hji : j = index.val
            · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he; omega
            · exact hnone_prev ⟨j, by omega, e, he, hte, hae, hin⟩
        · simp only [hlt, ↓reduceIte, Bool.false_eq_true, hedge, bind_ok, ht, lift,
            WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          rw [hnext_val]
          refine ⟨False.elim, ?_⟩
          rintro ⟨j, hj, e, he, hte, hae, hin⟩
          by_cases hji : j = index.val
          · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he; exact absurd hte ht
          · exact hnone_prev ⟨j, by omega, e, he, hte, hae, hin⟩
    · have hge : defeats.length ≤ index.val := by scalar_tac
      have heq : index.val = defeats.length := by omega
      simp only [hlt, ite_false, WP.spec_ok]
      rw [hinv, heq]
      constructor
      · rintro ⟨j, hj, e, he, ht, ha, hin⟩
        rw [List.getElem?_eq_getElem hj, Option.some.injEq] at he
        subst he
        exact ⟨defeats.val[j], List.getElem_mem hj, ht, ha, hin⟩
      · rintro ⟨e, hmem, ht, ha, hin⟩
        obtain ⟨j, hj, he⟩ := List.getElem_of_mem hmem
        exact ⟨j, hj, e, by rw [List.getElem?_eq_getElem hj, he], ht, ha, hin⟩
  · simp

private theorem is_admissible_loop_spec
    (defeats : Slice DefeatEdge) (labels : Slice Label) :
    is_admissible_loop defeats labels true 0#usize ⦃ res =>
      res = true ↔ ∀ e ∈ defeats.val,
        e.attacker.val < labels.length → e.target.val < labels.length →
        labels.val[e.target.val]? = some Label.In →
        ∃ d ∈ defeats.val, d.target = e.attacker ∧ d.attacker.val < labels.length ∧
          labels.val[d.attacker.val]? = some Label.In ⦄ := by
  unfold is_admissible_loop
  apply loop.spec_decr_nat
    (fun (p : Bool × Usize) => defeats.length - p.2.val)
    (fun (p : Bool × Usize) =>
      p.2.val ≤ defeats.length ∧
      (p.1 = true ↔ ∀ j, j < p.2.val →
        ∀ e, defeats.val[j]? = some e →
          e.attacker.val < labels.length → e.target.val < labels.length →
          labels.val[e.target.val]? = some Label.In →
          ∃ d ∈ defeats.val, d.target = e.attacker ∧ d.attacker.val < labels.length ∧
            labels.val[d.attacker.val]? = some Label.In))
  · rintro ⟨flag, index⟩ ⟨hle, hinv⟩
    simp only at hle hinv ⊢
    unfold is_admissible_loop.body
    by_cases hlt : index < Slice.len defeats
    · have hlt' : index.val < defeats.length := by scalar_tac
      cases flag with
      | false =>
        simp only [hlt, ite_true, Bool.false_eq_true, ite_false, WP.spec_ok]
        refine ⟨False.elim, fun hall => ?_⟩
        apply Bool.false_ne_true
        apply hinv.mpr
        intro j hj e he ha ht hin
        have hj_lt : j < defeats.length := by omega
        rw [List.getElem?_eq_getElem hj_lt, Option.some.injEq] at he
        subst he
        exact hall defeats.val[j] (List.getElem_mem hj_lt) ha ht hin
      | true =>
        obtain ⟨edge, hedge, hedgev⟩ := ok_of_spec (Slice.index_usize_spec defeats index hlt')
        have hedge_get : defeats.val[index.val]? = some edge := by
          rw [List.getElem?_eq_getElem hlt', hedgev]
        have hidx_max : index.val < Usize.max := by scalar_tac
        have hnext_val : (core.num.Usize.saturating_add index 1#usize).val = index.val + 1 :=
          usize_saturating_add_one_val index hidx_max
        have hall_prev := hinv.mp rfl
        by_cases ha : edge.attacker < Slice.len labels
        · have ha' : edge.attacker.val < labels.length := by scalar_tac
          by_cases ht : edge.target < Slice.len labels
          · have ht' : edge.target.val < labels.length := by scalar_tac
            obtain ⟨lt_, hlt_, hltv⟩ := ok_of_spec (Slice.index_usize_spec labels edge.target ht')
            have hlt_get : labels.val[edge.target.val]? = some lt_ := by
              rw [List.getElem?_eq_getElem ht', hltv]
            cases lt_ with
            | In =>
              obtain ⟨hd_b, hdb_eq, hdb_iff⟩ :=
                ok_of_spec (has_in_counterattacker_loop_spec edge.attacker defeats labels)
              cases hd_b with
              | true =>
                have hdef := hdb_iff.mp rfl
                simp [hlt, hedge, ha', ht', hlt_, has_in_counterattacker, hdb_eq, lift]
                rw [hnext_val]
                refine ⟨by scalar_tac, ?_, by scalar_tac⟩
                intro j hj e he hae hte hine
                by_cases hji : j = index.val
                · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he; exact hdef
                · exact hall_prev j (by omega) e he hae hte hine
              | false =>
                have hnodef : ¬ ∃ d ∈ defeats.val, d.target = edge.attacker ∧
                    d.attacker.val < labels.length ∧ labels.val[d.attacker.val]? = some Label.In :=
                  fun h => Bool.false_ne_true (hdb_iff.mpr h)
                simp [hlt, hedge, ha', ht', hlt_, has_in_counterattacker, hdb_eq, lift]
                rw [hnext_val]
                refine ⟨by scalar_tac, ?_, by scalar_tac⟩
                exact ⟨index.val, by omega, edge, hedge_get, ha', ht', hlt_get,
                  fun d hd hdt hda hdin => hnodef ⟨d, hd, hdt, hda, hdin⟩⟩
            | Out =>
              simp only [hlt, ↓reduceIte, hedge, bind_ok, ha, ht, hlt_, Bool.false_eq_true,
                lift, WP.spec_ok]
              refine ⟨⟨by omega, ?_⟩, by omega⟩
              rw [hnext_val]
              refine ⟨fun _ j hj e he hae hte hine => ?_, fun _ => trivial⟩
              by_cases hji : j = index.val
              · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he
                rw [hlt_get] at hine; cases hine
              · exact hall_prev j (by omega) e he hae hte hine
            | Undec =>
              simp only [hlt, ↓reduceIte, hedge, bind_ok, ha, ht, hlt_, Bool.false_eq_true,
                lift, WP.spec_ok]
              refine ⟨⟨by omega, ?_⟩, by omega⟩
              rw [hnext_val]
              refine ⟨fun _ j hj e he hae hte hine => ?_, fun _ => trivial⟩
              by_cases hji : j = index.val
              · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he
                rw [hlt_get] at hine; cases hine
              · exact hall_prev j (by omega) e he hae hte hine
          · have ht_ge : labels.length ≤ edge.target.val := by scalar_tac
            simp only [hlt, ↓reduceIte, hedge, bind_ok, ha, ht, lift, WP.spec_ok]
            refine ⟨⟨by omega, ?_⟩, by omega⟩
            rw [hnext_val]
            refine ⟨fun _ j hj e he hae hte hine => ?_, fun _ => trivial⟩
            by_cases hji : j = index.val
            · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he; omega
            · exact hall_prev j (by omega) e he hae hte hine
        · have ha_ge : labels.length ≤ edge.attacker.val := by scalar_tac
          simp only [hlt, ↓reduceIte, hedge, bind_ok, ha, lift, WP.spec_ok]
          refine ⟨⟨by omega, ?_⟩, by omega⟩
          rw [hnext_val]
          refine ⟨fun _ j hj e he hae hte hine => ?_, fun _ => trivial⟩
          by_cases hji : j = index.val
          · subst hji; rw [hedge_get, Option.some.injEq] at he; subst he; omega
          · exact hall_prev j (by omega) e he hae hte hine
    · have hge : defeats.length ≤ index.val := by scalar_tac
      have heq : index.val = defeats.length := by omega
      simp only [hlt, ite_false, WP.spec_ok]
      rw [hinv, heq]
      constructor
      · intro hall e hmem ha ht hin
        obtain ⟨j, hj, he⟩ := List.getElem_of_mem hmem
        exact hall j hj e (by rw [List.getElem?_eq_getElem hj, he]) ha ht hin
      · intro hall j hj e he ha ht hin
        rw [List.getElem?_eq_getElem hj, Option.some.injEq] at he
        subst he
        exact hall defeats.val[j] (List.getElem_mem hj) ha ht hin
  · simp

/-- `is_admissible` never fails or diverges. -/
theorem is_admissible_total (defeats : Slice DefeatEdge) (labels : Slice Label) :
    ∃ r, is_admissible defeats labels = ok r := by
  unfold is_admissible
  obtain ⟨cf, hcf⟩ := is_conflict_free_total defeats labels
  cases cf with
  | false => exact ⟨false, by simp [hcf]⟩
  | true =>
    obtain ⟨adm, hadm, _⟩ := ok_of_spec (is_admissible_loop_spec defeats labels)
    exact ⟨adm, by simp [hcf, hadm]⟩

/-- `is_admissible defeats labels = ok true` iff `labels` is conflict-free and every
in-bounds attacker of an `In` argument is counter-attacked by an `In` argument. -/
theorem is_admissible_iff (defeats : Slice DefeatEdge) (labels : Slice Label) :
    is_admissible defeats labels = ok true ↔
      is_conflict_free defeats labels = ok true ∧
      ∀ e ∈ defeats.val,
        e.attacker.val < labels.length → e.target.val < labels.length →
        labels.val[e.target.val]? = some Label.In →
        ∃ d ∈ defeats.val, d.target = e.attacker ∧ d.attacker.val < labels.length ∧
          labels.val[d.attacker.val]? = some Label.In := by
  unfold is_admissible
  obtain ⟨cf, hcf⟩ := is_conflict_free_total defeats labels
  cases cf with
  | false =>
    simp [hcf]
  | true =>
    obtain ⟨adm, hadm, hadm_iff⟩ := ok_of_spec (is_admissible_loop_spec defeats labels)
    simp only [hcf, bind_ok, ↓reduceIte, hadm, true_and]
    cases adm with
    | true => simpa using hadm_iff
    | false =>
      constructor
      · intro h; rw [ok.injEq] at h; cases h
      · intro hall; exact absurd (hadm_iff.mpr hall) Bool.false_ne_true

/-! ## Dung Grounded Labelling: Conflict-Freeness, Admissibility, Termination & Uniqueness -/

/-- **Conflict-freeness of every fixpoint**: any fixpoint of `next_label` is conflict-free. -/
theorem fixpoint_conflict_free (defeats : Slice DefeatEdge) (labels : Slice Label)
    (hfix : is_fixpoint defeats labels = ok true) :
    is_conflict_free defeats labels = ok true := by
  have hfp := (is_fixpoint_iff defeats labels).mp hfix
  rw [is_conflict_free_iff]
  intro e he ha ht ⟨hin_a, hin_t⟩
  have hnext := hfp e.target.val ht e.target rfl Label.In hin_t
  obtain ⟨r, hr, hOut, _⟩ := next_label_spec e.target defeats labels
  rw [hnext, ok.injEq] at hr
  subst hr
  have hout := hOut.mpr ⟨ht, e, he, rfl, ha, hin_a⟩
  cases hout

/-- **Admissibility of every fixpoint**: any fixpoint of `next_label` is admissible
(conflict-free and every attacker of an `In` argument is counter-attacked by an `In` argument). -/
theorem fixpoint_admissible (defeats : Slice DefeatEdge) (labels : Slice Label)
    (hfix : is_fixpoint defeats labels = ok true) :
    is_admissible defeats labels = ok true := by
  have hcf := fixpoint_conflict_free defeats labels hfix
  have hfp := (is_fixpoint_iff defeats labels).mp hfix
  rw [is_admissible_iff]
  refine ⟨hcf, fun e he ha ht hin_t => ?_⟩
  -- Since target is `In` at fixpoint, attacker `e.attacker` must be `Out`.
  have hnext_t := hfp e.target.val ht e.target rfl Label.In hin_t
  obtain ⟨rt, hrt, _, hIn_t⟩ := next_label_spec e.target defeats labels
  rw [hnext_t, ok.injEq] at hrt
  subst hrt
  have hout_a : labels.val[e.attacker.val]? = some Label.Out :=
    (hIn_t.mp rfl).2 e he rfl ha
  -- Since attacker is `Out` at fixpoint, some `In` argument must defeat `e.attacker`.
  have hnext_a := hfp e.attacker.val ha e.attacker rfl Label.Out hout_a
  obtain ⟨ra, hra, hOut_a, _⟩ := next_label_spec e.attacker defeats labels
  rw [hnext_a, ok.injEq] at hra
  subst hra
  exact (hOut_a.mp rfl).2

private def listToListN {α : Type} : (xs : List α) → Aeneas.Data.ListN.ListN α xs.length
  | [] => .nil
  | x :: rest => .cons x (listToListN rest)

private theorem listToListN_toList {α : Type} : ∀ (xs : List α), (listToListN xs).toList = xs
  | [] => rfl
  | x :: rest => congrArg (x :: ·) (listToListN_toList rest)

private def sliceOfList {α : Type} (xs : List α) (h : xs.length ≤ Usize.max) : Slice α :=
  Slice.mk xs.length (listToListN xs) h

private theorem sliceOfList_val {α : Type} (xs : List α) (h : xs.length ≤ Usize.max) :
    (sliceOfList xs h).val = xs :=
  listToListN_toList xs

private theorem sliceOfList_length {α : Type} (xs : List α) (h : xs.length ≤ Usize.max) :
    (sliceOfList xs h).length = xs.length := by
  simp [Slice.length, sliceOfList_val]

/-- Pure deterministic step `F_AF(labels)` extracting the `ok` result of `next_label`
for every index `0 ..< n`. -/
private noncomputable def stepList (defeats : Slice DefeatEdge) (labels : Slice Label) :
    List Label :=
  List.ofFn (fun (idx : Fin labels.length) =>
    let u : Usize := UScalar.ofNatCore idx.val (by
      have h1 : idx.val < labels.length := idx.isLt
      have h2 : labels.length ≤ Usize.max := labels.property
      have hmax : Usize.max = 2 ^ UScalarTy.Usize.numBits - 1 := by
        simp [Usize.max, Usize.numBits, UScalarTy.numBits]
      have hpos : 0 < 2 ^ UScalarTy.Usize.numBits := Nat.two_pow_pos _
      simpa [UScalar.size] using (show idx.val < 2 ^ UScalarTy.Usize.numBits by omega))
    Classical.choose (next_label_total u defeats labels))

private theorem stepList_length (defeats : Slice DefeatEdge) (labels : Slice Label) :
    (stepList defeats labels).length = labels.length :=
  List.length_ofFn

private noncomputable def stepSlice (defeats : Slice DefeatEdge) (labels : Slice Label) :
    Slice Label :=
  sliceOfList (stepList defeats labels) (by rw [stepList_length]; exact labels.property)

private theorem stepSlice_val (defeats : Slice DefeatEdge) (labels : Slice Label) :
    (stepSlice defeats labels).val = stepList defeats labels :=
  sliceOfList_val _ _

private theorem stepSlice_length (defeats : Slice DefeatEdge) (labels : Slice Label) :
    (stepSlice defeats labels).length = labels.length := by
  rw [stepSlice, sliceOfList_length, stepList_length]

private theorem usize_ofNatCore_val (i : Nat) (hlt : i < 2 ^ UScalarTy.Usize.numBits) :
    (UScalar.ofNatCore (ty := UScalarTy.Usize) i hlt).val = i :=
  rfl

private theorem stepSlice_getElem (defeats : Slice DefeatEdge) (labels : Slice Label)
    (i : Nat) (hi : i < labels.length) (u : Usize) (hu : u.val = i) :
    ∃ l, (stepSlice defeats labels).val[i]? = some l ∧
      next_label u defeats labels = ok l := by
  have hlt_size : i < 2 ^ UScalarTy.Usize.numBits := by
    have h2 : labels.length ≤ Usize.max := labels.property
    have hmax : Usize.max = 2 ^ UScalarTy.Usize.numBits - 1 := by
      simp [Usize.max, Usize.numBits, UScalarTy.numBits]
    have hpos : 0 < 2 ^ UScalarTy.Usize.numBits := Nat.two_pow_pos _
    omega
  let u0 : Usize := UScalar.ofNatCore i hlt_size
  have hu0_val : u0.val = i := usize_ofNatCore_val i hlt_size
  have hu_eq : u = u0 := (UScalar.eq_equiv u u0).mpr (by omega)
  subst hu_eq
  refine ⟨Classical.choose (next_label_total u0 defeats labels), ?_,
    Classical.choose_spec (next_label_total u0 defeats labels)⟩
  simp [stepSlice_val, stepList, hi, u0]

private theorem stepSlice_monotone (defeats : Slice DefeatEdge) (l1 l2 : Slice Label)
    (hle : infoLeList l1.val l2.val) :
    infoLeList (stepSlice defeats l1).val (stepSlice defeats l2).val := by
  have hlen1 : (stepSlice defeats l1).val.length = l1.length := by
    rw [stepSlice_val, stepList_length]
  have hlen2 : (stepSlice defeats l2).val.length = l2.length := by
    rw [stepSlice_val, stepList_length]
  have h12 : l1.length = l2.length := hle.1
  refine ⟨by omega, fun i hi a b ha hb => ?_⟩
  have hi1 : i < l1.length := by omega
  have hi2 : i < l2.length := by omega
  have hlt_size : i < 2 ^ UScalarTy.Usize.numBits := by
    have h2 : l1.length ≤ Usize.max := l1.property
    have hmax : Usize.max = 2 ^ UScalarTy.Usize.numBits - 1 := by
      simp [Usize.max, Usize.numBits, UScalarTy.numBits]
    have hpos : 0 < 2 ^ UScalarTy.Usize.numBits := Nat.two_pow_pos _
    omega
  let u : Usize := UScalar.ofNatCore i hlt_size
  have hu_val : u.val = i := usize_ofNatCore_val i hlt_size
  obtain ⟨a', ha', hna⟩ := stepSlice_getElem defeats l1 i hi1 u hu_val
  obtain ⟨b', hb', hnb⟩ := stepSlice_getElem defeats l2 i hi2 u hu_val
  rw [ha, Option.some.injEq] at ha'; subst ha'
  rw [hb, Option.some.injEq] at hb'; subst hb'
  obtain ⟨r1, r2, hr1, hr2, hrel⟩ := next_label_monotone u defeats l1 l2 h12 hle.2
  rw [hna, ok.injEq] at hr1; subst hr1
  rw [hnb, ok.injEq] at hr2; subst hr2
  exact hrel

private theorem stepSlice_eq_iff_fixpoint (defeats : Slice DefeatEdge) (labels : Slice Label) :
    (stepSlice defeats labels).val = labels.val ↔ is_fixpoint defeats labels = ok true := by
  rw [is_fixpoint_iff]
  have hlen_val : (stepSlice defeats labels).val.length = labels.val.length := by
    rw [stepSlice_val, stepList_length]
  constructor
  · intro heq i hi u hu l hl
    obtain ⟨l', hl', hnext⟩ := stepSlice_getElem defeats labels i hi u hu
    rw [heq, hl, Option.some.injEq] at hl'
    subst hl'
    exact hnext
  · intro hfp
    apply List.ext_getElem hlen_val
    intro i h1 h2
    have hi_len : i < labels.length := h2
    have hlt_size : i < 2 ^ UScalarTy.Usize.numBits := by
      have hmax : Usize.max = 2 ^ UScalarTy.Usize.numBits - 1 := by
        simp [Usize.max, Usize.numBits, UScalarTy.numBits]
      have hpos : 0 < 2 ^ UScalarTy.Usize.numBits := Nat.two_pow_pos _
      have hb : labels.length ≤ Usize.max := labels.property
      omega
    let u : Usize := UScalar.ofNatCore i hlt_size
    have hu_val : u.val = i := usize_ofNatCore_val i hlt_size
    obtain ⟨l', hl', hnext⟩ := stepSlice_getElem defeats labels i hi_len u hu_val
    have hcur := hfp i hi_len u hu_val labels.val[i] (List.getElem?_eq_getElem h2)
    rw [hnext, ok.injEq] at hcur
    have hget : (stepSlice defeats labels).val[i]? = some (stepSlice defeats labels).val[i] :=
      List.getElem?_eq_getElem h1
    rw [hget, Option.some.injEq] at hl'
    rw [hl', hcur]

/-- `k`-round Kleene iteration of `F_AF` starting from `n` all-`Undec` arguments. -/
private noncomputable def groundedIter (defeats : Slice DefeatEdge) (n : Nat) (hn : n ≤ Usize.max) :
    Nat → Slice Label
  | 0 => sliceOfList (List.replicate n Label.Undec) (by simpa using hn)
  | k + 1 => stepSlice defeats (groundedIter defeats n hn k)

private theorem groundedIter_length (defeats : Slice DefeatEdge) (n : Nat) (hn : n ≤ Usize.max)
    (k : Nat) : (groundedIter defeats n hn k).length = n := by
  induction k with
  | zero => simp [groundedIter, sliceOfList_length]
  | succ k ih => rw [groundedIter, stepSlice_length, ih]

private theorem groundedIter_val_length (defeats : Slice DefeatEdge) (n : Nat) (hn : n ≤ Usize.max)
    (k : Nat) : (groundedIter defeats n hn k).val.length = n :=
  groundedIter_length defeats n hn k

private theorem groundedIter_zero_val (defeats : Slice DefeatEdge) (n : Nat) (hn : n ≤ Usize.max) :
    (groundedIter defeats n hn 0).val = List.replicate n Label.Undec :=
  sliceOfList_val _ _

private theorem groundedIter_chain (defeats : Slice DefeatEdge) (n : Nat) (hn : n ≤ Usize.max)
    (k : Nat) :
    infoLeList (groundedIter defeats n hn k).val (groundedIter defeats n hn (k + 1)).val := by
  induction k with
  | zero =>
    refine ⟨by rw [groundedIter_val_length, groundedIter_val_length], fun i hi a b ha _ => ?_⟩
    have hi' : i < n := by rw [groundedIter_val_length] at hi; exact hi
    rw [groundedIter_zero_val, List.getElem?_replicate] at ha
    simp only [hi', ↓reduceIte, Option.some.injEq] at ha
    subst ha
    exact Or.inl rfl
  | succ k ih =>
    exact stepSlice_monotone defeats _ _ ih

private def decidedCount : List Label → Nat
  | [] => 0
  | Label.Undec :: rest => decidedCount rest
  | Label.In :: rest => 1 + decidedCount rest
  | Label.Out :: rest => 1 + decidedCount rest

private theorem decidedCount_le_length (xs : List Label) : decidedCount xs ≤ xs.length := by
  induction xs with
  | nil => simp [decidedCount]
  | cons x rest ih =>
    cases x <;> simp [decidedCount] <;> omega

private theorem decidedCount_le_of_infoLeList :
    ∀ {xs ys : List Label}, infoLeList xs ys → decidedCount xs ≤ decidedCount ys
  | [], [], _ => Nat.le_refl 0
  | x :: xs, y :: ys, h => by
    have h0 : infoLe x y := h.2 0 (by simp) x y (by simp) (by simp)
    have htail : infoLeList xs ys := by
      refine ⟨by simpa using h.1, fun i hi a b ha hb => ?_⟩
      exact h.2 (i + 1) (by simpa using hi) a b (by simpa using ha) (by simpa using hb)
    have ih := decidedCount_le_of_infoLeList htail
    rcases h0 with rfl | rfl
    · cases y <;> simp [decidedCount] <;> omega
    · cases x <;> simp [decidedCount] <;> omega
  | [], _ :: _, h => by simp [infoLeList] at h
  | _ :: _, [], h => by simp [infoLeList] at h

private theorem decidedCount_lt_of_infoLeList_ne :
    ∀ {xs ys : List Label}, infoLeList xs ys → xs ≠ ys → decidedCount xs < decidedCount ys
  | [], [], _, hne => absurd rfl hne
  | x :: xs, y :: ys, h, hne => by
    have h0 : infoLe x y := h.2 0 (by simp) x y (by simp) (by simp)
    have htail : infoLeList xs ys := by
      refine ⟨by simpa using h.1, fun i hi a b ha hb => ?_⟩
      exact h.2 (i + 1) (by simpa using hi) a b (by simpa using ha) (by simpa using hb)
    by_cases hxy : x = y
    · subst hxy
      have hxs_ne : xs ≠ ys := fun h' => hne (by rw [h'])
      have ih := decidedCount_lt_of_infoLeList_ne htail hxs_ne
      cases x <;> simp [decidedCount] <;> omega
    · rcases h0 with rfl | rfl
      · have ih := decidedCount_le_of_infoLeList htail
        cases y with
        | Undec => exact absurd rfl hxy
        | In => simp [decidedCount]; omega
        | Out => simp [decidedCount]; omega
      · exact absurd rfl hxy
  | [], _ :: _, h, _ => by simp [infoLeList] at h
  | _ :: _, [], h, _ => by simp [infoLeList] at h

private theorem groundedIter_stable (defeats : Slice DefeatEdge) (n : Nat) (hn : n ≤ Usize.max)
    (k : Nat) (hfix : (groundedIter defeats n hn (k + 1)).val = (groundedIter defeats n hn k).val) :
    ∀ m, k ≤ m → (groundedIter defeats n hn m).val = (groundedIter defeats n hn k).val := by
  intro m hkm
  induction m with
  | zero =>
    have : k = 0 := by omega
    subst this; rfl
  | succ m ih =>
    by_cases heq : k = m + 1
    · subst heq; rfl
    · have hle : k ≤ m := by omega
      have ihm := ih hle
      have hslice_eq : groundedIter defeats n hn m = groundedIter defeats n hn k :=
        Slice.ext _ _ ihm
      show (stepSlice defeats (groundedIter defeats n hn m)).val = (groundedIter defeats n hn k).val
      rw [hslice_eq]
      exact hfix

private theorem groundedIter_reaches_fixpoint_by (defeats : Slice DefeatEdge)
    (n : Nat) (hn : n ≤ Usize.max) :
    ∀ k, (groundedIter defeats n hn (k + 1)).val = (groundedIter defeats n hn k).val ∨
      k ≤ decidedCount (groundedIter defeats n hn k).val := by
  intro k
  induction k with
  | zero => exact Or.inr (Nat.zero_le _)
  | succ k ih =>
    rcases ih with hfix | hcnt
    · left
      have h1 := groundedIter_stable defeats n hn k hfix (k + 2) (by omega)
      have h2 := groundedIter_stable defeats n hn k hfix (k + 1) (by omega)
      rw [h1, h2]
    · by_cases heq : (groundedIter defeats n hn (k + 1)).val = (groundedIter defeats n hn k).val
      · left
        have h1 := groundedIter_stable defeats n hn k heq (k + 2) (by omega)
        rw [h1, heq]
      · right
        have hlt := decidedCount_lt_of_infoLeList_ne (groundedIter_chain defeats n hn k) (Ne.symm heq)
        omega

/-- **Termination in `≤ |Ar|` rounds**: starting from all-`Undec`, iterating Dung's
characteristic operator `next_label` for `n = |Ar|` rounds reaches a fixpoint. -/
theorem grounded_terminates_in_n_rounds (defeats : Slice DefeatEdge) (n : Nat)
    (hn : n ≤ Usize.max) :
    ∃ g : Slice Label, g.length = n ∧
      is_fixpoint defeats g = ok true ∧
      is_conflict_free defeats g = ok true ∧
      is_admissible defeats g = ok true ∧
      ∀ h : Slice Label, h.length = n → is_fixpoint defeats h = ok true →
        ∀ i, i < n → ∀ a b, g.val[i]? = some a → h.val[i]? = some b →
          a = Label.Undec ∨ a = b := by
  let g := groundedIter defeats n hn n
  have hglen : g.length = n := groundedIter_length defeats n hn n
  have hfix_val : (stepSlice defeats g).val = g.val := by
    rcases groundedIter_reaches_fixpoint_by defeats n hn n with hfix | hcnt
    · exact hfix
    · change n ≤ decidedCount g.val at hcnt
      have hle_n : decidedCount g.val ≤ n := by
        have hgl : g.val.length = n := groundedIter_val_length defeats n hn n
        rw [← hgl]; exact decidedCount_le_length g.val
      by_cases hne : g.val = (stepSlice defeats g).val
      · exact hne.symm
      · have hlt := decidedCount_lt_of_infoLeList_ne (groundedIter_chain defeats n hn n) hne
        change decidedCount g.val < decidedCount (stepSlice defeats g).val at hlt
        have hle_next : decidedCount (stepSlice defeats g).val ≤ n := by
          have : (stepSlice defeats g).val.length = n := by
            rw [stepSlice_val, stepList_length, hglen]
          rw [← this]; exact decidedCount_le_length _
        omega
  have hfix : is_fixpoint defeats g = ok true :=
    (stepSlice_eq_iff_fixpoint defeats g).mp hfix_val
  have hcf := fixpoint_conflict_free defeats g hfix
  have hadm := fixpoint_admissible defeats g hfix
  have hleast : ∀ k, ∀ h : Slice Label, h.length = n → is_fixpoint defeats h = ok true →
      infoLeList (groundedIter defeats n hn k).val h.val := by
    intro k h hhlen hhfix
    have hhval : h.val.length = n := hhlen
    induction k with
    | zero =>
      refine ⟨by rw [groundedIter_val_length, hhval], fun i hi a b ha _ => ?_⟩
      have hi' : i < n := by rw [groundedIter_val_length] at hi; exact hi
      rw [groundedIter_zero_val, List.getElem?_replicate] at ha
      simp only [hi', ↓reduceIte, Option.some.injEq] at ha
      subst ha
      exact Or.inl rfl
    | succ k ih =>
      have hstep := stepSlice_monotone defeats (groundedIter defeats n hn k) h ih
      have hheq : (stepSlice defeats h).val = h.val :=
        (stepSlice_eq_iff_fixpoint defeats h).mpr hhfix
      simpa [groundedIter, hheq] using hstep
  refine ⟨g, hglen, hfix, hcf, hadm, fun h hhlen hhfix i hi a b ha hb => ?_⟩
  have hle := hleast n h hhlen hhfix
  have hgl : g.val.length = n := groundedIter_val_length defeats n hn n
  exact hle.2 i (by rw [hgl]; exact hi) a b ha hb

/-- **Uniqueness of the Grounded Labelling**: any two least fixpoints of `next_label`
of length `n` are identical. -/
theorem grounded_unique (defeats : Slice DefeatEdge) (g1 g2 : Slice Label)
    (hlen : g1.length = g2.length)
    (hf1 : is_fixpoint defeats g1 = ok true)
    (hf2 : is_fixpoint defeats g2 = ok true)
    (hl1 : ∀ h : Slice Label, h.length = g1.length → is_fixpoint defeats h = ok true →
      ∀ i, i < g1.length → ∀ a b, g1.val[i]? = some a → h.val[i]? = some b →
        a = Label.Undec ∨ a = b)
    (hl2 : ∀ h : Slice Label, h.length = g2.length → is_fixpoint defeats h = ok true →
      ∀ i, i < g2.length → ∀ a b, g2.val[i]? = some a → h.val[i]? = some b →
        a = Label.Undec ∨ a = b) :
    g1.val = g2.val := by
  have h12 : infoLeList g1.val g2.val :=
    ⟨hlen, hl1 g2 hlen.symm hf2⟩
  have h21 : infoLeList g2.val g1.val :=
    ⟨hlen.symm, hl2 g1 hlen hf1⟩
  exact infoLeList_antisymm h12 h21

/-- **Permutation invariance of the Grounded Labelling**: any two defeat slices with the
same edge set have identical least fixpoints (grounded labellings). -/
theorem grounded_perm_invariant (d1 d2 : Slice DefeatEdge) (g1 g2 : Slice Label) (n : Nat)
    (heq : ∀ e, e ∈ d1.val ↔ e ∈ d2.val)
    (h1len : g1.length = n) (h2len : g2.length = n)
    (hf1 : is_fixpoint d1 g1 = ok true)
    (hf2 : is_fixpoint d2 g2 = ok true)
    (hl1 : ∀ h : Slice Label, h.length = n → is_fixpoint d1 h = ok true →
      ∀ i, i < n → ∀ a b, g1.val[i]? = some a → h.val[i]? = some b →
        a = Label.Undec ∨ a = b)
    (hl2 : ∀ h : Slice Label, h.length = n → is_fixpoint d2 h = ok true →
      ∀ i, i < n → ∀ a b, g2.val[i]? = some a → h.val[i]? = some b →
        a = Label.Undec ∨ a = b) :
    g1.val = g2.val := by
  have hfp_equiv : ∀ h : Slice Label, is_fixpoint d1 h = ok true ↔ is_fixpoint d2 h = ok true := by
    intro h
    rw [is_fixpoint_iff, is_fixpoint_iff]
    constructor <;> intro hfp i hi u hu l hl
    · rw [← next_label_perm_invariant u d1 d2 h heq]; exact hfp i hi u hu l hl
    · rw [next_label_perm_invariant u d1 d2 h heq]; exact hfp i hi u hu l hl
  have hf2_on_d1 : is_fixpoint d1 g2 = ok true := (hfp_equiv g2).mpr hf2
  exact grounded_unique d1 g1 g2 (by omega) hf1 hf2_on_d1
    (fun h hlen' hfh i hi => hl1 h (by omega) hfh i (by omega))
    (fun h hlen' hfh i hi => hl2 h (by omega) ((hfp_equiv h).mp hfh) i (by omega))

end mneme_kernel.argumentation
