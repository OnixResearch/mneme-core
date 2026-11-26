import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Convergent capability attenuation and G-Set revocation rules

Theorems about the generated translation of
`crates/mneme-kernel/src/capability.rs`:
- Authority ordering and attenuation transitivity;
- Slice membership, subset, and scope attenuation transitivity;
- Single-step `attenuation_valid` characterization and inductive non-escalation
  across arbitrary valid delegation chains;
- G-Set revocation membership, ACI laws (commutativity, associativity,
  idempotence), and monotonicity / dominance.
-/

namespace mneme_kernel.capability

private theorem spec_imp_exists {α : Type} {m : Result α} {p : α → Prop}
    (h : WP.spec m p) : ∃ v, m = ok v ∧ p v := by
  cases m with
  | ret r => exact ⟨r, rfl, by simpa using h⟩
  | vis _ _ => simp at h
  | div => simp at h

private theorem index_usize_eq {α : Type} (s : Slice α) (i : Usize)
    (h : i.val < s.val.length) :
    Slice.index_usize s i = ok (s.val[i.val]'h) := by
  obtain ⟨x, hx, hv⟩ := spec_imp_exists (Slice.index_usize_spec s i h)
  rw [hx, hv]

private theorem usize_add_one_eq {α : Type} (s : Slice α) {i : Usize}
    (h : i.val < s.val.length) :
    ∃ j, i + 1#usize = ok j ∧ j.val = i.val + 1 := by
  have hb : i.val + (1#usize).val ≤ Usize.max := by scalar_tac
  obtain ⟨j, hj, hv⟩ := spec_imp_exists (Usize.add_spec hb)
  exact ⟨j, hj, by scalar_tac⟩

private instance : DecidableEq hashing.Digest := fun a b =>
  match a, b with
  | ⟨ahi, alo⟩, ⟨bhi, blo⟩ =>
    if h1 : ahi = bhi then
      if h2 : alo = blo then isTrue (by rw [h1, h2])
      else isFalse (fun h => h2 (by cases h; rfl))
    else isFalse (fun h => h1 (by cases h; rfl))

private theorem digest_eq_spec (a b : hashing.Digest) :
    ∃ r : Bool, hashing.digest_eq a b = ok r ∧ (r = true ↔ a = b) := by
  obtain ⟨ahi, alo⟩ := a
  obtain ⟨bhi, blo⟩ := b
  unfold hashing.digest_eq
  by_cases h : ahi = bhi
  · exact ⟨decide (alo = blo), by simp [h], by simp [h]⟩
  · exact ⟨false, by simp [h], by simp [h]⟩

private theorem digest_eq_decide (a b : hashing.Digest) :
    hashing.digest_eq a b = ok (decide (a = b)) := by
  obtain ⟨r, hr, hiff⟩ := digest_eq_spec a b
  cases r with
  | true =>
    have heq : a = b := hiff.mp rfl
    simpa [heq] using hr
  | false =>
    have hne : a ≠ b := fun heq => Bool.false_ne_true (hiff.mpr heq)
    simpa [hne] using hr

private theorem slice_is_empty_eq {α : Type} (s : Slice α) :
    core.slice.Slice.is_empty s = ok (decide (s.val = [])) := by
  unfold core.slice.Slice.is_empty
  by_cases h : s.val = []
  · simp [h]
  · simp [h]

/-! ## Authority lattice -/

/-- `authority_rank` orders `ReadOnly (1) < SyncPull (2) < SyncPush (3)`. -/
theorem authority_rank_order :
    authority_rank Authority.ReadOnly = ok 1#u8 ∧
      authority_rank Authority.SyncPull = ok 2#u8 ∧
      authority_rank Authority.SyncPush = ok 3#u8 := by
  simp [authority_rank]

/-- `authority_permits held required` holds exactly when `held` may attenuate to `required`. -/
theorem authority_permits_iff (held required : Authority) :
    ∃ r, authority_permits held required = ok r ∧
      (r = true ↔ authority_attenuates held required = ok true) := by
  cases held <;> cases required <;> simp [authority_permits, authority_attenuates, authority_rank]

/-- Authority attenuation is reflexive. -/
theorem authority_attenuates_refl (level : Authority) :
    authority_attenuates level level = ok true := by
  cases level <;> simp [authority_attenuates, authority_rank]

/-- Authority attenuation is transitive: no chain of valid attenuations can escalate authority. -/
theorem authority_attenuates_trans (root mid leaf : Authority)
    (h1 : authority_attenuates root mid = ok true)
    (h2 : authority_attenuates mid leaf = ok true) :
    authority_attenuates root leaf = ok true := by
  cases root <;> cases mid <;> cases leaf <;>
    simp_all [authority_attenuates, authority_rank]

/-! ## `digest_in_slice` and `slice_is_subset` -/

private theorem digest_in_slice_loop_spec (needle : hashing.Digest)
    (haystack : Slice hashing.Digest) (found : Bool) (index : Usize)
    (hindex : index.val ≤ haystack.val.length) :
    digest_in_slice_loop needle haystack found index ⦃ r =>
      r = (found || (haystack.val.drop index.val).any (fun d => decide (needle = d))) ⦄ := by
  unfold digest_in_slice_loop
  apply loop.spec_decr_nat
    (fun (x : Bool × Usize) => haystack.val.length - x.2.val)
    (fun (x : Bool × Usize) => x.2.val ≤ haystack.val.length ∧
      (x.1 || (haystack.val.drop x.2.val).any (fun d => decide (needle = d))) =
        (found || (haystack.val.drop index.val).any (fun d => decide (needle = d))))
  · rintro ⟨f, i⟩ ⟨hi, hinv⟩
    simp only at hi hinv ⊢
    unfold digest_in_slice_loop.body
    by_cases hlt : i < Slice.len haystack
    · have hlt' : i.val < haystack.val.length := by scalar_tac
      cases f with
      | true =>
        simp only [hlt, ↓reduceIte, WP.spec_ok]
        simpa using hinv.symm
      | false =>
        obtain ⟨j, hj, hjv⟩ := usize_add_one_eq haystack hlt'
        simp only [hlt, ↓reduceIte, Bool.false_eq_true, index_usize_eq haystack i hlt', bind_ok,
          digest_eq_decide, hj, WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        rw [← hinv, hjv, List.drop_eq_getElem_cons hlt']
        simp only [List.any_cons, Bool.false_or]
    · have heq : i.val = haystack.val.length := by scalar_tac
      simp only [hlt, ↓reduceIte, WP.spec_ok]
      rw [← hinv, heq, List.drop_length]
      simp
  · exact ⟨hindex, rfl⟩

/-- `digest_in_slice` never fails and returns `true` exactly when `needle` is in `haystack`. -/
theorem digest_in_slice_iff (needle : hashing.Digest) (haystack : Slice hashing.Digest) :
    ∃ found, digest_in_slice needle haystack = ok found ∧
      (found = true ↔ needle ∈ haystack.val) := by
  have hspec := digest_in_slice_loop_spec needle haystack false 0#usize (by simp)
  obtain ⟨r, hr, hval⟩ := spec_imp_exists hspec
  refine ⟨r, hr, ?_⟩
  simp only [UScalar.ofNatCore_val_eq, List.drop_zero, Bool.false_or] at hval
  rw [hval, List.any_eq_true]
  constructor
  · rintro ⟨d, hd, hdec⟩
    have heq : needle = d := of_decide_eq_true hdec
    rwa [heq]
  · intro hmem
    exact ⟨needle, hmem, by simp⟩

private theorem digest_in_slice_eq (needle : hashing.Digest) (haystack : Slice hashing.Digest) :
    digest_in_slice needle haystack = ok (haystack.val.any (fun d => decide (needle = d))) := by
  have hspec := digest_in_slice_loop_spec needle haystack false 0#usize (by simp)
  obtain ⟨r, hr, hval⟩ := spec_imp_exists hspec
  simp only [UScalar.ofNatCore_val_eq, List.drop_zero, Bool.false_or] at hval
  rwa [hval] at hr

private theorem slice_is_subset_loop_spec (child parent : Slice hashing.Digest)
    (all_present : Bool) (index : Usize) (hindex : index.val ≤ child.val.length) :
    slice_is_subset_loop child parent all_present index ⦃ r =>
      r = (all_present &&
        (child.val.drop index.val).all
          (fun c => parent.val.any (fun p => decide (c = p)))) ⦄ := by
  unfold slice_is_subset_loop
  apply loop.spec_decr_nat
    (fun (x : Bool × Usize) => child.val.length - x.2.val)
    (fun (x : Bool × Usize) => x.2.val ≤ child.val.length ∧
      (x.1 &&
        (child.val.drop x.2.val).all
          (fun c => parent.val.any (fun p => decide (c = p)))) =
        (all_present &&
          (child.val.drop index.val).all
            (fun c => parent.val.any (fun p => decide (c = p)))))
  · rintro ⟨ok_so_far, i⟩ ⟨hi, hinv⟩
    simp only at hi hinv ⊢
    unfold slice_is_subset_loop.body
    by_cases hlt : i < Slice.len child
    · have hlt' : i.val < child.val.length := by scalar_tac
      cases ok_so_far with
      | true =>
        obtain ⟨j, hj, hjv⟩ := usize_add_one_eq child hlt'
        simp only [hlt, ↓reduceIte, index_usize_eq child i hlt', bind_ok,
          digest_in_slice_eq, hj, WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        rw [← hinv, hjv, List.drop_eq_getElem_cons hlt']
        simp only [List.all_cons, Bool.true_and]
      | false =>
        simp only [hlt, ↓reduceIte, Bool.false_eq_true, WP.spec_ok]
        simpa using hinv.symm
    · have heq : i.val = child.val.length := by scalar_tac
      simp only [hlt, ↓reduceIte, WP.spec_ok]
      rw [← hinv, heq, List.drop_length]
      simp
  · exact ⟨hindex, rfl⟩

/-- `slice_is_subset` never fails and returns `true` exactly when every element
    of `child` appears in `parent`. -/
theorem slice_is_subset_iff (child parent : Slice hashing.Digest) :
    ∃ ok_sub, slice_is_subset child parent = ok ok_sub ∧
      (ok_sub = true ↔ ∀ x, x ∈ child.val → x ∈ parent.val) := by
  have hspec := slice_is_subset_loop_spec child parent true 0#usize (by simp)
  obtain ⟨r, hr, hval⟩ := spec_imp_exists hspec
  refine ⟨r, hr, ?_⟩
  simp only [UScalar.ofNatCore_val_eq, List.drop_zero, Bool.true_and] at hval
  rw [hval, List.all_eq_true]
  constructor
  · intro hall x hx
    have hany := hall x hx
    rw [List.any_eq_true] at hany
    obtain ⟨p, hp, hdec⟩ := hany
    have heq : x = p := of_decide_eq_true hdec
    rwa [heq]
  · intro hsub x hx
    rw [List.any_eq_true]
    exact ⟨x, hsub x hx, by simp⟩

/-! ## `scope_subset` -/

/-- `scope_subset` never fails or diverges. -/
theorem scope_subset_total (child_mode : ScopeMode) (child_scopes : Slice hashing.Digest)
    (parent_mode : ScopeMode) (parent_scopes : Slice hashing.Digest) :
    ∃ allowed, scope_subset child_mode child_scopes parent_mode parent_scopes = ok allowed := by
  cases child_mode <;> cases parent_mode
  · exact ⟨true, by simp [scope_subset]⟩
  · exact ⟨false, by simp [scope_subset]⟩
  · exact ⟨!decide (child_scopes.val = []), by rw [scope_subset, slice_is_empty_eq]; simp⟩
  · unfold scope_subset
    rw [slice_is_empty_eq child_scopes]
    by_cases hc : child_scopes.val = []
    · simp [hc]
    · simp only [hc, decide_false, bind_ok, Bool.false_eq_true, ↓reduceIte]
      rw [slice_is_empty_eq parent_scopes]
      by_cases hp : parent_scopes.val = []
      · simp [hp]
      · simp only [hp, decide_false, bind_ok, Bool.false_eq_true, ↓reduceIte]
        obtain ⟨ok_sub, hsub, _⟩ := slice_is_subset_iff child_scopes parent_scopes
        exact ⟨ok_sub, hsub⟩

/-- Exact characterization of `scope_subset`. -/
theorem scope_subset_iff (child_mode : ScopeMode) (child_scopes : Slice hashing.Digest)
    (parent_mode : ScopeMode) (parent_scopes : Slice hashing.Digest) :
    scope_subset child_mode child_scopes parent_mode parent_scopes = ok true ↔
      (child_mode = ScopeMode.Wildcard ∧ parent_mode = ScopeMode.Wildcard) ∨
      (child_mode = ScopeMode.Explicit ∧ child_scopes.val ≠ [] ∧
        parent_mode = ScopeMode.Wildcard) ∨
      (child_mode = ScopeMode.Explicit ∧ parent_mode = ScopeMode.Explicit ∧
        child_scopes.val ≠ [] ∧ parent_scopes.val ≠ [] ∧
        ∀ x, x ∈ child_scopes.val → x ∈ parent_scopes.val) := by
  cases child_mode <;> cases parent_mode
  · simp [scope_subset]
  · simp [scope_subset]
  · unfold scope_subset
    rw [slice_is_empty_eq child_scopes]
    by_cases hc : child_scopes.val = [] <;> simp [hc]
  · unfold scope_subset
    rw [slice_is_empty_eq child_scopes]
    by_cases hc : child_scopes.val = []
    · simp [hc]
    · simp only [hc, decide_false, bind_ok, Bool.false_eq_true, ↓reduceIte]
      rw [slice_is_empty_eq parent_scopes]
      by_cases hp : parent_scopes.val = []
      · simp [hp]
      · simp only [hp, decide_false, bind_ok, Bool.false_eq_true, ↓reduceIte]
        obtain ⟨ok_sub, hsub, hiff⟩ := slice_is_subset_iff child_scopes parent_scopes
        rw [hsub]
        simp only [Result.ok.injEq, reduceCtorEq, and_false, false_or, ne_eq, hc, not_false_eq_true,
          hp, true_and]
        exact hiff

/-- Scope attenuation is transitive: delegating through any intermediate scope
    can never widen beyond the parent scope. -/
theorem scope_subset_trans
    (c_mode : ScopeMode) (c_scopes : Slice hashing.Digest)
    (m_mode : ScopeMode) (m_scopes : Slice hashing.Digest)
    (p_mode : ScopeMode) (p_scopes : Slice hashing.Digest)
    (hcm : scope_subset c_mode c_scopes m_mode m_scopes = ok true)
    (hmp : scope_subset m_mode m_scopes p_mode p_scopes = ok true) :
    scope_subset c_mode c_scopes p_mode p_scopes = ok true := by
  rw [scope_subset_iff] at hcm hmp ⊢
  rcases hcm with ⟨rfl, rfl⟩ | ⟨rfl, hcne, rfl⟩ | ⟨rfl, rfl, hcne, _, hsub_cm⟩
  · rcases hmp with ⟨_, rfl⟩ | ⟨h, _, _⟩ | ⟨h, _, _, _, _⟩
    · exact Or.inl ⟨rfl, rfl⟩
    · cases h
    · cases h
  · rcases hmp with ⟨_, rfl⟩ | ⟨h, _, _⟩ | ⟨h, _, _, _, _⟩
    · exact Or.inr (Or.inl ⟨rfl, hcne, rfl⟩)
    · cases h
    · cases h
  · rcases hmp with ⟨h, _⟩ | ⟨_, _, rfl⟩ | ⟨_, rfl, _, hpne, hsub_mp⟩
    · cases h
    · exact Or.inr (Or.inl ⟨rfl, hcne, rfl⟩)
    · exact Or.inr (Or.inr ⟨rfl, rfl, hcne, hpne, fun x hx => hsub_mp x (hsub_cm x hx)⟩)

/-! ## `attenuation_valid` and arbitrary-chain non-escalation -/

/-- `attenuation_valid` never fails or diverges. -/
theorem attenuation_valid_total (parent : LinkPolicy) (parent_scopes : Slice hashing.Digest)
    (child : LinkPolicy) (child_scopes : Slice hashing.Digest) (depth max_depth : U8) :
    ∃ ok_att, attenuation_valid parent parent_scopes child child_scopes depth max_depth =
      ok ok_att := by
  unfold attenuation_valid
  obtain ⟨bv, hbv, _⟩ := digest_eq_spec child.vault_id parent.vault_id
  rw [hbv]
  cases bv with
  | false => exact ⟨false, by simp⟩
  | true =>
    simp only [bind_ok, ↓reduceIte]
    have ha : ∃ ba, authority_attenuates parent.authority child.authority = ok ba := by
      cases parent.authority <;> cases child.authority <;>
        simp [authority_attenuates, authority_rank]
    obtain ⟨ba, hba⟩ := ha
    rw [hba]
    cases ba with
    | false => exact ⟨false, by simp⟩
    | true =>
      simp only [bind_ok, ↓reduceIte]
      obtain ⟨bs, hbs⟩ :=
        scope_subset_total child.scope_mode child_scopes parent.scope_mode parent_scopes
      rw [hbs]
      cases bs with
      | false => exact ⟨false, by simp⟩
      | true =>
        simp only [bind_ok, ↓reduceIte]
        by_cases he : child.expires_at ≤ parent.expires_at
        · simp only [he, ↓reduceIte]
          by_cases hd : child.remaining_depth < parent.remaining_depth
          · exact ⟨decide (depth ≤ max_depth), by simp [hd]⟩
          · exact ⟨false, by simp [hd]⟩
        · exact ⟨false, by simp [he]⟩

/-- Exact characterization of `attenuation_valid`. -/
theorem attenuation_valid_iff (parent : LinkPolicy) (parent_scopes : Slice hashing.Digest)
    (child : LinkPolicy) (child_scopes : Slice hashing.Digest) (depth max_depth : U8) :
    attenuation_valid parent parent_scopes child child_scopes depth max_depth = ok true ↔
      child.vault_id = parent.vault_id ∧
        authority_attenuates parent.authority child.authority = ok true ∧
        scope_subset child.scope_mode child_scopes parent.scope_mode parent_scopes = ok true ∧
        child.expires_at.val ≤ parent.expires_at.val ∧
        child.remaining_depth.val < parent.remaining_depth.val ∧
        depth.val ≤ max_depth.val := by
  unfold attenuation_valid
  obtain ⟨bv, hbv, hbv_iff⟩ := digest_eq_spec child.vault_id parent.vault_id
  rw [hbv]
  cases bv with
  | false =>
    have hne : child.vault_id ≠ parent.vault_id :=
      fun heq => Bool.false_ne_true (hbv_iff.mpr heq)
    simp [hne]
  | true =>
    have hveq : child.vault_id = parent.vault_id := hbv_iff.mp rfl
    simp only [bind_ok, ↓reduceIte, hveq, true_and]
    have ha : ∃ ba, authority_attenuates parent.authority child.authority = ok ba := by
      cases parent.authority <;> cases child.authority <;>
        simp [authority_attenuates, authority_rank]
    obtain ⟨ba, hba⟩ := ha
    rw [hba]
    cases ba with
    | false => simp
    | true =>
      simp only [bind_ok, ↓reduceIte, true_and]
      obtain ⟨bs, hbs⟩ :=
        scope_subset_total child.scope_mode child_scopes parent.scope_mode parent_scopes
      rw [hbs]
      cases bs with
      | false => simp
      | true =>
        simp only [bind_ok, ↓reduceIte, true_and]
        have hexp : (child.expires_at ≤ parent.expires_at) ↔
            child.expires_at.val ≤ parent.expires_at.val := by
          simp [UScalar.le_equiv]
        have hrem : (child.remaining_depth < parent.remaining_depth) ↔
            child.remaining_depth.val < parent.remaining_depth.val := by
          simp [UScalar.lt_equiv]
        have hdep : (depth ≤ max_depth) ↔ depth.val ≤ max_depth.val := by
          simp [UScalar.le_equiv]
        by_cases he : child.expires_at ≤ parent.expires_at
        · have he' : child.expires_at.val ≤ parent.expires_at.val := hexp.mp he
          simp only [he, ↓reduceIte, he', true_and]
          by_cases hr : child.remaining_depth < parent.remaining_depth
          · have hr' : child.remaining_depth.val < parent.remaining_depth.val := hrem.mp hr
            simp [hr, hr', hdep]
          · have hr' : ¬ child.remaining_depth.val < parent.remaining_depth.val :=
              fun h => hr (hrem.mpr h)
            simp [hr, hr']
        · have he' : ¬ child.expires_at.val ≤ parent.expires_at.val :=
            fun h => he (hexp.mpr h)
          simp [he, he']

/-- Inductive validity of a delegation chain: every adjacent `(parent, child)`
    pair passes `attenuation_valid` at some depth bounded by `max_depth`. -/
def ValidChain (max_depth : U8) : List (LinkPolicy × Slice hashing.Digest) → Prop
  | [] => True
  | [_] => True
  | p :: c :: rest =>
    (∃ d : U8, attenuation_valid p.1 p.2 c.1 c.2 d max_depth = ok true) ∧
      ValidChain max_depth (c :: rest)

/-- Transitive non-escalation across arbitrary valid delegation chains:
    a leaf link can never change vault binding or exceed the root's authority,
    scope, expiration, or remaining delegation depth. -/
theorem chain_non_escalation (max_depth : U8)
    (root leaf : LinkPolicy × Slice hashing.Digest)
    (middle : List (LinkPolicy × Slice hashing.Digest))
    (hvalid : ValidChain max_depth (root :: (middle ++ [leaf]))) :
    leaf.1.vault_id = root.1.vault_id ∧
      authority_attenuates root.1.authority leaf.1.authority = ok true ∧
      scope_subset leaf.1.scope_mode leaf.2 root.1.scope_mode root.2 = ok true ∧
      leaf.1.expires_at.val ≤ root.1.expires_at.val ∧
      leaf.1.remaining_depth.val < root.1.remaining_depth.val := by
  induction middle generalizing root with
  | nil =>
    simp only [List.nil_append, ValidChain] at hvalid
    obtain ⟨⟨d, hd⟩, _⟩ := hvalid
    rw [attenuation_valid_iff] at hd
    exact ⟨hd.1, hd.2.1, hd.2.2.1, hd.2.2.2.1, hd.2.2.2.2.1⟩
  | cons mid rest ih =>
    simp only [List.cons_append, ValidChain] at hvalid
    obtain ⟨⟨d, hd⟩, htail⟩ := hvalid
    rw [attenuation_valid_iff] at hd
    have hrest := ih mid htail
    refine ⟨hrest.1.trans hd.1, ?_, ?_, ?_, ?_⟩
    · exact authority_attenuates_trans root.1.authority mid.1.authority leaf.1.authority
        hd.2.1 hrest.2.1
    · exact scope_subset_trans leaf.1.scope_mode leaf.2 mid.1.scope_mode mid.2
        root.1.scope_mode root.2 hrest.2.2.1 hd.2.2.1
    · omega
    · omega

/-! ## G-Set revocation checks and ACI / monotonicity laws -/

private theorem token_in_revocations_loop_spec (token : U128) (revocations : Slice U128)
    (found : Bool) (index : Usize) (hindex : index.val ≤ revocations.val.length) :
    token_in_revocations_loop token revocations found index ⦃ r =>
      r = (found || (revocations.val.drop index.val).any (fun t => decide (token = t))) ⦄ := by
  unfold token_in_revocations_loop
  apply loop.spec_decr_nat
    (fun (x : Bool × Usize) => revocations.val.length - x.2.val)
    (fun (x : Bool × Usize) => x.2.val ≤ revocations.val.length ∧
      (x.1 || (revocations.val.drop x.2.val).any (fun t => decide (token = t))) =
        (found || (revocations.val.drop index.val).any (fun t => decide (token = t))))
  · rintro ⟨f, i⟩ ⟨hi, hinv⟩
    simp only at hi hinv ⊢
    unfold token_in_revocations_loop.body
    by_cases hlt : i < Slice.len revocations
    · have hlt' : i.val < revocations.val.length := by scalar_tac
      cases f with
      | true =>
        simp only [hlt, ↓reduceIte, WP.spec_ok]
        simpa using hinv.symm
      | false =>
        obtain ⟨j, hj, hjv⟩ := usize_add_one_eq revocations hlt'
        simp only [hlt, ↓reduceIte, Bool.false_eq_true, index_usize_eq revocations i hlt',
          bind_ok, hj, WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        rw [← hinv, hjv, List.drop_eq_getElem_cons hlt']
        simp only [List.any_cons, Bool.false_or]
    · have heq : i.val = revocations.val.length := by scalar_tac
      simp only [hlt, ↓reduceIte, WP.spec_ok]
      rw [← hinv, heq, List.drop_length]
      simp
  · exact ⟨hindex, rfl⟩

/-- `token_in_revocations` never fails and returns `true` exactly when `token`
    appears in `revocations`. -/
theorem token_in_revocations_iff (token : U128) (revocations : Slice U128) :
    ∃ found, token_in_revocations token revocations = ok found ∧
      (found = true ↔ token ∈ revocations.val) := by
  have hspec := token_in_revocations_loop_spec token revocations false 0#usize (by simp)
  obtain ⟨r, hr, hval⟩ := spec_imp_exists hspec
  refine ⟨r, hr, ?_⟩
  simp only [UScalar.ofNatCore_val_eq, List.drop_zero, Bool.false_or] at hval
  rw [hval, List.any_eq_true]
  constructor
  · rintro ⟨t, ht, hdec⟩
    have heq : token = t := of_decide_eq_true hdec
    rwa [heq]
  · intro hmem
    exact ⟨token, hmem, by simp⟩

private theorem token_in_revocations_eq (token : U128) (revocations : Slice U128) :
    token_in_revocations token revocations =
      ok (revocations.val.any (fun t => decide (token = t))) := by
  have hspec := token_in_revocations_loop_spec token revocations false 0#usize (by simp)
  obtain ⟨r, hr, hval⟩ := spec_imp_exists hspec
  simp only [UScalar.ofNatCore_val_eq, List.drop_zero, Bool.false_or] at hval
  rwa [hval] at hr

private theorem is_revoked_loop_spec (chain_ids revocations : Slice U128)
    (revoked : Bool) (index : Usize) (hindex : index.val ≤ chain_ids.val.length) :
    is_revoked_loop chain_ids revocations revoked index ⦃ r =>
      r = (revoked ||
        (chain_ids.val.drop index.val).any
          (fun id => revocations.val.any (fun t => decide (id = t)))) ⦄ := by
  unfold is_revoked_loop
  apply loop.spec_decr_nat
    (fun (x : Bool × Usize) => chain_ids.val.length - x.2.val)
    (fun (x : Bool × Usize) => x.2.val ≤ chain_ids.val.length ∧
      (x.1 ||
        (chain_ids.val.drop x.2.val).any
          (fun id => revocations.val.any (fun t => decide (id = t)))) =
        (revoked ||
          (chain_ids.val.drop index.val).any
            (fun id => revocations.val.any (fun t => decide (id = t)))))
  · rintro ⟨f, i⟩ ⟨hi, hinv⟩
    simp only at hi hinv ⊢
    unfold is_revoked_loop.body
    by_cases hlt : i < Slice.len chain_ids
    · have hlt' : i.val < chain_ids.val.length := by scalar_tac
      cases f with
      | true =>
        simp only [hlt, ↓reduceIte, WP.spec_ok]
        simpa using hinv.symm
      | false =>
        obtain ⟨j, hj, hjv⟩ := usize_add_one_eq chain_ids hlt'
        simp only [hlt, ↓reduceIte, Bool.false_eq_true, index_usize_eq chain_ids i hlt',
          bind_ok, token_in_revocations_eq, hj, WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        rw [← hinv, hjv, List.drop_eq_getElem_cons hlt']
        simp only [List.any_cons, Bool.false_or]
    · have heq : i.val = chain_ids.val.length := by scalar_tac
      simp only [hlt, ↓reduceIte, WP.spec_ok]
      rw [← hinv, heq, List.drop_length]
      simp
  · exact ⟨hindex, rfl⟩

/-- `is_revoked` never fails and returns `true` exactly when some token ID in
    `chain_ids` is present in `revocations`. -/
theorem is_revoked_iff (chain_ids revocations : Slice U128) :
    ∃ revoked, is_revoked chain_ids revocations = ok revoked ∧
      (revoked = true ↔ ∃ id, id ∈ chain_ids.val ∧ id ∈ revocations.val) := by
  have hspec := is_revoked_loop_spec chain_ids revocations false 0#usize (by simp)
  obtain ⟨r, hr, hval⟩ := spec_imp_exists hspec
  refine ⟨r, hr, ?_⟩
  simp only [UScalar.ofNatCore_val_eq, List.drop_zero, Bool.false_or] at hval
  rw [hval, List.any_eq_true]
  constructor
  · rintro ⟨id, hid, hany⟩
    rw [List.any_eq_true] at hany
    obtain ⟨t, ht, hdec⟩ := hany
    have heq : id = t := of_decide_eq_true hdec
    exact ⟨id, hid, heq ▸ ht⟩
  · rintro ⟨id, hid, hrev⟩
    refine ⟨id, hid, ?_⟩
    rw [List.any_eq_true]
    exact ⟨id, hrev, by simp⟩

/-- G-Set revocation monotonicity: adding tombstones can never un-revoke a chain. -/
theorem is_revoked_monotone (chain_ids revs1 revs2 : Slice U128)
    (hsub : ∀ x, x ∈ revs1.val → x ∈ revs2.val)
    (hrev : is_revoked chain_ids revs1 = ok true) :
    is_revoked chain_ids revs2 = ok true := by
  obtain ⟨r1, hr1, hiff1⟩ := is_revoked_iff chain_ids revs1
  obtain ⟨r2, hr2, hiff2⟩ := is_revoked_iff chain_ids revs2
  rw [hr1] at hrev
  have hr1_true : r1 = true := by simpa using hrev
  obtain ⟨id, hchain, hmem1⟩ := hiff1.mp hr1_true
  have hr2_true : r2 = true := hiff2.mpr ⟨id, hchain, hsub id hmem1⟩
  rwa [hr2_true] at hr2

/-- `revocation_state` returns `Revoked` exactly when any link in `chain_ids` is revoked. -/
theorem revocation_state_iff (chain_ids revocations : Slice U128) :
    ∃ state, revocation_state chain_ids revocations = ok state ∧
      (state = RevocationState.Revoked ↔ ∃ id, id ∈ chain_ids.val ∧ id ∈ revocations.val) := by
  obtain ⟨r, hr, hiff⟩ := is_revoked_iff chain_ids revocations
  unfold revocation_state
  rw [hr]
  cases r with
  | false =>
    refine ⟨RevocationState.Active, by simp, ?_⟩
    simpa using hiff
  | true =>
    refine ⟨RevocationState.Revoked, by simp, ?_⟩
    simpa using hiff

/-- `merge_revocation_state` is commutative. -/
theorem merge_revocation_state_comm (left right : RevocationState) :
    ∃ r, merge_revocation_state left right = ok r ∧ merge_revocation_state right left = ok r := by
  cases left <;> cases right <;> simp [merge_revocation_state]

/-- `merge_revocation_state` is associative. -/
theorem merge_revocation_state_assoc (a b c : RevocationState) :
    ∃ ab bc r, merge_revocation_state a b = ok ab ∧
      merge_revocation_state b c = ok bc ∧
      merge_revocation_state ab c = ok r ∧
      merge_revocation_state a bc = ok r := by
  cases a <;> cases b <;> cases c <;> simp [merge_revocation_state]

/-- `merge_revocation_state` is idempotent. -/
theorem merge_revocation_state_idem (state : RevocationState) :
    merge_revocation_state state state = ok state := by
  cases state <;> simp [merge_revocation_state]

/-- Dominance: once revoked on either side, merging always yields `Revoked`. -/
theorem merge_revocation_state_dominance (left right : RevocationState)
    (h : left = RevocationState.Revoked ∨ right = RevocationState.Revoked) :
    merge_revocation_state left right = ok RevocationState.Revoked := by
  rcases h with rfl | rfl
  · simp [merge_revocation_state]
  · cases left <;> simp [merge_revocation_state]

/-- Exact characterization of `is_revoked_in_merge` as the G-Set union of `left` and `right`. -/
theorem is_revoked_in_merge_iff (chain_ids left right : Slice U128) :
    ∃ revoked, is_revoked_in_merge chain_ids left right = ok revoked ∧
      (revoked = true ↔
        (∃ id, id ∈ chain_ids.val ∧ id ∈ left.val) ∨
        (∃ id, id ∈ chain_ids.val ∧ id ∈ right.val)) := by
  obtain ⟨sl, hsl, hiffl⟩ := revocation_state_iff chain_ids left
  obtain ⟨sr, hsr, hiffr⟩ := revocation_state_iff chain_ids right
  unfold is_revoked_in_merge
  rw [hsl, hsr]
  cases sl <;> cases sr
  · refine ⟨false, by simp [merge_revocation_state], ?_⟩
    simp [← hiffl, ← hiffr]
  · refine ⟨true, by simp [merge_revocation_state], ?_⟩
    simp [← hiffr]
  · refine ⟨true, by simp [merge_revocation_state], ?_⟩
    simp [← hiffl]
  · refine ⟨true, by simp [merge_revocation_state], ?_⟩
    simp [← hiffl]

/-- G-Set revocation merge is commutative over arbitrary revocation slices. -/
theorem is_revoked_in_merge_comm (chain_ids left right : Slice U128) :
    ∃ revoked, is_revoked_in_merge chain_ids left right = ok revoked ∧
      is_revoked_in_merge chain_ids right left = ok revoked := by
  obtain ⟨r1, h1, hiff1⟩ := is_revoked_in_merge_iff chain_ids left right
  obtain ⟨r2, h2, hiff2⟩ := is_revoked_in_merge_iff chain_ids right left
  have heq : r1 = r2 := by
    cases r1 <;> cases r2
    · rfl
    · exfalso
      have h := hiff2.mp rfl
      exact Bool.false_ne_true (hiff1.mpr (Or.symm h))
    · exfalso
      have h := hiff1.mp rfl
      exact Bool.false_ne_true (hiff2.mpr (Or.symm h))
    · rfl
  exact ⟨r1, h1, heq ▸ h2⟩

/-- G-Set revocation merge is idempotent: merging a revocation set with itself
    matches checking that set directly. -/
theorem is_revoked_in_merge_idem (chain_ids revs : Slice U128) :
    ∃ revoked, is_revoked_in_merge chain_ids revs revs = ok revoked ∧
      is_revoked chain_ids revs = ok revoked := by
  obtain ⟨r1, h1, hiff1⟩ := is_revoked_in_merge_iff chain_ids revs revs
  obtain ⟨r2, h2, hiff2⟩ := is_revoked_iff chain_ids revs
  have heq : r1 = r2 := by
    cases r1 <;> cases r2
    · rfl
    · exfalso
      have h := hiff2.mp rfl
      exact Bool.false_ne_true (hiff1.mpr (Or.inl h))
    · exfalso
      have h := hiff1.mp rfl
      rcases h with h | h <;> exact Bool.false_ne_true (hiff2.mpr h)
    · rfl
  exact ⟨r1, h1, heq ▸ h2⟩

/-- G-Set revocation merge is monotone: if a chain is revoked in either replica,
    it remains revoked after merging in any order. -/
theorem is_revoked_in_merge_monotone (chain_ids left right : Slice U128)
    (h : is_revoked chain_ids left = ok true ∨ is_revoked chain_ids right = ok true) :
    is_revoked_in_merge chain_ids left right = ok true := by
  obtain ⟨rm, hrm, hiffm⟩ := is_revoked_in_merge_iff chain_ids left right
  have htrue : rm = true := by
    rcases h with hl | hr
    · obtain ⟨rl, hrl, hiffl⟩ := is_revoked_iff chain_ids left
      rw [hrl] at hl
      have hrl_true : rl = true := by simpa using hl
      exact hiffm.mpr (Or.inl (hiffl.mp hrl_true))
    · obtain ⟨rr, hrr, hiffr⟩ := is_revoked_iff chain_ids right
      rw [hrr] at hr
      have hrr_true : rr = true := by simpa using hr
      exact hiffm.mpr (Or.inr (hiffr.mp hrr_true))
  rwa [htrue] at hrm

end mneme_kernel.capability
