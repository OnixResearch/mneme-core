import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# CALM monotonicity stratification and `CalmSeal` gating

Theorems about the generated translation of `crates/mneme-kernel/src/calm.rs`.
Every Stratum M suppression join is inflationary, associative, commutative,
and idempotent; unsealed federated Stratum B negated queries never emit
`absence_established = true`.
-/

namespace mneme_kernel.calm

/-! ## `classify_op` and `requires_barrier` -/

/-- `classify_op` never fails or diverges. -/
theorem classify_op_total (op : DistributedOp) :
    ∃ s, classify_op op = ok s := by
  cases op <;> simp [classify_op]

/-- All four Stratum M operations classify as `CalmStratum.Monotonic`. -/
theorem classify_op_monotonic :
    classify_op DistributedOp.AppendImmutableRecord = ok CalmStratum.Monotonic ∧
      classify_op DistributedOp.MergeRevocationTombstone = ok CalmStratum.Monotonic ∧
      classify_op DistributedOp.MergeSuppression = ok CalmStratum.Monotonic ∧
      classify_op DistributedOp.PositiveFederatedDatalog = ok CalmStratum.Monotonic := by
  simp [classify_op]

/-- All three Stratum B operations classify as `CalmStratum.Barrier`. -/
theorem classify_op_barrier :
    classify_op DistributedOp.PromoteDecision = ok CalmStratum.Barrier ∧
      classify_op DistributedOp.NegatedFederatedDatalog = ok CalmStratum.Barrier ∧
      classify_op DistributedOp.SharedBlobPhysicalGc = ok CalmStratum.Barrier := by
  simp [classify_op]

/-- `requires_barrier` never fails or diverges. -/
theorem requires_barrier_total (op : DistributedOp) :
    ∃ b, requires_barrier op = ok b := by
  cases op <;> simp [requires_barrier, classify_op]

/-- `requires_barrier` holds exactly for Stratum B operations. -/
theorem requires_barrier_iff (op : DistributedOp) :
    requires_barrier op = ok true ↔ classify_op op = ok CalmStratum.Barrier := by
  cases op <;> simp [requires_barrier, classify_op]

/-! ## `suppression_rank` and `join_suppression_level` -/

/-- `suppression_rank` never fails or diverges. -/
theorem suppression_rank_total (level : SuppressionLevel) :
    ∃ r, suppression_rank level = ok r := by
  cases level <;> simp [suppression_rank]

/-- `suppression_rank` assigns the strict order `None (0) < Withdrawn (1) < Forgotten (2)`. -/
theorem suppression_rank_order :
    suppression_rank SuppressionLevel.None = ok 0#u8 ∧
      suppression_rank SuppressionLevel.Withdrawn = ok 1#u8 ∧
      suppression_rank SuppressionLevel.Forgotten = ok 2#u8 := by
  simp [suppression_rank, SUPPRESSION_RANK_NONE, SUPPRESSION_RANK_WITHDRAWN,
    SUPPRESSION_RANK_FORGOTTEN]

/-- `join_suppression_level` never fails or diverges. -/
theorem join_suppression_level_total (left right : SuppressionLevel) :
    ∃ joined, join_suppression_level left right = ok joined := by
  cases left <;> cases right <;>
    simp [join_suppression_level, suppression_rank, SUPPRESSION_RANK_NONE,
      SUPPRESSION_RANK_WITHDRAWN, SUPPRESSION_RANK_FORGOTTEN]

/-- `join_suppression_level` is commutative. -/
theorem join_suppression_level_comm (left right : SuppressionLevel) :
    ∃ joined, join_suppression_level left right = ok joined ∧
      join_suppression_level right left = ok joined := by
  cases left <;> cases right <;>
    simp [join_suppression_level, suppression_rank, SUPPRESSION_RANK_NONE,
      SUPPRESSION_RANK_WITHDRAWN, SUPPRESSION_RANK_FORGOTTEN]

/-- `join_suppression_level` is associative. -/
theorem join_suppression_level_assoc (a b c : SuppressionLevel) :
    ∃ ab bc r, join_suppression_level a b = ok ab ∧
      join_suppression_level b c = ok bc ∧
      join_suppression_level ab c = ok r ∧
      join_suppression_level a bc = ok r := by
  cases a <;> cases b <;> cases c <;>
    simp [join_suppression_level, suppression_rank, SUPPRESSION_RANK_NONE,
      SUPPRESSION_RANK_WITHDRAWN, SUPPRESSION_RANK_FORGOTTEN]

/-- `join_suppression_level` is idempotent. -/
theorem join_suppression_level_idem (a : SuppressionLevel) :
    join_suppression_level a a = ok a := by
  cases a <;>
    simp [join_suppression_level, suppression_rank, SUPPRESSION_RANK_NONE,
      SUPPRESSION_RANK_WITHDRAWN, SUPPRESSION_RANK_FORGOTTEN]

/-- `join_suppression_level` is inflationary: the joined rank is at least each input's rank. -/
theorem join_suppression_level_inflationary (left right : SuppressionLevel) :
    ∃ joined rl rr rj, join_suppression_level left right = ok joined ∧
      suppression_rank left = ok rl ∧
      suppression_rank right = ok rr ∧
      suppression_rank joined = ok rj ∧
      rl.val ≤ rj.val ∧ rr.val ≤ rj.val := by
  cases left <;> cases right <;>
    simp [join_suppression_level, suppression_rank, SUPPRESSION_RANK_NONE,
      SUPPRESSION_RANK_WITHDRAWN, SUPPRESSION_RANK_FORGOTTEN]

/-- `Forgotten` absorbs every suppression level and is never weakened. -/
theorem join_suppression_level_absorbing_forgotten (a : SuppressionLevel) :
    join_suppression_level SuppressionLevel.Forgotten a = ok SuppressionLevel.Forgotten ∧
      join_suppression_level a SuppressionLevel.Forgotten = ok SuppressionLevel.Forgotten := by
  cases a <;>
    simp [join_suppression_level, suppression_rank, SUPPRESSION_RANK_NONE,
      SUPPRESSION_RANK_WITHDRAWN, SUPPRESSION_RANK_FORGOTTEN]

/-! ## `join_suppression` (Stratum M join-semilattice) -/

private theorem join_suppression_eval (left right : SuppressionState) :
    ∃ lvl, join_suppression_level left.level right.level = ok lvl ∧
      join_suppression left right = ok {
        level := lvl,
        generation := if left.generation ≥ right.generation then left.generation else right.generation
      } := by
  obtain ⟨lvl, hlvl⟩ := join_suppression_level_total left.level right.level
  refine ⟨lvl, hlvl, ?_⟩
  unfold join_suppression
  by_cases h : left.generation ≥ right.generation <;> simp [hlvl, h]

/-- `join_suppression` never fails or diverges. -/
theorem join_suppression_total (left right : SuppressionState) :
    ∃ joined, join_suppression left right = ok joined := by
  obtain ⟨_, _, h⟩ := join_suppression_eval left right
  exact ⟨_, h⟩

/-- `join_suppression` is commutative. -/
theorem join_suppression_comm (left right : SuppressionState) :
    ∃ joined, join_suppression left right = ok joined ∧
      join_suppression right left = ok joined := by
  obtain ⟨lvl, hlr, hrl⟩ := join_suppression_level_comm left.level right.level
  obtain ⟨lvl1, hlvl1, h1⟩ := join_suppression_eval left right
  obtain ⟨lvl2, hlvl2, h2⟩ := join_suppression_eval right left
  have heq1 : lvl1 = lvl := by rw [hlr, Result.ok.injEq] at hlvl1; exact hlvl1.symm
  have heq2 : lvl2 = lvl := by rw [hrl, Result.ok.injEq] at hlvl2; exact hlvl2.symm
  rw [heq1] at h1
  rw [heq2] at h2
  by_cases hge : left.generation ≥ right.generation
  · by_cases hge2 : right.generation ≥ left.generation
    · have hval : left.generation = right.generation := by
        rw [UScalar.eq_equiv]; scalar_tac
      exact ⟨{ level := lvl, generation := left.generation }, by simpa [hge] using h1,
        by simpa [hge2, hval] using h2⟩
    · exact ⟨{ level := lvl, generation := left.generation }, by simpa [hge] using h1,
        by simpa [hge2] using h2⟩
  · have hge2 : right.generation ≥ left.generation := by scalar_tac
    exact ⟨{ level := lvl, generation := right.generation }, by simpa [hge] using h1,
      by simpa [hge2] using h2⟩

/-- `join_suppression` is associative. -/
theorem join_suppression_assoc (a b c : SuppressionState) :
    ∃ ab bc joined, join_suppression a b = ok ab ∧
      join_suppression b c = ok bc ∧
      join_suppression ab c = ok joined ∧
      join_suppression a bc = ok joined := by
  obtain ⟨lab, lbc, lr, hlab, hlbc, hl1, hl2⟩ :=
    join_suppression_level_assoc a.level b.level c.level
  obtain ⟨lab', hlab', hab⟩ := join_suppression_eval a b
  obtain ⟨lbc', hlbc', hbc⟩ := join_suppression_eval b c
  have h1 : lab' = lab := by rw [hlab, Result.ok.injEq] at hlab'; exact hlab'.symm
  have h2 : lbc' = lbc := by rw [hlbc, Result.ok.injEq] at hlbc'; exact hlbc'.symm
  rw [h1] at hab
  rw [h2] at hbc
  set ab : SuppressionState :=
    { level := lab, generation := if a.generation ≥ b.generation then a.generation else b.generation }
  set bc : SuppressionState :=
    { level := lbc, generation := if b.generation ≥ c.generation then b.generation else c.generation }
  obtain ⟨lr1, hlr1, habc⟩ := join_suppression_eval ab c
  obtain ⟨lr2, hlr2, ha_bc⟩ := join_suppression_eval a bc
  have h3 : lr1 = lr := by
    have : ab.level = lab := rfl
    rw [this, hl1, Result.ok.injEq] at hlr1
    exact hlr1.symm
  have h4 : lr2 = lr := by
    have : bc.level = lbc := rfl
    rw [this, hl2, Result.ok.injEq] at hlr2
    exact hlr2.symm
  rw [h3] at habc
  rw [h4] at ha_bc
  have hgen :
      (if ab.generation ≥ c.generation then ab.generation else c.generation) =
        (if a.generation ≥ bc.generation then a.generation else bc.generation) := by
    show (if (if a.generation ≥ b.generation then a.generation else b.generation) ≥ c.generation
        then (if a.generation ≥ b.generation then a.generation else b.generation) else c.generation) =
      (if a.generation ≥ (if b.generation ≥ c.generation then b.generation else c.generation)
        then a.generation else (if b.generation ≥ c.generation then b.generation else c.generation))
    split_ifs <;> rw [UScalar.eq_equiv] <;> scalar_tac
  refine ⟨ab, bc, { level := lr, generation := if ab.generation ≥ c.generation then ab.generation else c.generation },
    hab, hbc, habc, ?_⟩
  rw [hgen]
  exact ha_bc

/-- `join_suppression` is idempotent. -/
theorem join_suppression_idem (a : SuppressionState) :
    join_suppression a a = ok a := by
  obtain ⟨lvl, hlvl, h⟩ := join_suppression_eval a a
  have hl : lvl = a.level := by
    rw [join_suppression_level_idem, Result.ok.injEq] at hlvl
    exact hlvl.symm
  rw [h]
  simp [hl]

/-- `join_suppression` is inflationary on both suppression rank and generation. -/
theorem join_suppression_inflationary (left right : SuppressionState) :
    ∃ joined rl rr rj, join_suppression left right = ok joined ∧
      suppression_rank left.level = ok rl ∧
      suppression_rank right.level = ok rr ∧
      suppression_rank joined.level = ok rj ∧
      rl.val ≤ rj.val ∧ rr.val ≤ rj.val ∧
      left.generation.val ≤ joined.generation.val ∧
      right.generation.val ≤ joined.generation.val := by
  obtain ⟨lvl, rl, rr, rj, hlvl, hrl, hrr, hrj, hle_l, hle_r⟩ :=
    join_suppression_level_inflationary left.level right.level
  obtain ⟨lvl', hlvl', hjoin⟩ := join_suppression_eval left right
  have heq : lvl' = lvl := by rw [hlvl, Result.ok.injEq] at hlvl'; exact hlvl'.symm
  rw [heq] at hjoin
  refine ⟨_, rl, rr, rj, hjoin, hrl, hrr, hrj, hle_l, hle_r, ?_, ?_⟩
  · split_ifs <;> scalar_tac
  · split_ifs <;> scalar_tac

/-! ## `seal_valid` and `federated_absence_established` (Stratum B gate) -/

/-- `seal_valid` never fails or diverges. -/
theorem seal_valid_total (facts : CalmSealFacts) :
    ∃ valid, seal_valid facts = ok valid := by
  obtain ⟨sealed, quorum, epoch⟩ := facts
  cases sealed <;> cases quorum <;> cases epoch <;> simp [seal_valid]

/-- A `CalmSeal` is valid exactly when sealed, quorum-satisfied, and epoch-matched. -/
theorem seal_valid_iff (facts : CalmSealFacts) :
    seal_valid facts = ok true ↔
      facts.sealed = true ∧ facts.quorum_satisfied = true ∧ facts.epoch_matches = true := by
  obtain ⟨sealed, quorum, epoch⟩ := facts
  cases sealed <;> cases quorum <;> cases epoch <;> simp [seal_valid]

/-- `federated_absence_established` never fails or diverges. -/
theorem federated_absence_established_total (facts : FederatedNegationFacts) :
    ∃ established, federated_absence_established facts = ok established := by
  obtain ⟨local_abs, stratum, fed, ⟨sealed, quorum, epoch⟩⟩ := facts
  cases local_abs <;> cases stratum <;> cases fed <;>
    cases sealed <;> cases quorum <;> cases epoch <;>
    simp [federated_absence_established, seal_valid]

/-- Exact characterization of `federated_absence_established`. -/
theorem federated_absence_established_iff (facts : FederatedNegationFacts) :
    federated_absence_established facts = ok true ↔
      facts.local_absence_established = true ∧
        (facts.is_federated = true ∧ facts.stratum = CalmStratum.Barrier →
          facts.barrier_seal.sealed = true ∧
            facts.barrier_seal.quorum_satisfied = true ∧
            facts.barrier_seal.epoch_matches = true) := by
  obtain ⟨local_abs, stratum, fed, ⟨sealed, quorum, epoch⟩⟩ := facts
  cases local_abs <;> cases stratum <;> cases fed <;>
    cases sealed <;> cases quorum <;> cases epoch <;>
    simp [federated_absence_established, seal_valid]

/-- Unsealed federated Stratum B negated queries never emit `absence_established = true`. -/
theorem unsealed_federated_negation_refuses_absence (facts : FederatedNegationFacts)
    (hfed : facts.is_federated = true)
    (hbarrier : facts.stratum = CalmStratum.Barrier)
    (hunsealed : facts.barrier_seal.sealed = false) :
    federated_absence_established facts = ok false := by
  obtain ⟨local_abs, stratum, fed, ⟨sealed, quorum, epoch⟩⟩ := facts
  cases hfed; cases hbarrier; cases hunsealed
  cases local_abs <;> simp [federated_absence_established, seal_valid]

end mneme_kernel.calm
