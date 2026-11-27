import MnemeKernel
import MnemeKernelProofs.Calm
open Aeneas Aeneas.Std Result

/-!
# Bloom^L Merkle-CRDT multi-parent DAG lattice and concurrent frontier proofs

Theorems about the generated translation of `crates/mneme-kernel/src/lattice.rs`.
Every DAG frontier join is total, associative, commutative, idempotent, and
inflationary; concurrent offline frontiers (`|frontier(r)| >= 2`) always project
to `Disputed` (never auto-promoting to `Accepted`); and inflationary suppression
(`None < Withdrawn < Forgotten`) dominates all DAG branches and merges.
-/

namespace mneme_kernel.lattice

/-! ## Helper lemmas on `U64` bitwise algebra -/

private theorem u64_or_comm (a b : U64) : (a ||| b) = (b ||| a) := by
  cases a; cases b
  simp only [HOr.hOr, OrOp.or, UScalar.or]
  congr 1
  exact BitVec.or_comm _ _

private theorem u64_or_assoc (a b c : U64) : ((a ||| b) ||| c) = (a ||| (b ||| c)) := by
  cases a; cases b; cases c
  simp only [HOr.hOr, OrOp.or, UScalar.or]
  congr 1
  exact BitVec.or_assoc _ _ _

private theorem u64_or_self (a : U64) : (a ||| a) = a := by
  cases a
  simp only [HOr.hOr, OrOp.or, UScalar.or]
  congr 1
  exact BitVec.or_self

private theorem u64_and_or_left (a b : U64) : (a &&& (a ||| b)) = a := by
  cases a with | mk va =>
  cases b with | mk vb =>
  change UScalar.mk (va &&& (va ||| vb)) = UScalar.mk va
  congr 1
  apply BitVec.eq_of_getLsbD_eq
  intro i _hi
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_or]
  cases va.getLsbD i <;> cases vb.getLsbD i <;> rfl

private theorem u64_and_or_right (a b : U64) : (b &&& (a ||| b)) = b := by
  rw [u64_or_comm a b]
  exact u64_and_or_left b a

private theorem u64_frontier_subset_nodes (nodes cited : U64) :
    ((nodes &&& ~~~cited) &&& nodes) = (nodes &&& ~~~cited) := by
  cases nodes with | mk vn =>
  cases cited with | mk vc =>
  change UScalar.mk ((vn &&& ~~~vc) &&& vn) = UScalar.mk (vn &&& ~~~vc)
  congr 1
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_not, hi, decide_true, Bool.true_and]
  cases vn.getLsbD i <;> cases vc.getLsbD i <;> rfl

private theorem u64_frontier_disjoint_cited (nodes cited : U64) :
    ((nodes &&& ~~~cited) &&& cited) = 0#u64 := by
  cases nodes with | mk vn =>
  cases cited with | mk vc =>
  simp only [HAnd.hAnd, AndOp.and, UScalar.and, Complement.complement, UScalar.not]
  change UScalar.mk ((vn &&& ~~~vc) &&& vc) = UScalar.mk (BitVec.ofNat UScalarTy.U64.numBits 0)
  congr 1
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_not, BitVec.getLsbD_ofNat, Nat.zero_testBit, hi,
    decide_true, Bool.true_and]
  cases vn.getLsbD i <;> cases vc.getLsbD i <;> rfl

/-! ## `join_frontier` (Stratum M ACI join-semilattice) -/

private theorem join_frontier_eval (left right : FrontierState) :
    ∃ ss, calm.join_suppression left.suppression right.suppression = ok ss ∧
      join_frontier left right = ok {
        nodes_mask := left.nodes_mask ||| right.nodes_mask,
        cited_mask := left.cited_mask ||| right.cited_mask,
        suppression := ss
      } := by
  obtain ⟨ss, hss⟩ := calm.join_suppression_total left.suppression right.suppression
  refine ⟨ss, hss, ?_⟩
  simp [join_frontier, lift, hss]

/-- `join_frontier` never fails or diverges. -/
theorem join_frontier_total (left right : FrontierState) :
    ∃ joined, join_frontier left right = ok joined := by
  obtain ⟨_, _, h⟩ := join_frontier_eval left right
  exact ⟨_, h⟩

/-- `join_frontier` is commutative. -/
theorem join_frontier_comm (left right : FrontierState) :
    ∃ joined, join_frontier left right = ok joined ∧
      join_frontier right left = ok joined := by
  obtain ⟨ss, hlr, hrl⟩ := calm.join_suppression_comm left.suppression right.suppression
  obtain ⟨ss1, hss1, h1⟩ := join_frontier_eval left right
  obtain ⟨ss2, hss2, h2⟩ := join_frontier_eval right left
  have heq1 : ss1 = ss := by rw [hlr, Result.ok.injEq] at hss1; exact hss1.symm
  have heq2 : ss2 = ss := by rw [hrl, Result.ok.injEq] at hss2; exact hss2.symm
  rw [heq1] at h1
  rw [heq2] at h2
  refine ⟨{
    nodes_mask := left.nodes_mask ||| right.nodes_mask,
    cited_mask := left.cited_mask ||| right.cited_mask,
    suppression := ss
  }, h1, ?_⟩
  rw [u64_or_comm right.nodes_mask left.nodes_mask,
    u64_or_comm right.cited_mask left.cited_mask] at h2
  exact h2

/-- `join_frontier` is associative. -/
theorem join_frontier_assoc (a b c : FrontierState) :
    ∃ ab bc joined, join_frontier a b = ok ab ∧
      join_frontier b c = ok bc ∧
      join_frontier ab c = ok joined ∧
      join_frontier a bc = ok joined := by
  obtain ⟨sab, sbc, sr, hsab, hsbc, hs1, hs2⟩ :=
    calm.join_suppression_assoc a.suppression b.suppression c.suppression
  obtain ⟨sab', hsab', hab⟩ := join_frontier_eval a b
  obtain ⟨sbc', hsbc', hbc⟩ := join_frontier_eval b c
  have h1 : sab' = sab := by rw [hsab, Result.ok.injEq] at hsab'; exact hsab'.symm
  have h2 : sbc' = sbc := by rw [hsbc, Result.ok.injEq] at hsbc'; exact hsbc'.symm
  rw [h1] at hab
  rw [h2] at hbc
  set ab : FrontierState := {
    nodes_mask := a.nodes_mask ||| b.nodes_mask,
    cited_mask := a.cited_mask ||| b.cited_mask,
    suppression := sab
  }
  set bc : FrontierState := {
    nodes_mask := b.nodes_mask ||| c.nodes_mask,
    cited_mask := b.cited_mask ||| c.cited_mask,
    suppression := sbc
  }
  obtain ⟨sr1, hsr1, habc⟩ := join_frontier_eval ab c
  obtain ⟨sr2, hsr2, ha_bc⟩ := join_frontier_eval a bc
  have h3 : sr1 = sr := by
    have : ab.suppression = sab := rfl
    rw [this, hs1, Result.ok.injEq] at hsr1
    exact hsr1.symm
  have h4 : sr2 = sr := by
    have : bc.suppression = sbc := rfl
    rw [this, hs2, Result.ok.injEq] at hsr2
    exact hsr2.symm
  rw [h3] at habc
  rw [h4] at ha_bc
  refine ⟨ab, bc, {
    nodes_mask := ab.nodes_mask ||| c.nodes_mask,
    cited_mask := ab.cited_mask ||| c.cited_mask,
    suppression := sr
  }, hab, hbc, habc, ?_⟩
  have hn : a.nodes_mask ||| bc.nodes_mask = ab.nodes_mask ||| c.nodes_mask :=
    (u64_or_assoc a.nodes_mask b.nodes_mask c.nodes_mask).symm
  have hc : a.cited_mask ||| bc.cited_mask = ab.cited_mask ||| c.cited_mask :=
    (u64_or_assoc a.cited_mask b.cited_mask c.cited_mask).symm
  rw [hn, hc] at ha_bc
  exact ha_bc

/-- `join_frontier` is idempotent. -/
theorem join_frontier_idem (a : FrontierState) :
    join_frontier a a = ok a := by
  obtain ⟨ss, hss, h⟩ := join_frontier_eval a a
  have hse : ss = a.suppression := by
    rw [calm.join_suppression_idem, Result.ok.injEq] at hss
    exact hss.symm
  rw [h, hse, u64_or_self, u64_or_self]

/-- `join_frontier` is inflationary on nodes, cited parents, suppression rank, and generation. -/
theorem join_frontier_inflationary (left right : FrontierState) :
    ∃ joined rl rr rj, join_frontier left right = ok joined ∧
      (left.nodes_mask &&& joined.nodes_mask) = left.nodes_mask ∧
      (right.nodes_mask &&& joined.nodes_mask) = right.nodes_mask ∧
      (left.cited_mask &&& joined.cited_mask) = left.cited_mask ∧
      (right.cited_mask &&& joined.cited_mask) = right.cited_mask ∧
      calm.suppression_rank left.suppression.level = ok rl ∧
      calm.suppression_rank right.suppression.level = ok rr ∧
      calm.suppression_rank joined.suppression.level = ok rj ∧
      rl.val ≤ rj.val ∧ rr.val ≤ rj.val ∧
      left.suppression.generation.val ≤ joined.suppression.generation.val ∧
      right.suppression.generation.val ≤ joined.suppression.generation.val := by
  obtain ⟨ss, rl, rr, rj, hss, hrl, hrr, hrj, hle_l, hle_r, hgl, hgr⟩ :=
    calm.join_suppression_inflationary left.suppression right.suppression
  obtain ⟨ss', hss', hjoin⟩ := join_frontier_eval left right
  have heq : ss' = ss := by rw [hss, Result.ok.injEq] at hss'; exact hss'.symm
  rw [heq] at hjoin
  exact ⟨_, rl, rr, rj, hjoin,
    u64_and_or_left left.nodes_mask right.nodes_mask,
    u64_and_or_right left.nodes_mask right.nodes_mask,
    u64_and_or_left left.cited_mask right.cited_mask,
    u64_and_or_right left.cited_mask right.cited_mask,
    hrl, hrr, hrj, hle_l, hle_r, hgl, hgr⟩

/-! ## `frontier_mask` and `ingest_node` -/

/-- `frontier_mask` never fails or diverges. -/
theorem frontier_mask_total (state : FrontierState) :
    ∃ mask, frontier_mask state = ok mask := by
  exact ⟨state.nodes_mask &&& ~~~state.cited_mask, by simp [frontier_mask, lift]⟩

/-- Every element in `frontier_mask` is an ingested node and is not cited as a parent. -/
theorem frontier_mask_invariants (state : FrontierState) :
    ∃ mask, frontier_mask state = ok mask ∧
      (mask &&& state.nodes_mask) = mask ∧
      (mask &&& state.cited_mask) = 0#u64 := by
  refine ⟨state.nodes_mask &&& ~~~state.cited_mask, by simp [frontier_mask, lift], ?_, ?_⟩
  · exact u64_frontier_subset_nodes state.nodes_mask state.cited_mask
  · exact u64_frontier_disjoint_cited state.nodes_mask state.cited_mask

/-- `ingest_node` never fails or diverges. -/
theorem ingest_node_total (state : FrontierState) (node_bit parents_mask : U64) :
    ∃ next, ingest_node state node_bit parents_mask = ok next := by
  exact ⟨{ state with
    nodes_mask := state.nodes_mask ||| node_bit,
    cited_mask := state.cited_mask ||| parents_mask
  }, by simp [ingest_node, lift]⟩

/-- Ingesting two revision nodes in either order produces the exact same [`FrontierState`]. -/
theorem ingest_node_comm (state : FrontierState) (n1 p1 n2 p2 : U64) :
    ∃ s1 s2 final,
      ingest_node state n1 p1 = ok s1 ∧
      ingest_node state n2 p2 = ok s2 ∧
      ingest_node s1 n2 p2 = ok final ∧
      ingest_node s2 n1 p1 = ok final := by
  set s1 : FrontierState := { state with
    nodes_mask := state.nodes_mask ||| n1,
    cited_mask := state.cited_mask ||| p1
  }
  set s2 : FrontierState := { state with
    nodes_mask := state.nodes_mask ||| n2,
    cited_mask := state.cited_mask ||| p2
  }
  have hn : (state.nodes_mask ||| n2) ||| n1 = (state.nodes_mask ||| n1) ||| n2 := by
    rw [u64_or_assoc, u64_or_comm n2 n1, ← u64_or_assoc]
  have hp : (state.cited_mask ||| p2) ||| p1 = (state.cited_mask ||| p1) ||| p2 := by
    rw [u64_or_assoc, u64_or_comm p2 p1, ← u64_or_assoc]
  refine ⟨s1, s2, { state with
    nodes_mask := (state.nodes_mask ||| n1) ||| n2,
    cited_mask := (state.cited_mask ||| p1) ||| p2
  }, by simp [ingest_node, lift, s1], by simp [ingest_node, lift, s2], by simp [ingest_node, lift, s1], ?_⟩
  simp [ingest_node, lift, s2, hn, hp]

/-- Re-ingesting the same revision node and parents is idempotent. -/
theorem ingest_node_idem (state : FrontierState) (n p : U64) :
    ∃ s1, ingest_node state n p = ok s1 ∧ ingest_node s1 n p = ok s1 := by
  set s1 : FrontierState := { state with
    nodes_mask := state.nodes_mask ||| n,
    cited_mask := state.cited_mask ||| p
  }
  have hn : (state.nodes_mask ||| n) ||| n = state.nodes_mask ||| n := by
    rw [u64_or_assoc, u64_or_self]
  have hp : (state.cited_mask ||| p) ||| p = state.cited_mask ||| p := by
    rw [u64_or_assoc, u64_or_self]
  refine ⟨s1, by simp [ingest_node, lift, s1], ?_⟩
  simp [ingest_node, lift, s1, hn, hp]

/-! ## `is_concurrent_mask` and `is_concurrent_frontier` -/

/-- `is_concurrent_mask` never fails or diverges. -/
theorem is_concurrent_mask_total (mask : U64) :
    ∃ b, is_concurrent_mask mask = ok b := by
  by_cases hz : mask = EMPTY_FRONTIER_MASK
  · exact ⟨false, by simp [is_concurrent_mask, hz]⟩
  · exact ⟨(mask &&& core.num.U64.wrapping_sub mask SINGLE_BIT_STEP) != EMPTY_FRONTIER_MASK,
      by simp [is_concurrent_mask, lift, hz]⟩

/-- An empty frontier mask is never concurrent. -/
theorem is_concurrent_mask_empty :
    is_concurrent_mask 0#u64 = ok false := by
  simp [is_concurrent_mask, EMPTY_FRONTIER_MASK]

/-- `is_concurrent_frontier` never fails or diverges. -/
theorem is_concurrent_frontier_total (frontier_count : U32) :
    ∃ b, is_concurrent_frontier frontier_count = ok b := by
  exact ⟨decide (frontier_count ≥ CONCURRENT_FRONTIER_MIN), by simp [is_concurrent_frontier]⟩

/-- `is_concurrent_frontier` holds exactly when `frontier_count >= 2`. -/
theorem is_concurrent_frontier_iff (frontier_count : U32) :
    is_concurrent_frontier frontier_count = ok true ↔ 2 ≤ frontier_count.val := by
  simp only [is_concurrent_frontier, CONCURRENT_FRONTIER_MIN, Result.ok.injEq, decide_eq_true_eq]
  constructor <;> intro h <;> scalar_tac

/-! ## `project_frontier` and `projected_lifecycle` (Disputed projection & suppression dominance) -/

/-- `project_frontier` never fails or diverges. -/
theorem project_frontier_total (input : FrontierProjectionInput) :
    ∃ view, project_frontier input = ok view := by
  obtain ⟨fc, hl, sup⟩ := input
  cases sup <;>
    simp only [project_frontier, calm.suppression_rank,
      calm.SUPPRESSION_RANK_NONE, calm.SUPPRESSION_RANK_WITHDRAWN, calm.SUPPRESSION_RANK_FORGOTTEN,
      SUPPRESSION_FORGOTTEN_RANK, SUPPRESSION_WITHDRAWN_RANK, EMPTY_FRONTIER_COUNT,
      is_concurrent_frontier, CONCURRENT_FRONTIER_MIN]
  · by_cases h0 : fc = 0#u32
    · exact ⟨ProjectedView.Absent, by simp [h0]⟩
    · by_cases hc : fc ≥ 2#u32
      · exact ⟨ProjectedView.DisputedConcurrent fc, by simp [h0, hc]⟩
      · exact ⟨ProjectedView.Active hl, by simp [h0, hc]⟩
  · exact ⟨ProjectedView.Withdrawn, by simp⟩
  · exact ⟨ProjectedView.Forgotten, by simp⟩

/-- `Forgotten` suppression dominates every DAG branch regardless of frontier cardinality or head lifecycle. -/
theorem project_frontier_forgotten_dominates (fc : U32) (hl : claim.Lifecycle) :
    project_frontier {
      frontier_count := fc,
      head_lifecycle := hl,
      suppression := calm.SuppressionLevel.Forgotten
    } = ok ProjectedView.Forgotten := by
  simp [project_frontier, calm.suppression_rank, calm.SUPPRESSION_RANK_FORGOTTEN,
    SUPPRESSION_FORGOTTEN_RANK]

/-- `Withdrawn` suppression dominates every DAG branch regardless of frontier cardinality or head lifecycle. -/
theorem project_frontier_withdrawn_dominates (fc : U32) (hl : claim.Lifecycle) :
    project_frontier {
      frontier_count := fc,
      head_lifecycle := hl,
      suppression := calm.SuppressionLevel.Withdrawn
    } = ok ProjectedView.Withdrawn := by
  simp [project_frontier, calm.suppression_rank, calm.SUPPRESSION_RANK_WITHDRAWN,
    SUPPRESSION_FORGOTTEN_RANK, SUPPRESSION_WITHDRAWN_RANK]

/-- Unsuppressed concurrent frontiers (`|frontier(r)| >= 2`) always project to `DisputedConcurrent`. -/
theorem project_frontier_concurrent_disputed (fc : U32) (hl : claim.Lifecycle) (hfc : 2 ≤ fc.val) :
    project_frontier {
      frontier_count := fc,
      head_lifecycle := hl,
      suppression := calm.SuppressionLevel.None
    } = ok (ProjectedView.DisputedConcurrent fc) := by
  have hne0 : fc ≠ 0#u32 := by intro h; subst h; scalar_tac
  have hge2 : fc ≥ 2#u32 := by scalar_tac
  simp [project_frontier, calm.suppression_rank, calm.SUPPRESSION_RANK_NONE,
    SUPPRESSION_FORGOTTEN_RANK, SUPPRESSION_WITHDRAWN_RANK, EMPTY_FRONTIER_COUNT,
    is_concurrent_frontier, CONCURRENT_FRONTIER_MIN, hne0, hge2]

/-- `projected_lifecycle` never fails or diverges. -/
theorem projected_lifecycle_total (view : ProjectedView) :
    ∃ lc, projected_lifecycle view = ok lc := by
  cases view <;> simp [projected_lifecycle]

/-- Any concurrent frontier (`|frontier(r)| >= 2`) never auto-promotes to `Lifecycle.Accepted`. -/
theorem concurrent_frontier_never_auto_promotes_accepted (input : FrontierProjectionInput)
    (hfc : 2 ≤ input.frontier_count.val) :
    ∃ view lc, project_frontier input = ok view ∧
      projected_lifecycle view = ok lc ∧
      lc ≠ some claim.Lifecycle.Accepted := by
  obtain ⟨fc, hl, sup⟩ := input
  cases sup with
  | None =>
    have hp := project_frontier_concurrent_disputed fc hl hfc
    exact ⟨ProjectedView.DisputedConcurrent fc, some claim.Lifecycle.Disputed, hp,
      by simp [projected_lifecycle], by intro h; cases h⟩
  | Withdrawn =>
    have hp := project_frontier_withdrawn_dominates fc hl
    exact ⟨ProjectedView.Withdrawn, none, hp, by simp [projected_lifecycle], by intro h; cases h⟩
  | Forgotten =>
    have hp := project_frontier_forgotten_dominates fc hl
    exact ⟨ProjectedView.Forgotten, none, hp, by simp [projected_lifecycle], by intro h; cases h⟩

/-! ## `decide_frontier_merge` (Explicit `Decision` merge gate) -/

/-- `decide_frontier_merge` never fails or diverges. -/
theorem decide_frontier_merge_total (facts : MergeResolutionFacts) :
    ∃ verdict, decide_frontier_merge facts = ok verdict := by
  obtain ⟨fc, cited, dec, sup⟩ := facts
  cases sup <;>
    simp only [decide_frontier_merge, calm.suppression_rank,
      calm.SUPPRESSION_RANK_NONE, calm.SUPPRESSION_RANK_WITHDRAWN, calm.SUPPRESSION_RANK_FORGOTTEN,
      SUPPRESSION_NONE_RANK, is_concurrent_frontier, CONCURRENT_FRONTIER_MIN]
  · by_cases hc : fc ≥ 2#u32
    · by_cases hcite : cited = fc
      · cases dec
        · exact ⟨MergeResolutionVerdict.RefusedMissingDecision, by simp [hc, hcite]⟩
        · exact ⟨MergeResolutionVerdict.Allowed, by simp [hc, hcite]⟩
      · exact ⟨MergeResolutionVerdict.RefusedIncompleteParents, by simp [hc, hcite]⟩
    · exact ⟨MergeResolutionVerdict.RefusedIncompleteParents, by simp [hc]⟩
  · exact ⟨MergeResolutionVerdict.RefusedSuppressed, by simp⟩
  · exact ⟨MergeResolutionVerdict.RefusedSuppressed, by simp⟩

/-- A merge is allowed iff the record is unsuppressed, has a concurrent frontier (`>= 2`),
    cites every active frontier parent, and carries an explicit `ConflictResolution` decision. -/
theorem decide_frontier_merge_allowed_iff (facts : MergeResolutionFacts) :
    decide_frontier_merge facts = ok MergeResolutionVerdict.Allowed ↔
      facts.suppression = calm.SuppressionLevel.None ∧
        2 ≤ facts.frontier_count.val ∧
        facts.cited_frontier_count = facts.frontier_count ∧
        facts.has_conflict_resolution_decision = true := by
  obtain ⟨fc, cited, dec, sup⟩ := facts
  cases sup with
  | Withdrawn =>
    simp [decide_frontier_merge, calm.suppression_rank, calm.SUPPRESSION_RANK_WITHDRAWN,
      SUPPRESSION_NONE_RANK]
  | Forgotten =>
    simp [decide_frontier_merge, calm.suppression_rank, calm.SUPPRESSION_RANK_FORGOTTEN,
      SUPPRESSION_NONE_RANK]
  | None =>
    simp only [decide_frontier_merge, calm.suppression_rank, calm.SUPPRESSION_RANK_NONE,
      SUPPRESSION_NONE_RANK, is_concurrent_frontier, CONCURRENT_FRONTIER_MIN]
    by_cases hc : fc ≥ 2#u32
    · have hfc2 : 2 ≤ fc.val := by scalar_tac
      by_cases hcite : cited = fc
      · cases dec <;> simp [hc, hcite, hfc2]
      · simp [hc, hcite]
    · have hnot : ¬ (2 ≤ fc.val) := by intro h; exact hc (by scalar_tac)
      simp [hc, hnot]

/-- Any withdrawn or forgotten record refuses merge resolution. -/
theorem decide_frontier_merge_suppressed_refused (facts : MergeResolutionFacts)
    (hsup : facts.suppression ≠ calm.SuppressionLevel.None) :
    decide_frontier_merge facts = ok MergeResolutionVerdict.RefusedSuppressed := by
  obtain ⟨fc, cited, dec, sup⟩ := facts
  cases sup with
  | None => exact absurd rfl hsup
  | Withdrawn =>
    simp [decide_frontier_merge, calm.suppression_rank, calm.SUPPRESSION_RANK_WITHDRAWN,
      SUPPRESSION_NONE_RANK]
  | Forgotten =>
    simp [decide_frontier_merge, calm.suppression_rank, calm.SUPPRESSION_RANK_FORGOTTEN,
      SUPPRESSION_NONE_RANK]

end mneme_kernel.lattice
