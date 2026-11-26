import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Epistemic provenance semiring

Theorems about the generated translation of `crates/mneme-kernel/src/epistemic.rs`.
`(EpistemicStatus, union, join, Rejected, Accepted)` forms a commutative
idempotent semiring where `join` never promotes a premise (`join a b ≤ min a b`)
and `Rejected` (`ZERO`) is excluded from active facts and negation blocking.
-/

namespace mneme_kernel.epistemic

/-! ## `rank` -/

/-- `rank` never fails or diverges. -/
theorem rank_total (status : EpistemicStatus) :
    ∃ r, rank status = ok r := by
  cases status <;> simp [rank]

/-- `rank` assigns the strict order `Rejected (0) < Proposed (1) < Accepted (2)`. -/
theorem rank_order :
    rank EpistemicStatus.Rejected = ok 0#u8 ∧
      rank EpistemicStatus.Proposed = ok 1#u8 ∧
      rank EpistemicStatus.Accepted = ok 2#u8 := by
  simp [rank]

/-! ## `join` (`×`, conjunction over premises) -/

/-- `join` never fails or diverges. -/
theorem join_total (a b : EpistemicStatus) :
    ∃ r, join a b = ok r := by
  cases a <;> cases b <;> simp [join, rank]

/-- `join` is commutative. -/
theorem join_comm (a b : EpistemicStatus) :
    ∃ r, join a b = ok r ∧ join b a = ok r := by
  cases a <;> cases b <;> simp [join, rank]

/-- `join` is associative. -/
theorem join_assoc (a b c : EpistemicStatus) :
    ∃ ab bc r, join a b = ok ab ∧ join b c = ok bc ∧
      join ab c = ok r ∧ join a bc = ok r := by
  cases a <;> cases b <;> cases c <;> simp [join, rank]

/-- `join` is idempotent. -/
theorem join_idem (a : EpistemicStatus) :
    join a a = ok a := by
  cases a <;> simp [join, rank]

/-- `Accepted` (`ONE`) is the two-sided identity of `join`. -/
theorem join_identity_accepted (a : EpistemicStatus) :
    join EpistemicStatus.Accepted a = ok a ∧ join a EpistemicStatus.Accepted = ok a := by
  cases a <;> simp [join, rank]

/-- `Rejected` (`ZERO`) is the two-sided annihilator of `join`. -/
theorem join_annihilator_rejected (a : EpistemicStatus) :
    join EpistemicStatus.Rejected a = ok EpistemicStatus.Rejected ∧
      join a EpistemicStatus.Rejected = ok EpistemicStatus.Rejected := by
  cases a <;> simp [join, rank]

/-- Monotonic non-promotion: `join a b` never exceeds the rank of either premise. -/
theorem join_non_promoting (a b : EpistemicStatus) :
    ∃ r ra rb rr, join a b = ok r ∧ rank a = ok ra ∧ rank b = ok rb ∧
      rank r = ok rr ∧ rr.val ≤ ra.val ∧ rr.val ≤ rb.val := by
  cases a <;> cases b <;> simp [join, rank]

/-! ## `union` (`+`, disjunction over derivations) -/

/-- `union` never fails or diverges. -/
theorem union_total (a b : EpistemicStatus) :
    ∃ r, union a b = ok r := by
  cases a <;> cases b <;> simp [union, rank]

/-- `union` is commutative. -/
theorem union_comm (a b : EpistemicStatus) :
    ∃ r, union a b = ok r ∧ union b a = ok r := by
  cases a <;> cases b <;> simp [union, rank]

/-- `union` is associative. -/
theorem union_assoc (a b c : EpistemicStatus) :
    ∃ ab bc r, union a b = ok ab ∧ union b c = ok bc ∧
      union ab c = ok r ∧ union a bc = ok r := by
  cases a <;> cases b <;> cases c <;> simp [union, rank]

/-- `union` is idempotent. -/
theorem union_idem (a : EpistemicStatus) :
    union a a = ok a := by
  cases a <;> simp [union, rank]

/-- `Rejected` (`ZERO`) is the two-sided additive identity of `union`. -/
theorem union_identity_rejected (a : EpistemicStatus) :
    union EpistemicStatus.Rejected a = ok a ∧ union a EpistemicStatus.Rejected = ok a := by
  cases a <;> simp [union, rank]

/-- `Accepted` (`ONE`) absorbs every status under `union`. -/
theorem union_absorbing_accepted (a : EpistemicStatus) :
    union EpistemicStatus.Accepted a = ok EpistemicStatus.Accepted ∧
      union a EpistemicStatus.Accepted = ok EpistemicStatus.Accepted := by
  cases a <;> simp [union, rank]

/-! ## Distributivity -/

/-- `join` distributes over `union`: `a × (b + c) = (a × b) + (a × c)`. -/
theorem join_distributes_over_union (a b c : EpistemicStatus) :
    ∃ bc ab ac r, union b c = ok bc ∧ join a bc = ok r ∧
      join a b = ok ab ∧ join a c = ok ac ∧ union ab ac = ok r := by
  cases a <;> cases b <;> cases c <;> simp [join, union, rank]

/-! ## Annihilator exclusion (`is_active`, `negation_blocks`) -/

/-- `is_active` never fails or diverges. -/
theorem is_active_total (status : EpistemicStatus) :
    ∃ active, is_active status = ok active := by
  cases status <;> simp [is_active]

/-- `Rejected` (`ZERO`) is excluded from active projections. -/
theorem is_active_rejected_false :
    is_active EpistemicStatus.Rejected = ok false := by
  simp [is_active]

/-- A status is active exactly when it is not `Rejected`. -/
theorem is_active_iff (status : EpistemicStatus) :
    is_active status = ok true ↔ status ≠ EpistemicStatus.Rejected := by
  cases status <;> simp [is_active]

/-- `negation_blocks` never fails or diverges. -/
theorem negation_blocks_total (status : EpistemicStatus) :
    ∃ blocks, negation_blocks status = ok blocks := by
  cases status <;> simp [negation_blocks, is_active]

/-- A `Rejected` (`ZERO`) fact never blocks a negated literal. -/
theorem negation_blocks_rejected_false :
    negation_blocks EpistemicStatus.Rejected = ok false := by
  simp [negation_blocks, is_active]

/-- A fact blocks negation exactly when its status is not `Rejected`. -/
theorem negation_blocks_iff (status : EpistemicStatus) :
    negation_blocks status = ok true ↔ status ≠ EpistemicStatus.Rejected := by
  cases status <;> simp [negation_blocks, is_active]

end mneme_kernel.epistemic
