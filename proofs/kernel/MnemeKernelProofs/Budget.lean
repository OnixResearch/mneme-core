import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Work and size budgets

Theorems about the generated translation of `crates/mneme-kernel/src/budget.rs`.
`charge` is total: it returns `ok` for every input (`charge_total`).
-/

namespace mneme_kernel.budget

/-! ## `charge` -/

/-- The two outcomes of `charge`: the exact sum when it is within the limit,
and a refusal when it is above the limit. -/
private theorem charge_cases (used cost limit : U64) :
    (used.val + cost.val ≤ limit.val ∧
        ∃ total, charge used cost limit = ok (some total) ∧
          total.val = used.val + cost.val) ∨
      (limit.val < used.val + cost.val ∧ charge used cost limit = ok none) := by
  have hspec := U64.checked_add_bv_spec used cost
  unfold charge
  cases hsum : U64.checked_add used cost with
  | none =>
    rw [hsum] at hspec
    replace hspec : U64.max < used.val + cost.val := hspec
    exact Or.inr ⟨by scalar_tac, by simp [lift]⟩
  | some sum =>
    rw [hsum] at hspec
    obtain ⟨-, hval, -⟩ := hspec
    by_cases hle : sum.val ≤ limit.val
    · exact Or.inl ⟨by omega, sum, by simp [lift, hle], hval⟩
    · exact Or.inr ⟨by omega, by simp [lift, hle]⟩

/-- `charge` never fails or diverges. -/
theorem charge_total (used cost limit : U64) :
    ∃ charged, charge used cost limit = ok charged := by
  rcases charge_cases used cost limit with ⟨-, total, htotal, -⟩ | ⟨-, hnone⟩
  · exact ⟨some total, htotal⟩
  · exact ⟨none, hnone⟩

/-- A charge is accepted with new total `total` exactly when `total` is the
exact sum of the amount used and the cost, and that sum is within the limit. -/
theorem charge_some_iff (used cost limit total : U64) :
    charge used cost limit = ok (some total) ↔
      total.val = used.val + cost.val ∧ used.val + cost.val ≤ limit.val := by
  rcases charge_cases used cost limit with ⟨hle, sum, hsum, hval⟩ | ⟨hlt, hnone⟩
  · rw [hsum, Result.ok.injEq, Option.some.injEq, UScalar.eq_equiv]
    omega
  · rw [hnone, Result.ok.injEq]
    constructor
    · intro h
      cases h
    · rintro ⟨-, hle⟩
      omega

/-- A charge is refused exactly when the exact sum of the amount used and the
cost is above the limit; a sum that overflows `u64` is above every limit. -/
theorem charge_none_iff (used cost limit : U64) :
    charge used cost limit = ok none ↔ limit.val < used.val + cost.val := by
  rcases charge_cases used cost limit with ⟨hle, sum, hsum, -⟩ | ⟨hlt, hnone⟩
  · rw [hsum, Result.ok.injEq]
    constructor
    · intro h
      cases h
    · intro hlt
      omega
  · exact ⟨fun _ => hlt, fun _ => hnone⟩

/-- An accepted charge never passes the limit and never wraps below the amount
already used. -/
theorem charge_never_exceeds (used cost limit total : U64)
    (h : charge used cost limit = ok (some total)) :
    total.val ≤ limit.val ∧ used.val ≤ total.val := by
  obtain ⟨hval, hle⟩ := (charge_some_iff used cost limit total).mp h
  omega

end mneme_kernel.budget
