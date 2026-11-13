import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Assertion lifecycle transitions and the decisions that back them

Theorems about the generated translation of
`crates/mneme-kernel/src/claim.rs`. The five rules of the module are total:
each returns `ok` for every input (the `*_total` theorems), so each
`= ok true ↔ …` statement also determines when the rule returns `ok false`.
-/

namespace mneme_kernel.claim

/-! ## `transition_allowed` -/

/-- `transition_allowed` never fails or diverges. -/
theorem transition_allowed_total (prior : Option Lifecycle) (next : Lifecycle) :
    ∃ allowed, transition_allowed prior next = ok allowed := by
  cases prior with
  | none => cases next <;> simp [transition_allowed]
  | some previous => cases previous <;> cases next <;> simp [transition_allowed]

/-- An assertion is born proposed: the first revision of a new assertion is
allowed exactly when it is proposed. -/
theorem transition_allowed_new_iff (next : Lifecycle) :
    transition_allowed none next = ok true ↔ next = Lifecycle.Proposed := by
  cases next <;> simp [transition_allowed]

/-- A retracted assertion stays retracted: no revision may follow it. -/
theorem retracted_is_terminal (next : Lifecycle) :
    transition_allowed (some Lifecycle.Retracted) next = ok false := by
  simp [transition_allowed]

/-- A superseded assertion may only be retracted. -/
theorem superseded_only_retracts (next : Lifecycle) :
    transition_allowed (some Lifecycle.Superseded) next = ok true ↔
      next = Lifecycle.Retracted := by
  cases next <;> simp [transition_allowed]

/-- An assertion that left the proposed lifecycle never returns to it. -/
theorem no_return_to_proposed (previous : Lifecycle)
    (h : previous ≠ Lifecycle.Proposed) :
    transition_allowed (some previous) Lifecycle.Proposed = ok false := by
  cases previous <;> simp_all [transition_allowed]

/-! ## `required_decision` -/

/-- `required_decision` never fails or diverges. -/
theorem required_decision_total (state : Lifecycle) :
    ∃ required, required_decision state = ok required := by
  cases state <;> simp [required_decision]

/-- Only a proposed revision needs no decision. -/
theorem required_decision_none_iff (state : Lifecycle) :
    required_decision state = ok none ↔ state = Lifecycle.Proposed := by
  cases state <;> simp [required_decision]

/-- The complete table of `required_decision`: a proposed revision cites no
decision; an accepted one cites an acceptance, a disputed one a conflict
resolution, a superseded one a supersession, and a retracted one a
retraction. -/
theorem required_decision_table :
    required_decision Lifecycle.Proposed = ok none ∧
      required_decision Lifecycle.Accepted =
        ok (some DecisionKind.Acceptance) ∧
      required_decision Lifecycle.Disputed =
        ok (some DecisionKind.ConflictResolution) ∧
      required_decision Lifecycle.Superseded =
        ok (some DecisionKind.Supersession) ∧
      required_decision Lifecycle.Retracted =
        ok (some DecisionKind.Retraction) := by
  simp [required_decision]

/-! ## `kind_eq` -/

/-- `kind_eq` never fails or diverges. -/
theorem kind_eq_total (left right : DecisionKind) :
    ∃ same, kind_eq left right = ok same := by
  cases left <;> cases right <;> simp [kind_eq]

/-- `kind_eq` decides equality of decision kinds. -/
theorem kind_eq_iff (left right : DecisionKind) :
    kind_eq left right = ok true ↔ left = right := by
  cases left <;> cases right <;> simp [kind_eq]

/-! ## `decision_backs` -/

/-- `decision_backs` never fails or diverges. -/
theorem decision_backs_total (state : Lifecycle)
    (cited : Option CitedDecision) :
    ∃ backed, decision_backs state cited = ok backed := by
  cases cited with
  | none => cases state <;> simp [decision_backs, required_decision]
  | some decision =>
    obtain ⟨kind, outcome, targets, binds⟩ := decision
    cases state <;> cases kind <;> cases outcome <;> cases targets <;>
      simp [decision_backs, required_decision, kind_eq]

/-- A proposed revision is backed exactly when it cites no decision. -/
theorem decision_backs_proposed_iff (cited : Option CitedDecision) :
    decision_backs Lifecycle.Proposed cited = ok true ↔ cited = none := by
  cases cited <;> simp [decision_backs, required_decision]

/-- A revision in any other lifecycle is backed exactly when it cites a
decision of the kind its lifecycle requires, with the matching outcome, about
this assertion, and about exactly the revision being replaced. -/
theorem decision_backs_non_proposed_iff (state : Lifecycle)
    (cited : Option CitedDecision) (h : state ≠ Lifecycle.Proposed) :
    decision_backs state cited = ok true ↔
      ∃ decision, cited = some decision ∧
        required_decision state = ok (some decision.kind) ∧
        decision.outcome_matches = true ∧
        decision.targets_assertion = true ∧
        decision.binds_replaced_revision = true := by
  cases cited with
  | none => cases state <;> simp_all [decision_backs, required_decision]
  | some decision =>
    obtain ⟨kind, outcome, targets, binds⟩ := decision
    cases state <;> cases kind <;> cases outcome <;> cases targets <;>
      simp_all [decision_backs, required_decision, kind_eq]

/-! ## `revision_admissible` -/

/-- `revision_admissible` never fails or diverges. -/
theorem revision_admissible_total (prior : Option Lifecycle) (next : Lifecycle)
    (cited : Option CitedDecision) (commit : CommitTimeFacts) :
    ∃ admissible, revision_admissible prior next cited commit = ok admissible := by
  obtain ⟨allowed, hallowed⟩ := transition_allowed_total prior next
  obtain ⟨backed, hbacked⟩ := decision_backs_total next cited
  obtain ⟨in_batch, committer⟩ := commit
  cases allowed <;> cases backed <;> cases cited <;> cases in_batch <;>
    simp [revision_admissible, hallowed, hbacked]

/-- An admissible revision makes an allowed transition, is backed by the
decision it cites, and any cited decision is committed by the same batch and
made by the committing principal. -/
theorem revision_admissible_sound (prior : Option Lifecycle) (next : Lifecycle)
    (cited : Option CitedDecision) (commit : CommitTimeFacts)
    (h : revision_admissible prior next cited commit = ok true) :
    transition_allowed prior next = ok true ∧
      decision_backs next cited = ok true ∧
      (cited ≠ none →
        commit.decision_in_batch = true ∧ commit.actor_is_committer = true) := by
  obtain ⟨allowed, hallowed⟩ := transition_allowed_total prior next
  obtain ⟨backed, hbacked⟩ := decision_backs_total next cited
  obtain ⟨in_batch, committer⟩ := commit
  cases allowed <;> cases backed <;> cases cited <;> cases in_batch <;>
    simp_all [revision_admissible]

/-- The three conditions of `revision_admissible_sound` are sufficient. -/
theorem revision_admissible_complete (prior : Option Lifecycle)
    (next : Lifecycle) (cited : Option CitedDecision) (commit : CommitTimeFacts)
    (htransition : transition_allowed prior next = ok true)
    (hbacked : decision_backs next cited = ok true)
    (hfresh : cited ≠ none →
      commit.decision_in_batch = true ∧ commit.actor_is_committer = true) :
    revision_admissible prior next cited commit = ok true := by
  obtain ⟨in_batch, committer⟩ := commit
  cases cited <;> simp_all [revision_admissible]

/-- An accepted revision always cites an acceptance decision with the matching
outcome, about this assertion and about exactly the revision it replaces,
committed by the same batch and made by the committing principal; and it
replaces a proposed, accepted or disputed revision, never a new record, a
retracted or a superseded assertion. -/
theorem accepted_needs_fresh_bound_acceptance (prior : Option Lifecycle)
    (cited : Option CitedDecision) (commit : CommitTimeFacts)
    (h : revision_admissible prior Lifecycle.Accepted cited commit = ok true) :
    ∃ decision, cited = some decision ∧
      decision.kind = DecisionKind.Acceptance ∧
      decision.outcome_matches = true ∧
      decision.targets_assertion = true ∧
      decision.binds_replaced_revision = true ∧
      commit.decision_in_batch = true ∧
      commit.actor_is_committer = true ∧
      (prior = some Lifecycle.Proposed ∨ prior = some Lifecycle.Accepted ∨
        prior = some Lifecycle.Disputed) := by
  obtain ⟨htransition, hbacked, hfresh⟩ :=
    revision_admissible_sound prior Lifecycle.Accepted cited commit h
  obtain ⟨decision, hcited, hkind, houtcome, htargets, hbinds⟩ :=
    (decision_backs_non_proposed_iff Lifecycle.Accepted cited (by simp)).mp
      hbacked
  subst hcited
  obtain ⟨hbatch, hcommitter⟩ := hfresh (by simp)
  refine ⟨decision, rfl, ?_, houtcome, htargets, hbinds, hbatch, hcommitter, ?_⟩
  · rw [required_decision_table.2.1] at hkind
    exact (Option.some.inj (Result.ok_injective hkind)).symm
  · cases prior with
    | none => simp [transition_allowed] at htransition
    | some previous =>
      cases previous <;> simp [transition_allowed] at htransition ⊢

end mneme_kernel.claim
