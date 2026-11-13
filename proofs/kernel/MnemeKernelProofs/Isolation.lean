import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Scope isolation rules

Theorems about the generated translation of `crates/mneme-kernel/src/isolation.rs`.
The six rules of the module are total: each returns `ok` for every input (the
`*_total` theorems), so each `= ok true ↔ …` statement also determines when the
rule returns `ok false`.
-/

namespace mneme_kernel.isolation

/-! ## `reference_allowed` -/

/-- `reference_allowed` never fails or diverges. -/
theorem reference_allowed_total (facts : ReferenceFacts) :
    ∃ allowed, reference_allowed facts = ok allowed := by
  obtain ⟨same, source, target, authorized⟩ := facts
  cases same <;> cases authorized <;> cases source <;> cases target <;>
    simp [reference_allowed]

/-- A reference inside one scope is always allowed. -/
theorem reference_allowed_same_scope (facts : ReferenceFacts)
    (h : facts.same_scope = true) : reference_allowed facts = ok true := by
  simp [reference_allowed, h]

/-- A cross-scope reference is allowed exactly when the target scope is
authorized and the reference is not from operational memory to a hypothesis. -/
theorem reference_allowed_cross_scope_iff (facts : ReferenceFacts)
    (h : facts.same_scope = false) :
    reference_allowed facts = ok true ↔
      facts.target_authorized = true ∧
        ¬ (facts.source_class = ScopeClass.Operational ∧
            facts.target_class = ScopeClass.Hypothesis) := by
  obtain ⟨same, source, target, authorized⟩ := facts
  cases same <;> cases authorized <;> cases source <;> cases target <;>
    simp_all [reference_allowed]

/-- An allowed reference stays inside its scope or targets an authorized scope. -/
theorem reference_allowed_needs_authorization (facts : ReferenceFacts)
    (h : reference_allowed facts = ok true) :
    facts.same_scope = true ∨ facts.target_authorized = true := by
  obtain ⟨same, source, target, authorized⟩ := facts
  cases same <;> cases authorized <;> simp_all [reference_allowed]

/-- Operational memory never depends on a hypothesis of another scope, whatever
the caller is authorized for. -/
theorem operational_never_depends_on_foreign_hypothesis (facts : ReferenceFacts)
    (hscope : facts.same_scope = false)
    (hsource : facts.source_class = ScopeClass.Operational)
    (htarget : facts.target_class = ScopeClass.Hypothesis) :
    reference_allowed facts = ok false := by
  obtain ⟨same, source, target, authorized⟩ := facts
  cases authorized <;> simp_all [reference_allowed]

/-! ## `content_readable` -/

/-- `content_readable` never fails or diverges. -/
theorem content_readable_total (facts : ContentFacts) :
    ∃ readable, content_readable facts = ok readable := by
  obtain ⟨same_scope, target_authorized⟩ := facts
  cases same_scope <;> simp [content_readable]

/-- Stored content is readable exactly inside the scope or with authorization
for the target scope. -/
theorem content_readable_iff (facts : ContentFacts) :
    content_readable facts = ok true ↔
      facts.same_scope = true ∨ facts.target_authorized = true := by
  obtain ⟨same_scope, target_authorized⟩ := facts
  cases same_scope <;> simp [content_readable]

/-! ## `revision_scope_structural` -/

/-- `revision_scope_structural` never fails or diverges. -/
theorem revision_scope_structural_total (change : ScopeChange) :
    ∃ allowed, revision_scope_structural change = ok allowed := by
  obtain ⟨same_scope, prior_class, next_class⟩ := change
  cases same_scope <;> cases prior_class <;> cases next_class <;>
    simp [revision_scope_structural]

/-- The structural rule: a revision keeps its scope, or promotes a hypothesis
into operational memory. -/
theorem revision_scope_structural_iff (change : ScopeChange) :
    revision_scope_structural change = ok true ↔
      change.same_scope = true ∨
        (change.prior_class = ScopeClass.Hypothesis ∧
          change.next_class = ScopeClass.Operational) := by
  obtain ⟨same_scope, prior_class, next_class⟩ := change
  cases same_scope <;> cases prior_class <;> cases next_class <;>
    simp [revision_scope_structural]

/-! ## `revision_scope_allowed` -/

/-- `revision_scope_allowed` never fails or diverges. -/
theorem revision_scope_allowed_total (facts : RevisionFacts) :
    ∃ allowed, revision_scope_allowed facts = ok allowed := by
  obtain ⟨same, prior, next, carries, both⟩ := facts
  cases same <;> cases prior <;> cases next <;> cases carries <;>
    simp [revision_scope_allowed, revision_scope_structural]

/-- A revision that keeps its scope is always allowed. -/
theorem revision_scope_allowed_same_scope (facts : RevisionFacts)
    (h : facts.same_scope = true) : revision_scope_allowed facts = ok true := by
  simp [revision_scope_allowed, h]

/-- A revision that changes scope is allowed exactly when it promotes a
hypothesis into operational memory, carries an acceptance decision, and the
caller is authorized for both scopes. -/
theorem revision_scope_allowed_cross_scope_iff (facts : RevisionFacts)
    (h : facts.same_scope = false) :
    revision_scope_allowed facts = ok true ↔
      facts.prior_class = ScopeClass.Hypothesis ∧
        facts.next_class = ScopeClass.Operational ∧
        facts.carries_acceptance = true ∧
        facts.both_authorized = true := by
  obtain ⟨same, prior, next, carries, both⟩ := facts
  cases same <;> cases prior <;> cases next <;> cases carries <;>
    simp_all [revision_scope_allowed, revision_scope_structural]

/-- The policy rule never allows a revision the structural rule refuses. -/
theorem revision_scope_allowed_implies_structural (facts : RevisionFacts)
    (h : revision_scope_allowed facts = ok true) :
    revision_scope_structural
      { same_scope := facts.same_scope, prior_class := facts.prior_class,
        next_class := facts.next_class } = ok true := by
  obtain ⟨same, prior, next, carries, both⟩ := facts
  cases same <;> cases prior <;> cases next <;>
    simp_all [revision_scope_allowed, revision_scope_structural]

/-! ## `record_visible` -/

/-- `record_visible` never fails or diverges. -/
theorem record_visible_total (facts : VisibilityFacts) :
    ∃ visible, record_visible facts = ok visible := by
  obtain ⟨same, record, hypothetical, authorized⟩ := facts
  cases same <;> cases record <;> cases hypothetical <;>
    simp [record_visible]

/-- A view shows a record exactly when the record is in the view's scope, or
the request includes hypothetical claims and the record is in a hypothesis
scope the caller is authorized for. -/
theorem record_visible_iff (facts : VisibilityFacts) :
    record_visible facts = ok true ↔
      facts.same_scope = true ∨
        (facts.include_hypothetical = true ∧
          facts.record_class = ScopeClass.Hypothesis ∧
          facts.record_scope_authorized = true) := by
  obtain ⟨same, record, hypothetical, authorized⟩ := facts
  cases same <;> cases record <;> cases hypothetical <;>
    simp [record_visible]

/-- Including hypothetical claims never widens a view to a scope the caller is
not authorized for. -/
theorem record_visible_never_widens_to_unauthorized (facts : VisibilityFacts)
    (hscope : facts.same_scope = false)
    (hauthorized : facts.record_scope_authorized = false) :
    record_visible facts = ok false := by
  obtain ⟨same, record, hypothetical, authorized⟩ := facts
  cases record <;> cases hypothetical <;> simp_all [record_visible]

/-! ## `blob_claim_allowed` -/

/-- `blob_claim_allowed` never fails or diverges. -/
theorem blob_claim_allowed_total (facts : BlobClaimFacts) :
    ∃ allowed, blob_claim_allowed facts = ok allowed := by
  obtain ⟨supplied, bound⟩ := facts
  cases supplied <;> simp [blob_claim_allowed]

/-- A record may claim stored bytes exactly when it supplies them or the digest
is already bound in its own scope. -/
theorem blob_claim_allowed_iff (facts : BlobClaimFacts) :
    blob_claim_allowed facts = ok true ↔
      facts.bytes_supplied = true ∨ facts.bound_in_scope = true := by
  obtain ⟨supplied, bound⟩ := facts
  cases supplied <;> simp [blob_claim_allowed]

end mneme_kernel.isolation
