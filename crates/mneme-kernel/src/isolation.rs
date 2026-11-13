//! Scope isolation rules.
//!
//! Records live in exactly one scope. These rules decide which records a
//! record may depend on, which scope a revision may carry, which records a
//! belief view may show, and which stored bytes a record may claim. The shells
//! compare scope identifiers and consult the caller's authorization; the
//! kernel combines those facts.

/// The isolation class of a scope.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum ScopeClass {
    /// User, workspace, project, agent and task scopes hold operational memory.
    Operational,
    /// Hypothesis scopes hold claims that must stay out of operational views.
    Hypothesis,
}

/// Facts about one reference from a record to a target record.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct ReferenceFacts {
    /// The target record's scope equals the referencing record's scope.
    pub same_scope: bool,
    /// Class of the referencing record's scope.
    pub source_class: ScopeClass,
    /// Class of the target record's scope.
    pub target_class: ScopeClass,
    /// The caller is explicitly authorized for the target record's scope.
    pub target_authorized: bool,
}

/// Whether a record may cite, derive from, decide on, checkpoint or otherwise
/// depend on a target record.
///
/// Same-scope references are always allowed. A cross-scope reference needs
/// explicit authorization for the target scope, and operational memory never
/// depends on a hypothesis.
pub fn reference_allowed(facts: &ReferenceFacts) -> bool {
    if facts.same_scope {
        true
    } else if !facts.target_authorized {
        false
    } else {
        !(matches!(facts.source_class, ScopeClass::Operational)
            && matches!(facts.target_class, ScopeClass::Hypothesis))
    }
}

/// Facts about reading stored content of a target record from another
/// record's scope.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct ContentFacts {
    /// The target record's scope equals the scope the caller works in.
    pub same_scope: bool,
    /// The caller is explicitly authorized for the target record's scope.
    pub target_authorized: bool,
}

/// Whether stored content of a target record may be read back to a caller
/// working in another record's scope (explanations, excerpts, lengths).
pub fn content_readable(facts: &ContentFacts) -> bool {
    facts.same_scope || facts.target_authorized
}

/// Facts about the scope a new revision of an existing record carries.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct ScopeChange {
    /// The new revision's scope equals its predecessor's scope.
    pub same_scope: bool,
    /// Class of the predecessor's scope.
    pub prior_class: ScopeClass,
    /// Class of the new revision's scope.
    pub next_class: ScopeClass,
}

/// Facts about the scope of a new revision of an existing record.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct RevisionFacts {
    /// The new revision's scope equals its predecessor's scope.
    pub same_scope: bool,
    /// Class of the predecessor's scope.
    pub prior_class: ScopeClass,
    /// Class of the new revision's scope.
    pub next_class: ScopeClass,
    /// The same batch commits an acceptance decision for this revision.
    pub carries_acceptance: bool,
    /// The caller is authorized for both the predecessor's and the new scope.
    pub both_authorized: bool,
}

/// The structural rule the store enforces on every revision: a record keeps
/// its scope, except that a hypothesis may be promoted into operational memory.
pub fn revision_scope_structural(change: &ScopeChange) -> bool {
    change.same_scope
        || (matches!(change.prior_class, ScopeClass::Hypothesis)
            && matches!(change.next_class, ScopeClass::Operational))
}

/// The policy rule the memory service enforces: a promotion additionally needs
/// an acceptance decision in the same batch and authorization for both scopes.
pub fn revision_scope_allowed(facts: &RevisionFacts) -> bool {
    if facts.same_scope {
        true
    } else {
        let change = ScopeChange {
            same_scope: facts.same_scope,
            prior_class: facts.prior_class,
            next_class: facts.next_class,
        };
        revision_scope_structural(&change) && facts.carries_acceptance && facts.both_authorized
    }
}

/// Facts about one record considered for a belief, conflict or recall view.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct VisibilityFacts {
    /// The record's scope equals the view's scope.
    pub same_scope: bool,
    /// Class of the record's scope.
    pub record_class: ScopeClass,
    /// The request asked to include hypothetical claims.
    pub include_hypothetical: bool,
    /// The caller is explicitly authorized for the record's scope.
    pub record_scope_authorized: bool,
}

/// Whether a view may show a record.
///
/// Including hypothetical claims widens a view only to hypothesis scopes the
/// caller is explicitly authorized for, never to every hypothesis scope.
pub fn record_visible(facts: &VisibilityFacts) -> bool {
    facts.same_scope
        || (facts.include_hypothetical
            && matches!(facts.record_class, ScopeClass::Hypothesis)
            && facts.record_scope_authorized)
}

/// Facts about a source record that names stored bytes by digest.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct BlobClaimFacts {
    /// The command supplies the bytes themselves.
    pub bytes_supplied: bool,
    /// A retained record in the command's own scope already binds the digest.
    pub bound_in_scope: bool,
}

/// Whether a record may claim stored bytes by digest.
///
/// Knowing a digest is not access: without the bytes, the digest must already
/// belong to the same scope.
pub fn blob_claim_allowed(facts: &BlobClaimFacts) -> bool {
    facts.bytes_supplied || facts.bound_in_scope
}
