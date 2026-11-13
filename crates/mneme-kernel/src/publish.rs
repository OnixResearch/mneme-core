//! Working-file publication: never replace content the user changed.
//!
//! The coordinator first moves the working file aside (an atomic rename), then
//! hashes the moved file and asks for a decision. Because the observed digest
//! is taken from the quarantined file, no path-based writer can change it
//! between the check and the replacement.

/// What to do with one publication intent.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum PublicationDecision {
    /// The working file already holds the desired bytes.
    AlreadyPublished,
    /// The working file is exactly what the committer expected; replace it.
    Replace,
    /// The working file differs from both the expected and desired content.
    Diverged,
}

/// Digests observed for one publication intent.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct PublicationFacts {
    /// Digest of the working file as found, or `None` when it is absent.
    pub observed: Option<crate::hashing::Digest>,
    /// Digest the committer expected to replace, or `None` for a new file.
    pub expected: Option<crate::hashing::Digest>,
    /// Digest of the bytes to publish.
    pub desired: crate::hashing::Digest,
}

/// Decide one publication.
pub fn decide_publication(facts: &PublicationFacts) -> PublicationDecision {
    let is_published = match &facts.observed {
        Some(found) => crate::hashing::digest_eq(found, &facts.desired),
        None => false,
    };
    if is_published {
        PublicationDecision::AlreadyPublished
    } else if crate::hashing::optional_digest_eq(&facts.observed, &facts.expected) {
        PublicationDecision::Replace
    } else {
        PublicationDecision::Diverged
    }
}

/// The recorded state of a publication intent.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum PublicationPhase {
    /// Committed, not yet attempted.
    Pending,
    /// The working file holds the desired bytes.
    Published,
    /// An external edit was found and kept.
    Diverged,
    /// An erasure barrier withdrew the intent.
    Suppressed,
    /// The last attempt failed before a decision could be applied.
    Failed,
}

/// Whether recovery or an explicit publish must attempt an intent again.
///
/// A failed attempt is retried: a transient filesystem error must not leave a
/// committed revision permanently unpublished. A divergence is final until the
/// user imports or discards the external edit.
pub fn should_attempt(phase: PublicationPhase) -> bool {
    matches!(phase, PublicationPhase::Pending | PublicationPhase::Failed)
}
