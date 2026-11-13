//! Physical purge decisions for retention cleanup.
//!
//! A purge removes bytes only when the shell has shown that the bytes are the
//! planned ones. Anything else is reported as it is, never as "purged".

/// What kind of directory entry sits at a working path.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum EntryKind {
    /// Nothing is there.
    Absent,
    /// A regular file, not reached through a symbolic link.
    Regular,
    /// A symbolic link, directory, FIFO, socket or device.
    Other,
}

/// Facts about one working file planned for purge.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct WorkingFacts {
    /// The entry kind, read without following a final symbolic link.
    pub kind: EntryKind,
    /// Digest of the quarantined regular file, when it could be read.
    pub observed: Option<crate::hashing::Digest>,
    /// Digest the cleanup plan names for this location.
    pub planned: crate::hashing::Digest,
}

/// What to do with a working file planned for purge.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum WorkingDecision {
    /// The file holds exactly the planned bytes; delete it.
    Purge,
    /// There is nothing to delete.
    AlreadyAbsent,
    /// The file holds other bytes; keep it and report the external edit.
    ExternalEdit,
    /// The entry is not a readable regular file; report it unavailable.
    Unsupported,
}

/// Decide the purge of one working file.
pub fn decide_working(facts: &WorkingFacts) -> WorkingDecision {
    match facts.kind {
        EntryKind::Absent => WorkingDecision::AlreadyAbsent,
        EntryKind::Other => WorkingDecision::Unsupported,
        EntryKind::Regular => match &facts.observed {
            Some(found) => {
                if crate::hashing::digest_eq(found, &facts.planned) {
                    WorkingDecision::Purge
                } else {
                    WorkingDecision::ExternalEdit
                }
            }
            None => WorkingDecision::Unsupported,
        },
    }
}

/// Facts about one content-addressed blob planned for purge, read inside the
/// same immediate transaction that will record the outcome.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct BlobFacts {
    /// A retained record, revision, intent or candidate still needs the bytes.
    pub required: bool,
    /// The blob file exists.
    pub present: bool,
}

/// What to do with a blob planned for purge.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum BlobDecision {
    /// No retained owner needs the bytes; delete the blob.
    Purge,
    /// Another retained owner needs the same bytes; keep them.
    RetainShared,
    /// The blob is already gone.
    AlreadyAbsent,
}

/// Decide the purge of one blob.
pub fn decide_blob(facts: &BlobFacts) -> BlobDecision {
    if facts.required {
        BlobDecision::RetainShared
    } else if facts.present {
        BlobDecision::Purge
    } else {
        BlobDecision::AlreadyAbsent
    }
}
