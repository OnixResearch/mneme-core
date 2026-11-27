//! Commands submitted to the workspace coordinator.
//!
//! A command names its base revision, actor, scope, idempotency key, new record
//! revisions, exact source bytes, working-file publication intents, and external
//! import candidates. The normalized request digest binds actor, scope, and
//! content without including the caller's recorded time, which the coordinator
//! assigns.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// A record revision proposed for the next snapshot.
#[derive(Clone, Debug)]
pub struct RecordDraft {
    pub schema_version: u32,
    pub kind: mneme_core::RecordKind,
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
    pub predecessor: Option<mneme_core::RevisionId>,
    pub scope: mneme_core::ScopeId,
    pub payload: mneme_core::Payload,
}

impl PartialEq for RecordDraft {
    fn eq(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.kind == other.kind
            && self.record_id == other.record_id
            && self.revision_id == other.revision_id
            && self.parents() == other.parents()
            && self.scope == other.scope
            && self.payload == other.payload
    }
}

impl Eq for RecordDraft {}

impl RecordDraft {
    /// Canonical sorted causal parent set for this draft revision.
    pub fn parents(&self) -> std::collections::BTreeSet<mneme_core::RevisionId> {
        let mut set = self.payload.envelope_extra_parents().clone();
        if let Some(predecessor) = self.predecessor {
            set.insert(predecessor);
        }
        set
    }

    /// Replace the causal parent set on this draft revision.
    pub fn set_parents(&mut self, parents: std::collections::BTreeSet<mneme_core::RevisionId>) {
        let mut iter = parents.into_iter();
        self.predecessor = iter.next();
        self.payload.set_envelope_extra_parents(iter.collect());
    }

    /// Return this draft with its causal parent set replaced by `parents`.
    #[must_use]
    pub fn with_parents(
        mut self,
        parents: std::collections::BTreeSet<mneme_core::RevisionId>,
    ) -> Self {
        self.set_parents(parents);
        self
    }

    /// Build the immutable envelope with coordinator-assigned recorded time.
    pub fn into_envelope(self, recorded: mneme_core::RecordedTime) -> mneme_core::RecordEnvelope {
        mneme_core::RecordEnvelope {
            schema_version: self.schema_version,
            kind: self.kind,
            record_id: self.record_id,
            revision_id: self.revision_id,
            predecessor: self.predecessor,
            scope: self.scope,
            recorded,
            payload: self.payload,
        }
    }

    fn request_value(&self) -> mneme_core::Value {
        let parents = self.parents();
        let parent_value = if parents.is_empty() {
            mneme_core::Value::symbol("none")
        } else if parents.len() == 1 {
            match parents.iter().next() {
                Some(revision) => revision.to_value(),
                None => mneme_core::Value::symbol("none"),
            }
        } else {
            mneme_core::Value::set(parents.iter().map(|revision| revision.to_value()))
        };
        mneme_core::Value::record_named(
            "draft-record",
            vec![
                mneme_core::Value::integer(i64::from(self.schema_version)),
                self.kind.to_value(),
                self.record_id.to_value(),
                self.revision_id.to_value(),
                parent_value,
                self.scope.to_value(),
                self.payload.to_value(),
            ],
        )
    }
}

/// A local file whose bytes are streamed into the blob store at commit.
///
/// The digest and length are taken by streaming the file once when the draft is
/// built; staging streams it again and refuses a file that changed in between.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceFile {
    pub path: std::path::PathBuf,
    pub digest: mneme_core::ContentDigest,
    pub size_bytes: u64,
}

/// Exact source bytes supplied for a committed source revision.
///
/// The bytes are either inline (`bytes`) or streamed from `file`; a draft with
/// a file leaves `bytes` empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceBlobDraft {
    pub bytes: Vec<u8>,
    pub media_type: mneme_core::Symbol,
    pub(crate) file: Option<SourceFile>,
}

impl SourceBlobDraft {
    /// An inline source-blob draft backed by in-memory `bytes`.
    pub fn inline(bytes: Vec<u8>, media_type: mneme_core::Symbol) -> Self {
        Self {
            bytes,
            media_type,
            file: None,
        }
    }
    /// A draft that streams the regular file at `path`, never loading it whole.
    ///
    /// Opens with `O_NOFOLLOW | O_NONBLOCK` on Unix, refuses non-regular files
    /// (symlinks, FIFOs, devices, sockets), and fails closed if the file size
    /// changes concurrently while hashing.
    pub fn from_file(
        path: &std::path::Path,
        media_type: mneme_core::Symbol,
    ) -> crate::error::Result<Self> {
        Self::from_file_bounded(path, media_type, u64::MAX)
    }

    /// A draft that streams the regular file at `path` enforcing an upper bound of `max_bytes`.
    pub fn from_file_bounded(
        path: &std::path::Path,
        media_type: mneme_core::Symbol,
        max_bytes: u64,
    ) -> crate::error::Result<Self> {
        let mut reader = open_regular_file_no_follow(path)?;
        let metadata = reader
            .metadata()
            .map_err(|error| crate::error::Failure::io(path, error))?;
        if !metadata.is_file() {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "source file {} is not a regular file",
                path.display()
            )));
        }
        debug_assert!(metadata.is_file());
        let expected_len = metadata.len();
        if expected_len > max_bytes {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "source file {} size ({expected_len} bytes) exceeds limit ({max_bytes} bytes)",
                path.display()
            )));
        }
        let mut bounded = std::io::Read::take(&mut reader, max_bytes.saturating_add(1));
        let (digest, size_bytes) = mneme_core::ContentDigest::of_source_reader(&mut bounded)
            .map_err(|error| crate::error::Failure::io(path, error))?;
        if size_bytes > max_bytes {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "source file {} grew past limit ({max_bytes} bytes) while reading",
                path.display()
            )));
        }
        if size_bytes != expected_len {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "source file {} changed concurrently while reading ({size_bytes} != {expected_len} bytes)",
                path.display()
            )));
        }
        debug_assert!(size_bytes <= max_bytes);
        Ok(Self {
            bytes: Vec::new(),
            media_type,
            file: Some(SourceFile {
                path: path.to_path_buf(),
                digest,
                size_bytes,
            }),
        })
    }

    /// The raw-source digest of these bytes.
    pub fn digest(&self) -> mneme_core::ContentDigest {
        match &self.file {
            Some(file) => file.digest,
            None => mneme_core::ContentDigest::of_source_bytes(&self.bytes),
        }
    }

    /// The number of source bytes, inline or streamed.
    pub fn byte_length(&self) -> u64 {
        match &self.file {
            Some(file) => file.size_bytes,
            None => self.bytes.len() as u64,
        }
    }
}

#[cfg(unix)]
fn open_regular_file_no_follow(path: &std::path::Path) -> crate::error::Result<std::fs::File> {
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::NONBLOCK
        | rustix::fs::OFlags::CLOEXEC;
    let fd = rustix::fs::open(path, flags, rustix::fs::Mode::empty()).map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            crate::error::Failure::InvalidCommand(format!(
                "source file {} must not be a symbolic link",
                path.display()
            ))
        } else {
            crate::error::Failure::io(path, std::io::Error::from(error))
        }
    })?;
    Ok(std::fs::File::from(fd))
}

#[cfg(not(unix))]
fn open_regular_file_no_follow(path: &std::path::Path) -> crate::error::Result<std::fs::File> {
    let link_meta =
        std::fs::symlink_metadata(path).map_err(|error| crate::error::Failure::io(path, error))?;
    if link_meta.file_type().is_symlink() {
        return Err(crate::error::Failure::InvalidCommand(format!(
            "source file {} must not be a symbolic link",
            path.display()
        )));
    }
    std::fs::File::open(path).map_err(|error| crate::error::Failure::io(path, error))
}

/// A working-file publication intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationDraft {
    /// Path relative to the workspace's `working/` directory.
    pub path: String,
    /// Exact digest expected in the working file before replacement.
    pub expected_previous: Option<mneme_core::ContentDigest>,
    /// Desired committed bytes.
    pub bytes: Vec<u8>,
}

impl PublicationDraft {
    /// The raw-source digest of the desired bytes.
    pub fn desired_digest(&self) -> mneme_core::ContentDigest {
        mneme_core::ContentDigest::of_source_bytes(&self.bytes)
    }

    fn request_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "publication",
            vec![
                mneme_core::Value::string(self.path.clone()),
                match self.expected_previous {
                    Some(digest) => digest.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
                self.desired_digest().to_value(),
            ],
        )
    }
}

/// An externally edited file offered for import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportCandidateDraft {
    /// Path relative to `working/`.
    pub path: String,
    /// Exact candidate bytes observed by the importer.
    pub bytes: Vec<u8>,
}

impl ImportCandidateDraft {
    /// The raw-source digest of the candidate bytes.
    pub fn digest(&self) -> mneme_core::ContentDigest {
        mneme_core::ContentDigest::of_source_bytes(&self.bytes)
    }

    fn request_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "import-candidate",
            vec![
                mneme_core::Value::string(self.path.clone()),
                self.digest().to_value(),
            ],
        )
    }
}

/// A complete mutation command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitCommand {
    pub base: mneme_core::WorkspaceRevisionId,
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub idempotency_key: String,
    pub records: Vec<RecordDraft>,
    pub source_blobs: Vec<SourceBlobDraft>,
    pub publications: Vec<PublicationDraft>,
    pub import_candidates: Vec<ImportCandidateDraft>,
    /// An atomically committed retention barrier and cleanup plan.
    pub retention: Option<crate::lifecycle::RetentionCommit>,
}

impl CommitCommand {
    /// The normalized command identity bound to actor and scope.
    pub fn request_digest(&self) -> mneme_core::ContentDigest {
        mneme_core::ContentDigest::of_payload(&self.request_value())
    }

    fn request_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "commit-request",
            vec![
                self.base.to_value(),
                mneme_core::Value::string(self.actor.clone()),
                self.scope.to_value(),
                mneme_core::Value::set(self.records.iter().map(RecordDraft::request_value)),
                mneme_core::Value::set(
                    self.source_blobs
                        .iter()
                        .map(|blob| blob.digest().to_value()),
                ),
                mneme_core::Value::set(
                    self.publications
                        .iter()
                        .map(PublicationDraft::request_value),
                ),
                mneme_core::Value::set(
                    self.import_candidates
                        .iter()
                        .map(ImportCandidateDraft::request_value),
                ),
                match &self.retention {
                    Some(retention) => retention.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_file_bounded_refuses_oversized_and_accepts_regular() {
        let temp = tempfile::tempdir().expect("tempdir");
        let regular = temp.path().join("sample.txt");
        std::fs::write(&regular, b"hello world").expect("write regular");

        let ok = SourceBlobDraft::from_file_bounded(
            &regular,
            mneme_core::Symbol::from("text/plain"),
            11,
        )
        .expect("within limit");
        assert_eq!(ok.byte_length(), 11);

        let too_big = SourceBlobDraft::from_file_bounded(
            &regular,
            mneme_core::Symbol::from("text/plain"),
            10,
        );
        assert!(too_big.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn from_file_refuses_symlinks_and_fifos_without_blocking() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("secret.txt");
        std::fs::write(&target, b"secret-key").expect("write target");
        let link = temp.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let symlink_err = SourceBlobDraft::from_file(&link, mneme_core::Symbol::from("text/plain"));
        assert!(symlink_err.is_err());

        let fifo = temp.path().join("pipe.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success());

        let fifo_err = SourceBlobDraft::from_file(&fifo, mneme_core::Symbol::from("text/plain"));
        assert!(fifo_err.is_err());
    }
}
