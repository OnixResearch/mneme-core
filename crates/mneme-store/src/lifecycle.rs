//! Persisted retention operations, suppression entries, and cleanup progress.
//!
//! The ledger contains minimal identity and status metadata. It never stores
//! forgotten source text, quotations, or human-readable storage errors.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Whether a suppression is inspectable but ineligible, or payload-hidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SuppressionMode {
    /// The record remains metadata-visible but cannot support a claim.
    Withdrawn,
    /// The record's payload is hidden from every read path.
    Forgotten,
}

impl SuppressionMode {
    /// Stable lower-case name.
    pub const fn as_str(self) -> &'static str {
        match self {
            SuppressionMode::Withdrawn => "withdrawn",
            SuppressionMode::Forgotten => "forgotten",
        }
    }

    /// Parse a stored name.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "withdrawn" => Some(SuppressionMode::Withdrawn),
            "forgotten" => Some(SuppressionMode::Forgotten),
            _ => None,
        }
    }
}

/// A retention selector retained in the plan for audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionSelector {
    pub ordinal: u32,
    /// `source`, `source-support`, `assertion`, or `content`.
    pub kind: String,
    pub target: Option<mneme_core::RecordId>,
    pub revision: Option<mneme_core::RevisionId>,
    pub digest: Option<mneme_core::ContentDigest>,
}

impl RetentionSelector {
    pub(crate) fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "retention-selector",
            vec![
                mneme_core::Value::integer(i64::from(self.ordinal)),
                mneme_core::Value::symbol(self.kind.clone()),
                match self.target {
                    Some(target) => target.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
                match self.revision {
                    Some(revision) => revision.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
                match self.digest {
                    Some(digest) => digest.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
            ],
        )
    }
}

/// One record/revision hidden from eligible use and optionally from reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionSuppression {
    pub operation_id: String,
    pub target: mneme_core::RecordId,
    pub revision: Option<mneme_core::RevisionId>,
    pub target_kind: String,
    pub mode: SuppressionMode,
    /// A digest used only for content-match replay blocking.
    pub content_digest: Option<mneme_core::ContentDigest>,
    pub generation: u64,
}

impl RetentionSuppression {
    // Generation is read from the SQLite i64 ledger column, so the conversion is
    // within range for every stored suppression.
    #[allow(unknown_lints, fallible_int_fallback, sentinel_fallback)]
    pub(crate) fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "retention-suppression",
            vec![
                mneme_core::Value::string(self.operation_id.clone()),
                self.target.to_value(),
                match self.revision {
                    Some(revision) => revision.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
                mneme_core::Value::symbol(self.target_kind.clone()),
                mneme_core::Value::symbol(self.mode.as_str().to_owned()),
                match self.content_digest {
                    Some(digest) => digest.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
                mneme_core::Value::integer(i64::try_from(self.generation).unwrap_or(i64::MAX)),
            ],
        )
    }
}

/// One managed location in the impact plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionLocationPlan {
    pub location_id: String,
    /// `source-blob`, `record-blob`, `publication-intent`, `staging`,
    /// `temporary-exports`, `sqlite-payloads`, or `working-file`.
    pub location_kind: String,
    /// Digest hex, publication intent id, or a safe inventory label.
    pub locator: String,
}

impl RetentionLocationPlan {
    fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "retention-location",
            vec![
                mneme_core::Value::string(self.location_id.clone()),
                mneme_core::Value::symbol(self.location_kind.clone()),
                mneme_core::Value::string(self.locator.clone()),
            ],
        )
    }
}

/// A complete retention barrier and cleanup plan committed atomically with the
/// lifecycle records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionCommit {
    pub operation_id: String,
    pub operation_kind: String,
    pub policy_version: String,
    pub selectors: Vec<RetentionSelector>,
    pub suppressions: Vec<RetentionSuppression>,
    pub locations: Vec<RetentionLocationPlan>,
    pub retained_metadata: Vec<String>,
}

impl RetentionCommit {
    /// Normalized identity used by the commit request digest.
    pub fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "retention-commit",
            vec![
                mneme_core::Value::string(self.operation_id.clone()),
                mneme_core::Value::symbol(self.operation_kind.clone()),
                mneme_core::Value::string(self.policy_version.clone()),
                mneme_core::Value::set(self.selectors.iter().map(RetentionSelector::to_value)),
                mneme_core::Value::set(
                    self.suppressions.iter().map(RetentionSuppression::to_value),
                ),
                mneme_core::Value::set(self.locations.iter().map(RetentionLocationPlan::to_value)),
                mneme_core::Value::set(
                    self.retained_metadata
                        .iter()
                        .cloned()
                        .map(mneme_core::Value::string),
                ),
            ],
        )
    }

    /// Validate identifiers and duplicate suppressions before the transaction.
    pub fn validate(&self) -> Result<(), String> {
        if self.operation_id.trim().is_empty() {
            return Err("retention operation id must not be empty".to_owned());
        }
        if self.operation_kind.trim().is_empty() {
            return Err("retention operation kind must not be empty".to_owned());
        }
        if self.policy_version.trim().is_empty() {
            return Err("retention policy version must not be empty".to_owned());
        }
        let mut suppressions = std::collections::BTreeSet::new();
        for suppression in &self.suppressions {
            if suppression.operation_id != self.operation_id {
                return Err("suppression names a different operation".to_owned());
            }
            if suppression.target_kind.trim().is_empty() {
                return Err("suppression target kind must not be empty".to_owned());
            }
            if !suppressions.insert((suppression.target, suppression.revision)) {
                return Err("duplicate retention suppression target".to_owned());
            }
        }
        let mut locations = std::collections::BTreeSet::new();
        for location in &self.locations {
            if location.location_id.trim().is_empty() {
                return Err("retention location id must not be empty".to_owned());
            }
            if location.location_kind.trim().is_empty() {
                return Err("retention location kind must not be empty".to_owned());
            }
            if !locations.insert(location.location_id.clone()) {
                return Err("duplicate retention location id".to_owned());
            }
        }
        Ok(())
    }
}

/// Durable state of a retention operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionJobState {
    BarrierCommitted,
    CleanupPending,
    Complete,
    Partial,
    Failed,
}

impl RetentionJobState {
    /// Stable lower-case name.
    pub const fn as_str(self) -> &'static str {
        match self {
            RetentionJobState::BarrierCommitted => "barrier-committed",
            RetentionJobState::CleanupPending => "cleanup-pending",
            RetentionJobState::Complete => "complete",
            RetentionJobState::Partial => "partial",
            RetentionJobState::Failed => "failed",
        }
    }

    /// Parse a stored name.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "barrier-committed" => Some(RetentionJobState::BarrierCommitted),
            "cleanup-pending" => Some(RetentionJobState::CleanupPending),
            "complete" => Some(RetentionJobState::Complete),
            "partial" => Some(RetentionJobState::Partial),
            "failed" => Some(RetentionJobState::Failed),
            _ => None,
        }
    }
}

/// A persisted retention operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionOperation {
    pub operation_id: String,
    pub operation_kind: String,
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub policy_version: String,
    pub state: RetentionJobState,
    pub generation: u64,
    pub outcome_revision: mneme_core::WorkspaceRevisionId,
    pub outcome_sequence: u64,
    pub retained_metadata: Vec<String>,
    pub created_at_ns: i64,
    pub updated_at_ns: i64,
}

/// Cleanup state of one managed location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionLocationState {
    Pending,
    Purged,
    Absent,
    RetainedShared,
    Unavailable,
    Verified,
    Failed,
}

impl RetentionLocationState {
    /// Stable lower-case name.
    pub const fn as_str(self) -> &'static str {
        match self {
            RetentionLocationState::Pending => "pending",
            RetentionLocationState::Purged => "purged",
            RetentionLocationState::Absent => "absent",
            RetentionLocationState::RetainedShared => "retained-shared",
            RetentionLocationState::Unavailable => "unavailable",
            RetentionLocationState::Verified => "verified",
            RetentionLocationState::Failed => "failed",
        }
    }

    /// Parse a stored name.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(RetentionLocationState::Pending),
            "purged" => Some(RetentionLocationState::Purged),
            "absent" => Some(RetentionLocationState::Absent),
            "retained-shared" => Some(RetentionLocationState::RetainedShared),
            "unavailable" => Some(RetentionLocationState::Unavailable),
            "verified" => Some(RetentionLocationState::Verified),
            "failed" => Some(RetentionLocationState::Failed),
            _ => None,
        }
    }

    /// Whether this state is terminal and physically accounted for.
    pub const fn is_terminal(self) -> bool {
        !matches!(self, RetentionLocationState::Pending)
    }
}

/// A persisted managed-location outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionLocationStateRecord {
    pub location_id: String,
    pub location_kind: String,
    pub locator: String,
    pub state: RetentionLocationState,
    pub attempts: u32,
    pub verified: bool,
    /// A safe diagnostic code; never raw adapter output.
    pub detail_code: Option<String>,
}

/// Result of attempting to remove one content-addressed payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobPurgeOutcome {
    /// The file was removed.
    Purged,
    /// The payload was already physically absent.
    Absent,
    /// A permitted untargeted reference still needs the bytes.
    RetainedShared,
}

/// A payload-bearing component's declared retention behavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionParticipant {
    pub name: String,
    /// Human-readable managed role, such as `lexical-index` or `backup`.
    pub storage_role: String,
    pub supports_invalidation: bool,
    pub supports_purge: bool,
    pub checks_generation: bool,
    /// A bounded inventory entry naming the managed location.
    pub inventory_locator: String,
}

impl RetentionParticipant {
    /// Every participant must provide all four retention capabilities.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("retention participant name must not be empty".to_owned());
        }
        if self.storage_role.trim().is_empty() {
            return Err("retention participant role must not be empty".to_owned());
        }
        if !self.supports_invalidation {
            return Err("retention participant must implement invalidation".to_owned());
        }
        if !self.supports_purge {
            return Err("retention participant must implement purge".to_owned());
        }
        if !self.checks_generation {
            return Err("retention participant must check eligibility generations".to_owned());
        }
        if self.inventory_locator.trim().is_empty() {
            return Err("retention participant must register a storage inventory entry".to_owned());
        }
        Ok(())
    }
}
