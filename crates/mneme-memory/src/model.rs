//! Typed views over the application payloads used by evidence memory.
//!
//! Parsing is strict about the fields this capability owns. Unknown extension
//! fields remain ordinary retained data; they are not interpreted here.

/// Whether exact source bytes are inspectable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceAvailability {
    Retained,
    Pruned,
    Erased,
    Inaccessible,
    Corrupt { reason: String },
    Unavailable { reason: String },
}

impl SourceAvailability {
    /// Stable name for reports.
    pub const fn name(&self) -> &'static str {
        match self {
            SourceAvailability::Retained => "retained",
            SourceAvailability::Pruned => "pruned",
            SourceAvailability::Erased => "erased",
            SourceAvailability::Inaccessible => "inaccessible",
            SourceAvailability::Corrupt { .. } => "corrupt",
            SourceAvailability::Unavailable { .. } => "unavailable",
        }
    }
}

/// A retained or explicitly unavailable source revision.
#[derive(Clone, Debug, PartialEq)]
pub struct SourceView {
    pub record: mneme_core::RecordEnvelope,
    pub content: mneme_core::SourceContent,
    pub availability: SourceAvailability,
    pub acquisition: mneme_core::Acquisition,
    /// The acquisition value as stored, re-emitted unchanged when the source
    /// is rewritten. A source older than
    /// [`mneme_core::ACQUISITION_SCHEMA_VERSION`] may hold a symbol outside the
    /// closed classes; it reads as [`mneme_core::Acquisition::Imported`].
    pub acquisition_value: mneme_core::Value,
    pub derived_from: Option<mneme_core::SourcePin>,
    pub media_extent: Option<mneme_core::MediaExtent>,
    pub media_transform: Option<mneme_core::MediaTransform>,
    /// The coordinate frame a page or ink source's pages use.
    pub media_frame: Option<mneme_core::CoordinateFrame>,
    /// The stroke ids an ink source declares.
    pub ink_inventory: Option<mneme_core::InkInventory>,
    pub correction: Option<mneme_core::CorrectionProvenance>,
    pub path_hint: Option<String>,
    pub entity: Option<mneme_core::RecordId>,
    pub media_type: Option<mneme_core::Symbol>,
    /// Identity of bytes removed by an authorized pruning/erasure step.
    pub prior_digest: Option<mneme_core::ContentDigest>,
}

impl SourceView {
    /// Parse a source-revision envelope.
    pub fn parse(record: mneme_core::RecordEnvelope) -> crate::failure::Result<Self> {
        expect_kind(&record, mneme_core::RecordKind::SourceRevision)?;
        let content = source_content(&record)?;
        let availability = source_availability(&record, &content);
        let media_type = retained_media_type(&content);
        let prior_digest = source_prior_digest(&record)?;
        let (acquisition, acquisition_value) = source_acquisition(&record)?;
        let derived_from = optional_source_pin(&record, "derived-from")?;
        let media_extent = optional_media_extent(&record)?;
        let media_transform = optional_media_transform(&record)?;
        let media_frame = parse_optional_media_value(
            &record,
            "media-frame",
            mneme_core::CoordinateFrame::from_value,
        )?;
        let ink_inventory = parse_optional_media_value(
            &record,
            "ink-strokes",
            mneme_core::InkInventory::from_value,
        )?;
        let correction = optional_correction(&record)?;
        Ok(SourceView {
            acquisition,
            acquisition_value,
            derived_from,
            media_extent,
            media_transform,
            media_frame,
            ink_inventory,
            correction,
            path_hint: optional_text(&record, "path-hint"),
            entity: optional_reference_target(&record, "entity")?,
            content,
            availability,
            media_type,
            prior_digest,
            record,
        })
    }

    /// The exact raw source digest when retained.
    pub fn digest(&self) -> Option<mneme_core::ContentDigest> {
        match &self.content {
            mneme_core::SourceContent::Retained(retained) => Some(retained.digest()),
            mneme_core::SourceContent::Unavailable { .. } => None,
        }
    }

    /// The declared byte length when retained.
    pub fn byte_length(&self) -> Option<u64> {
        match &self.content {
            mneme_core::SourceContent::Retained(retained) => Some(retained.byte_length()),
            mneme_core::SourceContent::Unavailable { .. } => None,
        }
    }
}

fn source_content(
    record: &mneme_core::RecordEnvelope,
) -> crate::failure::Result<mneme_core::SourceContent> {
    mneme_core::SourceContent::from_value(
        required(record, "content")?,
        &mneme_core::Path::root().field("content"),
    )
    .map_err(|diagnostic| source_parse_error(record, diagnostic))
}

fn source_acquisition(
    record: &mneme_core::RecordEnvelope,
) -> crate::failure::Result<(mneme_core::Acquisition, mneme_core::Value)> {
    let value = required(record, "acquisition")?;
    match mneme_core::Acquisition::from_value(value, &mneme_core::Path::root().field("acquisition"))
    {
        Ok(acquisition) => Ok((acquisition, value.clone())),
        Err(_)
            if record.schema_version < mneme_core::ACQUISITION_SCHEMA_VERSION
                && value.as_symbol().is_some() =>
        {
            Ok((mneme_core::Acquisition::Imported, value.clone()))
        }
        Err(diagnostic) => Err(source_parse_error(record, diagnostic)),
    }
}

fn source_prior_digest(
    record: &mneme_core::RecordEnvelope,
) -> crate::failure::Result<Option<mneme_core::ContentDigest>> {
    record
        .payload
        .get("content-digest")
        .map(|value| {
            mneme_core::ContentDigest::from_value(
                value,
                &mneme_core::Path::root().field("content-digest"),
            )
            .map_err(|diagnostic| source_parse_error(record, diagnostic))
        })
        .transpose()
}

fn source_availability(
    record: &mneme_core::RecordEnvelope,
    content: &mneme_core::SourceContent,
) -> SourceAvailability {
    match record
        .payload
        .get("availability")
        .and_then(mneme_core::Value::as_symbol)
    {
        Some(symbol) => match symbol.as_str() {
            "retained" => SourceAvailability::Retained,
            "pruned" => SourceAvailability::Pruned,
            "erased" => SourceAvailability::Erased,
            "inaccessible" => SourceAvailability::Inaccessible,
            other => SourceAvailability::Unavailable {
                reason: other.to_owned(),
            },
        },
        None => match content {
            mneme_core::SourceContent::Retained(_) => SourceAvailability::Retained,
            mneme_core::SourceContent::Unavailable { reason } => classify_unavailable(reason),
        },
    }
}

fn retained_media_type(content: &mneme_core::SourceContent) -> Option<mneme_core::Symbol> {
    match content {
        mneme_core::SourceContent::Retained(retained) => Some(retained.media_type().clone()),
        mneme_core::SourceContent::Unavailable { .. } => None,
    }
}

fn source_parse_error(
    record: &mneme_core::RecordEnvelope,
    diagnostic: mneme_core::Diagnostic,
) -> crate::failure::EvidenceError {
    crate::failure::EvidenceError::invalid(
        record.record_id,
        "source-revision",
        diagnostic.to_string(),
    )
}

/// One source revision pin parsed from a stored reference field.
fn optional_source_pin(
    record: &mneme_core::RecordEnvelope,
    field: &'static str,
) -> crate::failure::Result<Option<mneme_core::SourcePin>> {
    match record.payload.get(field) {
        Some(value) => {
            mneme_core::SourcePin::from_value(value, &mneme_core::Path::root().field(field))
                .map(Some)
                .map_err(|diagnostic| {
                    crate::failure::EvidenceError::invalid(
                        record.record_id,
                        "source-revision",
                        diagnostic.to_string(),
                    )
                })
        }
        None => Ok(None),
    }
}

fn optional_media_extent(
    record: &mneme_core::RecordEnvelope,
) -> crate::failure::Result<Option<mneme_core::MediaExtent>> {
    parse_optional_media_value(record, "media-extent", mneme_core::MediaExtent::from_value)
}

fn optional_media_transform(
    record: &mneme_core::RecordEnvelope,
) -> crate::failure::Result<Option<mneme_core::MediaTransform>> {
    parse_optional_media_value(
        record,
        "media-transform",
        mneme_core::MediaTransform::from_value,
    )
}

fn optional_correction(
    record: &mneme_core::RecordEnvelope,
) -> crate::failure::Result<Option<mneme_core::CorrectionProvenance>> {
    parse_optional_media_value(
        record,
        "correction",
        mneme_core::CorrectionProvenance::from_value,
    )
}

fn parse_optional_media_value<T>(
    record: &mneme_core::RecordEnvelope,
    field: &'static str,
    parse: impl FnOnce(&mneme_core::Value, &mneme_core::Path) -> Result<T, mneme_core::Diagnostic>,
) -> crate::failure::Result<Option<T>> {
    match record.payload.get(field) {
        Some(value) => parse(value, &mneme_core::Path::root().field(field))
            .map(Some)
            .map_err(|diagnostic| {
                crate::failure::EvidenceError::invalid(
                    record.record_id,
                    "source-revision",
                    diagnostic.to_string(),
                )
            }),
        None => Ok(None),
    }
}

fn classify_unavailable(reason: &str) -> SourceAvailability {
    let lower = reason.to_lowercase();
    if lower.contains("prun") {
        SourceAvailability::Pruned
    } else if lower.contains("eras") || lower.contains("forgot") {
        SourceAvailability::Erased
    } else if lower.contains("inaccess") {
        SourceAvailability::Inaccessible
    } else {
        SourceAvailability::Unavailable {
            reason: reason.to_owned(),
        }
    }
}

/// The kind of an episode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EpisodeType {
    Intent,
    Attempt,
    Observation,
    Outcome,
    Statement,
    Other(String),
}

impl EpisodeType {
    /// Stable name.
    pub fn name(&self) -> &str {
        match self {
            EpisodeType::Intent => "intent",
            EpisodeType::Attempt => "attempt",
            EpisodeType::Observation => "observation",
            EpisodeType::Outcome => "outcome",
            EpisodeType::Statement => "statement",
            EpisodeType::Other(name) => name,
        }
    }

    fn parse(text: &str) -> Self {
        match text {
            "intent" => EpisodeType::Intent,
            "attempt" => EpisodeType::Attempt,
            "observation" => EpisodeType::Observation,
            "outcome" => EpisodeType::Outcome,
            "statement" => EpisodeType::Statement,
            other => EpisodeType::Other(other.to_owned()),
        }
    }
}

/// A recorded interaction, observation, attempt, or outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpisodeView {
    pub record: mneme_core::RecordEnvelope,
    pub actor: String,
    pub episode_type: EpisodeType,
    pub occurred: mneme_core::ValidTime,
    pub summary: String,
    pub source: Option<mneme_core::RecordId>,
    pub related: std::collections::BTreeSet<mneme_core::RecordId>,
}

impl EpisodeView {
    /// Parse an episode envelope.
    pub fn parse(record: mneme_core::RecordEnvelope) -> crate::failure::Result<Self> {
        expect_kind(&record, mneme_core::RecordKind::Episode)?;
        Ok(EpisodeView {
            actor: required_text(&record, "actor")?,
            episode_type: EpisodeType::parse(
                required_symbol_text(&record, "episode-type")?.as_str(),
            ),
            occurred: required_valid_time(&record, "occurred")?,
            summary: required_text(&record, "summary")?,
            source: optional_reference_target(&record, "source")?,
            related: optional_reference_set(&record, "related")?,
            record,
        })
    }
}

/// Whether evidence supports or challenges a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportRelation {
    Supports,
    Challenges,
}

/// Evidence for one assertion, anchored to an exact source revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceView {
    pub record: mneme_core::RecordEnvelope,
    pub assertion: mneme_core::RecordId,
    pub source: mneme_core::RecordId,
    pub source_reference: mneme_core::Reference,
    pub span: Option<mneme_core::SourceSpan>,
    pub anchor: Option<String>,
    pub relation: SupportRelation,
    pub origin: mneme_core::Origin,
    pub ancestry: std::collections::BTreeSet<mneme_core::RecordId>,
}

impl EvidenceView {
    /// Parse an evidence envelope.
    pub fn parse(record: mneme_core::RecordEnvelope) -> crate::failure::Result<Self> {
        expect_kind(&record, mneme_core::RecordKind::Evidence)?;
        let relation = match required_symbol_text(&record, "relation")?.as_str() {
            "supports" => SupportRelation::Supports,
            "challenges" => SupportRelation::Challenges,
            other => {
                return Err(crate::failure::EvidenceError::invalid(
                    record.record_id,
                    "evidence",
                    format!("unknown support relation {other}"),
                ));
            }
        };
        let origin = mneme_core::Origin::parse(&required_symbol_text(&record, "origin")?)
            .ok_or_else(|| {
                crate::failure::EvidenceError::invalid(
                    record.record_id,
                    "evidence",
                    "unknown origin",
                )
            })?;
        Ok(EvidenceView {
            assertion: required_reference_target(&record, "assertion")?,
            source: required_reference_target(&record, "source")?,
            source_reference: mneme_core::Reference::from_value(
                required(&record, "source")?,
                &mneme_core::Path::root().field("source"),
            )
            .map_err(|diagnostic| {
                crate::failure::EvidenceError::invalid(
                    record.record_id,
                    "evidence",
                    diagnostic.to_string(),
                )
            })?,
            span: match record.payload.get("span") {
                Some(value) => Some(
                    mneme_core::SourceSpan::from_value(
                        value,
                        &mneme_core::Path::root().field("span"),
                    )
                    .map_err(|diagnostic| {
                        crate::failure::EvidenceError::invalid(
                            record.record_id,
                            "evidence",
                            diagnostic.to_string(),
                        )
                    })?,
                ),
                None => None,
            },
            anchor: optional_text(&record, "anchor"),
            relation,
            origin,
            ancestry: required_reference_set(&record, "ancestry")?,
            record,
        })
    }
}

/// The stance of an assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stance {
    Affirm,
    Deny,
    Hypothesis,
}

/// The typed shape of a claim, which selects the extra evidence a claim needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimType {
    /// A claim that an action completed; it needs an observed outcome.
    ActionCompleted,
    /// Any other claim.
    General,
}

/// Declared symbol for the completed-action claim type.
pub const ACTION_COMPLETED_CLAIM_TYPE: &str = "action-completed";

impl ClaimType {
    /// Classify a claim from its optional declared type and its predicate.
    ///
    /// A declared type can never remove the guard: a claim whose predicate is
    /// the completed-action predicate stays a completed-action claim whatever
    /// type it declares. Unknown declared types are refused rather than
    /// silently classified as general claims.
    fn parse(record: &mneme_core::RecordEnvelope, predicate: &str) -> crate::failure::Result<Self> {
        let declared = match record.payload.get("claim-type") {
            None => None,
            Some(value) => {
                let Some(symbol) = value.as_symbol() else {
                    return Err(crate::failure::EvidenceError::invalid(
                        record.record_id,
                        "assertion",
                        "claim-type must be a symbol",
                    ));
                };
                Some(symbol.as_str())
            }
        };
        match declared {
            Some(ACTION_COMPLETED_CLAIM_TYPE) => Ok(ClaimType::ActionCompleted),
            Some("general") => Ok(ClaimType::from_predicate(predicate)),
            Some(other) => Err(crate::failure::EvidenceError::invalid(
                record.record_id,
                "assertion",
                format!("unknown claim type {other}"),
            )),
            None => Ok(ClaimType::from_predicate(predicate)),
        }
    }

    /// Classify a claim by the predicate conventions of the capability.
    fn from_predicate(predicate: &str) -> Self {
        if predicate == crate::beliefs::ACTION_COMPLETED_PREDICATE {
            ClaimType::ActionCompleted
        } else {
            ClaimType::General
        }
    }
}

/// Extraction lineage attached to a model-produced assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extraction {
    pub model: String,
    pub prompt: String,
}

/// A claim with origin, lifecycle, scope, and evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionView {
    pub record: mneme_core::RecordEnvelope,
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub value: mneme_core::Value,
    pub stance: Stance,
    pub lifecycle: mneme_core::Lifecycle,
    pub claim_type: ClaimType,
    pub origin: mneme_core::Origin,
    pub asserted_by: String,
    pub valid_time: mneme_core::ValidTime,
    pub evidence: std::collections::BTreeSet<mneme_core::RecordId>,
    pub confidence: Option<mneme_core::Value>,
    pub superseded_by: Option<mneme_core::RecordId>,
    pub decision: Option<mneme_core::RecordId>,
    pub extraction: Option<Extraction>,
}

impl AssertionView {
    /// Parse an assertion envelope.
    pub fn parse(record: mneme_core::RecordEnvelope) -> crate::failure::Result<Self> {
        expect_kind(&record, mneme_core::RecordKind::Assertion)?;
        let stance = match required_symbol_text(&record, "stance")?.as_str() {
            "affirm" => Stance::Affirm,
            "deny" => Stance::Deny,
            "hypothesis" => Stance::Hypothesis,
            other => {
                return Err(crate::failure::EvidenceError::invalid(
                    record.record_id,
                    "assertion",
                    format!("unknown stance {other}"),
                ));
            }
        };
        let lifecycle = record.assertion_lifecycle().ok_or_else(|| {
            crate::failure::EvidenceError::invalid(
                record.record_id,
                "assertion",
                "missing lifecycle",
            )
        })?;
        let origin = mneme_core::Origin::parse(&required_symbol_text(&record, "origin")?)
            .ok_or_else(|| {
                crate::failure::EvidenceError::invalid(
                    record.record_id,
                    "assertion",
                    "unknown origin",
                )
            })?;
        let predicate = required_symbol_text(&record, "predicate")?;
        Ok(AssertionView {
            subject: required_reference_target(&record, "subject")?,
            claim_type: ClaimType::parse(&record, &predicate)?,
            predicate,
            value: required(&record, "value")?.clone(),
            stance,
            lifecycle,
            origin,
            asserted_by: required_text(&record, "asserted-by")?,
            valid_time: required_valid_time(&record, "valid-time")?,
            evidence: required_reference_set(&record, "evidence")?,
            confidence: record.payload.get("confidence").cloned(),
            superseded_by: optional_reference_target(&record, "superseded-by")?,
            decision: optional_reference_target(&record, "decision")?,
            extraction: parse_extraction(&record)?,
            record,
        })
    }

    /// The record identity.
    pub fn record_id(&self) -> mneme_core::RecordId {
        self.record.record_id
    }
}

fn parse_extraction(
    record: &mneme_core::RecordEnvelope,
) -> crate::failure::Result<Option<Extraction>> {
    let Some(value) = record.payload.get("extraction") else {
        return Ok(None);
    };
    let Some(extraction) = value.as_record() else {
        return Err(crate::failure::EvidenceError::invalid(
            record.record_id,
            "assertion",
            "extraction must be a record",
        ));
    };
    if extraction.label() != &mneme_core::Value::symbol("extraction")
        || extraction.fields().len() != 2
    {
        return Err(crate::failure::EvidenceError::invalid(
            record.record_id,
            "assertion",
            "expected <extraction model prompt>",
        ));
    }
    let model = extraction.fields()[0].as_string().ok_or_else(|| {
        crate::failure::EvidenceError::invalid(record.record_id, "assertion", "model must be text")
    })?;
    let prompt = extraction.fields()[1].as_string().ok_or_else(|| {
        crate::failure::EvidenceError::invalid(record.record_id, "assertion", "prompt must be text")
    })?;
    Ok(Some(Extraction {
        model: model.to_owned(),
        prompt: prompt.to_owned(),
    }))
}

/// A complete justification with its own required premises.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationView {
    pub record: mneme_core::RecordEnvelope,
    pub conclusion: mneme_core::RecordId,
    pub premises: std::collections::BTreeSet<mneme_core::RecordId>,
    pub rule_id: String,
    pub rule_version: i64,
    pub evaluation_revision: mneme_core::WorkspaceRevisionId,
    pub completeness: String,
}

/// Declared symbol for a justification its author declares complete.
pub const COMPLETE_COMPLETENESS: &str = "complete";

impl DerivationView {
    /// Whether the author declared the justification complete.
    ///
    /// Only the complete symbol is complete: any other symbol, including a
    /// partial or open marker, leaves the justification incomplete.
    pub fn is_complete(&self) -> bool {
        self.completeness == COMPLETE_COMPLETENESS
    }

    /// Parse a derivation envelope.
    pub fn parse(record: mneme_core::RecordEnvelope) -> crate::failure::Result<Self> {
        expect_kind(&record, mneme_core::RecordKind::Derivation)?;
        let rule_version = required_integer(&record, "rule-version")?;
        let evaluation_revision = mneme_core::WorkspaceRevisionId::from_value(
            required(&record, "evaluation-revision")?,
            &mneme_core::Path::root().field("evaluation-revision"),
        )
        .map_err(|diagnostic| {
            crate::failure::EvidenceError::invalid(
                record.record_id,
                "derivation",
                diagnostic.to_string(),
            )
        })?;
        Ok(DerivationView {
            conclusion: required_reference_target(&record, "conclusion")?,
            premises: required_reference_set(&record, "premises")?,
            rule_id: required_text(&record, "rule-id")?,
            rule_version,
            evaluation_revision,
            completeness: required_symbol_text(&record, "completeness")?,
            record,
        })
    }
}

/// The kind of an attributed decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionKind {
    Acceptance,
    ConflictResolution,
    Retraction,
    Supersession,
    Other(String),
}

impl DecisionKind {
    /// Stable name.
    pub fn name(&self) -> &str {
        match self {
            DecisionKind::Acceptance => "acceptance",
            DecisionKind::ConflictResolution => "conflict-resolution",
            DecisionKind::Retraction => "retraction",
            DecisionKind::Supersession => "supersession",
            DecisionKind::Other(other) => other,
        }
    }

    fn parse(text: &str) -> Self {
        match text {
            "acceptance" => DecisionKind::Acceptance,
            "conflict-resolution" => DecisionKind::ConflictResolution,
            "retraction" => DecisionKind::Retraction,
            "supersession" => DecisionKind::Supersession,
            other => DecisionKind::Other(other.to_owned()),
        }
    }
}

/// An explicit attributed lifecycle or conflict decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionView {
    pub record: mneme_core::RecordEnvelope,
    pub decision_kind: DecisionKind,
    pub target: mneme_core::RecordId,
    pub actor: String,
    pub policy: String,
    pub input_revision: mneme_core::WorkspaceRevisionId,
    pub outcome: String,
    pub rationale: String,
    pub evidence: std::collections::BTreeSet<mneme_core::RecordId>,
    pub related: std::collections::BTreeSet<mneme_core::RecordId>,
}

impl DecisionView {
    /// Parse a decision envelope.
    pub fn parse(record: mneme_core::RecordEnvelope) -> crate::failure::Result<Self> {
        expect_kind(&record, mneme_core::RecordKind::Decision)?;
        let input_revision = mneme_core::WorkspaceRevisionId::from_value(
            required(&record, "input-revision")?,
            &mneme_core::Path::root().field("input-revision"),
        )
        .map_err(|diagnostic| {
            crate::failure::EvidenceError::invalid(
                record.record_id,
                "decision",
                diagnostic.to_string(),
            )
        })?;
        Ok(DecisionView {
            decision_kind: DecisionKind::parse(&required_symbol_text(&record, "decision-kind")?),
            target: required_reference_target(&record, "target")?,
            actor: required_text(&record, "actor")?,
            policy: required_text(&record, "policy")?,
            input_revision,
            outcome: required_symbol_text(&record, "outcome")?,
            rationale: required_text(&record, "rationale")?,
            evidence: required_reference_set(&record, "evidence")?,
            related: optional_reference_set(&record, "related")?,
            record,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommentView {
    pub record: mneme_core::RecordEnvelope,
    pub actor: String,
    pub document: mneme_core::RecordId,
    pub source_revision: mneme_core::RecordId,
    /// The source revision the comment names, when its reference is pinned.
    pub source_pin: Option<mneme_core::RevisionId>,
    pub span: Option<mneme_core::SourceSpan>,
    pub block: Option<String>,
    pub text: String,
    pub reply_to: Option<mneme_core::RecordId>,
    pub mentions: std::collections::BTreeSet<String>,
    pub status: String,
    pub resolves: Option<mneme_core::RecordId>,
}

impl CommentView {
    /// Parse a comment envelope.
    pub fn parse(record: mneme_core::RecordEnvelope) -> crate::failure::Result<Self> {
        expect_kind(&record, mneme_core::RecordKind::Comment)?;
        let status = required_symbol_text(&record, "status")?;
        let span = match record.payload.get("span") {
            Some(value) => Some(
                mneme_core::SourceSpan::from_value(value, &mneme_core::Path::root().field("span"))
                    .map_err(|diagnostic| {
                        crate::failure::EvidenceError::invalid(
                            record.record_id,
                            "comment",
                            diagnostic.to_string(),
                        )
                    })?,
            ),
            None => None,
        };
        let mentions = match record.payload.get("mentions") {
            Some(value) => {
                let mut set = std::collections::BTreeSet::new();
                if let Some(items) = value.as_set() {
                    for item in items {
                        if let Some(text) = item.as_string() {
                            set.insert(text.to_owned());
                        }
                    }
                }
                set
            }
            None => std::collections::BTreeSet::new(),
        };
        Ok(CommentView {
            actor: required_text(&record, "actor")?,
            document: required_reference_target(&record, "document")?,
            source_revision: required_reference_target(&record, "source-revision")?,
            source_pin: record
                .payload
                .get("source-revision")
                .and_then(|value| {
                    mneme_core::Reference::from_value(value, &mneme_core::Path::root()).ok()
                })
                .and_then(|reference| match reference {
                    mneme_core::Reference::Pinned { revision, .. } => Some(revision),
                    mneme_core::Reference::Local { .. }
                    | mneme_core::Reference::External { .. }
                    | mneme_core::Reference::Unresolved { .. } => None,
                }),
            span,
            block: optional_text(&record, "block"),
            text: required_text(&record, "text")?,
            reply_to: optional_reference_target(&record, "reply-to")?,
            mentions,
            status,
            resolves: optional_reference_target(&record, "resolves")?,
            record,
        })
    }
}

/// Exact provider input/output and execution identities for one recognition.
#[derive(Clone, Debug, PartialEq)]
pub struct RecognitionRunView {
    pub record: mneme_core::RecordEnvelope,
    pub input: mneme_core::SourcePin,
    pub input_digest: mneme_core::ContentDigest,
    pub output: mneme_core::SourcePin,
    pub output_digest: mneme_core::ContentDigest,
    pub model: String,
    pub runtime: String,
    pub adapter: String,
    pub preprocessing: String,
    pub configuration: String,
    pub segments: std::collections::BTreeSet<mneme_core::RecordId>,
    pub coverage: mneme_core::RecognitionCoverage,
    pub status: mneme_core::RecognitionStatus,
    pub scores: Vec<mneme_core::RecognitionScore>,
    pub alternatives: Vec<mneme_core::RecognitionAlternative>,
}

impl RecognitionRunView {
    /// Parse a recognition-run envelope.
    pub fn parse(record: mneme_core::RecordEnvelope) -> crate::failure::Result<Self> {
        expect_kind(&record, mneme_core::RecordKind::RecognitionRun)?;
        let status = required_symbol_text(&record, "status")?;
        let status = mneme_core::RecognitionStatus::parse(&status).ok_or_else(|| {
            crate::failure::EvidenceError::invalid(
                record.record_id,
                "recognition-run",
                "unknown recognition status",
            )
        })?;
        let coverage = mneme_core::RecognitionCoverage::from_value(
            required(&record, "coverage")?,
            &mneme_core::Path::root().field("coverage"),
        )
        .map_err(|diagnostic| {
            crate::failure::EvidenceError::invalid(
                record.record_id,
                "recognition-run",
                diagnostic.to_string(),
            )
        })?;
        let input = required_source_pin(&record, "input")?;
        let output = required_source_pin(&record, "output")?;
        Ok(RecognitionRunView {
            input,
            input_digest: required_digest(&record, "input-digest")?,
            output,
            output_digest: required_digest(&record, "output-digest")?,
            model: required_text(&record, "model")?,
            runtime: required_text(&record, "runtime")?,
            adapter: required_text(&record, "adapter")?,
            preprocessing: required_text(&record, "preprocessing")?,
            configuration: required_text(&record, "configuration")?,
            segments: required_reference_set(&record, "segments")?,
            coverage,
            status,
            scores: optional_typed_sequence(
                &record,
                "scores",
                mneme_core::RecognitionScore::from_value,
            )?,
            alternatives: optional_typed_sequence(
                &record,
                "alternatives",
                mneme_core::RecognitionAlternative::from_value,
            )?,
            record,
        })
    }
}

/// One text byte span mapped to an exact source and typed media-native location.
#[derive(Clone, Debug, PartialEq)]
pub struct RecognitionSegmentView {
    pub record: mneme_core::RecordEnvelope,
    pub run: Option<mneme_core::RecordId>,
    pub text_source: mneme_core::SourcePin,
    pub text_span: mneme_core::SourceSpan,
    pub media_source: mneme_core::SourcePin,
    pub media_digest: mneme_core::ContentDigest,
    pub location: mneme_core::MediaLocation,
}

impl RecognitionSegmentView {
    /// Parse a recognition-segment envelope.
    pub fn parse(record: mneme_core::RecordEnvelope) -> crate::failure::Result<Self> {
        expect_kind(&record, mneme_core::RecordKind::RecognitionSegment)?;
        let text_span = mneme_core::SourceSpan::from_value(
            required(&record, "span")?,
            &mneme_core::Path::root().field("span"),
        )
        .map_err(|diagnostic| {
            crate::failure::EvidenceError::invalid(
                record.record_id,
                "recognition-segment",
                diagnostic.to_string(),
            )
        })?;
        let location = mneme_core::MediaLocation::from_value(
            required(&record, "location")?,
            &mneme_core::Path::root().field("location"),
        )
        .map_err(|diagnostic| {
            crate::failure::EvidenceError::invalid(
                record.record_id,
                "recognition-segment",
                diagnostic.to_string(),
            )
        })?;
        Ok(RecognitionSegmentView {
            run: optional_reference_target(&record, "run")?,
            text_source: required_source_pin(&record, "text-source")?,
            text_span,
            media_source: required_source_pin(&record, "media-source")?,
            media_digest: required_digest(&record, "media-digest")?,
            location,
            record,
        })
    }
}

fn required_source_pin(
    record: &mneme_core::RecordEnvelope,
    field: &'static str,
) -> crate::failure::Result<mneme_core::SourcePin> {
    mneme_core::SourcePin::from_value(
        required(record, field)?,
        &mneme_core::Path::root().field(field),
    )
    .map_err(|diagnostic| {
        crate::failure::EvidenceError::invalid(
            record.record_id,
            "source-pin",
            diagnostic.to_string(),
        )
    })
}

fn required_digest(
    record: &mneme_core::RecordEnvelope,
    field: &'static str,
) -> crate::failure::Result<mneme_core::ContentDigest> {
    mneme_core::ContentDigest::from_value(
        required(record, field)?,
        &mneme_core::Path::root().field(field),
    )
    .map_err(|diagnostic| {
        crate::failure::EvidenceError::invalid(
            record.record_id,
            "recognition",
            diagnostic.to_string(),
        )
    })
}

fn optional_typed_sequence<T>(
    record: &mneme_core::RecordEnvelope,
    field: &'static str,
    parse: impl Fn(&mneme_core::Value, &mneme_core::Path) -> Result<T, mneme_core::Diagnostic>,
) -> crate::failure::Result<Vec<T>> {
    let Some(value) = record.payload.get(field) else {
        return Ok(Vec::new());
    };
    let items = value.as_sequence().ok_or_else(|| {
        crate::failure::EvidenceError::invalid(record.record_id, field, "expected a typed sequence")
    })?;
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            parse(item, &mneme_core::Path::root().field(field).index(index)).map_err(|diagnostic| {
                crate::failure::EvidenceError::invalid(
                    record.record_id,
                    field,
                    diagnostic.to_string(),
                )
            })
        })
        .collect()
}

fn expect_kind(
    record: &mneme_core::RecordEnvelope,
    kind: mneme_core::RecordKind,
) -> crate::failure::Result<()> {
    if record.kind == kind {
        Ok(())
    } else {
        Err(crate::failure::EvidenceError::invalid(
            record.record_id,
            kind.symbol(),
            format!("found kind {}", record.kind.symbol()),
        ))
    }
}

pub(crate) fn required<'a>(
    record: &'a mneme_core::RecordEnvelope,
    name: &str,
) -> crate::failure::Result<&'a mneme_core::Value> {
    record.payload.get(name).ok_or_else(|| {
        crate::failure::EvidenceError::invalid(
            record.record_id,
            record.kind.symbol(),
            format!("missing field {name}"),
        )
    })
}

pub(crate) fn required_text(
    record: &mneme_core::RecordEnvelope,
    name: &str,
) -> crate::failure::Result<String> {
    required(record, name)?
        .as_string()
        .map(str::to_owned)
        .ok_or_else(|| {
            crate::failure::EvidenceError::invalid(
                record.record_id,
                record.kind.symbol(),
                format!("{name} must be text"),
            )
        })
}

pub(crate) fn required_symbol_text(
    record: &mneme_core::RecordEnvelope,
    name: &str,
) -> crate::failure::Result<String> {
    required(record, name)?
        .as_symbol()
        .map(|symbol| symbol.as_str().to_owned())
        .ok_or_else(|| {
            crate::failure::EvidenceError::invalid(
                record.record_id,
                record.kind.symbol(),
                format!("{name} must be a symbol"),
            )
        })
}

pub(crate) fn required_integer(
    record: &mneme_core::RecordEnvelope,
    name: &str,
) -> crate::failure::Result<i64> {
    required(record, name)?
        .as_integer()
        .and_then(|integer| integer.to_i64())
        .ok_or_else(|| {
            crate::failure::EvidenceError::invalid(
                record.record_id,
                record.kind.symbol(),
                format!("{name} must be an integer"),
            )
        })
}

pub(crate) fn required_valid_time(
    record: &mneme_core::RecordEnvelope,
    name: &str,
) -> crate::failure::Result<mneme_core::ValidTime> {
    mneme_core::ValidTime::from_value(
        required(record, name)?,
        &mneme_core::Path::root().field("valid-time"),
    )
    .map_err(|diagnostic| {
        crate::failure::EvidenceError::invalid(
            record.record_id,
            record.kind.symbol(),
            diagnostic.to_string(),
        )
    })
}

pub(crate) fn required_reference_target(
    record: &mneme_core::RecordEnvelope,
    name: &str,
) -> crate::failure::Result<mneme_core::RecordId> {
    reference_target(record, required(record, name)?).and_then(|target| {
        target.ok_or_else(|| {
            crate::failure::EvidenceError::invalid(
                record.record_id,
                record.kind.symbol(),
                format!("{name} must name a local record"),
            )
        })
    })
}

pub(crate) fn optional_reference_target(
    record: &mneme_core::RecordEnvelope,
    name: &str,
) -> crate::failure::Result<Option<mneme_core::RecordId>> {
    match record.payload.get(name) {
        Some(value) => reference_target(record, value),
        None => Ok(None),
    }
}

pub(crate) fn required_reference_set(
    record: &mneme_core::RecordEnvelope,
    name: &str,
) -> crate::failure::Result<std::collections::BTreeSet<mneme_core::RecordId>> {
    let values = required(record, name)?;
    let set = values.as_set().ok_or_else(|| {
        crate::failure::EvidenceError::invalid(
            record.record_id,
            record.kind.symbol(),
            format!("{name} must be a set of references"),
        )
    })?;
    let mut targets = std::collections::BTreeSet::new();
    for value in set {
        if let Some(target) = reference_target(record, value)? {
            targets.insert(target);
        }
    }
    Ok(targets)
}

pub(crate) fn optional_reference_set(
    record: &mneme_core::RecordEnvelope,
    name: &str,
) -> crate::failure::Result<std::collections::BTreeSet<mneme_core::RecordId>> {
    if record.payload.get(name).is_some() {
        required_reference_set(record, name)
    } else {
        Ok(std::collections::BTreeSet::new())
    }
}

fn reference_target(
    record: &mneme_core::RecordEnvelope,
    value: &mneme_core::Value,
) -> crate::failure::Result<Option<mneme_core::RecordId>> {
    let reference = mneme_core::Reference::from_value(value, &mneme_core::Path::root()).map_err(
        |diagnostic| {
            crate::failure::EvidenceError::invalid(
                record.record_id,
                record.kind.symbol(),
                diagnostic.to_string(),
            )
        },
    )?;
    match &reference {
        mneme_core::Reference::External { .. } => Err(crate::failure::EvidenceError::invalid(
            record.record_id,
            record.kind.symbol(),
            "memory references cannot be external",
        )),
        mneme_core::Reference::Unresolved { .. } => Err(crate::failure::EvidenceError::invalid(
            record.record_id,
            record.kind.symbol(),
            "memory references cannot be unresolved",
        )),
        _ => Ok(reference.target()),
    }
}

pub(crate) fn optional_text(record: &mneme_core::RecordEnvelope, name: &str) -> Option<String> {
    record
        .payload
        .get(name)
        .and_then(mneme_core::Value::as_string)
        .map(str::to_owned)
}

/// Re-exported for callers constructing views from a payload.
pub fn payload_of(record: &mneme_core::RecordEnvelope) -> &mneme_core::Payload {
    &record.payload
}

/// Parse a decision or assertion revision identity from a record.
pub fn revision_of(record: &mneme_core::RecordEnvelope) -> mneme_core::RevisionId {
    record.revision_id
}

/// The recorded time assigned by the coordinator.
pub fn recorded_of(record: &mneme_core::RecordEnvelope) -> mneme_core::RecordedTime {
    record.recorded
}
