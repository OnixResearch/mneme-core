//! Typed views over the application payloads used by evidence memory.
//!
//! Parsing is strict about the fields this capability owns. Unknown extension
//! fields remain ordinary retained data; they are not interpreted here.

use std::collections::BTreeSet;

use mneme_core::{
    Lifecycle, Origin, Payload, RecordEnvelope, RecordId, RecordKind, RecordedTime, Reference,
    RevisionId, SourceContent, SourceSpan, Symbol, ValidTime, Value, WorkspaceRevisionId,
};

use crate::error::{MemoryError, Result};

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceView {
    pub record: RecordEnvelope,
    pub content: SourceContent,
    pub availability: SourceAvailability,
    pub path_hint: Option<String>,
    pub entity: Option<RecordId>,
    pub media_type: Option<Symbol>,
}

impl SourceView {
    /// Parse a source-revision envelope.
    pub fn parse(record: RecordEnvelope) -> Result<Self> {
        expect_kind(&record, RecordKind::SourceRevision)?;
        let content = SourceContent::from_value(
            required(&record, "content")?,
            &mneme_core::Path::root().field("content"),
        )
        .map_err(|diagnostic| {
            MemoryError::invalid(record.record_id, "source-revision", diagnostic.to_string())
        })?;
        let availability = match record
            .payload
            .get("availability")
            .and_then(Value::as_symbol)
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
            None => match &content {
                SourceContent::Retained(_) => SourceAvailability::Retained,
                SourceContent::Unavailable { reason } => classify_unavailable(reason),
            },
        };
        let media_type = match &content {
            SourceContent::Retained(retained) => Some(retained.media_type().clone()),
            SourceContent::Unavailable { .. } => None,
        };
        Ok(SourceView {
            path_hint: optional_text(&record, "path-hint"),
            entity: optional_reference_target(&record, "entity")?,
            content,
            availability,
            media_type,
            record,
        })
    }

    /// The exact raw source digest when retained.
    pub fn digest(&self) -> Option<mneme_core::ContentDigest> {
        match &self.content {
            SourceContent::Retained(retained) => Some(retained.digest()),
            SourceContent::Unavailable { .. } => None,
        }
    }

    /// The declared byte length when retained.
    pub fn byte_length(&self) -> Option<u64> {
        match &self.content {
            SourceContent::Retained(retained) => Some(retained.byte_length()),
            SourceContent::Unavailable { .. } => None,
        }
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
    pub record: RecordEnvelope,
    pub actor: String,
    pub episode_type: EpisodeType,
    pub occurred: ValidTime,
    pub summary: String,
    pub source: Option<RecordId>,
    pub related: BTreeSet<RecordId>,
}

impl EpisodeView {
    /// Parse an episode envelope.
    pub fn parse(record: RecordEnvelope) -> Result<Self> {
        expect_kind(&record, RecordKind::Episode)?;
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
    pub record: RecordEnvelope,
    pub assertion: RecordId,
    pub source: RecordId,
    pub source_reference: Reference,
    pub span: Option<SourceSpan>,
    pub anchor: Option<String>,
    pub relation: SupportRelation,
    pub origin: Origin,
    pub ancestry: BTreeSet<RecordId>,
}

impl EvidenceView {
    /// Parse an evidence envelope.
    pub fn parse(record: RecordEnvelope) -> Result<Self> {
        expect_kind(&record, RecordKind::Evidence)?;
        let relation = match required_symbol_text(&record, "relation")?.as_str() {
            "supports" => SupportRelation::Supports,
            "challenges" => SupportRelation::Challenges,
            other => {
                return Err(MemoryError::invalid(
                    record.record_id,
                    "evidence",
                    format!("unknown support relation {other}"),
                ));
            }
        };
        let origin = Origin::parse(&required_symbol_text(&record, "origin")?)
            .ok_or_else(|| MemoryError::invalid(record.record_id, "evidence", "unknown origin"))?;
        Ok(EvidenceView {
            assertion: required_reference_target(&record, "assertion")?,
            source: required_reference_target(&record, "source")?,
            source_reference: Reference::from_value(
                required(&record, "source")?,
                &mneme_core::Path::root().field("source"),
            )
            .map_err(|diagnostic| {
                MemoryError::invalid(record.record_id, "evidence", diagnostic.to_string())
            })?,
            span: match record.payload.get("span") {
                Some(value) => Some(
                    SourceSpan::from_value(value, &mneme_core::Path::root().field("span"))
                        .map_err(|diagnostic| {
                            MemoryError::invalid(
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

/// Extraction lineage attached to a model-produced assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extraction {
    pub model: String,
    pub prompt: String,
}

/// A claim with origin, lifecycle, scope, and evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionView {
    pub record: RecordEnvelope,
    pub subject: RecordId,
    pub predicate: String,
    pub value: Value,
    pub stance: Stance,
    pub lifecycle: Lifecycle,
    pub origin: Origin,
    pub asserted_by: String,
    pub valid_time: ValidTime,
    pub evidence: BTreeSet<RecordId>,
    pub confidence: Option<Value>,
    pub superseded_by: Option<RecordId>,
    pub decision: Option<RecordId>,
    pub extraction: Option<Extraction>,
}

impl AssertionView {
    /// Parse an assertion envelope.
    pub fn parse(record: RecordEnvelope) -> Result<Self> {
        expect_kind(&record, RecordKind::Assertion)?;
        let stance = match required_symbol_text(&record, "stance")?.as_str() {
            "affirm" => Stance::Affirm,
            "deny" => Stance::Deny,
            "hypothesis" => Stance::Hypothesis,
            other => {
                return Err(MemoryError::invalid(
                    record.record_id,
                    "assertion",
                    format!("unknown stance {other}"),
                ));
            }
        };
        let lifecycle = record.assertion_lifecycle().ok_or_else(|| {
            MemoryError::invalid(record.record_id, "assertion", "missing lifecycle")
        })?;
        let origin = Origin::parse(&required_symbol_text(&record, "origin")?)
            .ok_or_else(|| MemoryError::invalid(record.record_id, "assertion", "unknown origin"))?;
        Ok(AssertionView {
            subject: required_reference_target(&record, "subject")?,
            predicate: required_symbol_text(&record, "predicate")?,
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
    pub fn record_id(&self) -> RecordId {
        self.record.record_id
    }
}

fn parse_extraction(record: &RecordEnvelope) -> Result<Option<Extraction>> {
    let Some(value) = record.payload.get("extraction") else {
        return Ok(None);
    };
    let Some(extraction) = value.as_record() else {
        return Err(MemoryError::invalid(
            record.record_id,
            "assertion",
            "extraction must be a record",
        ));
    };
    if extraction.label() != &Value::symbol("extraction") || extraction.fields().len() != 2 {
        return Err(MemoryError::invalid(
            record.record_id,
            "assertion",
            "expected <extraction model prompt>",
        ));
    }
    let model = extraction.fields()[0]
        .as_string()
        .ok_or_else(|| MemoryError::invalid(record.record_id, "assertion", "model must be text"))?;
    let prompt = extraction.fields()[1].as_string().ok_or_else(|| {
        MemoryError::invalid(record.record_id, "assertion", "prompt must be text")
    })?;
    Ok(Some(Extraction {
        model: model.to_owned(),
        prompt: prompt.to_owned(),
    }))
}

/// A complete justification with its own required premises.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationView {
    pub record: RecordEnvelope,
    pub conclusion: RecordId,
    pub premises: BTreeSet<RecordId>,
    pub rule_id: String,
    pub rule_version: i64,
    pub evaluation_revision: WorkspaceRevisionId,
    pub completeness: String,
}

impl DerivationView {
    /// Parse a derivation envelope.
    pub fn parse(record: RecordEnvelope) -> Result<Self> {
        expect_kind(&record, RecordKind::Derivation)?;
        let rule_version = required_integer(&record, "rule-version")?;
        let evaluation_revision = WorkspaceRevisionId::from_value(
            required(&record, "evaluation-revision")?,
            &mneme_core::Path::root().field("evaluation-revision"),
        )
        .map_err(|diagnostic| {
            MemoryError::invalid(record.record_id, "derivation", diagnostic.to_string())
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
    pub record: RecordEnvelope,
    pub decision_kind: DecisionKind,
    pub target: RecordId,
    pub actor: String,
    pub policy: String,
    pub input_revision: WorkspaceRevisionId,
    pub outcome: String,
    pub rationale: String,
    pub evidence: BTreeSet<RecordId>,
    pub related: BTreeSet<RecordId>,
}

impl DecisionView {
    /// Parse a decision envelope.
    pub fn parse(record: RecordEnvelope) -> Result<Self> {
        expect_kind(&record, RecordKind::Decision)?;
        let input_revision = WorkspaceRevisionId::from_value(
            required(&record, "input-revision")?,
            &mneme_core::Path::root().field("input-revision"),
        )
        .map_err(|diagnostic| {
            MemoryError::invalid(record.record_id, "decision", diagnostic.to_string())
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

fn expect_kind(record: &RecordEnvelope, kind: RecordKind) -> Result<()> {
    if record.kind == kind {
        Ok(())
    } else {
        Err(MemoryError::invalid(
            record.record_id,
            kind.symbol(),
            format!("found kind {}", record.kind.symbol()),
        ))
    }
}

pub(crate) fn required<'a>(record: &'a RecordEnvelope, name: &str) -> Result<&'a Value> {
    record.payload.get(name).ok_or_else(|| {
        MemoryError::invalid(
            record.record_id,
            record.kind.symbol(),
            format!("missing field {name}"),
        )
    })
}

pub(crate) fn required_text(record: &RecordEnvelope, name: &str) -> Result<String> {
    required(record, name)?
        .as_string()
        .map(str::to_owned)
        .ok_or_else(|| {
            MemoryError::invalid(
                record.record_id,
                record.kind.symbol(),
                format!("{name} must be text"),
            )
        })
}

pub(crate) fn required_symbol_text(record: &RecordEnvelope, name: &str) -> Result<String> {
    required(record, name)?
        .as_symbol()
        .map(|symbol| symbol.as_str().to_owned())
        .ok_or_else(|| {
            MemoryError::invalid(
                record.record_id,
                record.kind.symbol(),
                format!("{name} must be a symbol"),
            )
        })
}

pub(crate) fn required_integer(record: &RecordEnvelope, name: &str) -> Result<i64> {
    required(record, name)?
        .as_integer()
        .and_then(|integer| integer.to_i64())
        .ok_or_else(|| {
            MemoryError::invalid(
                record.record_id,
                record.kind.symbol(),
                format!("{name} must be an integer"),
            )
        })
}

pub(crate) fn required_valid_time(record: &RecordEnvelope, name: &str) -> Result<ValidTime> {
    ValidTime::from_value(
        required(record, name)?,
        &mneme_core::Path::root().field("valid-time"),
    )
    .map_err(|diagnostic| {
        MemoryError::invalid(
            record.record_id,
            record.kind.symbol(),
            diagnostic.to_string(),
        )
    })
}

pub(crate) fn required_reference_target(record: &RecordEnvelope, name: &str) -> Result<RecordId> {
    reference_target(record, required(record, name)?).and_then(|target| {
        target.ok_or_else(|| {
            MemoryError::invalid(
                record.record_id,
                record.kind.symbol(),
                format!("{name} must name a local record"),
            )
        })
    })
}

pub(crate) fn optional_reference_target(
    record: &RecordEnvelope,
    name: &str,
) -> Result<Option<RecordId>> {
    match record.payload.get(name) {
        Some(value) => reference_target(record, value),
        None => Ok(None),
    }
}

pub(crate) fn required_reference_set(
    record: &RecordEnvelope,
    name: &str,
) -> Result<BTreeSet<RecordId>> {
    let values = required(record, name)?;
    let set = values.as_set().ok_or_else(|| {
        MemoryError::invalid(
            record.record_id,
            record.kind.symbol(),
            format!("{name} must be a set of references"),
        )
    })?;
    let mut targets = BTreeSet::new();
    for value in set {
        if let Some(target) = reference_target(record, value)? {
            targets.insert(target);
        }
    }
    Ok(targets)
}

pub(crate) fn optional_reference_set(
    record: &RecordEnvelope,
    name: &str,
) -> Result<BTreeSet<RecordId>> {
    if record.payload.get(name).is_some() {
        required_reference_set(record, name)
    } else {
        Ok(BTreeSet::new())
    }
}

fn reference_target(record: &RecordEnvelope, value: &Value) -> Result<Option<RecordId>> {
    let reference =
        Reference::from_value(value, &mneme_core::Path::root()).map_err(|diagnostic| {
            MemoryError::invalid(
                record.record_id,
                record.kind.symbol(),
                diagnostic.to_string(),
            )
        })?;
    match &reference {
        Reference::External { .. } => Err(MemoryError::invalid(
            record.record_id,
            record.kind.symbol(),
            "memory references cannot be external",
        )),
        Reference::Unresolved { .. } => Err(MemoryError::invalid(
            record.record_id,
            record.kind.symbol(),
            "memory references cannot be unresolved",
        )),
        _ => Ok(reference.target()),
    }
}

pub(crate) fn optional_text(record: &RecordEnvelope, name: &str) -> Option<String> {
    record
        .payload
        .get(name)
        .and_then(Value::as_string)
        .map(str::to_owned)
}

/// Re-exported for callers constructing views from a payload.
pub fn payload_of(record: &RecordEnvelope) -> &Payload {
    &record.payload
}

/// Parse a decision or assertion revision identity from a record.
pub fn revision_of(record: &RecordEnvelope) -> RevisionId {
    record.revision_id
}

/// The recorded time assigned by the coordinator.
pub fn recorded_of(record: &RecordEnvelope) -> RecordedTime {
    record.recorded
}
