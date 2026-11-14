//! Deterministic and optional-extractor proposal generation.
//!
//! Mechanical checks validate exact input identity, reviewed batch membership,
//! span bounds, and quoted bytes. They do not establish semantic entailment:
//! generated proposals begin with an unsupported-hypothesis support review and
//! require a separate attributed review before acceptance.
//!
//! Generation is bounded by the job it runs under. An extractor runs only when
//! the job declares the identical extractor identity, and every model call and
//! every returned proposal is charged against the job's limits. Nothing is
//! generated from input bytes that are no longer retained.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Exact text associated with one reviewed input unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratorInput {
    pub key: crate::InputKey,
    /// The reviewed text. It is exactly the bytes at `span` in the source
    /// record, never a wider window, so a proposal can quote it verbatim.
    pub text: String,
    /// The absolute extent of `text` in the source record, or `None` when the
    /// text starts at the first byte of that record.
    pub span: Option<mneme_core::SourceSpan>,
    /// The authority the reviewed unit's content carries.
    pub authority: crate::ProposalAuthority,
    /// The derivation record the unit came from, when it came from one.
    pub derivation: Option<mneme_core::RecordId>,
    /// The distinct ancestry roots the reviewed unit stands for.
    pub ancestry_roots: std::collections::BTreeSet<crate::InputKey>,
}

impl GeneratorInput {
    /// Review one batch unit's text, inheriting its ancestry and authority.
    pub fn from_unit(
        unit: &crate::InputUnit,
        text: impl Into<String>,
        span: Option<mneme_core::SourceSpan>,
    ) -> Self {
        GeneratorInput {
            key: unit.key,
            text: text.into(),
            span,
            authority: unit.authority,
            derivation: unit.derivation,
            ancestry_roots: unit.ancestry_roots.clone(),
        }
    }
}

/// One extractor output. It remains untrusted until mechanically checked and
/// separately reviewed for semantic support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractedClaim {
    pub claim_id: String,
    /// Host-resolved entity identity. Model output contains an opaque entity handle instead.
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub value: mneme_core::Value,
    /// Byte offsets relative to `GeneratorInput::text`, not the whole source.
    pub span: mneme_core::SourceSpan,
    pub quote: String,
    pub stance: crate::ProposalStance,
    pub valid_time: mneme_core::ValidTime,
    pub uncertainty: Option<String>,
}

/// A host-only mapping from a model-visible opaque handle to a local entity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntityHandle {
    pub handle: String,
    pub label: String,
    pub record_id: mneme_core::RecordId,
}

/// One extraction attempt and its content-free runtime receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractorAttempt {
    pub status: mneme_recall::inference::InvocationStatus,
    pub claims: Vec<ExtractedClaim>,
    /// Exact serialized worker request bytes when preparation succeeded.
    pub input_bytes: Option<usize>,
    pub elapsed: std::time::Duration,
    pub usage: mneme_recall::inference::UsageTelemetry,
    pub input_digest: String,
    pub configuration_digest: String,
    pub reported_model: Option<String>,
    pub output_bytes: Option<usize>,
    /// SHA-256 of exact fully captured worker stdout, before schema parsing.
    pub observed_output_digest: Option<String>,
    pub detail: Option<String>,
    /// False for deterministic test/custom adapters; only a subprocess-backed
    /// attempt can create ModelExtraction provenance.
    pub supervised_model: bool,
}

/// Optional extractor boundary.
///
/// An implementation declares the exact identity it embodies, so a job can
/// never attribute its output to a different model, revision or prompt.
pub trait Extractor {
    /// The extractor identity this implementation embodies.
    fn descriptor(&self) -> &crate::ExtractorDescriptor;

    fn extract(&self, input: &GeneratorInput) -> Result<Vec<ExtractedClaim>, String>;

    /// Invoke one extraction with a host-visible, pre-resolved entity roster.
    /// Implementations must report whether output came from the supervised
    /// model transport; synchronous custom extraction is never model-attributed.
    fn extract_attempt(
        &self,
        input: &GeneratorInput,
        _entities: &[EntityHandle],
        control: &mneme_recall::inference::InvocationControl,
    ) -> ExtractorAttempt;
}

/// Deterministic extractive summary generator.
pub struct DeterministicGenerator;

impl DeterministicGenerator {
    /// Generate one source-linked summary proposal per reviewed input.
    ///
    /// The summary text is exactly the bytes the premise cites, so a reader can
    /// always verify the summary against the recorded span.
    pub fn generate(
        &self,
        job: &crate::Job,
        batch: &crate::InputBatch,
        inputs: &[GeneratorInput],
    ) -> Result<Vec<crate::Proposal>, String> {
        job.validate()?;
        if job.batch != *batch {
            return Err("generator batch does not belong to the job".to_owned());
        }
        validate_inputs(batch, inputs)?;
        let mut proposals = Vec::with_capacity(inputs.len());
        let mut ids = std::collections::BTreeSet::new();
        for input in inputs {
            if input.text.trim().is_empty() {
                return Err("generator input has no text".to_owned());
            }
            let (text, span) = cited_extent(&input.text, input.span)?;
            let proposal = crate::Proposal {
                proposal_id: summary_id(job, input.key),
                job_id: job.job_id.clone(),
                recorded_at: job.recorded_at,
                base_revision: job.base_revision,
                scope: job.scope.clone(),
                policy_version: job.policy_version.clone(),
                eligibility_generation: batch.eligibility_generation,
                operation: crate::ProposalOperation::Summary(crate::SummaryProposal { text }),
                premises: vec![premise(input, span)],
                rationale: "deterministic extractive summary; semantic support needs review"
                    .to_owned(),
                support: pending_support(),
                disposition: crate::ProposalDisposition::Pending,
            };
            push_unique(&mut proposals, &mut ids, proposal)?;
        }
        Ok(proposals)
    }
}

/// Generate assertion proposals from an optional extractor.
///
/// The extractor must be the one the job declares, and both its calls and its
/// output are charged against the job's limits, so an untrusted extractor can
/// neither run under another job's identity nor emit unbounded work.
pub fn generate_extracted(
    job: &crate::Job,
    batch: &crate::InputBatch,
    inputs: &[GeneratorInput],
    extractor: &dyn Extractor,
) -> Result<Vec<crate::Proposal>, String> {
    job.validate()?;
    if job.batch != *batch {
        return Err("generator batch does not belong to the job".to_owned());
    }
    let Some(declared) = &job.extractor else {
        return Err("the job declares no extractor".to_owned());
    };
    if extractor.descriptor() != declared {
        return Err("extractor identity does not match the job's extractor".to_owned());
    }
    validate_inputs(batch, inputs)?;
    let call_limit = u64::from(job.limits.max_model_calls);
    let proposal_limit = u64::try_from(job.limits.max_proposals)
        .map_err(|_| "job proposal limit is too large".to_owned())?;
    let mut model_calls = 0_u64;
    let mut counted = 0_u64;
    let mut proposals = Vec::with_capacity(inputs.len());
    let mut ids = std::collections::BTreeSet::new();
    for input in inputs {
        model_calls = mneme_kernel::budget::charge(model_calls, 1, call_limit)
            .ok_or_else(|| "job model call limit exceeded".to_owned())?;
        for claim in extractor.extract(input)? {
            if claim.claim_id.trim().is_empty() || claim.predicate.trim().is_empty() {
                return Err("extractor returned an incomplete claim".to_owned());
            }
            validate_span(&input.text, claim.span, "extractor claim")?;
            if !quote_matches(&input.text, claim.span, &claim.quote) {
                return Err("extractor quote does not match the cited source bytes".to_owned());
            }
            counted = mneme_kernel::budget::charge(counted, 1, proposal_limit)
                .ok_or_else(|| "job proposal limit exceeded".to_owned())?;
            let proposal = crate::Proposal {
                proposal_id: claim_id(job, input.key, &claim.claim_id),
                job_id: job.job_id.clone(),
                recorded_at: job.recorded_at,
                base_revision: job.base_revision,
                scope: job.scope.clone(),
                policy_version: job.policy_version.clone(),
                eligibility_generation: batch.eligibility_generation,
                operation: crate::ProposalOperation::Assertion(crate::AssertionProposal {
                    subject: claim.subject,
                    predicate: claim.predicate,
                    value: claim.value,
                    stance: claim.stance,
                    valid_time: claim.valid_time,
                    uncertainty: claim.uncertainty,
                    extraction: None,
                }),
                premises: vec![premise(input, absolute_span(input, claim.span)?)],
                rationale:
                    "extractor candidate; mechanical citation check does not prove semantic support"
                        .to_owned(),
                support: pending_support(),
                disposition: crate::ProposalDisposition::Pending,
            };
            push_unique(&mut proposals, &mut ids, proposal)?;
        }
    }
    Ok(proposals)
}

/// Generate proposals from claims already produced by one supervised attempt.
///
/// This narrow path keeps model execution outside pure validation while
/// preserving the exact invocation receipt on every generated assertion.
pub fn generate_extracted_attempt(
    job: &crate::Job,
    batch: &crate::InputBatch,
    input: &GeneratorInput,
    attempt: &ExtractorAttempt,
) -> Result<Vec<crate::Proposal>, String> {
    job.validate()?;
    if job.batch != *batch {
        return Err("generator batch does not belong to the job".to_owned());
    }
    let Some(declared) = &job.extractor else {
        return Err("the job declares no extractor".to_owned());
    };
    validate_inputs(batch, std::slice::from_ref(input))?;
    if attempt.status != mneme_recall::inference::InvocationStatus::Complete {
        return Err(attempt
            .detail
            .clone()
            .unwrap_or_else(|| "extractor did not complete".to_owned()));
    }
    if !attempt.supervised_model {
        return Err("workspace model extraction requires a supervised model attempt".to_owned());
    }
    let proposal_limit = u64::try_from(job.limits.max_proposals)
        .map_err(|_| "job proposal limit is too large".to_owned())?;
    let mut proposals = Vec::with_capacity(attempt.claims.len());
    let mut ids = std::collections::BTreeSet::new();
    let context = SupervisedProposalContext {
        job,
        batch,
        input,
        attempt,
        proposal_limit,
    };
    for claim in &attempt.claims {
        let proposal = context.proposal(claim, proposals.len())?;
        push_unique(&mut proposals, &mut ids, proposal)?;
    }
    if declared.identity.trim().is_empty() {
        return Err("the declared extractor identity is empty".to_owned());
    }
    Ok(proposals)
}

struct SupervisedProposalContext<'a> {
    job: &'a crate::Job,
    batch: &'a crate::InputBatch,
    input: &'a GeneratorInput,
    attempt: &'a ExtractorAttempt,
    proposal_limit: u64,
}

impl SupervisedProposalContext<'_> {
    fn proposal(
        &self,
        claim: &ExtractedClaim,
        used_proposals: usize,
    ) -> Result<crate::Proposal, String> {
        validate_supervised_claim(self.input, claim)?;
        if u64::try_from(used_proposals)
            .ok()
            .and_then(|used| mneme_kernel::budget::charge(used, 1, self.proposal_limit))
            .is_none()
        {
            return Err("job proposal limit exceeded".to_owned());
        }
        Ok(crate::Proposal {
            proposal_id: claim_id(self.job, self.input.key, &claim.claim_id),
            job_id: self.job.job_id.clone(),
            recorded_at: self.job.recorded_at,
            base_revision: self.job.base_revision,
            scope: self.job.scope.clone(),
            policy_version: self.job.policy_version.clone(),
            eligibility_generation: self.batch.eligibility_generation,
            operation: crate::ProposalOperation::Assertion(crate::AssertionProposal {
                subject: claim.subject,
                predicate: claim.predicate.clone(),
                value: claim.value.clone(),
                stance: claim.stance,
                valid_time: claim.valid_time,
                uncertainty: claim.uncertainty.clone(),
                extraction: Some(crate::ExtractionProvenance {
                    input_digest: self.attempt.input_digest.clone(),
                    configuration_digest: self.attempt.configuration_digest.clone(),
                    reported_model: self.attempt.reported_model.clone(),
                    elapsed_ns: crate::elapsed_ns_telemetry(self.attempt.elapsed),
                    usage: self.attempt.usage.clone(),
                }),
            }),
            premises: vec![premise(self.input, absolute_span(self.input, claim.span)?)],
            rationale: claim.uncertainty.as_ref().map_or_else(
                || "model extractor candidate; semantic support remains pending review".to_owned(),
                |uncertainty| format!("model extractor candidate; uncertainty: {uncertainty}"),
            ),
            support: pending_support(),
            disposition: crate::ProposalDisposition::Pending,
        })
    }
}

fn validate_supervised_claim(input: &GeneratorInput, claim: &ExtractedClaim) -> Result<(), String> {
    if claim.claim_id.trim().is_empty() || claim.predicate.trim().is_empty() {
        return Err("extractor returned an incomplete claim".to_owned());
    }
    validate_span(&input.text, claim.span, "extractor claim")?;
    if !quote_matches(&input.text, claim.span, &claim.quote) {
        return Err("extractor quote does not match the cited source bytes".to_owned());
    }
    if claim
        .uncertainty
        .as_ref()
        .is_some_and(|detail| detail.trim().is_empty() || detail.len() > 1_024)
    {
        return Err("extractor uncertainty is empty or exceeds its byte limit".to_owned());
    }
    Ok(())
}

/// Record a separate attributed semantic-support review.
pub fn record_support_review(
    proposal: &mut crate::Proposal,
    review: crate::SupportReview,
) -> Result<(), String> {
    review.validate()?;
    if matches!(
        proposal.disposition,
        crate::ProposalDisposition::Accepted { .. }
            | crate::ProposalDisposition::Rejected { .. }
            | crate::ProposalDisposition::Blocked { .. }
    ) {
        return Err("cannot change support review after a terminal disposition".to_owned());
    }
    proposal.support = review;
    Ok(())
}

/// One premise citing exactly the bytes it was generated from.
fn premise(input: &GeneratorInput, span: mneme_core::SourceSpan) -> crate::ProposalPremise {
    crate::ProposalPremise {
        record_id: input.key.record_id,
        revision_id: input.key.revision_id,
        span: Some(span),
        derivation: input.derivation,
        ancestry_roots: input.ancestry_roots.clone(),
        authority: input.authority,
    }
}

/// A summary proposal identity bound to the exact input revision.
fn summary_id(job: &crate::Job, key: crate::InputKey) -> String {
    format!(
        "{}-summary-{}:{}",
        job.job_id,
        key.record_id.to_hex(),
        key.revision_id.to_hex()
    )
}

/// An extractor proposal identity namespaced by input and claim.
///
/// Two inputs never share an identity, and a claim id the extractor repeats is
/// a collision the caller must see rather than a silently dropped proposal.
fn claim_id(job: &crate::Job, key: crate::InputKey, claim: &str) -> String {
    format!(
        "{}-claim-{}:{}:{}",
        job.job_id,
        key.record_id.to_hex(),
        key.revision_id.to_hex(),
        claim
    )
}

fn push_unique(
    proposals: &mut Vec<crate::Proposal>,
    ids: &mut std::collections::BTreeSet<String>,
    proposal: crate::Proposal,
) -> Result<(), String> {
    if !ids.insert(proposal.proposal_id.clone()) {
        return Err("generated proposals share a proposal identity".to_owned());
    }
    proposals.push(proposal);
    Ok(())
}

fn pending_support() -> crate::SupportReview {
    crate::SupportReview {
        actor: "deterministic-generator".to_owned(),
        policy: "semantic-review/pending".to_owned(),
        outcome: crate::SupportOutcome::UnsupportedHypothesis,
        detail: "mechanical source/span check only; semantic support review required".to_owned(),
    }
}

fn validate_inputs(batch: &crate::InputBatch, inputs: &[GeneratorInput]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for input in inputs {
        if !seen.insert(input.key) {
            return Err("generator received a duplicate input".to_owned());
        }
        if !batch.reviewed.contains(&input.key) {
            return Err("generator input is not in the reviewed batch".to_owned());
        }
        let unit = batch
            .units
            .iter()
            .find(|unit| unit.key == input.key)
            .ok_or_else(|| "generator input has no batch unit".to_owned())?;
        if !unit.availability.is_retained() {
            return Err(format!(
                "generator cannot use {} input bytes",
                unit.availability.name()
            ));
        }
        if input.ancestry_roots.is_empty() {
            return Err("generator input needs ancestry roots".to_owned());
        }
        if let Some(span) = input.span {
            // The span is absolute in the source record, so its length must
            // equal the offered text; text-relative bounds do not apply.
            let length = usize::try_from(span.end())
                .ok()
                .and_then(|end| end.checked_add(1))
                .and_then(|end| end.checked_sub(usize::try_from(span.start()).ok()?))
                .ok_or_else(|| "generator input span is inverted".to_owned())?;
            if length != input.text.len() {
                return Err("generator input text does not match its cited span".to_owned());
            }
        }
    }
    Ok(())
}

/// The exact text a proposal may cite, and the span citing it.
///
/// A summary is an interpretation of the bytes it names, never of bytes outside
/// its citation: the premise records the absolute extent of the reviewed text,
/// and `validate_inputs` has already refused a text that is not exactly that
/// extent. Without a span the text is cited from the first byte of the record.
fn cited_extent(
    text: &str,
    span: Option<mneme_core::SourceSpan>,
) -> Result<(String, mneme_core::SourceSpan), String> {
    let Some(span) = span else {
        let end = text
            .len()
            .checked_sub(1)
            .ok_or_else(|| "generator input has no text".to_owned())?;
        let end = u64::try_from(end).map_err(|_| "input text is too large".to_owned())?;
        let span = mneme_core::SourceSpan::new(0, end).map_err(|error| error.to_owned())?;
        return Ok((text.to_owned(), span));
    };
    Ok((text.to_owned(), span))
}

fn validate_span(text: &str, span: mneme_core::SourceSpan, label: &str) -> Result<(), String> {
    let end = usize::try_from(span.end())
        .ok()
        .and_then(|end| end.checked_add(1))
        .filter(|end| *end <= text.len())
        .ok_or_else(|| format!("{label} span is outside source bytes"))?;
    let start =
        usize::try_from(span.start()).map_err(|_| format!("{label} span start is too large"))?;
    if end < start {
        return Err(format!("{label} span is inverted"));
    }
    Ok(())
}

/// Translate one text-relative claim span into its absolute source extent.
fn absolute_span(
    input: &GeneratorInput,
    relative: mneme_core::SourceSpan,
) -> Result<mneme_core::SourceSpan, String> {
    let base = input.span.map_or(0, |span| span.start());
    let start = base
        .checked_add(relative.start())
        .ok_or_else(|| "extractor span start overflows the source offset".to_owned())?;
    let end = base
        .checked_add(relative.end())
        .ok_or_else(|| "extractor span end overflows the source offset".to_owned())?;
    mneme_core::SourceSpan::new(start, end).map_err(|error| error.to_owned())
}

fn quote_matches(text: &str, span: mneme_core::SourceSpan, quote: &str) -> bool {
    let Some(start) = usize::try_from(span.start()).ok() else {
        return false;
    };
    let Some(end) = usize::try_from(span.end())
        .ok()
        .and_then(|end| end.checked_add(1))
        .filter(|end| *end <= text.len())
    else {
        return false;
    };
    text.as_bytes().get(start..end) == Some(quote.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestExtractor {
        descriptor: crate::ExtractorDescriptor,
        claims: Vec<ExtractedClaim>,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl TestExtractor {
        fn new(claim: ExtractedClaim) -> Self {
            TestExtractor::with_claims(vec![claim])
        }

        fn with_claims(claims: Vec<ExtractedClaim>) -> Self {
            TestExtractor {
                descriptor: extractor_descriptor(),
                claims,
                calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }
    }

    impl Extractor for TestExtractor {
        fn descriptor(&self) -> &crate::ExtractorDescriptor {
            &self.descriptor
        }

        fn extract(&self, _input: &GeneratorInput) -> Result<Vec<ExtractedClaim>, String> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self.claims.clone())
        }

        #[allow(unknown_lints, ambient_clock)] // fixture attempt elapsed time is test-only telemetry
        fn extract_attempt(
            &self,
            input: &GeneratorInput,
            _entities: &[EntityHandle],
            control: &mneme_recall::inference::InvocationControl,
        ) -> ExtractorAttempt {
            let started = std::time::Instant::now();
            let input_digest = mneme_recall::inference::input_digest(input.text.as_bytes());
            let configuration_digest = mneme_recall::inference::input_digest(
                format!(
                    "{}\0{}\0{}",
                    self.descriptor.identity,
                    self.descriptor.revision,
                    self.descriptor.prompt_digest
                )
                .as_bytes(),
            );
            let was_cancelled = control.is_cancelled();
            let result = if was_cancelled {
                Err("cancelled before extractor start".to_owned())
            } else {
                self.extract(input)
            };
            match result {
                Ok(claims) => ExtractorAttempt {
                    status: mneme_recall::inference::InvocationStatus::Complete,
                    claims,
                    input_bytes: None,
                    elapsed: started.elapsed(),
                    usage: mneme_recall::inference::UsageTelemetry::Unavailable,
                    input_digest,
                    configuration_digest,
                    reported_model: None,
                    output_bytes: None,
                    observed_output_digest: None,
                    detail: None,
                    supervised_model: false,
                },
                Err(detail) => ExtractorAttempt {
                    status: if was_cancelled {
                        mneme_recall::inference::InvocationStatus::Cancelled
                    } else {
                        mneme_recall::inference::InvocationStatus::Failed
                    },
                    claims: Vec::new(),
                    input_bytes: None,
                    elapsed: started.elapsed(),
                    usage: mneme_recall::inference::UsageTelemetry::Unavailable,
                    input_digest,
                    configuration_digest,
                    reported_model: None,
                    output_bytes: None,
                    observed_output_digest: None,
                    detail: Some(detail),
                    supervised_model: false,
                },
            }
        }
    }

    fn extractor_descriptor() -> crate::ExtractorDescriptor {
        crate::ExtractorDescriptor {
            identity: "fixture-extractor".to_owned(),
            revision: "r1".to_owned(),
            prompt_digest: "sha256:prompt".to_owned(),
        }
    }

    fn source_key() -> crate::InputKey {
        crate::InputKey {
            record_id: mneme_core::RecordId::from_bytes([0x20; 16]),
            revision_id: mneme_core::RevisionId::from_bytes([0x21; 16]),
        }
    }

    fn input_and_job() -> (GeneratorInput, crate::Job, crate::InputBatch) {
        let fixture = crate::fixture().expect("fixture");
        let unit = fixture
            .job
            .batch
            .units
            .iter()
            .find(|unit| unit.key == source_key())
            .expect("source unit")
            .clone();
        let input = GeneratorInput::from_unit(
            &unit,
            "The Cedar project uses SQLite.",
            mneme_core::SourceSpan::new(0, 29).ok(),
        );
        (input, fixture.job.clone(), fixture.job.batch.clone())
    }

    fn extractor_job(job: crate::Job) -> crate::Job {
        let mut job = job;
        job.extractor = Some(extractor_descriptor());
        job.limits.max_model_calls = 4;
        job
    }

    fn valid_claim() -> ExtractedClaim {
        ExtractedClaim {
            claim_id: "storage".to_owned(),
            subject: mneme_core::RecordId::from_bytes([0x10; 16]),
            predicate: "storage-engine".to_owned(),
            value: mneme_core::Value::string("SQLite"),
            span: mneme_core::SourceSpan::new(23, 28).expect("span"),
            quote: "SQLite".to_owned(),
            stance: crate::ProposalStance::Affirm,
            valid_time: mneme_core::ValidTime::Unknown,
            uncertainty: None,
        }
    }

    #[test]
    fn deterministic_generator_marks_support_pending() {
        let (input, job, batch) = input_and_job();
        let proposals = DeterministicGenerator
            .generate(&job, &batch, &[input])
            .expect("summary");
        assert_eq!(proposals.len(), 1);
        assert!(matches!(
            proposals[0].operation,
            crate::ProposalOperation::Summary(_)
        ));
        assert_eq!(
            proposals[0].support.outcome,
            crate::SupportOutcome::UnsupportedHypothesis
        );
        assert!(matches!(
            proposals[0].disposition,
            crate::ProposalDisposition::Pending
        ));
        crate::validate_proposal_against_batch(&proposals[0], &batch).expect("batch-compatible");
    }

    #[test]
    fn summary_text_is_exactly_the_cited_span() {
        let (unit_input, job, batch) = input_and_job();
        let unit = crate::InputUnit::new(
            unit_input.key,
            crate::InputKind::SourceRevision,
            crate::InputAvailability::Retained,
        );
        let narrow =
            GeneratorInput::from_unit(&unit, "Cedar", mneme_core::SourceSpan::new(0, 4).ok());
        let proposals = DeterministicGenerator
            .generate(&job, &batch, std::slice::from_ref(&narrow))
            .expect("summary");
        let cited = match &proposals[0].operation {
            crate::ProposalOperation::Summary(summary) => summary.text.clone(),
            _ => String::new(),
        };
        assert_eq!(cited, "Cedar");
        assert_eq!(
            proposals[0].premises[0].span,
            mneme_core::SourceSpan::new(0, 4).ok()
        );

        // A text that is not exactly the cited extent would make the summary
        // quote bytes outside its own premise.
        let overlong = GeneratorInput {
            span: mneme_core::SourceSpan::new(0, 4).ok(),
            text: "Cedar uses SQLite every day.".to_owned(),
            ..narrow
        };
        assert!(
            DeterministicGenerator
                .generate(&job, &batch, &[overlong])
                .is_err()
        );
    }

    #[test]
    fn summary_without_a_span_cites_the_full_extent() {
        let (input, job, batch) = input_and_job();
        let whole = GeneratorInput {
            span: None,
            ..input
        };
        let proposals = DeterministicGenerator
            .generate(&job, &batch, &[whole])
            .expect("summary");
        let cited = proposals[0].premises[0].span.expect("cited extent");
        assert_eq!(cited, mneme_core::SourceSpan::new(0, 29).expect("span"));
    }

    #[test]
    fn generated_premises_keep_unit_ancestry_and_authority() {
        let (input, job, batch) = input_and_job();
        let root = crate::InputKey {
            record_id: mneme_core::RecordId::from_bytes([0x11; 16]),
            revision_id: mneme_core::RevisionId::from_bytes([0x12; 16]),
        };
        let derived = GeneratorInput {
            ancestry_roots: std::collections::BTreeSet::from([root]),
            authority: crate::ProposalAuthority::Derived,
            ..input
        };
        let proposals = DeterministicGenerator
            .generate(&job, &batch, &[derived])
            .expect("summary");
        let premise = &proposals[0].premises[0];
        assert_eq!(
            premise.ancestry_roots,
            std::collections::BTreeSet::from([root])
        );
        assert_eq!(premise.authority, crate::ProposalAuthority::Derived);
        assert_ne!(root, premise_key(premise));
    }

    fn premise_key(premise: &crate::ProposalPremise) -> crate::InputKey {
        crate::InputKey {
            record_id: premise.record_id,
            revision_id: premise.revision_id,
        }
    }

    #[test]
    fn summary_identities_distinguish_input_revisions() {
        let (input, job, batch) = input_and_job();
        let other_revision = crate::InputKey {
            record_id: input.key.record_id,
            revision_id: mneme_core::RevisionId::from_bytes([0x22; 16]),
        };
        let mut two = batch.clone();
        two.units.push(crate::InputUnit::new(
            other_revision,
            crate::InputKind::SourceRevision,
            crate::InputAvailability::Retained,
        ));
        two.reviewed.insert(other_revision);
        two.declared_extent = Some(two.reviewed.clone());
        let twin = GeneratorInput {
            key: other_revision,
            ancestry_roots: std::collections::BTreeSet::from([other_revision]),
            ..input.clone()
        };
        // The generator refuses a batch that is not the job's batch, so the job
        // must carry the same two-unit extent the call reviews.
        let mut job = job;
        job.batch = two.clone();
        let proposals = DeterministicGenerator
            .generate(&job, &two, &[input, twin])
            .expect("two summaries");
        assert_eq!(proposals.len(), 2);
        assert_ne!(proposals[0].proposal_id, proposals[1].proposal_id);
    }

    #[test]
    fn extractor_citation_is_checked_against_exact_bytes() {
        let (input, job, batch) = input_and_job();
        let job = extractor_job(job);
        let valid = TestExtractor::new(valid_claim());
        let proposals = generate_extracted(&job, &batch, std::slice::from_ref(&input), &valid)
            .expect("valid extractor");
        assert_eq!(proposals.len(), 1);
        assert_eq!(
            proposals[0].support.outcome,
            crate::SupportOutcome::UnsupportedHypothesis
        );
        let mut invalid = valid_claim();
        invalid.quote = "WAL".to_owned();
        let error = generate_extracted(&job, &batch, &[input], &TestExtractor::new(invalid))
            .expect_err("fabricated quote");
        assert!(error.contains("does not match"));
    }

    #[test]
    fn extractor_offsets_text_relative_spans_by_input_base_offset() {
        let (input, job, batch) = input_and_job();
        let job = extractor_job(job);
        let input = GeneratorInput {
            span: mneme_core::SourceSpan::new(100, 129).ok(),
            ..input
        };
        let proposals = generate_extracted(
            &job,
            &batch,
            std::slice::from_ref(&input),
            &TestExtractor::new(valid_claim()),
        )
        .expect("relative extractor span");
        assert_eq!(
            proposals[0].premises[0].span,
            mneme_core::SourceSpan::new(123, 128).ok(),
            "the stored premise span must include the input's absolute base offset"
        );
    }

    #[test]
    fn extractor_requires_the_identity_the_job_declares() {
        let (input, job, batch) = input_and_job();
        let job = extractor_job(job);
        let mut unnamed = job.clone();
        unnamed.extractor = None;
        let extractor = TestExtractor::new(valid_claim());
        assert!(
            generate_extracted(&unnamed, &batch, std::slice::from_ref(&input), &extractor).is_err()
        );
        let mut other = job;
        other.extractor = Some(crate::ExtractorDescriptor {
            identity: "another-extractor".to_owned(),
            revision: "r2".to_owned(),
            prompt_digest: "sha256:other".to_owned(),
        });
        assert!(
            generate_extracted(&other, &batch, std::slice::from_ref(&input), &extractor).is_err()
        );
    }

    #[test]
    fn extractor_calls_and_claims_are_charged_against_the_job() {
        let (input, job, batch) = input_and_job();
        let mut none = extractor_job(job.clone());
        none.limits.max_model_calls = 0;
        let extractor = TestExtractor::new(valid_claim());
        let error = generate_extracted(&none, &batch, std::slice::from_ref(&input), &extractor)
            .expect_err("model call limit");
        assert!(error.contains("model call limit"));
        assert_eq!(
            extractor.calls.load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        let mut first = valid_claim();
        first.claim_id = "storage".to_owned();
        let mut second = valid_claim();
        second.claim_id = "engine".to_owned();
        second.predicate = "engine-name".to_owned();
        let greedy = TestExtractor::with_claims(vec![first, second]);
        let mut narrow = extractor_job(job);
        narrow.limits.max_proposals = 1;
        let error = generate_extracted(&narrow, &batch, std::slice::from_ref(&input), &greedy)
            .expect_err("proposal limit");
        assert!(error.contains("proposal limit"));
    }

    #[test]
    fn extractor_claims_are_namespaced_by_input_revision() {
        let (input, job, batch) = input_and_job();
        let other_revision = crate::InputKey {
            record_id: input.key.record_id,
            revision_id: mneme_core::RevisionId::from_bytes([0x22; 16]),
        };
        let mut two = batch.clone();
        two.units.push(crate::InputUnit::new(
            other_revision,
            crate::InputKind::SourceRevision,
            crate::InputAvailability::Retained,
        ));
        two.reviewed.insert(other_revision);
        two.declared_extent = Some(two.reviewed.clone());
        let twin = GeneratorInput {
            key: other_revision,
            ancestry_roots: std::collections::BTreeSet::from([other_revision]),
            ..input.clone()
        };
        let mut job = extractor_job(job);
        job.batch = two.clone();
        let proposals = generate_extracted(
            &job,
            &two,
            &[input, twin],
            &TestExtractor::new(valid_claim()),
        )
        .expect("two claims");
        assert_eq!(proposals.len(), 2);
        assert_ne!(proposals[0].proposal_id, proposals[1].proposal_id);
    }

    #[test]
    fn valid_citation_does_not_certify_unsupported_detail() {
        let (input, job, batch) = input_and_job();
        let job = extractor_job(job);
        let mut claim = valid_claim();
        claim.value = mneme_core::Value::string("PostgreSQL");
        let mut proposal = generate_extracted(&job, &batch, &[input], &TestExtractor::new(claim))
            .expect("mechanical citation")
            .remove(0);
        record_support_review(
            &mut proposal,
            crate::SupportReview {
                actor: "reviewer".to_owned(),
                policy: "semantic-support/v1".to_owned(),
                outcome: crate::SupportOutcome::Rejected,
                detail: "the cited span says SQLite, not PostgreSQL".to_owned(),
            },
        )
        .expect("review");
        assert!(!matches!(
            proposal.disposition,
            crate::ProposalDisposition::Accepted { .. }
        ));
        proposal.disposition = crate::ProposalDisposition::Accepted {
            decision: mneme_core::RecordId::from_bytes([0x50; 16]),
        };
        assert!(proposal.validate().is_err());
    }

    #[test]
    fn no_generation_from_forgotten_pruned_or_corrupt_inputs() {
        let (input, job, _batch) = input_and_job();
        for availability in [
            crate::InputAvailability::Forgotten {
                reason: "explicit forget".to_owned(),
            },
            crate::InputAvailability::Pruned {
                reason: "source pruned".to_owned(),
            },
            crate::InputAvailability::Unavailable {
                reason: "source bytes are corrupt".to_owned(),
            },
        ] {
            let mut batch = job.batch.clone();
            let unit = batch
                .units
                .iter_mut()
                .find(|unit| unit.key == input.key)
                .expect("source unit");
            unit.availability = availability.clone();
            let mut job = job.clone();
            job.batch = batch.clone();
            let extraction_job = extractor_job(job.clone());
            let quoted = GeneratorInput {
                span: Some(mneme_core::SourceSpan::new(0, 6).expect("span")),
                ..input.clone()
            };
            let unquoted = GeneratorInput {
                span: None,
                ..input.clone()
            };
            let generator = DeterministicGenerator;
            for candidate in [quoted, unquoted] {
                assert!(
                    generator
                        .generate(&job, &batch, std::slice::from_ref(&candidate))
                        .is_err(),
                    "{availability:?} input was summarised"
                );
                assert!(
                    generate_extracted(
                        &extraction_job,
                        &batch,
                        std::slice::from_ref(&candidate),
                        &TestExtractor::new(valid_claim()),
                    )
                    .is_err(),
                    "{availability:?} input was re-extracted"
                );
            }
        }
    }

    #[test]
    fn generators_validate_the_job_envelope() {
        let (input, job, batch) = input_and_job();
        let mut mismatched = job.clone();
        mismatched.scope =
            mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "birch").expect("scope");
        assert!(
            DeterministicGenerator
                .generate(&mismatched, &batch, std::slice::from_ref(&input))
                .is_err()
        );
        let extractor = TestExtractor::new(valid_claim());
        let extractor_job = extractor_job(mismatched);
        assert!(
            generate_extracted(
                &extractor_job,
                &batch,
                std::slice::from_ref(&input),
                &extractor
            )
            .is_err()
        );
        assert_eq!(
            extractor.calls.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }
}
