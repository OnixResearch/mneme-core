//! Deterministic and optional-extractor proposal generation.
//!
//! Mechanical checks validate exact input identity, reviewed batch membership,
//! span bounds, and quoted bytes. They do not establish semantic entailment:
//! generated proposals begin with an unsupported-hypothesis support review and
//! require a separate attributed review before acceptance.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Exact text associated with one reviewed input unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratorInput {
    pub key: crate::InputKey,
    pub text: String,
    pub span: Option<mneme_core::SourceSpan>,
}

/// One extractor output. It remains untrusted until mechanically checked and
/// separately reviewed for semantic support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractedClaim {
    pub claim_id: String,
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub value: mneme_core::Value,
    pub span: mneme_core::SourceSpan,
    pub quote: String,
}

/// Optional extractor boundary.
pub trait Extractor {
    fn extract(&self, input: &GeneratorInput) -> Result<Vec<ExtractedClaim>, String>;
}

/// Deterministic extractive summary generator.
pub struct DeterministicGenerator;

impl DeterministicGenerator {
    /// Generate one source-linked summary proposal per reviewed input.
    pub fn generate(
        &self,
        job: &crate::Job,
        batch: &crate::InputBatch,
        inputs: &[GeneratorInput],
    ) -> Result<Vec<crate::Proposal>, String> {
        if job.batch != *batch {
            return Err("generator batch does not belong to the job".to_owned());
        }
        validate_inputs(batch, inputs)?;
        let mut proposals = Vec::with_capacity(inputs.len());
        for input in inputs {
            if input.text.trim().is_empty() {
                return Err(format!("input {} has no text", input.key.record_id));
            }
            proposals.push(crate::Proposal {
                proposal_id: format!("{}-summary-{}", job.job_id, input.key.record_id.to_hex()),
                job_id: job.job_id.clone(),
                recorded_at: job.recorded_at,
                base_revision: job.base_revision,
                scope: job.scope.clone(),
                operation: crate::ProposalOperation::Summary(crate::SummaryProposal {
                    text: input.text.clone(),
                }),
                premises: vec![crate::ProposalPremise {
                    record_id: input.key.record_id,
                    revision_id: input.key.revision_id,
                    span: input.span,
                    derivation: None,
                    ancestry_roots: std::collections::BTreeSet::from([input.key]),
                    authority: crate::ProposalAuthority::Observed,
                }],
                rationale: "deterministic extractive summary; semantic support needs review"
                    .to_owned(),
                support: pending_support(),
                disposition: crate::ProposalDisposition::Pending,
            });
        }
        Ok(proposals)
    }
}

/// Generate assertion proposals from an optional extractor.
pub fn generate_extracted(
    job: &crate::Job,
    batch: &crate::InputBatch,
    inputs: &[GeneratorInput],
    extractor: &dyn Extractor,
) -> Result<Vec<crate::Proposal>, String> {
    if job.batch != *batch {
        return Err("generator batch does not belong to the job".to_owned());
    }
    validate_inputs(batch, inputs)?;
    let mut proposals = Vec::with_capacity(inputs.len());
    for input in inputs {
        for claim in extractor.extract(input)? {
            if claim.claim_id.trim().is_empty() || claim.predicate.trim().is_empty() {
                return Err("extractor returned an incomplete claim".to_owned());
            }
            validate_span(&input.text, claim.span, "extractor claim")?;
            if !quote_matches(&input.text, claim.span, &claim.quote) {
                return Err(format!(
                    "extractor claim {} quote does not match source bytes",
                    claim.claim_id
                ));
            }
            proposals.push(crate::Proposal {
                proposal_id: format!("{}-{}", job.job_id, claim.claim_id),
                job_id: job.job_id.clone(),
                recorded_at: job.recorded_at,
                base_revision: job.base_revision,
                scope: job.scope.clone(),
                operation: crate::ProposalOperation::Assertion(crate::AssertionProposal {
                    subject: claim.subject,
                    predicate: claim.predicate,
                    value: claim.value,
                    stance: crate::ProposalStance::Affirm,
                    valid_time: mneme_core::ValidTime::Unknown,
                }),
                premises: vec![crate::ProposalPremise {
                    record_id: input.key.record_id,
                    revision_id: input.key.revision_id,
                    span: Some(claim.span),
                    derivation: None,
                    ancestry_roots: std::collections::BTreeSet::from([input.key]),
                    authority: crate::ProposalAuthority::ModelExtracted,
                }],
                rationale:
                    "extractor candidate; mechanical citation check does not prove semantic support"
                        .to_owned(),
                support: pending_support(),
                disposition: crate::ProposalDisposition::Pending,
            });
        }
    }
    Ok(proposals)
}

/// Record a separate attributed semantic-support review.
pub fn record_support_review(
    proposal: &mut crate::Proposal,
    review: crate::SupportReview,
) -> Result<(), String> {
    review.validate()?;
    if matches!(
        proposal.disposition,
        crate::ProposalDisposition::Accepted { .. } | crate::ProposalDisposition::Rejected { .. }
    ) {
        return Err("cannot change support review after a terminal disposition".to_owned());
    }
    proposal.support = review;
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
        match &unit.availability {
            crate::InputAvailability::Forgotten { .. } => {
                return Err("generator input was explicitly forgotten".to_owned());
            }
            crate::InputAvailability::Pruned { .. } if input.span.is_some() => {
                return Err("generator cannot quote a pruned input".to_owned());
            }
            _ => {}
        }
        if let Some(span) = input.span {
            validate_span(&input.text, span, "generator input")?;
        }
    }
    Ok(())
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
        claim: ExtractedClaim,
    }

    impl Extractor for TestExtractor {
        fn extract(&self, _input: &GeneratorInput) -> Result<Vec<ExtractedClaim>, String> {
            Ok(vec![self.claim.clone()])
        }
    }

    fn input_and_job() -> (GeneratorInput, crate::Job, crate::InputBatch) {
        let fixture = crate::fixture().expect("fixture");
        let input = GeneratorInput {
            key: crate::InputKey {
                record_id: mneme_core::RecordId::from_bytes([0x20; 16]),
                revision_id: mneme_core::RevisionId::from_bytes([0x21; 16]),
            },
            text: "The Cedar project uses SQLite.".to_owned(),
            span: mneme_core::SourceSpan::new(0, 29).ok(),
        };
        (input, fixture.job.clone(), fixture.job.batch.clone())
    }

    fn valid_claim() -> ExtractedClaim {
        ExtractedClaim {
            claim_id: "storage".to_owned(),
            subject: mneme_core::RecordId::from_bytes([0x10; 16]),
            predicate: "storage-engine".to_owned(),
            value: mneme_core::Value::string("SQLite"),
            span: mneme_core::SourceSpan::new(23, 28).expect("span"),
            quote: "SQLite".to_owned(),
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
    fn extractor_citation_is_checked_against_exact_bytes() {
        let (input, job, batch) = input_and_job();
        let valid = TestExtractor {
            claim: valid_claim(),
        };
        let proposals = generate_extracted(&job, &batch, std::slice::from_ref(&input), &valid)
            .expect("valid extractor");
        assert_eq!(proposals.len(), 1);
        assert_eq!(
            proposals[0].support.outcome,
            crate::SupportOutcome::UnsupportedHypothesis
        );
        let mut invalid = valid_claim();
        invalid.quote = "WAL".to_owned();
        let error = generate_extracted(&job, &batch, &[input], &TestExtractor { claim: invalid })
            .expect_err("fabricated quote");
        assert!(error.contains("does not match"));
    }

    #[test]
    fn valid_citation_does_not_certify_unsupported_detail() {
        let (input, job, batch) = input_and_job();
        let mut claim = valid_claim();
        claim.value = mneme_core::Value::string("PostgreSQL");
        let mut proposal = generate_extracted(
            &job,
            &batch,
            &[input],
            &TestExtractor {
                claim: claim.clone(),
            },
        )
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
    fn forgotten_or_quoted_pruned_inputs_are_rejected() {
        let (mut input, job, _batch) = input_and_job();
        let mut fixture = crate::fixture().expect("fixture");
        let unit = fixture.job.batch.units[1].clone();
        fixture.job.batch.units[1].availability = crate::InputAvailability::Forgotten {
            reason: "explicit forget".to_owned(),
        };
        let mut job = job;
        job.batch = fixture.job.batch.clone();
        let generator = DeterministicGenerator;
        assert!(
            generator
                .generate(&job, &fixture.job.batch, std::slice::from_ref(&input))
                .is_err()
        );

        fixture.job.batch.units[1].availability = crate::InputAvailability::Pruned {
            reason: "source pruned".to_owned(),
        };
        job.batch = fixture.job.batch.clone();
        input.span = Some(mneme_core::SourceSpan::new(0, 6).expect("span"));
        assert!(
            generator
                .generate(&job, &fixture.job.batch, std::slice::from_ref(&input))
                .is_err()
        );
        input.span = None;
        assert!(
            generator
                .generate(&job, &fixture.job.batch, std::slice::from_ref(&input))
                .is_ok()
        );
        let _ = unit;
    }
}
