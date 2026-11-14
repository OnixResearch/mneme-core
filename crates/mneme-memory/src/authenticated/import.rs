//! Bounded local authentication and admission for one external assertion.
//!
//! A valid signature establishes who signed a fixed byte commitment; it does
//! not establish truth or local permission. Admission is a second operation
//! against host-owned issuer, scope, audience, subject-mapping, and time policy.
//! The only write path creates a retained source, exact-span evidence, and a
//! proposed assertion through the ordinary memory coordinator.

use sha2::Digest as _;

/// Maximum encoded tagged-JSON bundle size.
pub const MAX_BUNDLE_BYTES: u64 = 2 * 1024 * 1024;
/// Maximum exact source payload in one bundle.
pub const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
/// Maximum canonical encoding of the assertion value.
pub const MAX_ASSERTION_BYTES: u64 = 64 * 1024;
/// Maximum signed validity interval.
pub const MAX_VALIDITY_WINDOW_SECONDS: i64 = 366 * 24 * 60 * 60;

const BUNDLE_LABEL: &str = "mneme-authenticated-import-v1";
const SIGNED_LABEL: &str = "mneme-authenticated-import-signed-v1";
const ASSERTION_LABEL: &str = "mneme-import-assertion-v1";
const EVIDENCE_LABEL: &str = "mneme-import-evidence-v1";
const ENCODING_PROFILE: &str = "preserves-canonical-binary-v1";
const SIGNATURE_PROFILE: &str = "ed25519-strict-v1";
const SIGNATURE_DOMAIN: &[u8] = b"mneme.authenticated-import.v1\0";
const KEY_ID_DOMAIN: &[u8] = b"mneme.authenticated-import.key-id.v1\0";
const EXTERNAL_ID_DOMAIN: &[u8] = b"mneme.authenticated-import.external-id.v1\0";
const LOCAL_SOURCE_DOMAIN: &[u8] = b"mneme.authenticated-import.source-record.v1\0";
const LOCAL_SOURCE_REVISION_DOMAIN: &[u8] = b"mneme.authenticated-import.source-revision.v1\0";
const LOCAL_EVIDENCE_DOMAIN: &[u8] = b"mneme.authenticated-import.evidence-record.v1\0";
const LOCAL_EVIDENCE_REVISION_DOMAIN: &[u8] = b"mneme.authenticated-import.evidence-revision.v1\0";
const LOCAL_ASSERTION_DOMAIN: &[u8] = b"mneme.authenticated-import.assertion-record.v1\0";
const LOCAL_ASSERTION_REVISION_DOMAIN: &[u8] =
    b"mneme.authenticated-import.assertion-revision.v1\0";

const SOURCE_MEDIA_TYPE: &str = "application/octet-stream";
const SOURCE_ACQUISITION: &str = "authenticated-import-v1";
const MAX_TEXT_BYTES: u64 = 512;

/// Whether the configured host key is currently eligible for admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyState {
    /// Verify and admit subject to the rest of the host policy.
    Active,
    /// Retain the key for historical cryptographic verification, but refuse
    /// new admissions signed by it.
    Revoked,
}

/// Host-owned fields used to construct an issuer policy.
pub struct ImportPolicyConfig {
    /// Issuer identity expected in signed bundles.
    pub issuer: String,
    /// Current host-managed key epoch.
    pub key_epoch: u64,
    /// Ed25519 public key trusted by this host.
    pub public_key: [u8; 32],
    /// Whether the key may admit new bundles.
    pub key_state: KeyState,
    /// Monotone host policy generation.
    pub generation: u64,
    /// Allowed host/workspace audiences.
    pub allowed_audiences: std::collections::BTreeSet<String>,
    /// Allowed target scopes.
    pub allowed_scopes: std::collections::BTreeSet<mneme_core::ScopeId>,
    /// Explicit mapping from foreign subjects to existing local entities.
    pub subject_mappings: std::collections::BTreeMap<String, mneme_core::RecordId>,
}

/// Host-owned issuer, key, allowlists, and foreign-subject mapping.
///
/// No public key or permission is read from a bundle. `key_id` is derived from
/// the configured Ed25519 public key and the key epoch is supplied by the host.
pub struct ImportPolicy {
    issuer: String,
    key_id: String,
    key_epoch: u64,
    verifying_key: ed25519_dalek::VerifyingKey,
    key_state: KeyState,
    generation: u64,
    allowed_audiences: std::collections::BTreeSet<String>,
    allowed_scopes: std::collections::BTreeSet<mneme_core::ScopeId>,
    subject_mappings: std::collections::BTreeMap<String, mneme_core::RecordId>,
}

impl ImportPolicy {
    /// Construct policy exclusively from host-owned key and admission inputs.
    pub fn new(config: ImportPolicyConfig) -> Result<Self, PolicyError> {
        let ImportPolicyConfig {
            issuer,
            key_epoch,
            public_key,
            key_state,
            generation,
            allowed_audiences,
            allowed_scopes,
            subject_mappings,
        } = config;
        validate_policy_text(&issuer).map_err(|()| PolicyError::InvalidIssuer)?;
        for audience in &allowed_audiences {
            validate_policy_text(audience).map_err(|()| PolicyError::InvalidAudience)?;
        }
        for subject in subject_mappings.keys() {
            validate_policy_text(subject).map_err(|()| PolicyError::InvalidSubjectMapping)?;
        }
        if i64::try_from(key_epoch).is_err() {
            return Err(PolicyError::InvalidKeyEpoch);
        }
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .map_err(|_| PolicyError::InvalidPublicKey)?;
        let key_id = key_id(&public_key);
        Ok(ImportPolicy {
            issuer,
            key_id,
            key_epoch,
            verifying_key,
            key_state,
            generation,
            allowed_audiences,
            allowed_scopes,
            subject_mappings,
        })
    }

    /// The host policy generation captured by an authenticated plan.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The stable public-key identity carried in a signed bundle.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The configured issuer identity.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

/// One issuer-authored assertion over an exact raw-source byte span.
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalAssertion {
    /// Foreign subject identity; the host must map it to a local entity.
    pub subject: String,
    /// Predicate represented as a Preserves symbol in the local assertion.
    pub predicate: String,
    /// Claim value. The importer treats this as data and never evaluates it.
    pub value: mneme_core::Value,
    /// Claim stance; it does not change the proposed lifecycle.
    pub stance: crate::model::Stance,
    /// Claim valid-time interval, distinct from signed bundle validity.
    pub valid_time: mneme_core::ValidTime,
    /// Inclusive byte offsets in `Bundle::source_bytes`.
    pub source_span: mneme_core::SourceSpan,
    /// Whether the exact source span supports or challenges the assertion.
    pub relation: crate::model::SupportRelation,
}

impl ExternalAssertion {
    fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            ASSERTION_LABEL,
            vec![
                mneme_core::Value::string(self.subject.clone()),
                mneme_core::Value::string(self.predicate.clone()),
                self.value.clone(),
                mneme_core::Value::symbol(match self.stance {
                    crate::model::Stance::Affirm => "affirm",
                    crate::model::Stance::Deny => "deny",
                    crate::model::Stance::Hypothesis => "hypothesis",
                }),
                self.valid_time.to_value(),
                self.source_span.to_value(),
                mneme_core::Value::symbol(match self.relation {
                    crate::model::SupportRelation::Supports => "supports",
                    crate::model::SupportRelation::Challenges => "challenges",
                }),
            ],
        )
    }
}

/// Version-one signed source-plus-one-assertion transport.
///
/// Source bytes are preserved exactly in the resulting source blob. The signed
/// message commits to their raw-byte digest, not to JSON whitespace or member
/// order. There are no embedded public keys or local record identifiers.
#[derive(Clone, PartialEq, Eq)]
pub struct Bundle {
    /// Issuer identity, checked against host policy after signature verification.
    pub issuer: String,
    /// Host-derived identity of the signing key.
    pub key_id: String,
    /// Host-managed key epoch.
    pub key_epoch: u64,
    /// Foreign record identity.
    pub external_record: String,
    /// Foreign revision identity.
    pub external_revision: String,
    /// Intended workspace audience; this grants no access by itself.
    pub audience: String,
    /// Intended scope; host policy must independently allow it.
    pub scope: mneme_core::ScopeId,
    /// Only sequence 1 without a predecessor is admitted in this profile.
    pub sequence: u64,
    /// A nonempty predecessor is authenticated but not supported by this profile.
    pub predecessor: Option<String>,
    /// Inclusive beginning of the signed validity interval, Unix seconds.
    pub not_before_unix_seconds: i64,
    /// Exclusive end of the signed validity interval, Unix seconds.
    pub expires_at_unix_seconds: i64,
    /// Exact external source bytes; never decoded as instructions.
    pub source_bytes: Vec<u8>,
    /// One fixed-shape attributed assertion.
    pub assertion: ExternalAssertion,
    /// Ed25519 signature over `canonical_signing_bytes`.
    pub signature: [u8; 64],
}

impl Bundle {
    /// Canonical, domain-separated bytes to sign with the configured Ed25519 key.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>, AuthenticationError> {
        validate_bundle_fields(self)?;
        let encoded = mneme_core::encode(&self.signed_value()?);
        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + encoded.len());
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(&encoded);
        Ok(message)
    }

    /// Encode the bundle as the existing strict tagged-JSON transport document.
    pub fn to_json_document(&self) -> Result<String, AuthenticationError> {
        validate_bundle_fields(self)?;
        let value = mneme_core::Value::record_named(
            BUNDLE_LABEL,
            vec![
                self.signed_value()?,
                mneme_core::Value::bytes(self.source_bytes.clone()),
                mneme_core::Value::bytes(self.signature.to_vec()),
            ],
        );
        let document = mneme_core::encode_document_string(&value);
        if length_exceeds(document.len(), MAX_BUNDLE_BYTES) {
            return Err(AuthenticationError::InputTooLarge);
        }
        Ok(document)
    }

    fn signed_value(&self) -> Result<mneme_core::Value, AuthenticationError> {
        let assertion = self.assertion.to_value();
        let assertion_encoding = mneme_core::encode(&assertion);
        if length_exceeds(assertion_encoding.len(), MAX_ASSERTION_BYTES) {
            return Err(AuthenticationError::AssertionTooLarge);
        }
        let source_digest = mneme_core::ContentDigest::of_source_bytes(&self.source_bytes);
        let evidence_digest =
            mneme_core::ContentDigest::of_payload(&self.evidence_value(source_digest));
        let assertion_digest = mneme_core::ContentDigest::of_payload(&assertion);
        Ok(mneme_core::Value::record_named(
            SIGNED_LABEL,
            vec![
                mneme_core::Value::symbol(ENCODING_PROFILE),
                mneme_core::Value::symbol(SIGNATURE_PROFILE),
                mneme_core::Value::string(self.issuer.clone()),
                mneme_core::Value::string(self.key_id.clone()),
                mneme_core::Value::integer(self.key_epoch),
                mneme_core::Value::string(self.external_record.clone()),
                mneme_core::Value::string(self.external_revision.clone()),
                mneme_core::Value::string(self.audience.clone()),
                self.scope.to_value(),
                mneme_core::Value::integer(self.sequence),
                optional_text_value(self.predecessor.as_deref()),
                mneme_core::Value::integer(self.not_before_unix_seconds),
                mneme_core::Value::integer(self.expires_at_unix_seconds),
                source_digest.to_value(),
                evidence_digest.to_value(),
                assertion_digest.to_value(),
                assertion,
            ],
        ))
    }

    fn evidence_value(&self, source_digest: mneme_core::ContentDigest) -> mneme_core::Value {
        mneme_core::Value::record_named(
            EVIDENCE_LABEL,
            vec![
                source_digest.to_value(),
                self.assertion.source_span.to_value(),
                mneme_core::Value::symbol(match self.assertion.relation {
                    crate::model::SupportRelation::Supports => "supports",
                    crate::model::SupportRelation::Challenges => "challenges",
                }),
                mneme_core::Value::symbol(mneme_core::Origin::Import.symbol()),
                mneme_core::Value::set(std::iter::empty()),
            ],
        )
    }
}

/// A successfully signature-verified bundle, not yet admitted for local use.
pub struct AuthenticatedBundle {
    bundle: Bundle,
    verified_key_id: String,
    policy_generation: u64,
}

impl AuthenticatedBundle {
    /// The key identity used by the host during cryptographic verification.
    pub fn verified_key_id(&self) -> &str {
        &self.verified_key_id
    }

    /// The host policy generation used during cryptographic verification.
    pub fn policy_generation(&self) -> u64 {
        self.policy_generation
    }
}

/// Verify a bounded JSON document using only the supplied host key.
///
/// A bundle may not introduce its own trusted key. Issuer/key-id/epoch labels
/// are authenticated data and are checked against policy by [`plan_import`].
pub fn authenticate_json(
    input: &[u8],
    policy: &ImportPolicy,
) -> Result<AuthenticatedBundle, AuthenticationError> {
    if length_exceeds(input.len(), MAX_BUNDLE_BYTES) {
        return Err(AuthenticationError::InputTooLarge);
    }
    let text = std::str::from_utf8(input).map_err(|_| AuthenticationError::InvalidUtf8)?;
    let value =
        mneme_core::decode_document(text).map_err(|_| AuthenticationError::MalformedDocument)?;
    let bundle = parse_bundle(value)?;
    validate_bundle_fields(&bundle)?;
    let signed = bundle.signed_value()?;
    let signed_bytes = mneme_core::encode(&signed);
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + signed_bytes.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&signed_bytes);
    let signature = ed25519_dalek::Signature::from_bytes(&bundle.signature);
    policy
        .verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| AuthenticationError::InvalidSignature)?;
    Ok(AuthenticatedBundle {
        bundle,
        verified_key_id: policy.key_id.clone(),
        policy_generation: policy.generation,
    })
}

/// Host-selected audience, target scope, actor, and trusted time.
pub struct ImportRequest<'a> {
    /// Workspace identity supplied by the local host, not the bundle.
    pub audience: &'a str,
    /// Target scope selected by the local host, not a signed scope grant.
    pub scope: &'a mneme_core::ScopeId,
    /// Actor attributed to the local coordinator command.
    pub actor: &'a str,
    /// Trusted host time in Unix seconds.
    pub trusted_now_unix_seconds: i64,
}

/// Deterministic mapping from foreign identity to local record identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalMapping {
    /// Retained source record id; same exact bytes in one scope share this root.
    pub source: mneme_core::RecordId,
    /// Retained source revision id.
    pub source_revision: mneme_core::RevisionId,
    /// Local evidence record id.
    pub evidence: mneme_core::RecordId,
    /// Local evidence revision id.
    pub evidence_revision: mneme_core::RevisionId,
    /// Local proposed assertion record id.
    pub assertion: mneme_core::RecordId,
    /// Local assertion revision id.
    pub assertion_revision: mneme_core::RevisionId,
}

/// An authenticated, host-admitted plan bound to one workspace/policy state.
///
/// The plan owns private source bytes only until commit. Its debug output is
/// intentionally unavailable so a source body cannot leak through diagnostics.
pub struct ImportPlan {
    expected_source: mneme_store::RecordDraft,
    evidence: mneme_store::RecordDraft,
    assertion: mneme_store::RecordDraft,
    source_bytes: Option<Vec<u8>>,
    mapping: LocalMapping,
    actor: String,
    scope: mneme_core::ScopeId,
    audience: String,
    issuer: String,
    key_id: String,
    key_epoch: u64,
    external_subject: String,
    local_subject: mneme_core::RecordId,
    external_identity_digest: [u8; 32],
    source_digest: mneme_core::ContentDigest,
    not_before_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    policy_generation: u64,
    workspace_base: mneme_core::WorkspaceRevisionId,
    eligibility_generation: u64,
}

impl ImportPlan {
    /// The stable foreign-to-local record mapping carried by this plan.
    pub fn mapping(&self) -> LocalMapping {
        self.mapping
    }

    /// The workspace revision used as the compare-and-swap base.
    pub fn workspace_base(&self) -> mneme_core::WorkspaceRevisionId {
        self.workspace_base
    }

    /// The host issuer-policy generation captured by this plan.
    pub fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// The current retention eligibility generation captured by this plan.
    pub fn eligibility_generation(&self) -> u64 {
        self.eligibility_generation
    }
}

/// Authenticate separately from issuer/scope/time and ordinary-memory admission.
pub fn plan_import(
    workspace: &mneme_store::Workspace,
    authenticated: AuthenticatedBundle,
    policy: &ImportPolicy,
    request: ImportRequest<'_>,
) -> Result<ImportPlan, AdmissionError> {
    check_admission(&authenticated, policy, &request)?;
    let bundle = authenticated.bundle;
    let mapping = local_mapping(&bundle, request.scope)?;
    let (workspace_base, eligibility_generation, snapshot) = capture_plan_snapshot(workspace)?;
    reject_suppressed(workspace, mapping)?;

    let external_identity_digest = external_identity_digest(&bundle);
    let source_digest = mneme_core::ContentDigest::of_source_bytes(&bundle.source_bytes);
    let local_subject = *policy
        .subject_mappings
        .get(&bundle.assertion.subject)
        .ok_or(AdmissionError::SubjectUnmapped)?;
    let expected_source = source_draft(mapping, request.scope, &bundle)?;
    let source_current = current_record(&snapshot, mapping.source);
    if let Some(record) = source_current {
        verify_existing_source(
            workspace,
            &expected_source,
            record,
            Some(&bundle.source_bytes),
            source_digest,
        )?;
    } else if !workspace.record_revisions(mapping.source)?.is_empty() {
        return Err(AdmissionError::IdentityConflict);
    }

    let evidence = build_import_evidence(&bundle, mapping, request.scope, policy.generation)?;
    let assertion = build_import_assertion(
        &bundle,
        mapping,
        request.scope,
        local_subject,
        &external_identity_digest,
    );

    validate_occupied_record(workspace, &snapshot, &evidence)?;
    validate_occupied_record(workspace, &snapshot, &assertion)?;
    Ok(ImportPlan {
        expected_source,
        evidence,
        assertion,
        mapping,
        actor: request.actor.to_owned(),
        scope: request.scope.clone(),
        audience: request.audience.to_owned(),
        issuer: bundle.issuer,
        key_id: bundle.key_id,
        key_epoch: bundle.key_epoch,
        external_subject: bundle.assertion.subject,
        external_identity_digest,
        source_digest,
        source_bytes: if source_current.is_some() {
            None
        } else {
            Some(bundle.source_bytes)
        },
        local_subject,
        not_before_unix_seconds: bundle.not_before_unix_seconds,
        expires_at_unix_seconds: bundle.expires_at_unix_seconds,
        policy_generation: policy.generation,
        workspace_base,
        eligibility_generation,
    })
}

fn capture_plan_snapshot(
    workspace: &mneme_store::Workspace,
) -> Result<(mneme_core::WorkspaceRevisionId, u64, mneme_store::Snapshot), AdmissionError> {
    let status = workspace.status()?;
    let snapshot = workspace.snapshot_at(status.revision, Some(status.eligibility_generation))?;
    let after_snapshot = workspace.status()?;
    if after_snapshot.revision != status.revision {
        return Err(AdmissionError::WorkspaceChanged);
    }
    if after_snapshot.eligibility_generation != status.eligibility_generation {
        return Err(AdmissionError::EligibilityGenerationChanged);
    }
    Ok((status.revision, status.eligibility_generation, snapshot))
}

fn build_import_evidence(
    bundle: &Bundle,
    mapping: LocalMapping,
    scope: &mneme_core::ScopeId,
    policy_generation: u64,
) -> Result<mneme_store::RecordDraft, AdmissionError> {
    let mut evidence = crate::service::build_evidence(
        mapping.evidence,
        mapping.evidence_revision,
        scope,
        crate::service::EvidenceOptions {
            assertion: mapping.assertion,
            source: mapping.source,
            source_revision: mapping.source_revision,
            span: Some(bundle.assertion.source_span),
            anchor: None,
            relation: bundle.assertion.relation,
            origin: mneme_core::Origin::Import,
            ancestry: &[],
        },
    );
    let canonical_signed_bytes = bundle
        .canonical_signing_bytes()
        .map_err(|_| AdmissionError::InvalidSource)?;
    evidence.payload.insert(
        "import-authentication",
        mneme_core::Value::record_named(
            "authenticated-import-provenance-v1",
            vec![
                mneme_core::Value::string(bundle.issuer.clone()),
                mneme_core::Value::string(bundle.key_id.clone()),
                mneme_core::Value::integer(bundle.key_epoch),
                mneme_core::Value::string(bundle.external_record.clone()),
                mneme_core::Value::string(bundle.external_revision.clone()),
                mneme_core::Value::string(bundle.assertion.subject.clone()),
                mneme_core::Value::string(bundle.audience.clone()),
                bundle.scope.to_value(),
                mneme_core::Value::integer(bundle.sequence),
                optional_text_value(bundle.predecessor.as_deref()),
                mneme_core::Value::integer(bundle.not_before_unix_seconds),
                mneme_core::Value::integer(bundle.expires_at_unix_seconds),
                mneme_core::Value::integer(policy_generation),
                mneme_core::ContentDigest::of_source_bytes(&canonical_signed_bytes).to_value(),
                mneme_core::Value::bytes(bundle.signature.to_vec()),
            ],
        ),
    );
    Ok(evidence)
}

fn build_import_assertion(
    bundle: &Bundle,
    mapping: LocalMapping,
    scope: &mneme_core::ScopeId,
    local_subject: mneme_core::RecordId,
    external_identity_digest: &[u8; 32],
) -> mneme_store::RecordDraft {
    let evidence_reference =
        mneme_core::Reference::local(mapping.evidence, mneme_core::RecordKind::Evidence);
    let asserted_by = format!(
        "{} [authenticated-import-v1:{}]",
        bundle.issuer,
        hex_digest(external_identity_digest)
    );
    crate::service::build_proposed_assertion(
        mapping.assertion,
        mapping.assertion_revision,
        scope,
        crate::service::ProposedAssertionOptions {
            subject: local_subject,
            predicate: &bundle.assertion.predicate,
            value: bundle.assertion.value.clone(),
            stance: bundle.assertion.stance,
            origin: mneme_core::Origin::Import,
            asserted_by: &asserted_by,
            valid_time: bundle.assertion.valid_time,
            evidence: std::slice::from_ref(&evidence_reference),
            extraction: None,
            superseded_by: None,
        },
    )
}

/// Result of the existing coordinator commit or an exact already-imported replay.
pub enum ImportCommitOutcome {
    /// A new or coordinator-replayed ordinary memory commit.
    Committed(mneme_store::CommitOutcome),
    /// The exact local mapping is already current; no additional evidence was written.
    AlreadyImported,
}

/// Commit one plan through `Memory::commit_at_base`, with current host-policy
/// and retention-generation checks before replay and before result release.
pub fn commit_import(
    workspace: &mut mneme_store::Workspace,
    plan: ImportPlan,
    policy: &ImportPolicy,
    trusted_now_unix_seconds: i64,
    access: crate::authorization::Access,
) -> Result<ImportCommitOutcome, ImportCommitError> {
    check_current_policy(&plan, policy, trusted_now_unix_seconds)?;
    let policy_binding = PolicyBinding::from_plan(&plan);
    if !access.allows(&plan.scope) {
        return Err(ImportCommitError::UnauthorizedScope);
    }

    let _eligibility_guard = pin_eligibility_generation(workspace, plan.eligibility_generation)?;
    let before = workspace.status()?;
    if before.eligibility_generation != plan.eligibility_generation {
        return Err(ImportCommitError::EligibilityGenerationChanged);
    }
    let existing = existing_import_at(
        workspace,
        &plan,
        before.revision,
        before.eligibility_generation,
    )?;
    if existing == ExistingImport::Complete {
        confirm_exact_replay(workspace, &plan, policy, trusted_now_unix_seconds)?;
        return Ok(ImportCommitOutcome::AlreadyImported);
    }
    if before.revision != plan.workspace_base {
        return Err(ImportCommitError::StaleBase);
    }
    let eligibility_generation = plan.eligibility_generation;
    let outcome = commit_missing_records(workspace, plan, existing, access)?;
    let after = workspace.status()?;
    if after.eligibility_generation != eligibility_generation {
        return Err(ImportCommitError::EligibilityGenerationChanged);
    }
    check_policy_binding(&policy_binding, policy, trusted_now_unix_seconds)?;
    Ok(ImportCommitOutcome::Committed(outcome))
}

fn existing_import_at(
    workspace: &mneme_store::Workspace,
    plan: &ImportPlan,
    revision: mneme_core::WorkspaceRevisionId,
    eligibility_generation: u64,
) -> Result<ExistingImport, ImportCommitError> {
    let snapshot = workspace.snapshot_at(revision, Some(eligibility_generation))?;
    reject_suppressed(workspace, plan.mapping)?;
    let existing =
        validate_import_records(workspace, &snapshot, plan, plan.source_bytes.as_deref())?;
    if workspace.status()?.revision != revision {
        return Err(ImportCommitError::StaleBase);
    }
    Ok(existing)
}

fn confirm_exact_replay(
    workspace: &mneme_store::Workspace,
    plan: &ImportPlan,
    policy: &ImportPolicy,
    trusted_now_unix_seconds: i64,
) -> Result<(), ImportCommitError> {
    let after = workspace.status()?;
    if after.eligibility_generation != plan.eligibility_generation {
        return Err(ImportCommitError::EligibilityGenerationChanged);
    }
    check_current_policy(plan, policy, trusted_now_unix_seconds)?;
    Ok(())
}

fn commit_missing_records(
    workspace: &mut mneme_store::Workspace,
    plan: ImportPlan,
    existing: ExistingImport,
    access: crate::authorization::Access,
) -> Result<mneme_store::CommitOutcome, ImportCommitError> {
    let mut records = Vec::with_capacity(3);
    let mut source_blobs = Vec::with_capacity(1);
    let ImportPlan {
        expected_source,
        evidence,
        assertion,
        source_bytes,
        actor,
        scope,
        external_identity_digest,
        workspace_base,
        ..
    } = plan;
    if !existing.source() {
        let bytes = source_bytes.ok_or(ImportCommitError::SourceUnavailable)?;
        records.push(expected_source);
        source_blobs.push(mneme_store::SourceBlobDraft {
            bytes,
            media_type: mneme_core::Symbol::from(SOURCE_MEDIA_TYPE),
        });
    }
    if !existing.evidence() {
        records.push(evidence);
    }
    if !existing.assertion() {
        records.push(assertion);
    }
    if records.is_empty() {
        return Err(ImportCommitError::IdentityConflict);
    }
    let batch = crate::service::Batch {
        actor,
        scope,
        idempotency_key: idempotency_key(&external_identity_digest),
        records,
        source_blobs,
        publications: Vec::new(),
    };

    let outcome = {
        let mut engine = crate::service::Engine::new(workspace, access);
        engine.commit_at_base(batch, workspace_base)?
    };
    Ok(outcome)
}

fn pin_eligibility_generation(
    workspace: &mneme_store::Workspace,
    generation: u64,
) -> Result<mneme_store::coordinator::CommitGuard, ImportCommitError> {
    workspace
        .eligibility_guard(generation)
        .map_err(|error| match error {
            mneme_store::Failure::BarrierAdvanced { .. } => {
                ImportCommitError::EligibilityGenerationChanged
            }
            other => ImportCommitError::Workspace(other),
        })
}

/// Authentication-stage failures. These do not include host admission outcomes.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthenticationError {
    /// The raw tagged-JSON document exceeded its byte bound.
    #[error("authenticated import exceeds the input byte limit")]
    InputTooLarge,
    /// The source payload exceeded its byte bound.
    #[error("authenticated import source exceeds the byte limit")]
    SourceTooLarge,
    /// The canonical assertion exceeded its byte bound.
    #[error("authenticated import assertion exceeds the byte limit")]
    AssertionTooLarge,
    /// The JSON document was not valid UTF-8.
    #[error("authenticated import is not UTF-8 JSON")]
    InvalidUtf8,
    /// The document is malformed, noncanonical, ambiguous, or has unknown fields.
    #[error("authenticated import document is malformed or noncanonical")]
    MalformedDocument,
    /// The profile or algorithm is not supported by this implementation.
    #[error("authenticated import profile is unsupported")]
    UnsupportedProfile,
    /// The signed source digest does not match the exact raw bytes.
    #[error("authenticated import source digest does not match its bytes")]
    SourceDigestMismatch,
    /// The signed assertion digest does not match its canonical value.
    #[error("authenticated import assertion digest does not match its value")]
    AssertionDigestMismatch,
    /// The signed evidence digest does not match its exact source span and relation.
    #[error("authenticated import evidence digest does not match its content")]
    EvidenceDigestMismatch,
    /// The host policy key did not verify the signature strictly.
    #[error("authenticated import signature is invalid")]
    InvalidSignature,
}

/// Errors constructing a host-owned issuer policy.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    /// Issuer identity is empty, oversized, or contains controls.
    #[error("issuer policy identity is invalid")]
    InvalidIssuer,
    /// Audience allowlist contains invalid text.
    #[error("issuer policy audience is invalid")]
    InvalidAudience,
    /// A foreign-subject mapping key is invalid.
    #[error("issuer policy subject mapping is invalid")]
    InvalidSubjectMapping,
    /// Host-supplied public key is not a valid Ed25519 key.
    #[error("issuer policy public key is invalid")]
    InvalidPublicKey,
    /// The host key epoch cannot be represented by the signed profile.
    #[error("issuer policy key epoch is out of range")]
    InvalidKeyEpoch,
}

/// Valid-signature admission and plan-construction failures.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// Host policy changed after cryptographic verification.
    #[error("issuer policy changed after authentication")]
    StalePolicy,
    /// Signed issuer does not match the configured issuer.
    #[error("signed issuer is not eligible under the configured policy")]
    IssuerMismatch,
    /// Signed key identity does not match the configured key.
    #[error("signed key identity is not eligible under the configured policy")]
    KeyMismatch,
    /// Signed key epoch differs from the currently configured epoch.
    #[error("signed key epoch is not current")]
    KeyEpochMismatch,
    /// The configured key has been revoked.
    #[error("issuer key is revoked")]
    Revoked,
    /// Signed audience differs from host-selected audience or is not allowed.
    #[error("signed audience is not allowed for this workspace")]
    AudienceMismatch,
    /// Signed scope differs from host-selected scope or is not allowed.
    #[error("signed scope is not allowed for this import")]
    ScopeMismatch,
    /// Host time is before the signed validity interval.
    #[error("authenticated import is not yet valid")]
    NotYetValid,
    /// Host time is at or beyond the signed expiry.
    #[error("authenticated import has expired")]
    Expired,
    /// A signed chain predecessor or noninitial sequence is unsupported.
    #[error("authenticated import revision chain is incomplete or unsupported")]
    UnsupportedRevisionChain,
    /// The host has no local entity mapping for the foreign subject.
    #[error("authenticated import subject has no host-owned local mapping")]
    SubjectUnmapped,
    /// The local caller identity is malformed.
    #[error("authenticated import actor is invalid")]
    InvalidActor,
    /// The workspace changed while the plan snapshot was captured.
    #[error("workspace changed while the import plan was prepared")]
    WorkspaceChanged,
    /// The retention generation advanced during plan preparation.
    #[error("retention eligibility changed while the import plan was prepared")]
    EligibilityGenerationChanged,
    /// A local mapping collides with another record or a different external revision.
    #[error("authenticated import identity conflicts with existing records")]
    IdentityConflict,
    /// The deterministic source identity is already suppressed by retention.
    #[error("authenticated import source or assertion is suppressed")]
    Suppressed,
    /// The exact source artifact could not be constructed.
    #[error("authenticated import source metadata is invalid")]
    InvalidSource,
    /// A bounded workspace read failed.
    #[error("workspace read failed: {0}")]
    Workspace(#[from] mneme_store::Failure),
}

/// Current-authority and ordinary-memory commit failures.
#[derive(Debug, thiserror::Error)]
pub enum ImportCommitError {
    /// Current issuer policy no longer admits the plan.
    #[error("authenticated import policy is stale or no longer eligible: {0}")]
    Admission(#[from] AdmissionError),
    /// The current caller is not authorized for the target scope.
    #[error("caller is not authorized for the import scope")]
    UnauthorizedScope,
    /// A current forget/retention barrier advanced after planning.
    #[error("retention eligibility changed before import commit")]
    EligibilityGenerationChanged,
    /// The plan's workspace base is stale and it is not an exact already-imported item.
    #[error("authenticated import workspace base is stale")]
    StaleBase,
    /// Existing records conflict with the deterministic external identity mapping.
    #[error("authenticated import identity conflicts with existing records")]
    IdentityConflict,
    /// The source is no longer present and this plan does not retain bytes to re-create it.
    #[error("authenticated import source is unavailable")]
    SourceUnavailable,
    /// Coordinator or committed payload read failed.
    #[error("workspace operation failed: {0}")]
    Workspace(#[from] mneme_store::Failure),
    /// Ordinary memory validation or commit failed.
    #[error("memory commit failed: {0}")]
    Memory(#[from] crate::failure::EvidenceError),
}

fn check_admission(
    authenticated: &AuthenticatedBundle,
    policy: &ImportPolicy,
    request: &ImportRequest<'_>,
) -> Result<(), AdmissionError> {
    let bundle = &authenticated.bundle;
    if authenticated.policy_generation != policy.generation {
        return Err(AdmissionError::StalePolicy);
    }
    if policy.key_state == KeyState::Revoked {
        return Err(AdmissionError::Revoked);
    }
    if bundle.issuer != policy.issuer {
        return Err(AdmissionError::IssuerMismatch);
    }
    if bundle.key_id != policy.key_id || authenticated.verified_key_id != policy.key_id {
        return Err(AdmissionError::KeyMismatch);
    }
    if bundle.key_epoch != policy.key_epoch {
        return Err(AdmissionError::KeyEpochMismatch);
    }
    if bundle.sequence != 1 || bundle.predecessor.is_some() {
        return Err(AdmissionError::UnsupportedRevisionChain);
    }
    if request.audience != bundle.audience || !policy.allowed_audiences.contains(request.audience) {
        return Err(AdmissionError::AudienceMismatch);
    }
    if request.scope != &bundle.scope || !policy.allowed_scopes.contains(request.scope) {
        return Err(AdmissionError::ScopeMismatch);
    }
    if !policy
        .subject_mappings
        .contains_key(&bundle.assertion.subject)
    {
        return Err(AdmissionError::SubjectUnmapped);
    }
    if request.trusted_now_unix_seconds < bundle.not_before_unix_seconds {
        return Err(AdmissionError::NotYetValid);
    }
    if request.trusted_now_unix_seconds >= bundle.expires_at_unix_seconds {
        return Err(AdmissionError::Expired);
    }
    if request.actor.trim().is_empty()
        || length_exceeds(request.actor.len(), 128)
        || request.actor.chars().any(char::is_control)
    {
        return Err(AdmissionError::InvalidActor);
    }
    Ok(())
}

fn check_current_policy(
    plan: &ImportPlan,
    policy: &ImportPolicy,
    trusted_now_unix_seconds: i64,
) -> Result<(), AdmissionError> {
    check_policy_binding(
        &PolicyBinding::from_plan(plan),
        policy,
        trusted_now_unix_seconds,
    )
}

struct PolicyBinding {
    issuer: String,
    key_id: String,
    key_epoch: u64,
    audience: String,
    scope: mneme_core::ScopeId,
    external_subject: String,
    local_subject: mneme_core::RecordId,
    not_before_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    generation: u64,
}

impl PolicyBinding {
    fn from_plan(plan: &ImportPlan) -> Self {
        PolicyBinding {
            issuer: plan.issuer.clone(),
            key_id: plan.key_id.clone(),
            key_epoch: plan.key_epoch,
            audience: plan.audience.clone(),
            scope: plan.scope.clone(),
            external_subject: plan.external_subject.clone(),
            local_subject: plan.local_subject,
            not_before_unix_seconds: plan.not_before_unix_seconds,
            expires_at_unix_seconds: plan.expires_at_unix_seconds,
            generation: plan.policy_generation,
        }
    }
}

fn check_policy_binding(
    binding: &PolicyBinding,
    policy: &ImportPolicy,
    trusted_now_unix_seconds: i64,
) -> Result<(), AdmissionError> {
    if policy.generation != binding.generation {
        return Err(AdmissionError::StalePolicy);
    }
    if policy.key_state == KeyState::Revoked {
        return Err(AdmissionError::Revoked);
    }
    if policy.issuer != binding.issuer
        || policy.key_id != binding.key_id
        || policy.key_epoch != binding.key_epoch
    {
        return Err(AdmissionError::KeyMismatch);
    }
    if !policy.allowed_audiences.contains(&binding.audience) {
        return Err(AdmissionError::AudienceMismatch);
    }
    if !policy.allowed_scopes.contains(&binding.scope) {
        return Err(AdmissionError::ScopeMismatch);
    }
    if policy.subject_mappings.get(&binding.external_subject) != Some(&binding.local_subject) {
        return Err(AdmissionError::SubjectUnmapped);
    }
    if trusted_now_unix_seconds < binding.not_before_unix_seconds {
        return Err(AdmissionError::NotYetValid);
    }
    if trusted_now_unix_seconds >= binding.expires_at_unix_seconds {
        return Err(AdmissionError::Expired);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExistingImport {
    Complete,
    Partial {
        source: bool,
        evidence: bool,
        assertion: bool,
    },
}

impl ExistingImport {
    fn source(self) -> bool {
        match self {
            ExistingImport::Complete => true,
            ExistingImport::Partial { source, .. } => source,
        }
    }

    fn evidence(self) -> bool {
        match self {
            ExistingImport::Complete => true,
            ExistingImport::Partial { evidence, .. } => evidence,
        }
    }

    fn assertion(self) -> bool {
        match self {
            ExistingImport::Complete => true,
            ExistingImport::Partial { assertion, .. } => assertion,
        }
    }
}

fn validate_import_records(
    workspace: &mneme_store::Workspace,
    snapshot: &mneme_store::Snapshot,
    plan: &ImportPlan,
    candidate_source_bytes: Option<&[u8]>,
) -> Result<ExistingImport, ImportCommitError> {
    let is_source = occupied_record(workspace, snapshot, &plan.expected_source)?;
    if is_source {
        let stored = mneme_store::payload::read(workspace.root(), plan.source_digest)?;
        if mneme_core::ContentDigest::of_source_bytes(&stored) != plan.source_digest
            || candidate_source_bytes.is_some_and(|candidate| candidate != stored)
        {
            return Err(ImportCommitError::IdentityConflict);
        }
    }
    let is_evidence = occupied_record(workspace, snapshot, &plan.evidence)?;
    let is_assertion = occupied_record(workspace, snapshot, &plan.assertion)?;
    if is_evidence != is_assertion || (is_evidence && !is_source) {
        return Err(ImportCommitError::IdentityConflict);
    }
    if is_source && is_evidence && is_assertion {
        return Ok(ExistingImport::Complete);
    }
    Ok(ExistingImport::Partial {
        source: is_source,
        evidence: is_evidence,
        assertion: is_assertion,
    })
}

fn occupied_record(
    workspace: &mneme_store::Workspace,
    snapshot: &mneme_store::Snapshot,
    expected: &mneme_store::RecordDraft,
) -> Result<bool, ImportCommitError> {
    if let Some(current) = current_record(snapshot, expected.record_id) {
        if !draft_matches_record(expected, current) {
            return Err(ImportCommitError::IdentityConflict);
        }
        return Ok(true);
    }
    if !workspace.record_revisions(expected.record_id)?.is_empty() {
        return Err(ImportCommitError::IdentityConflict);
    }
    Ok(false)
}

fn validate_occupied_record(
    workspace: &mneme_store::Workspace,
    snapshot: &mneme_store::Snapshot,
    expected: &mneme_store::RecordDraft,
) -> Result<(), AdmissionError> {
    if let Some(current) = current_record(snapshot, expected.record_id) {
        if !draft_matches_record(expected, current) {
            return Err(AdmissionError::IdentityConflict);
        }
    } else if !workspace.record_revisions(expected.record_id)?.is_empty() {
        return Err(AdmissionError::IdentityConflict);
    }
    Ok(())
}

fn verify_existing_source(
    workspace: &mneme_store::Workspace,
    expected: &mneme_store::RecordDraft,
    record: &mneme_core::RecordEnvelope,
    candidate: Option<&[u8]>,
    source_digest: mneme_core::ContentDigest,
) -> Result<(), AdmissionError> {
    if !draft_matches_record(expected, record) {
        return Err(AdmissionError::IdentityConflict);
    }
    let stored = mneme_store::payload::read(workspace.root(), source_digest)?;
    if mneme_core::ContentDigest::of_source_bytes(&stored) != source_digest
        || candidate.is_some_and(|candidate| candidate != stored)
    {
        return Err(AdmissionError::IdentityConflict);
    }
    Ok(())
}

fn draft_matches_record(
    draft: &mneme_store::RecordDraft,
    record: &mneme_core::RecordEnvelope,
) -> bool {
    draft.schema_version == record.schema_version
        && draft.kind == record.kind
        && draft.record_id == record.record_id
        && draft.revision_id == record.revision_id
        && draft.predecessor == record.predecessor
        && draft.scope == record.scope
        && payloads_match_import_identity(&draft.payload, &record.payload, draft.kind)
}

fn payloads_match_import_identity(
    expected: &mneme_core::Payload,
    current: &mneme_core::Payload,
    kind: mneme_core::RecordKind,
) -> bool {
    if kind != mneme_core::RecordKind::Evidence {
        return expected == current;
    }
    let expected_provenance = expected.get("import-authentication").and_then(|value| {
        value.as_record().filter(|record| {
            record.label() == &mneme_core::Value::symbol("authenticated-import-provenance-v1")
                && record.fields().len() == 15
        })
    });
    let current_provenance = current.get("import-authentication").and_then(|value| {
        value.as_record().filter(|record| {
            record.label() == &mneme_core::Value::symbol("authenticated-import-provenance-v1")
                && record.fields().len() == 15
        })
    });
    let (Some(expected_provenance), Some(current_provenance)) =
        (expected_provenance, current_provenance)
    else {
        return false;
    };
    let expected_identity = &expected_provenance.fields();
    let current_identity = &current_provenance.fields();
    // Key identity/epoch, host policy generation, signed-byte digest, and
    // signature may differ for an eligible re-sign. The issuer's external
    // revision content and all its non-key provenance must still be identical.
    if [0_usize, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        .into_iter()
        .any(|index| expected_identity[index] != current_identity[index])
    {
        return false;
    }
    expected
        .as_map()
        .iter()
        .filter(|(name, _)| name.as_str() != "import-authentication")
        .eq(current
            .as_map()
            .iter()
            .filter(|(name, _)| name.as_str() != "import-authentication"))
}

fn current_record(
    snapshot: &mneme_store::Snapshot,
    record_id: mneme_core::RecordId,
) -> Option<&mneme_core::RecordEnvelope> {
    snapshot
        .records
        .iter()
        .find(|record| record.record_id == record_id)
}

fn reject_suppressed(
    workspace: &mneme_store::Workspace,
    mapping: LocalMapping,
) -> Result<(), AdmissionError> {
    let suppressions = workspace.active_suppressions()?;
    if suppressions.iter().any(|suppression| {
        suppression.target == mapping.source
            || suppression.target == mapping.evidence
            || suppression.target == mapping.assertion
    }) {
        return Err(AdmissionError::Suppressed);
    }
    Ok(())
}

fn source_draft(
    mapping: LocalMapping,
    scope: &mneme_core::ScopeId,
    bundle: &Bundle,
) -> Result<mneme_store::RecordDraft, AdmissionError> {
    let digest = mneme_core::ContentDigest::of_source_bytes(&bundle.source_bytes);
    let length =
        u64::try_from(bundle.source_bytes.len()).map_err(|_| AdmissionError::InvalidSource)?;
    let retained = mneme_core::RetainedSource::new(digest, length, SOURCE_MEDIA_TYPE)
        .map_err(|_| AdmissionError::InvalidSource)?;
    let draft = mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id: mapping.source,
        revision_id: mapping.source_revision,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("content"),
                mneme_core::SourceContent::Retained(retained).to_value(),
            ),
            (
                mneme_core::Symbol::from("acquisition"),
                mneme_core::Value::symbol(SOURCE_ACQUISITION),
            ),
        ]),
    };
    Ok(draft)
}

fn local_mapping(
    bundle: &Bundle,
    scope: &mneme_core::ScopeId,
) -> Result<LocalMapping, AdmissionError> {
    let scope_encoding = mneme_core::encode(&scope.to_value());
    let source_digest = mneme_core::ContentDigest::of_source_bytes(&bundle.source_bytes);
    let source_digest_encoding = mneme_core::encode(&source_digest.to_value());
    let source_identity = framed_hash(
        LOCAL_SOURCE_DOMAIN,
        &[&scope_encoding, &source_digest_encoding],
    );
    let external_identity = external_identity_digest(bundle);
    let source = mneme_core::RecordId::from_bytes(id_bytes(LOCAL_SOURCE_DOMAIN, &source_identity));
    let source_revision = mneme_core::RevisionId::from_bytes(id_bytes(
        LOCAL_SOURCE_REVISION_DOMAIN,
        &source_identity,
    ));
    let evidence =
        mneme_core::RecordId::from_bytes(id_bytes(LOCAL_EVIDENCE_DOMAIN, &external_identity));
    let evidence_revision = mneme_core::RevisionId::from_bytes(id_bytes(
        LOCAL_EVIDENCE_REVISION_DOMAIN,
        &external_identity,
    ));
    let assertion =
        mneme_core::RecordId::from_bytes(id_bytes(LOCAL_ASSERTION_DOMAIN, &external_identity));
    let assertion_revision = mneme_core::RevisionId::from_bytes(id_bytes(
        LOCAL_ASSERTION_REVISION_DOMAIN,
        &external_identity,
    ));
    if source == evidence || source == assertion || evidence == assertion {
        return Err(AdmissionError::IdentityConflict);
    }
    Ok(LocalMapping {
        source,
        source_revision,
        evidence,
        evidence_revision,
        assertion,
        assertion_revision,
    })
}

fn external_identity_digest(bundle: &Bundle) -> [u8; 32] {
    framed_hash(
        EXTERNAL_ID_DOMAIN,
        &[
            bundle.issuer.as_bytes(),
            bundle.external_record.as_bytes(),
            bundle.external_revision.as_bytes(),
            mneme_core::encode(&bundle.scope.to_value()).as_slice(),
        ],
    )
}

fn id_bytes(domain: &[u8], identity: &[u8; 32]) -> [u8; 16] {
    let digest = framed_hash(domain, &[identity]);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes
}

fn framed_hash(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn key_id(public_key: &[u8; 32]) -> String {
    let digest = framed_hash(KEY_ID_DOMAIN, &[public_key]);
    format!("ed25519-sha256:{}", hex_digest(&digest))
}

fn idempotency_key(identity: &[u8; 32]) -> String {
    format!("authenticated-import-v1:{}", hex_digest(identity))
}

fn hex_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn validate_bundle_fields(bundle: &Bundle) -> Result<(), AuthenticationError> {
    for text in [
        bundle.issuer.as_str(),
        bundle.key_id.as_str(),
        bundle.external_record.as_str(),
        bundle.external_revision.as_str(),
        bundle.audience.as_str(),
        bundle.assertion.subject.as_str(),
        bundle.assertion.predicate.as_str(),
    ] {
        validate_wire_text(text)?;
    }
    if let Some(predecessor) = &bundle.predecessor {
        validate_wire_text(predecessor)?;
    }
    if length_exceeds(bundle.source_bytes.len(), MAX_SOURCE_BYTES) {
        return Err(AuthenticationError::SourceTooLarge);
    }
    if bundle.source_bytes.is_empty()
        || bundle
            .assertion
            .source_span
            .end()
            .checked_add(1)
            .is_none_or(|stop| stop > bundle.source_bytes.len() as u64)
    {
        return Err(AuthenticationError::MalformedDocument);
    }
    if bundle.expires_at_unix_seconds <= bundle.not_before_unix_seconds
        || bundle
            .expires_at_unix_seconds
            .checked_sub(bundle.not_before_unix_seconds)
            .is_none_or(|window| window > MAX_VALIDITY_WINDOW_SECONDS)
    {
        return Err(AuthenticationError::MalformedDocument);
    }
    if i64::try_from(bundle.key_epoch).is_err() || i64::try_from(bundle.sequence).is_err() {
        return Err(AuthenticationError::MalformedDocument);
    }
    let assertion = bundle.assertion.to_value();
    if length_exceeds(mneme_core::encode(&assertion).len(), MAX_ASSERTION_BYTES) {
        return Err(AuthenticationError::AssertionTooLarge);
    }
    Ok(())
}

fn validate_wire_text(text: &str) -> Result<(), AuthenticationError> {
    if text.is_empty()
        || text.trim() != text
        || length_exceeds(text.len(), MAX_TEXT_BYTES)
        || text.chars().any(char::is_control)
    {
        return Err(AuthenticationError::MalformedDocument);
    }
    Ok(())
}

fn validate_policy_text(text: &str) -> Result<(), ()> {
    if text.is_empty()
        || text.trim() != text
        || length_exceeds(text.len(), MAX_TEXT_BYTES)
        || text.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(())
}

fn length_exceeds(length: usize, maximum: u64) -> bool {
    u64::try_from(length).map_or(true, |length| length > maximum)
}

fn optional_text_value(text: Option<&str>) -> mneme_core::Value {
    match text {
        Some(text) => mneme_core::Value::string(text),
        None => mneme_core::Value::symbol("none"),
    }
}

fn parse_bundle(value: mneme_core::Value) -> Result<Bundle, AuthenticationError> {
    let outer = parse_record(&value, BUNDLE_LABEL, 3)?;
    let signed = &outer[0];
    let fields = parse_record(signed, SIGNED_LABEL, 17)?;
    if read_symbol(&fields[0])? != ENCODING_PROFILE || read_symbol(&fields[1])? != SIGNATURE_PROFILE
    {
        return Err(AuthenticationError::UnsupportedProfile);
    }
    let issuer = read_text(&fields[2])?;
    let key_id = read_text(&fields[3])?;
    let key_epoch = read_u64(&fields[4])?;
    let external_record = read_text(&fields[5])?;
    let external_revision = read_text(&fields[6])?;
    let audience = read_text(&fields[7])?;
    let scope = mneme_core::ScopeId::from_value(&fields[8], &mneme_core::Path::root())
        .map_err(|_| AuthenticationError::MalformedDocument)?;
    let sequence = read_u64(&fields[9])?;
    let predecessor = read_optional_text(&fields[10])?;
    let not_before_unix_seconds = read_i64(&fields[11])?;
    let expires_at_unix_seconds = read_i64(&fields[12])?;
    let source_digest = read_digest(&fields[13])?;
    let evidence_digest = read_digest(&fields[14])?;
    let assertion_digest = read_digest(&fields[15])?;
    let assertion = parse_assertion(&fields[16])?;
    let source = outer[1]
        .as_bytes()
        .ok_or(AuthenticationError::MalformedDocument)?;
    if length_exceeds(source.len(), MAX_SOURCE_BYTES) {
        return Err(AuthenticationError::SourceTooLarge);
    }
    let source_bytes = source.to_vec();
    let signature_bytes = outer[2]
        .as_bytes()
        .ok_or(AuthenticationError::MalformedDocument)?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| AuthenticationError::MalformedDocument)?;
    let bundle = Bundle {
        issuer,
        key_id,
        key_epoch,
        external_record,
        external_revision,
        audience,
        scope,
        sequence,
        predecessor,
        not_before_unix_seconds,
        expires_at_unix_seconds,
        source_bytes,
        assertion,
        signature,
    };
    if mneme_core::ContentDigest::of_source_bytes(&bundle.source_bytes) != source_digest {
        return Err(AuthenticationError::SourceDigestMismatch);
    }
    if mneme_core::ContentDigest::of_payload(&bundle.evidence_value(
        mneme_core::ContentDigest::of_source_bytes(&bundle.source_bytes),
    )) != evidence_digest
    {
        return Err(AuthenticationError::EvidenceDigestMismatch);
    }
    if mneme_core::ContentDigest::of_payload(&bundle.assertion.to_value()) != assertion_digest {
        return Err(AuthenticationError::AssertionDigestMismatch);
    }
    Ok(bundle)
}

fn parse_assertion(value: &mneme_core::Value) -> Result<ExternalAssertion, AuthenticationError> {
    let fields = parse_record(value, ASSERTION_LABEL, 7)?;
    let subject = read_text(&fields[0])?;
    let predicate = read_text(&fields[1])?;
    let stance = match read_symbol(&fields[3])? {
        "affirm" => crate::model::Stance::Affirm,
        "deny" => crate::model::Stance::Deny,
        "hypothesis" => crate::model::Stance::Hypothesis,
        _ => return Err(AuthenticationError::MalformedDocument),
    };
    let valid_time = mneme_core::ValidTime::from_value(&fields[4], &mneme_core::Path::root())
        .map_err(|_| AuthenticationError::MalformedDocument)?;
    let source_span = mneme_core::SourceSpan::from_value(&fields[5], &mneme_core::Path::root())
        .map_err(|_| AuthenticationError::MalformedDocument)?;
    let relation = match read_symbol(&fields[6])? {
        "supports" => crate::model::SupportRelation::Supports,
        "challenges" => crate::model::SupportRelation::Challenges,
        _ => return Err(AuthenticationError::MalformedDocument),
    };
    Ok(ExternalAssertion {
        subject,
        predicate,
        value: fields[2].clone(),
        stance,
        valid_time,
        source_span,
        relation,
    })
}

fn parse_record<'a>(
    value: &'a mneme_core::Value,
    label: &str,
    arity: usize,
) -> Result<&'a [mneme_core::Value], AuthenticationError> {
    let record = value
        .as_record()
        .ok_or(AuthenticationError::MalformedDocument)?;
    if record.label() != &mneme_core::Value::symbol(label) || record.fields().len() != arity {
        return Err(AuthenticationError::MalformedDocument);
    }
    Ok(record.fields())
}

fn read_text(value: &mneme_core::Value) -> Result<String, AuthenticationError> {
    let text = value
        .as_string()
        .ok_or(AuthenticationError::MalformedDocument)?;
    validate_wire_text(text)?;
    Ok(text.to_owned())
}

fn read_symbol(value: &mneme_core::Value) -> Result<&str, AuthenticationError> {
    value
        .as_symbol()
        .map(mneme_core::Symbol::as_str)
        .ok_or(AuthenticationError::MalformedDocument)
}

fn read_i64(value: &mneme_core::Value) -> Result<i64, AuthenticationError> {
    value
        .as_integer()
        .and_then(mneme_core::SignedInteger::to_i64)
        .ok_or(AuthenticationError::MalformedDocument)
}

fn read_u64(value: &mneme_core::Value) -> Result<u64, AuthenticationError> {
    let value = read_i64(value)?;
    u64::try_from(value).map_err(|_| AuthenticationError::MalformedDocument)
}

fn read_optional_text(value: &mneme_core::Value) -> Result<Option<String>, AuthenticationError> {
    if value
        .as_symbol()
        .is_some_and(|symbol| symbol.as_str() == "none")
    {
        return Ok(None);
    }
    read_text(value).map(Some)
}

fn read_digest(
    value: &mneme_core::Value,
) -> Result<mneme_core::ContentDigest, AuthenticationError> {
    mneme_core::ContentDigest::from_value(value, &mneme_core::Path::root())
        .map_err(|_| AuthenticationError::MalformedDocument)
}

#[cfg(test)]
mod tests {
    #![allow(
        unknown_lints,
        no_unwrap,
        no_expect,
        clippy::unwrap_used,
        clippy::expect_used
    )]

    use super::*;
    use ed25519_dalek::Signer;

    const AUDIENCE: &str = "workspace:cedar";
    const ISSUER: &str = "synthetic-issuer";
    const FOREIGN_SUBJECT: &str = "foreign-cedar";
    const SOURCE_BYTES: &[u8] = b"synthetic signed statement: the sky is orange\n";

    fn scope() -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
    }

    fn make_policy(
        signing_key: &ed25519_dalek::SigningKey,
        generation: u64,
        key_epoch: u64,
        key_state: KeyState,
    ) -> ImportPolicy {
        ImportPolicy::new(ImportPolicyConfig {
            issuer: ISSUER.to_owned(),
            key_epoch,
            public_key: signing_key.verifying_key().to_bytes(),
            key_state,
            generation,
            allowed_audiences: std::collections::BTreeSet::from([AUDIENCE.to_owned()]),
            allowed_scopes: std::collections::BTreeSet::from([scope()]),
            subject_mappings: std::collections::BTreeMap::from([(
                FOREIGN_SUBJECT.to_owned(),
                mneme_core::fixtures::entity_id(),
            )]),
        })
        .expect("host policy")
    }

    fn bundle(
        signing_key: &ed25519_dalek::SigningKey,
        key_id: &str,
        key_epoch: u64,
        source_bytes: Vec<u8>,
        value: mneme_core::Value,
    ) -> Bundle {
        let source_span =
            mneme_core::SourceSpan::new(0, u64::try_from(source_bytes.len()).expect("length") - 1)
                .expect("span");
        let mut bundle = Bundle {
            issuer: ISSUER.to_owned(),
            key_id: key_id.to_owned(),
            key_epoch,
            external_record: "foreign-record-17".to_owned(),
            external_revision: "foreign-revision-1".to_owned(),
            audience: AUDIENCE.to_owned(),
            scope: scope(),
            sequence: 1,
            predecessor: None,
            not_before_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            assertion: ExternalAssertion {
                subject: FOREIGN_SUBJECT.to_owned(),
                predicate: "weather-description".to_owned(),
                value,
                stance: crate::model::Stance::Affirm,
                valid_time: mneme_core::ValidTime::always(),
                source_span,
                relation: crate::model::SupportRelation::Supports,
            },
            source_bytes,
            signature: [0; 64],
        };
        bundle.signature = signing_key
            .sign(&bundle.canonical_signing_bytes().expect("canonical bytes"))
            .to_bytes();
        bundle
    }

    fn workspace() -> (tempfile::TempDir, mneme_store::Workspace) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let config = mneme_store::WorkspaceConfig::new(
            Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_000),
            )),
            Box::new(mneme_store::NoFaults),
        );
        let mut workspace =
            mneme_store::Workspace::create(temporary.path(), config).expect("create workspace");
        let entity = mneme_core::fixtures::entity();
        let mut memory =
            crate::service::Engine::new(&mut workspace, crate::authorization::Access::Operator);
        memory
            .commit(crate::service::Batch {
                actor: "synthetic-seed".to_owned(),
                scope: entity.scope.clone(),
                idempotency_key: "seed-entity".to_owned(),
                records: vec![mneme_store::RecordDraft {
                    schema_version: entity.schema_version,
                    kind: entity.kind,
                    record_id: entity.record_id,
                    revision_id: entity.revision_id,
                    predecessor: entity.predecessor,
                    scope: entity.scope,
                    payload: entity.payload,
                }],
                source_blobs: Vec::new(),
                publications: Vec::new(),
            })
            .expect("seed local entity");
        drop(memory);
        (temporary, workspace)
    }

    fn authenticate_and_plan(
        workspace: &mneme_store::Workspace,
        bundle: Bundle,
        policy: &ImportPolicy,
    ) -> Result<ImportPlan, AdmissionError> {
        let document = bundle.to_json_document().expect("bundle document");
        let authenticated = authenticate_json(document.as_bytes(), policy).expect("signature");
        plan_import(
            workspace,
            authenticated,
            policy,
            ImportRequest {
                audience: AUDIENCE,
                scope: &scope(),
                actor: "synthetic-importer",
                trusted_now_unix_seconds: 150,
            },
        )
    }

    fn commit(
        workspace: &mut mneme_store::Workspace,
        bundle: Bundle,
        policy: &ImportPolicy,
    ) -> Result<ImportCommitOutcome, ImportCommitError> {
        let plan = authenticate_and_plan(workspace, bundle, policy)?;
        commit_import(
            workspace,
            plan,
            policy,
            150,
            crate::authorization::Access::Operator,
        )
    }

    fn commit_forget(
        workspace: &mut mneme_store::Workspace,
        target: mneme_core::RecordId,
        target_kind: &str,
    ) {
        let operation = format!("forget-{target}");
        let generation = workspace
            .eligibility_generation()
            .expect("generation")
            .saturating_add(1);
        let scope = scope();
        workspace
            .commit(mneme_store::CommitCommand {
                base: workspace.current_revision().expect("base"),
                actor: "synthetic-retention".to_owned(),
                scope,
                idempotency_key: operation.clone(),
                records: Vec::new(),
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: Some(mneme_store::RetentionCommit {
                    operation_id: operation.clone(),
                    operation_kind: "forget".to_owned(),
                    policy_version: "synthetic-policy-v1".to_owned(),
                    selectors: Vec::new(),
                    suppressions: vec![mneme_store::RetentionSuppression {
                        operation_id: operation,
                        target,
                        revision: None,
                        target_kind: target_kind.to_owned(),
                        mode: mneme_store::SuppressionMode::Forgotten,
                        content_digest: None,
                        generation,
                    }],
                    locations: Vec::new(),
                    retained_metadata: Vec::new(),
                }),
            })
            .expect("retention barrier");
    }

    #[test]
    fn signed_false_claim_is_proposed_with_exact_source_and_replay_adds_no_support() {
        let (_temporary, mut workspace) = workspace();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x41; 32]);
        let policy = make_policy(&signing_key, 3, 7, KeyState::Active);
        let bundle = bundle(
            &signing_key,
            policy.key_id(),
            7,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("false claim: the sky is orange"),
        );
        let document = bundle.to_json_document().expect("bundle document");
        let authenticated = authenticate_json(document.as_bytes(), &policy).expect("signature");
        let plan = plan_import(
            &workspace,
            authenticated,
            &policy,
            ImportRequest {
                audience: AUDIENCE,
                scope: &scope(),
                actor: "synthetic-importer",
                trusted_now_unix_seconds: 150,
            },
        )
        .expect("admission");
        let mapping = plan.mapping();
        let replay_plan = authenticate_and_plan(&workspace, bundle.clone(), &policy)
            .expect("same signed revision has a repeatable mapping");
        assert_eq!(replay_plan.mapping(), mapping);
        drop(replay_plan);
        let first = commit_import(
            &mut workspace,
            plan,
            &policy,
            150,
            crate::authorization::Access::Operator,
        )
        .expect("first commit");
        assert!(matches!(first, ImportCommitOutcome::Committed(_)));

        let snapshot = workspace.snapshot().expect("snapshot");
        let assertion_record = snapshot
            .records
            .iter()
            .find(|record| record.record_id == mapping.assertion)
            .expect("proposed assertion");
        let assertion =
            crate::model::AssertionView::parse(assertion_record.clone()).expect("parsed assertion");
        assert_eq!(
            assertion.value,
            mneme_core::Value::string("false claim: the sky is orange")
        );
        assert_eq!(assertion.origin, mneme_core::Origin::Import);
        assert_eq!(assertion.lifecycle, mneme_core::Lifecycle::Proposed);
        assert_eq!(assertion.decision, None);
        assert_eq!(assertion.evidence.len(), 1);

        let evidence = snapshot
            .records
            .iter()
            .find(|record| record.record_id == mapping.evidence)
            .expect("evidence");
        let provenance = evidence
            .payload
            .get("import-authentication")
            .and_then(mneme_core::Value::as_record)
            .expect("retained authentication provenance");
        assert_eq!(
            provenance.label(),
            &mneme_core::Value::symbol("authenticated-import-provenance-v1")
        );
        assert_eq!(provenance.fields().len(), 15);
        let signed_digest = provenance.fields()[13]
            .as_record()
            .expect("canonical signed-message digest");
        assert_eq!(signed_digest.label(), &mneme_core::Value::symbol("digest"));
        assert_eq!(
            provenance.fields()[14].as_bytes().map(|bytes| bytes.len()),
            Some(64)
        );
        let provenance_value =
            mneme_core::Value::record(provenance.label().clone(), provenance.fields().to_vec());
        assert!(
            !mneme_core::encode(&provenance_value)
                .windows(SOURCE_BYTES.len())
                .any(|window| window == SOURCE_BYTES)
        );

        let source_record = snapshot
            .records
            .iter()
            .find(|record| record.record_id == mapping.source)
            .expect("source record");
        let source_digest = source_record
            .payload
            .get("content")
            .and_then(|value| {
                mneme_core::SourceContent::from_value(value, &mneme_core::Path::root()).ok()
            })
            .and_then(|content| match content {
                mneme_core::SourceContent::Retained(source) => Some(source.digest()),
                mneme_core::SourceContent::Unavailable { .. } => None,
            })
            .expect("retained exact source");
        let stored_source =
            mneme_store::payload::read(workspace.root(), source_digest).expect("source bytes");
        assert_eq!(stored_source.as_slice(), SOURCE_BYTES);

        let duplicate = commit(&mut workspace, bundle, &policy).expect("replay");
        assert!(matches!(duplicate, ImportCommitOutcome::AlreadyImported));
        let after_replay = workspace.snapshot().expect("snapshot after replay");
        assert_eq!(after_replay.records.len(), snapshot.records.len());
        assert_eq!(
            after_replay
                .records
                .iter()
                .filter(|record| record.kind == mneme_core::RecordKind::Evidence)
                .count(),
            1
        );
    }

    #[test]
    fn valid_resigning_under_a_rotated_host_key_does_not_add_support() {
        let (_temporary, mut workspace) = workspace();
        let first_key = ed25519_dalek::SigningKey::from_bytes(&[0x41; 32]);
        let first_policy = make_policy(&first_key, 3, 7, KeyState::Active);
        let first_bundle = bundle(
            &first_key,
            first_policy.key_id(),
            7,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("same claim"),
        );
        assert!(matches!(
            commit(&mut workspace, first_bundle.clone(), &first_policy).expect("first commit"),
            ImportCommitOutcome::Committed(_)
        ));

        let rotated_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let rotated_policy = make_policy(&rotated_key, 4, 8, KeyState::Active);
        let resigned = bundle(
            &rotated_key,
            rotated_policy.key_id(),
            8,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("same claim"),
        );
        let replay = commit(&mut workspace, resigned, &rotated_policy).expect("rotated replay");
        assert!(matches!(replay, ImportCommitOutcome::AlreadyImported));
        let records = workspace.snapshot().expect("snapshot").records;
        assert_eq!(
            records
                .iter()
                .filter(|record| record.kind == mneme_core::RecordKind::SourceRevision)
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record.kind == mneme_core::RecordKind::Evidence)
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record.kind == mneme_core::RecordKind::Assertion)
                .count(),
            1
        );
    }

    #[test]
    fn same_external_revision_with_changed_signed_validity_conflicts() {
        let (_temporary, mut workspace) = workspace();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x4a; 32]);
        let policy = make_policy(&signing_key, 1, 2, KeyState::Active);
        let original = bundle(
            &signing_key,
            policy.key_id(),
            2,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("same claim"),
        );
        commit(&mut workspace, original.clone(), &policy).expect("initial import");

        let mut changed_provenance = original;
        changed_provenance.not_before_unix_seconds = 90;
        changed_provenance.signature = signing_key
            .sign(
                &changed_provenance
                    .canonical_signing_bytes()
                    .expect("canonical bytes"),
            )
            .to_bytes();
        assert!(matches!(
            authenticate_and_plan(&workspace, changed_provenance, &policy),
            Err(AdmissionError::IdentityConflict)
        ));
    }

    #[test]
    fn same_foreign_revision_with_changed_assertion_or_source_is_refused() {
        let (_temporary, mut workspace) = workspace();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x43; 32]);
        let policy = make_policy(&signing_key, 1, 2, KeyState::Active);
        let original = bundle(
            &signing_key,
            policy.key_id(),
            2,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("first value"),
        );
        commit(&mut workspace, original.clone(), &policy).expect("initial import");

        let changed_claim = bundle(
            &signing_key,
            policy.key_id(),
            2,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("equivocated value"),
        );
        assert!(matches!(
            authenticate_and_plan(&workspace, changed_claim, &policy),
            Err(AdmissionError::IdentityConflict)
        ));

        let changed_source = bundle(
            &signing_key,
            policy.key_id(),
            2,
            b"changed exact source bytes\n".to_vec(),
            mneme_core::Value::string("first value"),
        );
        assert!(matches!(
            authenticate_and_plan(&workspace, changed_source, &policy),
            Err(AdmissionError::IdentityConflict)
        ));
    }

    #[test]
    fn tampered_source_assertion_audience_scope_and_external_identity_break_signature() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
        let policy = make_policy(&signing_key, 1, 2, KeyState::Active);
        let original = bundle(
            &signing_key,
            policy.key_id(),
            2,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("signed value"),
        );
        let tamper = [
            {
                let mut changed = original.clone();
                changed.source_bytes[0] ^= 1;
                changed
            },
            {
                let mut changed = original.clone();
                changed.assertion.value = mneme_core::Value::string("altered value");
                changed
            },
            {
                let mut changed = original.clone();
                changed.assertion.source_span =
                    mneme_core::SourceSpan::new(1, SOURCE_BYTES.len() as u64 - 1)
                        .expect("altered evidence span");
                changed
            },
            {
                let mut changed = original.clone();
                changed.assertion.relation = crate::model::SupportRelation::Challenges;
                changed
            },
            {
                let mut changed = original.clone();
                changed.audience = "workspace:other".to_owned();
                changed
            },
            {
                let mut changed = original.clone();
                changed.scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "birch")
                    .expect("other scope");
                changed
            },
            {
                let mut changed = original.clone();
                changed.external_revision = "foreign-revision-2".to_owned();
                changed
            },
            {
                let mut changed = original.clone();
                changed.issuer = "spoofed-issuer".to_owned();
                changed
            },
            {
                let mut changed = original.clone();
                changed.signature[0] ^= 1;
                changed
            },
        ];
        for changed in tamper {
            let document = changed.to_json_document().expect("tampered document");
            assert!(matches!(
                authenticate_json(document.as_bytes(), &policy),
                Err(AuthenticationError::InvalidSignature)
            ));
        }
    }

    #[test]
    fn spoofed_key_binding_and_malformed_inputs_fail_closed() {
        let trusted_key = ed25519_dalek::SigningKey::from_bytes(&[0x45; 32]);
        let trusted_policy = make_policy(&trusted_key, 1, 2, KeyState::Active);
        let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0xa5; 32]);
        let spoofed = bundle(
            &attacker_key,
            trusted_policy.key_id(),
            2,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("attacker claim"),
        );
        let spoofed_document = spoofed.to_json_document().expect("spoofed document");
        assert!(matches!(
            authenticate_json(spoofed_document.as_bytes(), &trusted_policy),
            Err(AuthenticationError::InvalidSignature)
        ));

        let valid = bundle(
            &trusted_key,
            trusted_policy.key_id(),
            2,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("valid claim"),
        );
        let document = valid.to_json_document().expect("valid document");
        let decoded = mneme_core::decode_document(&document).expect("valid bundle value");
        let outer = decoded.as_record().expect("outer record").fields();
        let signed_fields = outer[0].as_record().expect("signed record").fields();
        let mut embedded_key_fields = signed_fields.to_vec();
        embedded_key_fields.push(mneme_core::Value::bytes(
            attacker_key.verifying_key().to_bytes(),
        ));
        let with_embedded_key = mneme_core::Value::record_named(
            BUNDLE_LABEL,
            vec![
                mneme_core::Value::record_named(SIGNED_LABEL, embedded_key_fields),
                outer[1].clone(),
                outer[2].clone(),
            ],
        );
        let embedded_document = mneme_core::encode_document_string(&with_embedded_key);
        assert!(matches!(
            authenticate_json(embedded_document.as_bytes(), &trusted_policy),
            Err(AuthenticationError::MalformedDocument)
        ));
        assert!(matches!(
            authenticate_json(&document.as_bytes()[..document.len() - 2], &trusted_policy),
            Err(AuthenticationError::MalformedDocument)
        ));
        let oversized =
            vec![b' '; usize::try_from(MAX_BUNDLE_BYTES).expect("bundle byte limit") + 1];
        assert!(matches!(
            authenticate_json(&oversized, &trusted_policy),
            Err(AuthenticationError::InputTooLarge)
        ));
        let mut oversized_source = valid.clone();
        oversized_source.source_bytes =
            vec![b'x'; usize::try_from(MAX_SOURCE_BYTES).expect("source byte limit") + 1];
        oversized_source.assertion.source_span =
            mneme_core::SourceSpan::new(0, 0).expect("one-byte span");
        assert!(matches!(
            oversized_source.canonical_signing_bytes(),
            Err(AuthenticationError::SourceTooLarge)
        ));
    }

    #[test]
    fn valid_signature_does_not_bypass_current_key_scope_audience_or_time_policy() {
        let (_temporary, workspace) = workspace();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x46; 32]);
        let active_policy = make_policy(&signing_key, 8, 9, KeyState::Active);

        let wrong_epoch = bundle(
            &signing_key,
            active_policy.key_id(),
            10,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("claim"),
        );
        assert!(matches!(
            authenticate_and_plan(&workspace, wrong_epoch, &active_policy),
            Err(AdmissionError::KeyEpochMismatch)
        ));

        let wrong_audience = {
            let mut value = bundle(
                &signing_key,
                active_policy.key_id(),
                9,
                SOURCE_BYTES.to_vec(),
                mneme_core::Value::string("claim"),
            );
            value.audience = "workspace:other".to_owned();
            value.signature = signing_key
                .sign(&value.canonical_signing_bytes().expect("canonical bytes"))
                .to_bytes();
            value
        };
        assert!(matches!(
            authenticate_and_plan(&workspace, wrong_audience, &active_policy),
            Err(AdmissionError::AudienceMismatch)
        ));

        let wrong_scope = {
            let mut value = bundle(
                &signing_key,
                active_policy.key_id(),
                9,
                SOURCE_BYTES.to_vec(),
                mneme_core::Value::string("claim"),
            );
            value.scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "birch")
                .expect("other scope");
            value.signature = signing_key
                .sign(&value.canonical_signing_bytes().expect("canonical bytes"))
                .to_bytes();
            value
        };
        assert!(matches!(
            authenticate_and_plan(&workspace, wrong_scope, &active_policy),
            Err(AdmissionError::ScopeMismatch)
        ));

        let unsupported_chain = {
            let mut value = bundle(
                &signing_key,
                active_policy.key_id(),
                9,
                SOURCE_BYTES.to_vec(),
                mneme_core::Value::string("claim"),
            );
            value.sequence = 2;
            value.predecessor = Some("foreign-revision-0".to_owned());
            value.signature = signing_key
                .sign(&value.canonical_signing_bytes().expect("canonical bytes"))
                .to_bytes();
            value
        };
        assert!(matches!(
            authenticate_and_plan(&workspace, unsupported_chain, &active_policy),
            Err(AdmissionError::UnsupportedRevisionChain)
        ));

        let revoked_policy = make_policy(&signing_key, 8, 9, KeyState::Revoked);
        let revoked_bundle = bundle(
            &signing_key,
            revoked_policy.key_id(),
            9,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("claim"),
        );
        assert!(matches!(
            authenticate_and_plan(&workspace, revoked_bundle, &revoked_policy),
            Err(AdmissionError::Revoked)
        ));

        let unmapped_config = ImportPolicyConfig {
            issuer: ISSUER.to_owned(),
            key_epoch: 9,
            public_key: signing_key.verifying_key().to_bytes(),
            key_state: KeyState::Active,
            generation: 8,
            allowed_audiences: std::collections::BTreeSet::from([AUDIENCE.to_owned()]),
            allowed_scopes: std::collections::BTreeSet::from([scope()]),
            subject_mappings: std::collections::BTreeMap::new(),
        };
        let unmapped_policy = ImportPolicy::new(unmapped_config).expect("unmapped policy");
        let unmapped_bundle = bundle(
            &signing_key,
            unmapped_policy.key_id(),
            9,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("claim"),
        );
        assert!(matches!(
            authenticate_and_plan(&workspace, unmapped_bundle, &unmapped_policy),
            Err(AdmissionError::SubjectUnmapped)
        ));

        let document_bundle = bundle(
            &signing_key,
            active_policy.key_id(),
            9,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("claim"),
        );
        let document = document_bundle.to_json_document().expect("bundle document");
        let authenticated = authenticate_json(document.as_bytes(), &active_policy)
            .expect("cryptographic authentication remains distinct");
        let next_generation_policy = make_policy(&signing_key, 9, 9, KeyState::Active);
        assert!(matches!(
            plan_import(
                &workspace,
                authenticated,
                &next_generation_policy,
                ImportRequest {
                    audience: AUDIENCE,
                    scope: &scope(),
                    actor: "synthetic-importer",
                    trusted_now_unix_seconds: 150,
                }
            ),
            Err(AdmissionError::StalePolicy)
        ));

        let authenticated =
            authenticate_json(document.as_bytes(), &active_policy).expect("signature");
        assert!(matches!(
            plan_import(
                &workspace,
                authenticated,
                &active_policy,
                ImportRequest {
                    audience: AUDIENCE,
                    scope: &scope(),
                    actor: "synthetic-importer",
                    trusted_now_unix_seconds: 200,
                }
            ),
            Err(AdmissionError::Expired)
        ));

        let authenticated =
            authenticate_json(document.as_bytes(), &active_policy).expect("signature");
        assert!(matches!(
            plan_import(
                &workspace,
                authenticated,
                &active_policy,
                ImportRequest {
                    audience: AUDIENCE,
                    scope: &scope(),
                    actor: "synthetic-importer",
                    trusted_now_unix_seconds: 99,
                }
            ),
            Err(AdmissionError::NotYetValid)
        ));
    }

    #[test]
    fn commit_rechecks_policy_base_and_explicit_caller_authority() {
        let (_temporary, mut workspace) = workspace();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x48; 32]);
        let policy = make_policy(&signing_key, 1, 2, KeyState::Active);
        let signed = bundle(
            &signing_key,
            policy.key_id(),
            2,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("claim"),
        );

        let policy_plan =
            authenticate_and_plan(&workspace, signed.clone(), &policy).expect("policy-bound plan");
        let next_policy = make_policy(&signing_key, 2, 2, KeyState::Active);
        assert!(matches!(
            commit_import(
                &mut workspace,
                policy_plan,
                &next_policy,
                150,
                crate::authorization::Access::Operator,
            ),
            Err(ImportCommitError::Admission(AdmissionError::StalePolicy))
        ));

        let expired_plan =
            authenticate_and_plan(&workspace, signed.clone(), &policy).expect("fresh plan");
        assert!(matches!(
            commit_import(
                &mut workspace,
                expired_plan,
                &policy,
                200,
                crate::authorization::Access::Operator,
            ),
            Err(ImportCommitError::Admission(AdmissionError::Expired))
        ));

        let authority_plan =
            authenticate_and_plan(&workspace, signed.clone(), &policy).expect("authorized plan");
        assert!(matches!(
            commit_import(
                &mut workspace,
                authority_plan,
                &policy,
                150,
                crate::authorization::Access::Scopes(std::collections::BTreeSet::new()),
            ),
            Err(ImportCommitError::UnauthorizedScope)
        ));

        let stale_plan =
            authenticate_and_plan(&workspace, signed, &policy).expect("base-bound plan");
        let unrelated = crate::service::build_episode(
            mneme_core::RecordId::from_bytes([0xb1; 16]),
            mneme_core::RevisionId::from_bytes([0xb2; 16]),
            &scope(),
            crate::service::EpisodeOptions {
                actor: "concurrent-writer",
                episode_type: "statement",
                occurred: mneme_core::ValidTime::always(),
                summary: "unrelated committed operation",
                source: None,
                related: &[],
            },
        );
        let mut memory =
            crate::service::Engine::new(&mut workspace, crate::authorization::Access::Operator);
        memory
            .commit(crate::service::Batch {
                actor: "concurrent-writer".to_owned(),
                scope: scope(),
                idempotency_key: "unrelated-commit".to_owned(),
                records: vec![unrelated],
                source_blobs: Vec::new(),
                publications: Vec::new(),
            })
            .expect("advance workspace base");
        drop(memory);
        assert!(matches!(
            commit_import(
                &mut workspace,
                stale_plan,
                &policy,
                150,
                crate::authorization::Access::Operator,
            ),
            Err(ImportCommitError::StaleBase)
        ));
    }

    #[test]
    fn stale_policy_cannot_be_hidden_by_exact_import_replay() {
        let (_temporary, mut workspace) = workspace();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x49; 32]);
        let policy = make_policy(&signing_key, 1, 2, KeyState::Active);
        let signed = bundle(
            &signing_key,
            policy.key_id(),
            2,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("claim"),
        );
        assert!(matches!(
            commit(&mut workspace, signed.clone(), &policy).expect("initial import"),
            ImportCommitOutcome::Committed(_)
        ));
        let replay_plan =
            authenticate_and_plan(&workspace, signed, &policy).expect("exact replay plan");
        let next_policy = make_policy(&signing_key, 2, 2, KeyState::Active);
        assert!(matches!(
            commit_import(
                &mut workspace,
                replay_plan,
                &next_policy,
                150,
                crate::authorization::Access::Operator,
            ),
            Err(ImportCommitError::Admission(AdmissionError::StalePolicy))
        ));
    }

    #[test]
    fn stale_precommit_plan_cannot_replay_import_after_forget_barrier() {
        let (_temporary, mut workspace) = workspace();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x47; 32]);
        let policy = make_policy(&signing_key, 1, 2, KeyState::Active);
        let bundle = bundle(
            &signing_key,
            policy.key_id(),
            2,
            SOURCE_BYTES.to_vec(),
            mneme_core::Value::string("claim"),
        );
        let first =
            authenticate_and_plan(&workspace, bundle.clone(), &policy).expect("initial plan");
        let mapping = first.mapping();
        commit_import(
            &mut workspace,
            first,
            &policy,
            150,
            crate::authorization::Access::Operator,
        )
        .expect("initial commit");
        let stale_replay =
            authenticate_and_plan(&workspace, bundle, &policy).expect("same revision retry plan");
        commit_forget(&mut workspace, mapping.assertion, "assertion");

        assert!(matches!(
            commit_import(
                &mut workspace,
                stale_replay,
                &policy,
                150,
                crate::authorization::Access::Operator,
            ),
            Err(ImportCommitError::EligibilityGenerationChanged)
        ));
        let snapshot = workspace.snapshot().expect("post-forget snapshot");
        assert!(
            snapshot
                .records
                .iter()
                .all(|record| record.record_id != mapping.assertion)
        );
    }
}
