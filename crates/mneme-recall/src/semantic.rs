//! Exact, bounded semantic embedding over the already-authorized recall index.
//!
//! This module accepts only an operator-configured worker. It sends source text
//! only as JSON on the shared supervisor's stdin, validates every returned row
//! against its exact input position, and retains document vectors only in the
//! in-memory `CachedIndex` that already carries revision/scope/generation keys.

/// Version for exact semantic vectors and cosine ranking.
pub const SEMANTIC_INDEX_VERSION: &str = "mneme-semantic-exact-cosine-v1";

const MAX_SEMANTIC_CHUNKS: usize = 512;
const MAX_SEMANTIC_BATCH_ITEMS: usize = 16;
const MAX_SEMANTIC_QUERY_BYTES: usize = 4096;
const MAX_SEMANTIC_DIMENSIONS: usize = 4096;
const MAX_SEMANTIC_RAW_FLOAT_VALUES: usize = MAX_SEMANTIC_CHUNKS * MAX_SEMANTIC_DIMENSIONS;
const INPUT_TEMPLATE: &str = "mneme-openai-embeddings-input-v1:model,input[],encoding_format=float";
const OUTPUT_SCHEMA: &str = "mneme-openai-embeddings-output-v1:model,data[index,embedding][]";
const _: () = assert!(usize::BITS <= u64::BITS);

/// Supported embedding pooling operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbeddingPooling {
    Mean,
}

impl EmbeddingPooling {
    const fn name(self) -> &'static str {
        match self {
            EmbeddingPooling::Mean => "mean",
        }
    }
}

/// Supported vector normalization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbeddingNormalization {
    L2,
}

impl EmbeddingNormalization {
    const fn name(self) -> &'static str {
        match self {
            EmbeddingNormalization::L2 => "l2",
        }
    }
}

/// Supported semantic similarity metric.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimilarityMetric {
    Cosine,
}

impl SimilarityMetric {
    const fn name(self) -> &'static str {
        match self {
            SimilarityMetric::Cosine => "cosine",
        }
    }
}

/// How multiple chunk similarities become one document score.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentAggregation {
    MaximumChunkCosine,
}

impl DocumentAggregation {
    const fn name(self) -> &'static str {
        match self {
            DocumentAggregation::MaximumChunkCosine => "maximum-chunk-cosine",
        }
    }
}

/// Versioned text preparation and exact-search bounds for an embedding model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddingSettings {
    /// Identity of the Mneme-side embedding adapter behavior.
    pub version: String,
    /// Prefix applied to every query before tokenization.
    pub query_prefix: String,
    /// Prefix applied to every document chunk before tokenization.
    pub document_prefix: String,
    /// Identity of UTF-8-safe, ordered, non-overlapping chunk generation.
    pub chunking_version: String,
    /// Maximum UTF-8 bytes in one source chunk; no chunk is truncated.
    pub chunk_bytes: usize,
    /// Maximum query bytes accepted by this embedding profile.
    pub max_query_bytes: usize,
    /// Maximum exact corpus chunks; larger corpora are unavailable, not sampled.
    pub max_chunks: usize,
    /// Maximum total embedding scalar values retained/parsed for the corpus.
    pub max_raw_float_values: usize,
    /// Maximum input rows sent in one supervised worker call.
    pub max_batch_items: usize,
    pub pooling: EmbeddingPooling,
    pub dimensions: usize,
    pub normalization: EmbeddingNormalization,
    pub metric: SimilarityMetric,
    pub document_aggregation: DocumentAggregation,
}

impl EmbeddingSettings {
    /// Settings selected for the pinned Nomic Embed Text v1.5 GGUF.
    pub fn nomic_embed_text_v1_5() -> Self {
        EmbeddingSettings {
            version: "mneme-nomic-embed-text-v1.5-profile-v1".to_owned(),
            query_prefix: "search_query: ".to_owned(),
            document_prefix: "search_document: ".to_owned(),
            chunking_version: "mneme-utf8-byte-chunks-no-overlap-v1".to_owned(),
            chunk_bytes: 1024,
            max_query_bytes: 1024,
            max_chunks: MAX_SEMANTIC_CHUNKS,
            max_raw_float_values: MAX_SEMANTIC_CHUNKS * 768,
            max_batch_items: MAX_SEMANTIC_BATCH_ITEMS,
            pooling: EmbeddingPooling::Mean,
            dimensions: 768,
            normalization: EmbeddingNormalization::L2,
            metric: SimilarityMetric::Cosine,
            document_aggregation: DocumentAggregation::MaximumChunkCosine,
        }
    }

    /// Digest of every preprocessing and vector-space setting.
    pub fn settings_digest(&self) -> String {
        let mut digest = sha2::Sha256::new();
        use sha2::Digest as _;
        digest.update(b"mneme-recall.embedding-settings.v1\0");
        for field in [
            self.version.as_bytes(),
            self.query_prefix.as_bytes(),
            self.document_prefix.as_bytes(),
            self.chunking_version.as_bytes(),
            self.pooling.name().as_bytes(),
            self.normalization.name().as_bytes(),
            self.metric.name().as_bytes(),
            self.document_aggregation.name().as_bytes(),
        ] {
            hash_field(&mut digest, field);
        }
        for value in [
            self.chunk_bytes,
            self.max_query_bytes,
            self.max_chunks,
            self.max_raw_float_values,
            self.max_batch_items,
            self.dimensions,
        ] {
            digest.update(length_bytes(value));
        }
        format_sha256(&digest.finalize())
    }

    /// Digest of the exact endpoint request serialization contract.
    pub fn input_template_digest(&self) -> String {
        digest_label_and_fields(
            b"mneme-recall.embedding-input-template.v1\0",
            &[INPUT_TEMPLATE.as_bytes()],
        )
    }

    /// Digest of the response contract accepted by this adapter.
    pub fn output_schema_digest(&self) -> String {
        digest_label_and_fields(
            b"mneme-recall.embedding-output-schema.v1\0",
            &[OUTPUT_SCHEMA.as_bytes()],
        )
    }

    fn validate(&self) -> Result<(), String> {
        if self.version.trim().is_empty() || self.chunking_version.trim().is_empty() {
            return Err("semantic adapter and chunking versions are required".to_owned());
        }
        if self.query_prefix.is_empty() || self.document_prefix.is_empty() {
            return Err("semantic query and document prefixes are required".to_owned());
        }
        if !(4..=4096).contains(&self.chunk_bytes)
            || self.max_query_bytes == 0
            || self.max_query_bytes > MAX_SEMANTIC_QUERY_BYTES
            || self.max_chunks == 0
            || self.max_chunks > MAX_SEMANTIC_CHUNKS
            || self.max_raw_float_values < self.dimensions
            || self.max_raw_float_values > MAX_SEMANTIC_RAW_FLOAT_VALUES
            || self.max_batch_items == 0
            || self.max_batch_items > MAX_SEMANTIC_BATCH_ITEMS
            || self.dimensions == 0
            || self.dimensions > MAX_SEMANTIC_DIMENSIONS
        {
            return Err("semantic settings exceed the adapter's finite bounds".to_owned());
        }
        Ok(())
    }
}

/// Operator-selected model worker and the complete embedding profile it serves.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(unknown_lints, path_segment_repetition)] // canonical exported request type
pub struct SemanticRequest {
    pub invocation: crate::inference::InvocationConfig,
    pub limits: crate::inference::InvocationLimits,
    pub settings: EmbeddingSettings,
}

/// Operator-pinned model/runtime identity without adapter-derived schema digests.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(unknown_lints, path_segment_repetition)] // canonical exported model identity
pub struct SemanticModelIdentity {
    pub adapter_id: String,
    pub adapter_version: String,
    pub model_id: String,
    pub model_revision: String,
    pub artifact_digest: String,
    pub tokenizer_id: String,
    pub tokenizer_digest: String,
}

impl SemanticRequest {
    /// Bind the embedding profile's request/response schema and settings digests
    /// into the generic worker descriptor before it can be invoked.
    pub fn new(
        mut invocation: crate::inference::InvocationConfig,
        limits: crate::inference::InvocationLimits,
        settings: EmbeddingSettings,
    ) -> Self {
        invocation.descriptor.prompt_template_digest = settings.input_template_digest();
        invocation.descriptor.output_schema_digest = settings.output_schema_digest();
        invocation.descriptor.settings_digest = settings.settings_digest();
        SemanticRequest {
            invocation,
            limits,
            settings,
        }
    }

    /// Construct a fully bound request from the host's pinned runtime/model
    /// identity, worker command, and finite limits.
    pub fn from_model(
        identity: SemanticModelIdentity,
        worker: crate::inference::WorkerCommand,
        limits: crate::inference::InvocationLimits,
        settings: EmbeddingSettings,
    ) -> Self {
        let invocation = crate::inference::InvocationConfig {
            descriptor: crate::inference::ModelDescriptor {
                adapter_id: identity.adapter_id,
                adapter_version: identity.adapter_version,
                model_id: identity.model_id,
                model_revision: identity.model_revision,
                artifact_digest: identity.artifact_digest,
                tokenizer_id: identity.tokenizer_id,
                tokenizer_digest: identity.tokenizer_digest,
                prompt_template_digest: String::new(),
                output_schema_digest: String::new(),
                settings_digest: String::new(),
            },
            worker,
        };
        SemanticRequest::new(invocation, limits, settings)
    }

    /// Full configuration identity used by the semantic cache and receipts.
    pub fn configuration_digest(&self) -> String {
        let mut digest = sha2::Sha256::new();
        use sha2::Digest as _;
        digest.update(b"mneme-recall.semantic-configuration.v1\0");
        hash_field(
            &mut digest,
            self.invocation.invocation_digest(self.limits).as_bytes(),
        );
        hash_field(&mut digest, self.settings.settings_digest().as_bytes());
        format_sha256(&digest.finalize())
    }

    /// Reject a configuration whose model identity no longer binds its settings.
    pub fn validate(&self) -> Result<(), String> {
        self.settings.validate()?;
        crate::inference::validate_invocation(&self.invocation, self.limits)?;
        if self.invocation.descriptor.prompt_template_digest
            != self.settings.input_template_digest()
            || self.invocation.descriptor.output_schema_digest
                != self.settings.output_schema_digest()
            || self.invocation.descriptor.settings_digest != self.settings.settings_digest()
        {
            return Err(
                "model descriptor does not bind the semantic input/output/settings profile"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// Cached document vector and its exact candidate/chunk source binding.
#[derive(Clone, Debug)]
pub(crate) struct Chunk {
    pub candidate_id: String,
    pub source_binding: String,
    pub chunk_ordinal: usize,
    pub byte_start: usize,
    pub byte_end: usize,
    pub vector: Vec<f64>,
}

/// One model-bound semantic index stored only inside `CachedIndex` memory.
#[derive(Clone, Debug)]
pub(crate) struct Index {
    pub context_digest: String,
    pub configuration_digest: String,
    pub chunks: Vec<Chunk>,
    pub coverage: crate::model::IndexCoverage,
}

/// Result of one semantic-mode attempt, including explicit failure and receipts.
pub(crate) struct ModeRun {
    pub status: crate::model::ModeStatus,
    pub index_version: Option<String>,
    pub coverage: crate::model::IndexCoverage,
    pub ranking: Vec<(String, f64)>,
    pub observation: Option<crate::model::SemanticObservation>,
    pub reason: Option<String>,
    pub execution: Option<crate::model::Execution>,
}

struct PendingChunk<'a> {
    candidate_id: String,
    source_binding: String,
    chunk_ordinal: usize,
    byte_start: usize,
    byte_end: usize,
    text: &'a str,
    vector: Option<Vec<f64>>,
}

fn assign_vectors(chunks: &mut [PendingChunk<'_>], vectors: Vec<Vec<f64>>) -> Result<(), String> {
    if chunks.len() != vectors.len() {
        return Err("embedding output count changed after validation".to_owned());
    }
    for (chunk, vector) in chunks.iter_mut().zip(vectors) {
        chunk.vector = Some(vector);
    }
    Ok(())
}

#[derive(Default)]
struct InvocationAccumulator {
    count: u64,
    input_digests: Vec<String>,
    elapsed_micros: u64,
    usage: UsageAccumulator,
}

#[derive(Default)]
enum UsageAccumulator {
    #[default]
    Empty,
    Unavailable,
    Measured(crate::inference::TokenUsage),
}

impl InvocationAccumulator {
    fn observe(&mut self, outcome: &crate::inference::InvocationOutcome) {
        self.count = self.count.saturating_add(1);
        self.input_digests.push(outcome.input_digest.clone());
        let elapsed = elapsed_micros_telemetry(outcome.elapsed);
        self.elapsed_micros = self.elapsed_micros.saturating_add(elapsed);
        self.usage.observe(&outcome.usage);
    }

    fn snapshot(&self) -> Option<crate::model::InvocationObservation> {
        (self.count > 0).then(|| crate::model::InvocationObservation {
            invocation_count: self.count,
            input_digests: self.input_digests.clone(),
            elapsed_micros: self.elapsed_micros,
            usage: self.usage.telemetry(),
        })
    }
}

#[allow(unknown_lints, unchecked_narrowing)] // guarded conversion; telemetry cannot represent values above u64 microseconds
fn elapsed_micros_telemetry(elapsed: std::time::Duration) -> u64 {
    let micros = elapsed.as_micros();
    if micros > u128::from(u64::MAX) {
        u64::MAX
    } else {
        micros as u64
    }
}

impl UsageAccumulator {
    fn observe(&mut self, telemetry: &crate::inference::UsageTelemetry) {
        let next = match telemetry {
            crate::inference::UsageTelemetry::Unavailable => UsageAccumulator::Unavailable,
            crate::inference::UsageTelemetry::Measured(usage) => {
                match std::mem::replace(self, UsageAccumulator::Empty) {
                    UsageAccumulator::Empty => UsageAccumulator::Measured(usage.clone()),
                    UsageAccumulator::Unavailable => UsageAccumulator::Unavailable,
                    UsageAccumulator::Measured(prior) => {
                        UsageAccumulator::Measured(add_usage(prior, usage))
                    }
                }
            }
        };
        *self = next;
    }

    fn telemetry(&self) -> crate::inference::UsageTelemetry {
        match self {
            UsageAccumulator::Measured(usage) => {
                crate::inference::UsageTelemetry::Measured(usage.clone())
            }
            UsageAccumulator::Empty | UsageAccumulator::Unavailable => {
                crate::inference::UsageTelemetry::Unavailable
            }
        }
    }
}

fn add_usage(
    prior: crate::inference::TokenUsage,
    next: &crate::inference::TokenUsage,
) -> crate::inference::TokenUsage {
    fn sum(left: Option<u64>, right: Option<u64>) -> Option<u64> {
        left.zip(right)
            .and_then(|(left, right)| left.checked_add(right))
    }
    crate::inference::TokenUsage {
        prompt_tokens: sum(prior.prompt_tokens, next.prompt_tokens),
        completion_tokens: sum(prior.completion_tokens, next.completion_tokens),
        total_tokens: sum(prior.total_tokens, next.total_tokens),
    }
}

/// Build/reuse the document index, embed this query, and rank exact cosine matches.
pub(crate) struct RankContext<'a, F> {
    pub(crate) index: &'a mut crate::model::CachedIndex,
    pub(crate) request: &'a crate::model::Request,
    pub(crate) semantic: &'a SemanticRequest,
    pub(crate) generation: u64,
    pub(crate) budget: &'a mut crate::engine::WorkBudget,
    pub(crate) require_current_generation: F,
}

pub(crate) fn rank<F>(context: RankContext<'_, F>) -> Result<ModeRun, crate::engine::AttemptFailure>
where
    F: FnMut() -> Result<(), crate::engine::AttemptFailure>,
{
    let RankContext {
        index,
        request,
        semantic,
        generation,
        budget,
        mut require_current_generation,
    } = context;
    let configuration_digest = semantic.configuration_digest();
    let index_version = format!("{SEMANTIC_INDEX_VERSION}:{configuration_digest}");
    if let Some(failure) = preflight(index, request, semantic, &index_version) {
        return Ok(failure);
    }
    let context_digest = context_digest(request, generation);
    let identity = IndexIdentity {
        context: &context_digest,
        configuration: &configuration_digest,
        version: &index_version,
    };
    let reused = reuse_index(
        index,
        IndexReuseContext {
            request,
            semantic,
            identity,
            budget: &mut *budget,
            require_current_generation: &mut require_current_generation,
        },
    )?;
    if let Some(failure) = reused.failure {
        return Ok(failure);
    }
    let is_cache_hit = reused.is_cache_hit;
    let document_accumulator = reused.document_accumulator;
    let Some(semantic_index) = index.semantic.as_ref() else {
        return Ok(missing_index_run(
            index,
            semantic,
            &index_version,
            is_cache_hit,
            document_accumulator.snapshot(),
        ));
    };
    rank_cached_index(
        semantic_index,
        CachedRankContext {
            request,
            semantic,
            index_version: &index_version,
            observed: observation(
                semantic,
                is_cache_hit,
                document_accumulator.snapshot(),
                None,
            ),
            budget,
            require_current_generation: &mut require_current_generation,
        },
    )
}

fn missing_index_run(
    index: &crate::model::CachedIndex,
    semantic: &SemanticRequest,
    index_version: &str,
    is_cache_hit: bool,
    document_build: Option<crate::model::InvocationObservation>,
) -> ModeRun {
    let reason = "semantic cache was not built".to_owned();
    failed_run(
        crate::model::ModeStatus::Failed,
        reason.clone(),
        FailureDetails {
            index_version: Some(index_version.to_owned()),
            coverage: crate::model::IndexCoverage::incomplete(0, index.documents.len(), reason),
            observation: Some(observation(semantic, is_cache_hit, document_build, None)),
            execution: Some(crate::model::Execution::Failed),
        },
    )
}

struct IndexReuseContext<'a, F> {
    request: &'a crate::model::Request,
    semantic: &'a SemanticRequest,
    identity: IndexIdentity<'a>,
    budget: &'a mut crate::engine::WorkBudget,
    require_current_generation: &'a mut F,
}

struct IndexReuse {
    is_cache_hit: bool,
    document_accumulator: InvocationAccumulator,
    failure: Option<ModeRun>,
}

fn reuse_index<F>(
    index: &mut crate::model::CachedIndex,
    context: IndexReuseContext<'_, F>,
) -> Result<IndexReuse, crate::engine::AttemptFailure>
where
    F: FnMut() -> Result<(), crate::engine::AttemptFailure>,
{
    let IndexReuseContext {
        request,
        semantic,
        identity,
        budget,
        require_current_generation,
    } = context;
    let is_cache_hit = index.semantic.as_ref().is_some_and(|cached| {
        cached.configuration_digest == identity.configuration
            && cached.context_digest == identity.context
            && cache_is_source_bound(cached, index, identity.context, &semantic.settings)
    });
    let mut document_accumulator = InvocationAccumulator::default();
    if !is_cache_hit {
        let build = build_index(
            index,
            IndexBuildContext {
                request,
                semantic,
                identity,
                budget: &mut *budget,
                accumulator: &mut document_accumulator,
                require_current_generation: &mut *require_current_generation,
            },
        )?;
        match build {
            BuildOutcome::Ready(built) => {
                require_current_generation()?;
                index.semantic = Some(built);
            }
            BuildOutcome::Failed(failure) => {
                return Ok(IndexReuse {
                    is_cache_hit,
                    document_accumulator,
                    failure: Some(failure),
                });
            }
        }
    }
    Ok(IndexReuse {
        is_cache_hit,
        document_accumulator,
        failure: None,
    })
}

fn preflight(
    index: &crate::model::CachedIndex,
    request: &crate::model::Request,
    semantic: &SemanticRequest,
    index_version: &str,
) -> Option<ModeRun> {
    if let Err(reason) = semantic.validate() {
        return Some(unavailable_before_invocation(
            index,
            index_version.to_owned(),
            reason,
        ));
    }
    if request.query.trim().is_empty() {
        return Some(unavailable_before_invocation(
            index,
            index_version.to_owned(),
            "semantic query is empty".to_owned(),
        ));
    }
    if request.query.len() > semantic.settings.max_query_bytes {
        let reason = format!(
            "query exceeds semantic profile's {}-byte bound",
            semantic.settings.max_query_bytes
        );
        return Some(unavailable_before_invocation(
            index,
            index_version.to_owned(),
            reason,
        ));
    }
    None
}

fn unavailable_before_invocation(
    index: &crate::model::CachedIndex,
    index_version: String,
    reason: String,
) -> ModeRun {
    failed_run(
        crate::model::ModeStatus::Unavailable,
        reason.clone(),
        FailureDetails {
            index_version: Some(index_version),
            coverage: crate::model::IndexCoverage::incomplete(0, index.documents.len(), reason),
            observation: None,
            execution: Some(crate::model::Execution::Partial),
        },
    )
}

// Transient stack result: boxing a failed observation would allocate on every refusal.
#[allow(clippy::large_enum_variant)]
enum BuildOutcome {
    Ready(Index),
    Failed(ModeRun),
}

#[derive(Clone, Copy)]
struct IndexIdentity<'a> {
    context: &'a str,
    configuration: &'a str,
    version: &'a str,
}

struct IndexBuildContext<'a, F> {
    request: &'a crate::model::Request,
    semantic: &'a SemanticRequest,
    identity: IndexIdentity<'a>,
    budget: &'a mut crate::engine::WorkBudget,
    accumulator: &'a mut InvocationAccumulator,
    require_current_generation: &'a mut F,
}

struct IndexFailureDetails {
    status: crate::model::ModeStatus,
    reason: String,
    observation: Option<crate::model::SemanticObservation>,
    execution: crate::model::Execution,
}

struct IndexEmbeddingContext<'a, F> {
    semantic: &'a SemanticRequest,
    request: &'a crate::model::Request,
    budget: &'a mut crate::engine::WorkBudget,
    accumulator: &'a mut InvocationAccumulator,
    require_current_generation: &'a mut F,
}

fn failed_index_build(
    index: &crate::model::CachedIndex,
    index_version: &str,
    failure: IndexFailureDetails,
) -> BuildOutcome {
    let coverage =
        crate::model::IndexCoverage::incomplete(0, index.documents.len(), failure.reason.clone());
    BuildOutcome::Failed(failed_run(
        failure.status,
        failure.reason,
        FailureDetails {
            index_version: Some(index_version.to_owned()),
            coverage,
            observation: failure.observation,
            execution: Some(failure.execution),
        },
    ))
}

fn build_index<F>(
    index: &crate::model::CachedIndex,
    context: IndexBuildContext<'_, F>,
) -> Result<BuildOutcome, crate::engine::AttemptFailure>
where
    F: FnMut() -> Result<(), crate::engine::AttemptFailure>,
{
    let IndexBuildContext {
        request,
        semantic,
        identity,
        budget,
        accumulator,
        require_current_generation,
    } = context;
    let (mut chunks, coverage) =
        match prepare_chunks(index, identity.context, &semantic.settings, budget) {
            Ok(prepared) => prepared,
            Err(PrepareFailure::Stop(stop)) => {
                return Err(crate::engine::AttemptFailure::Stop(stop));
            }
            Err(PrepareFailure::Unavailable(reason)) => {
                return Ok(failed_index_build(
                    index,
                    identity.version,
                    IndexFailureDetails {
                        status: crate::model::ModeStatus::Unavailable,
                        reason,
                        observation: None,
                        execution: crate::model::Execution::Partial,
                    },
                ));
            }
        };
    if !chunks.is_empty()
        && let Some(failure) = embed_index_chunks(
            &mut chunks,
            IndexEmbeddingContext {
                semantic,
                request,
                budget: &mut *budget,
                accumulator: &mut *accumulator,
                require_current_generation: &mut *require_current_generation,
            },
        )?
    {
        return Ok(failed_index_build(index, identity.version, failure));
    }
    let semantic_index = finish_index_build(
        chunks,
        coverage,
        identity,
        budget,
        require_current_generation,
    )?;
    Ok(BuildOutcome::Ready(semantic_index))
}

fn embed_index_chunks<F>(
    chunks: &mut [PendingChunk<'_>],
    context: IndexEmbeddingContext<'_, F>,
) -> Result<Option<IndexFailureDetails>, crate::engine::AttemptFailure>
where
    F: FnMut() -> Result<(), crate::engine::AttemptFailure>,
{
    let IndexEmbeddingContext {
        semantic,
        request,
        budget,
        accumulator,
        require_current_generation,
    } = context;
    let vectors = match embed_documents(
        chunks,
        EmbeddingContext {
            semantic,
            request,
            budget: &mut *budget,
            accumulator: &mut *accumulator,
            require_current_generation: &mut *require_current_generation,
        },
    ) {
        Ok(vectors) => vectors,
        Err(EmbeddingFailure::Attempt(error)) => return Err(error),
        Err(failure) => {
            let (status, reason, execution) = failure.status();
            return Ok(Some(IndexFailureDetails {
                status,
                reason,
                observation: Some(observation(semantic, false, accumulator.snapshot(), None)),
                execution,
            }));
        }
    };
    if let Err(reason) = assign_vectors(chunks, vectors) {
        return Ok(Some(IndexFailureDetails {
            status: crate::model::ModeStatus::Failed,
            reason,
            observation: Some(observation(semantic, false, accumulator.snapshot(), None)),
            execution: crate::model::Execution::Partial,
        }));
    }
    Ok(None)
}

fn finish_index_build<F>(
    chunks: Vec<PendingChunk<'_>>,
    coverage: crate::model::IndexCoverage,
    identity: IndexIdentity<'_>,
    budget: &mut crate::engine::WorkBudget,
    require_current_generation: &mut F,
) -> Result<Index, crate::engine::AttemptFailure>
where
    F: FnMut() -> Result<(), crate::engine::AttemptFailure>,
{
    budget.check()?;
    require_current_generation()?;
    Ok(Index {
        context_digest: identity.context.to_owned(),
        configuration_digest: identity.configuration.to_owned(),
        chunks: chunks
            .into_iter()
            .filter_map(|chunk| {
                chunk.vector.map(|vector| Chunk {
                    candidate_id: chunk.candidate_id,
                    source_binding: chunk.source_binding,
                    chunk_ordinal: chunk.chunk_ordinal,
                    byte_start: chunk.byte_start,
                    byte_end: chunk.byte_end,
                    vector,
                })
            })
            .collect(),
        coverage,
    })
}

struct CachedRankContext<'a, F> {
    request: &'a crate::model::Request,
    semantic: &'a SemanticRequest,
    index_version: &'a str,
    observed: crate::model::SemanticObservation,
    budget: &'a mut crate::engine::WorkBudget,
    require_current_generation: &'a mut F,
}

struct QueryEmbeddingContext<'a, F> {
    request: &'a crate::model::Request,
    semantic: &'a SemanticRequest,
    index_version: &'a str,
    coverage: &'a crate::model::IndexCoverage,
    observed: crate::model::SemanticObservation,
    budget: &'a mut crate::engine::WorkBudget,
    require_current_generation: &'a mut F,
}

enum QueryEmbeddingOutcome {
    Ready {
        query: Vec<f64>,
        observed: crate::model::SemanticObservation,
    },
    Failed(ModeRun),
}

fn embed_rank_query<F>(
    context: QueryEmbeddingContext<'_, F>,
) -> Result<QueryEmbeddingOutcome, crate::engine::AttemptFailure>
where
    F: FnMut() -> Result<(), crate::engine::AttemptFailure>,
{
    let QueryEmbeddingContext {
        request,
        semantic,
        index_version,
        coverage,
        mut observed,
        budget,
        require_current_generation,
    } = context;
    let mut query_accumulator = InvocationAccumulator::default();
    let query = match embed_query(
        &request.query,
        EmbeddingContext {
            semantic,
            request,
            budget,
            accumulator: &mut query_accumulator,
            require_current_generation,
        },
    ) {
        Ok(query) => query,
        Err(EmbeddingFailure::Attempt(error)) => return Err(error),
        Err(failure) => {
            let (status, reason, execution) = failure.status();
            observed.query = query_accumulator.snapshot();
            return Ok(QueryEmbeddingOutcome::Failed(failed_run(
                status,
                reason,
                FailureDetails {
                    index_version: Some(index_version.to_owned()),
                    coverage: coverage.clone(),
                    observation: Some(observed),
                    execution: Some(execution),
                },
            )));
        }
    };
    observed.query = query_accumulator.snapshot();
    Ok(QueryEmbeddingOutcome::Ready { query, observed })
}

fn empty_index_run(
    semantic_index: &Index,
    index_version: &str,
    observed: crate::model::SemanticObservation,
) -> ModeRun {
    let status = if semantic_index.coverage.complete {
        crate::model::ModeStatus::Used
    } else {
        crate::model::ModeStatus::Partial
    };
    let execution =
        (status == crate::model::ModeStatus::Partial).then_some(crate::model::Execution::Partial);
    ModeRun {
        status,
        index_version: Some(index_version.to_owned()),
        coverage: semantic_index.coverage.clone(),
        ranking: Vec::new(),
        observation: Some(observed),
        reason: semantic_index.coverage.reason.clone(),
        execution,
    }
}

fn rank_cached_index<F>(
    semantic_index: &Index,
    context: CachedRankContext<'_, F>,
) -> Result<ModeRun, crate::engine::AttemptFailure>
where
    F: FnMut() -> Result<(), crate::engine::AttemptFailure>,
{
    let CachedRankContext {
        request,
        semantic,
        index_version,
        observed,
        budget,
        require_current_generation,
    } = context;
    if semantic_index.chunks.is_empty() {
        return Ok(empty_index_run(semantic_index, index_version, observed));
    }
    let (query, observed) = match embed_rank_query(QueryEmbeddingContext {
        request,
        semantic,
        index_version,
        coverage: &semantic_index.coverage,
        observed,
        budget: &mut *budget,
        require_current_generation: &mut *require_current_generation,
    })? {
        QueryEmbeddingOutcome::Ready { query, observed } => (query, observed),
        QueryEmbeddingOutcome::Failed(failure) => return Ok(failure),
    };
    let work = semantic_index
        .chunks
        .len()
        .saturating_mul(semantic.settings.dimensions);
    let work = u64::try_from(work)
        .map_err(|_| crate::engine::AttemptFailure::Stop(crate::engine::Stop::WorkLimit))?;
    if let Err(stop) = budget.charge(work) {
        return Err(crate::engine::AttemptFailure::Stop(stop));
    }
    require_current_generation()?;
    let ranking = rank_candidates(&semantic_index.chunks, &query);
    let status = if semantic_index.coverage.complete {
        crate::model::ModeStatus::Used
    } else {
        crate::model::ModeStatus::Partial
    };
    let execution =
        (status == crate::model::ModeStatus::Partial).then_some(crate::model::Execution::Partial);
    Ok(ModeRun {
        status,
        index_version: Some(index_version.to_owned()),
        coverage: semantic_index.coverage.clone(),
        ranking,
        observation: Some(observed),
        reason: semantic_index.coverage.reason.clone(),
        execution,
    })
}

fn observation(
    semantic: &SemanticRequest,
    is_cache_hit: bool,
    document_build: Option<crate::model::InvocationObservation>,
    query: Option<crate::model::InvocationObservation>,
) -> crate::model::SemanticObservation {
    crate::model::SemanticObservation {
        model_id: semantic.invocation.descriptor.model_id.clone(),
        configuration_digest: semantic.configuration_digest(),
        cache_hit: is_cache_hit,
        document_build,
        query,
    }
}

struct FailureDetails {
    index_version: Option<String>,
    coverage: crate::model::IndexCoverage,
    observation: Option<crate::model::SemanticObservation>,
    execution: Option<crate::model::Execution>,
}

fn failed_run(
    status: crate::model::ModeStatus,
    reason: String,
    details: FailureDetails,
) -> ModeRun {
    ModeRun {
        status,
        index_version: details.index_version,
        coverage: details.coverage,
        ranking: Vec::new(),
        observation: details.observation,
        reason: Some(reason),
        execution: details.execution,
    }
}

enum PrepareFailure {
    Stop(crate::engine::Stop),
    Unavailable(String),
}

fn prepare_chunks<'a>(
    index: &'a crate::model::CachedIndex,
    context_digest: &str,
    settings: &EmbeddingSettings,
    budget: &mut crate::engine::WorkBudget,
) -> Result<(Vec<PendingChunk<'a>>, crate::model::IndexCoverage), PrepareFailure> {
    let mut chunks = Vec::with_capacity(index.documents.len().min(settings.max_chunks));
    let mut documents_indexed = 0_usize;
    let mut documents_skipped = 0_usize;
    for document in &index.documents {
        budget.charge(1).map_err(PrepareFailure::Stop)?;
        if document.text.is_empty() {
            documents_skipped = documents_skipped.saturating_add(1);
            continue;
        }
        documents_indexed = documents_indexed.saturating_add(1);
        let binding = source_binding(context_digest, document);
        let mut start = 0_usize;
        let mut ordinal = 0_usize;
        while start < document.text.len() {
            budget.charge(1).map_err(PrepareFailure::Stop)?;
            if chunks.len() >= settings.max_chunks {
                return Err(PrepareFailure::Unavailable(format!(
                    "authorized corpus exceeds the exact semantic bound of {} chunks",
                    settings.max_chunks
                )));
            }
            if !within_raw_float_value_bound(
                chunks.len(),
                settings.dimensions,
                settings.max_raw_float_values,
            ) {
                return Err(PrepareFailure::Unavailable(format!(
                    "authorized corpus exceeds the semantic raw-float-value bound of {}",
                    settings.max_raw_float_values
                )));
            }
            let Some(end) = next_utf8_chunk_end(&document.text, start, settings.chunk_bytes) else {
                return Err(PrepareFailure::Unavailable(
                    "semantic chunking could not preserve a UTF-8 boundary".to_owned(),
                ));
            };
            chunks.push(PendingChunk {
                candidate_id: document.id.clone(),
                source_binding: binding.clone(),
                chunk_ordinal: ordinal,
                byte_start: start,
                byte_end: end,
                text: &document.text[start..end],
                vector: None,
            });
            ordinal = ordinal.saturating_add(1);
            start = end;
        }
    }
    let skipped = documents_skipped.saturating_add(index.coverage.documents_skipped);
    let coverage = if index.coverage.complete && documents_skipped == 0 {
        crate::model::IndexCoverage::complete(documents_indexed)
    } else {
        let mut reasons = Vec::new();
        if let Some(reason) = &index.coverage.reason {
            reasons.push(reason.clone());
        }
        if documents_skipped > 0 {
            reasons.push(format!(
                "{documents_skipped} empty indexed documents could not be embedded"
            ));
        }
        crate::model::IndexCoverage::incomplete(documents_indexed, skipped, reasons.join("; "))
    };
    Ok((chunks, coverage))
}

fn next_utf8_chunk_end(text: &str, start: usize, chunk_bytes: usize) -> Option<usize> {
    if start >= text.len() || chunk_bytes == 0 || !text.is_char_boundary(start) {
        return None;
    }
    let mut end = start.saturating_add(chunk_bytes).min(text.len());
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (end > start).then_some(end)
}

fn within_raw_float_value_bound(prior_rows: usize, dimensions: usize, ceiling: usize) -> bool {
    prior_rows
        .checked_add(1)
        .and_then(|rows| rows.checked_mul(dimensions))
        .is_some_and(|values| values <= ceiling)
}

fn cache_is_source_bound(
    cached: &Index,
    index: &crate::model::CachedIndex,
    context_digest: &str,
    settings: &EmbeddingSettings,
) -> bool {
    if cached.chunks.len() > settings.max_chunks {
        return false;
    }
    let mut last_chunk =
        std::collections::HashMap::<String, (usize, usize)>::with_capacity(cached.chunks.len());
    let mut source_bindings =
        std::collections::HashMap::<String, String>::with_capacity(cached.chunks.len());
    for chunk in &cached.chunks {
        if chunk.vector.len() != settings.dimensions {
            return false;
        }
        let Some(document) = index.document(&chunk.candidate_id) else {
            return false;
        };
        let binding = source_bindings
            .entry(chunk.candidate_id.clone())
            .or_insert_with(|| source_binding(context_digest, document));
        if chunk.source_binding != *binding
            || chunk.byte_start >= chunk.byte_end
            || chunk.byte_end > document.text.len()
            || chunk.byte_end.saturating_sub(chunk.byte_start) > settings.chunk_bytes
            || !document.text.is_char_boundary(chunk.byte_start)
            || !document.text.is_char_boundary(chunk.byte_end)
        {
            return false;
        }
        match last_chunk.get(&chunk.candidate_id) {
            Some((ordinal, byte_end))
                if chunk.chunk_ordinal == ordinal.saturating_add(1)
                    && chunk.byte_start == *byte_end => {}
            Some(_) => return false,
            None if chunk.chunk_ordinal == 0 && chunk.byte_start == 0 => {}
            None => return false,
        }
        last_chunk.insert(
            chunk.candidate_id.clone(),
            (chunk.chunk_ordinal, chunk.byte_end),
        );
    }
    for document in &index.documents {
        if document.text.is_empty() {
            continue;
        }
        let is_complete = match last_chunk.get(&document.id) {
            Some((_, byte_end)) => *byte_end == document.text.len(),
            None => false,
        };
        if !is_complete {
            return false;
        }
    }
    true
}

struct EmbeddingContext<'a, F> {
    semantic: &'a SemanticRequest,
    request: &'a crate::model::Request,
    budget: &'a mut crate::engine::WorkBudget,
    accumulator: &'a mut InvocationAccumulator,
    require_current_generation: &'a mut F,
}

fn embed_documents<F>(
    chunks: &[PendingChunk<'_>],
    context: EmbeddingContext<'_, F>,
) -> Result<Vec<Vec<f64>>, EmbeddingFailure>
where
    F: FnMut() -> Result<(), crate::engine::AttemptFailure>,
{
    let EmbeddingContext {
        semantic,
        request,
        budget,
        accumulator,
        require_current_generation,
    } = context;
    let invocation = &semantic.invocation;
    let configured_limits = semantic.limits;
    let settings = &semantic.settings;
    let mut vectors = Vec::with_capacity(chunks.len());
    let mut start = 0_usize;
    while start < chunks.len() {
        if let Err(stop) = budget.charge(1) {
            return Err(EmbeddingFailure::Attempt(
                crate::engine::AttemptFailure::Stop(stop),
            ));
        }
        let max_items = (start + settings.max_batch_items).min(chunks.len());
        let mut end = max_items;
        let body = loop {
            match serialize_inputs(
                invocation.descriptor.model_id.as_str(),
                &chunks[start..end],
                settings.document_prefix.as_str(),
            ) {
                Ok(body) if body.len() <= configured_limits.max_input_bytes => break body,
                Ok(_) | Err(()) if end > start + 1 => end -= 1,
                Ok(_) => {
                    return Err(EmbeddingFailure::Unavailable(
                        "one semantic document input exceeds the configured input bound".to_owned(),
                    ));
                }
                Err(()) => {
                    return Err(EmbeddingFailure::Failed(
                        "semantic input could not be serialized as JSON".to_owned(),
                    ));
                }
            }
        };
        let limits = match invocation_limits(configured_limits, budget) {
            Ok(limits) => limits,
            Err(stop) => {
                return Err(EmbeddingFailure::Attempt(
                    crate::engine::AttemptFailure::Stop(stop),
                ));
            }
        };
        let control = invocation_control(request);
        let outcome = crate::inference::invoke_json(invocation, body, limits, &control);
        accumulator.observe(&outcome);
        if let Err(error) = require_current_generation() {
            return Err(EmbeddingFailure::Attempt(error));
        }
        let rows = validate_outcome(
            &outcome,
            invocation,
            limits,
            end - start,
            settings.dimensions,
        )?;
        if let Err(stop) = budget.check() {
            return Err(EmbeddingFailure::Attempt(
                crate::engine::AttemptFailure::Stop(stop),
            ));
        }
        vectors.extend(rows);
        start = end;
    }
    Ok(vectors)
}

fn embed_query<F>(
    query: &str,
    context: EmbeddingContext<'_, F>,
) -> Result<Vec<f64>, EmbeddingFailure>
where
    F: FnMut() -> Result<(), crate::engine::AttemptFailure>,
{
    let EmbeddingContext {
        semantic,
        request,
        budget,
        accumulator,
        require_current_generation,
    } = context;
    let invocation = &semantic.invocation;
    let configured_limits = semantic.limits;
    let settings = &semantic.settings;
    let body = serialize_query(
        invocation.descriptor.model_id.as_str(),
        query,
        settings.query_prefix.as_str(),
    )
    .map_err(|()| {
        EmbeddingFailure::Failed("semantic query could not be serialized as JSON".to_owned())
    })?;
    if body.len() > configured_limits.max_input_bytes {
        return Err(EmbeddingFailure::Unavailable(
            "semantic query exceeds the configured input bound".to_owned(),
        ));
    }
    budget
        .charge(1)
        .map_err(|stop| EmbeddingFailure::Attempt(crate::engine::AttemptFailure::Stop(stop)))?;
    let limits = invocation_limits(configured_limits, budget)
        .map_err(|stop| EmbeddingFailure::Attempt(crate::engine::AttemptFailure::Stop(stop)))?;
    let control = invocation_control(request);
    let outcome = crate::inference::invoke_json(invocation, body, limits, &control);
    accumulator.observe(&outcome);
    require_current_generation().map_err(EmbeddingFailure::Attempt)?;
    let mut vectors = validate_outcome(&outcome, invocation, limits, 1, settings.dimensions)?;
    if let Err(stop) = budget.check() {
        return Err(EmbeddingFailure::Attempt(
            crate::engine::AttemptFailure::Stop(stop),
        ));
    }
    if vectors.len() != 1 {
        return Err(EmbeddingFailure::Failed(
            "semantic query returned an invalid vector count".to_owned(),
        ));
    }
    Ok(vectors.remove(0))
}

fn invocation_limits(
    configured: crate::inference::InvocationLimits,
    budget: &mut crate::engine::WorkBudget,
) -> Result<crate::inference::InvocationLimits, crate::engine::Stop> {
    let remaining = budget.remaining_time()?;
    let max_wall_time = configured.max_wall_time.min(remaining);
    if max_wall_time.is_zero() {
        return Err(crate::engine::Stop::Timeout);
    }
    Ok(crate::inference::InvocationLimits {
        max_input_bytes: configured.max_input_bytes,
        max_output_bytes: configured.max_output_bytes,
        max_wall_time,
    })
}

fn invocation_control(request: &crate::model::Request) -> crate::inference::InvocationControl {
    match &request.cancellation {
        Some(cancelled) => crate::inference::InvocationControl::from_shared(cancelled.clone()),
        None => crate::inference::InvocationControl::new(),
    }
}

enum EmbeddingFailure {
    Attempt(crate::engine::AttemptFailure),
    Unavailable(String),
    TimedOut(String),
    Cancelled(String),
    Failed(String),
}

impl EmbeddingFailure {
    fn status(self) -> (crate::model::ModeStatus, String, crate::model::Execution) {
        match self {
            EmbeddingFailure::Attempt(crate::engine::AttemptFailure::Stop(
                crate::engine::Stop::Cancelled,
            )) => (
                crate::model::ModeStatus::Omitted,
                "recall cancelled".to_owned(),
                crate::model::Execution::Cancelled,
            ),
            EmbeddingFailure::Attempt(crate::engine::AttemptFailure::Stop(
                crate::engine::Stop::Timeout,
            )) => (
                crate::model::ModeStatus::TimedOut,
                "recall exceeded its time budget".to_owned(),
                crate::model::Execution::Timeout,
            ),
            EmbeddingFailure::Attempt(crate::engine::AttemptFailure::Stop(
                crate::engine::Stop::WorkLimit,
            )) => (
                crate::model::ModeStatus::TimedOut,
                "recall exceeded its work budget".to_owned(),
                crate::model::Execution::Timeout,
            ),
            EmbeddingFailure::Attempt(crate::engine::AttemptFailure::Error(error)) => (
                crate::model::ModeStatus::Failed,
                error.to_string(),
                crate::model::Execution::Failed,
            ),
            EmbeddingFailure::Unavailable(reason) => (
                crate::model::ModeStatus::Unavailable,
                reason,
                crate::model::Execution::Partial,
            ),
            EmbeddingFailure::TimedOut(reason) => (
                crate::model::ModeStatus::TimedOut,
                reason,
                crate::model::Execution::Timeout,
            ),
            EmbeddingFailure::Cancelled(reason) => (
                crate::model::ModeStatus::Omitted,
                reason,
                crate::model::Execution::Cancelled,
            ),
            EmbeddingFailure::Failed(reason) => (
                crate::model::ModeStatus::Failed,
                reason,
                crate::model::Execution::Partial,
            ),
        }
    }
}

fn validate_outcome(
    outcome: &crate::inference::InvocationOutcome,
    invocation: &crate::inference::InvocationConfig,
    limits: crate::inference::InvocationLimits,
    expected_count: usize,
    dimensions: usize,
) -> Result<Vec<Vec<f64>>, EmbeddingFailure> {
    if outcome.configuration_digest != invocation.invocation_digest(limits) {
        return Err(EmbeddingFailure::Failed(
            "inference worker configuration identity changed".to_owned(),
        ));
    }
    if !is_sha256(&outcome.input_digest) {
        return Err(EmbeddingFailure::Failed(
            "inference worker did not return a canonical input digest".to_owned(),
        ));
    }
    match outcome.status {
        crate::inference::InvocationStatus::Complete => {}
        crate::inference::InvocationStatus::Unavailable => {
            return Err(EmbeddingFailure::Unavailable(
                outcome
                    .detail
                    .clone()
                    .unwrap_or_else(|| "semantic worker unavailable".to_owned()),
            ));
        }
        crate::inference::InvocationStatus::Timeout => {
            return Err(EmbeddingFailure::TimedOut(
                outcome
                    .detail
                    .clone()
                    .unwrap_or_else(|| "semantic worker timed out".to_owned()),
            ));
        }
        crate::inference::InvocationStatus::Cancelled => {
            return Err(EmbeddingFailure::Cancelled(
                outcome
                    .detail
                    .clone()
                    .unwrap_or_else(|| "semantic worker cancelled".to_owned()),
            ));
        }
        crate::inference::InvocationStatus::Failed
        | crate::inference::InvocationStatus::Oversized
        | crate::inference::InvocationStatus::Malformed => {
            return Err(EmbeddingFailure::Failed(
                outcome
                    .detail
                    .clone()
                    .unwrap_or_else(|| "semantic worker failed".to_owned()),
            ));
        }
    }
    if outcome.reported_model.as_deref() != Some(invocation.descriptor.model_id.as_str()) {
        return Err(EmbeddingFailure::Failed(
            "worker-reported model does not match the pinned model id".to_owned(),
        ));
    }
    let output = outcome.output.as_deref().ok_or_else(|| {
        EmbeddingFailure::Failed("complete invocation has no JSON output".to_owned())
    })?;
    parse_embeddings(
        output,
        invocation.descriptor.model_id.as_str(),
        expected_count,
        dimensions,
    )
    .map_err(EmbeddingFailure::Failed)
}

fn parse_embeddings(
    output: &[u8],
    expected_model: &str,
    expected_count: usize,
    dimensions: usize,
) -> Result<Vec<Vec<f64>>, String> {
    let value: serde_json::Value = serde_json::from_slice(output)
        .map_err(|_| "embedding output is not valid JSON".to_owned())?;
    if value.get("model").and_then(serde_json::Value::as_str) != Some(expected_model) {
        return Err("embedding output model does not match the pinned model id".to_owned());
    }
    let rows = value
        .get("data")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "embedding output has no data array".to_owned())?;
    if rows.len() != expected_count {
        return Err(format!(
            "embedding output row count {} does not match requested count {expected_count}",
            rows.len()
        ));
    }
    let mut vectors = Vec::with_capacity(rows.len());
    for (expected_index, row) in rows.iter().enumerate() {
        let actual_index = row
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "embedding output row has no unsigned index".to_owned())?;
        if u64::try_from(expected_index).ok() != Some(actual_index) {
            return Err(
                "embedding output indices are missing, duplicated, or reordered".to_owned(),
            );
        }
        let values = row
            .get("embedding")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "embedding output row has no embedding array".to_owned())?;
        if values.len() != dimensions {
            return Err(format!(
                "embedding dimension {} does not match configured dimension {dimensions}",
                values.len()
            ));
        }
        let mut vector = Vec::with_capacity(dimensions);
        for value in values {
            let value = value
                .as_f64()
                .ok_or_else(|| "embedding vector contains a non-number".to_owned())?;
            if !value.is_finite() {
                return Err("embedding vector contains a non-finite value".to_owned());
            }
            vector.push(value);
        }
        normalize_l2(&mut vector)?;
        vectors.push(vector);
    }
    Ok(vectors)
}

fn normalize_l2(vector: &mut [f64]) -> Result<(), String> {
    let scale = vector
        .iter()
        .map(|value| value.abs())
        .fold(0.0_f64, f64::max);
    if scale == 0.0 || !scale.is_finite() {
        return Err("embedding vector has zero or non-finite L2 norm".to_owned());
    }
    let norm = vector
        .iter()
        .map(|value| (value / scale) * (value / scale))
        .sum::<f64>()
        .sqrt();
    if norm == 0.0 || !norm.is_finite() {
        return Err("embedding vector has zero or non-finite L2 norm".to_owned());
    }
    for value in vector {
        *value = (*value / scale) / norm;
        if !value.is_finite() {
            return Err("normalizing the embedding vector produced a non-finite value".to_owned());
        }
    }
    Ok(())
}

fn serialize_inputs(
    model_id: &str,
    rows: &[PendingChunk<'_>],
    prefix: &str,
) -> Result<Vec<u8>, ()> {
    let inputs = rows
        .iter()
        .map(|row| format!("{prefix}{}", row.text))
        .collect::<Vec<_>>();
    serialize_body(model_id, inputs)
}

fn serialize_query(model_id: &str, query: &str, prefix: &str) -> Result<Vec<u8>, ()> {
    serialize_body(model_id, vec![format!("{prefix}{query}")])
}

fn serialize_body(model_id: &str, inputs: Vec<String>) -> Result<Vec<u8>, ()> {
    let request = serde_json::json!({
        "model": model_id,
        "input": inputs,
        "encoding_format": "float"
    });
    serde_json::to_vec(&request).map_err(|_| ())
}

fn context_digest(request: &crate::model::Request, generation: u64) -> String {
    let access = match &request.access {
        mneme_memory::Access::Operator => mneme_core::Value::symbol("operator"),
        mneme_memory::Access::Scopes(scopes) => {
            mneme_core::Value::sequence(scopes.iter().map(mneme_core::ScopeId::to_value).collect())
        }
    };
    let identity = mneme_core::Value::record_named(
        "mneme-recall-semantic-context-v1",
        vec![
            mneme_core::Value::string(request.actor.clone()),
            request.revision.to_value(),
            request.scope.to_value(),
            access,
            mneme_core::Value::integer(generation),
            mneme_core::Value::symbol(request.temporal.name()),
            mneme_core::Value::string(request.at.to_rfc3339()),
            mneme_core::Value::Boolean(request.include_disputed),
            mneme_core::Value::Boolean(request.include_hypothetical),
        ],
    );
    format!(
        "sha256:{}",
        mneme_core::ContentDigest::of_payload(&identity).to_hex()
    )
}

fn optional_record_value(value: Option<mneme_core::RecordId>) -> mneme_core::Value {
    value
        .map(|record| {
            mneme_core::Value::sequence(vec![mneme_core::Value::symbol("some"), record.to_value()])
        })
        .unwrap_or_else(|| mneme_core::Value::symbol("none"))
}

fn optional_revision_value(value: Option<mneme_core::RevisionId>) -> mneme_core::Value {
    value
        .map(|revision| {
            mneme_core::Value::sequence(vec![
                mneme_core::Value::symbol("some"),
                revision.to_value(),
            ])
        })
        .unwrap_or_else(|| mneme_core::Value::symbol("none"))
}

fn optional_span_value(value: Option<mneme_core::SourceSpan>) -> mneme_core::Value {
    value
        .map(mneme_core::SourceSpan::to_value)
        .unwrap_or_else(|| mneme_core::Value::symbol("none"))
}

fn claim_status_binding(document: &crate::model::IndexedDocument) -> mneme_core::Value {
    document
        .claim_status
        .as_ref()
        .map(|status| {
            mneme_core::Value::record_named(
                "claim-status",
                vec![
                    mneme_core::Value::string(status.lifecycle.clone()),
                    mneme_core::Value::string(status.stance.clone()),
                    status.valid_time.to_value(),
                    status.recorded.to_value(),
                    optional_record_value(status.superseded_by),
                    optional_record_value(status.decision),
                    mneme_core::Value::string(status.asserted_by.clone()),
                ],
            )
        })
        .unwrap_or_else(|| mneme_core::Value::symbol("none"))
}

fn evidence_binding(document: &crate::model::IndexedDocument) -> mneme_core::Value {
    mneme_core::Value::sequence(
        document
            .evidence
            .iter()
            .map(|evidence| {
                let evidence_span = optional_span_value(evidence.span);
                let evidence_roots = mneme_core::Value::sequence(
                    evidence
                        .ancestry_roots
                        .iter()
                        .map(|(record, revision)| {
                            mneme_core::Value::sequence(vec![
                                record.to_value(),
                                revision.to_value(),
                            ])
                        })
                        .collect(),
                );
                let availability = match &evidence.availability {
                    mneme_memory::SourceAvailability::Retained
                    | mneme_memory::SourceAvailability::Pruned
                    | mneme_memory::SourceAvailability::Erased
                    | mneme_memory::SourceAvailability::Inaccessible => {
                        mneme_core::Value::symbol(evidence.availability.name())
                    }
                    mneme_memory::SourceAvailability::Corrupt { reason }
                    | mneme_memory::SourceAvailability::Unavailable { reason } => {
                        mneme_core::Value::sequence(vec![
                            mneme_core::Value::symbol(evidence.availability.name()),
                            mneme_core::Value::string(reason.clone()),
                        ])
                    }
                };
                mneme_core::Value::record_named(
                    "evidence-binding",
                    vec![
                        evidence.evidence.to_value(),
                        evidence.source.to_value(),
                        optional_revision_value(evidence.source_revision),
                        evidence_span,
                        availability,
                        mneme_core::Value::symbol(match evidence.relation {
                            mneme_memory::SupportRelation::Supports => "supports",
                            mneme_memory::SupportRelation::Challenges => "challenges",
                        }),
                        mneme_core::Value::Boolean(evidence.withdrawn),
                        mneme_core::Value::Boolean(evidence.eligible),
                        evidence_roots,
                    ],
                )
            })
            .collect(),
    )
}

fn ancestry_roots_binding(document: &crate::model::IndexedDocument) -> mneme_core::Value {
    mneme_core::Value::sequence(
        document
            .ancestry_roots
            .iter()
            .map(|(record, revision)| {
                mneme_core::Value::sequence(vec![record.to_value(), revision.to_value()])
            })
            .collect(),
    )
}

fn source_binding(context: &str, document: &crate::model::IndexedDocument) -> String {
    let span = optional_span_value(document.span);
    let claim_status = claim_status_binding(document);
    let evidence = evidence_binding(document);
    let ancestry_roots = ancestry_roots_binding(document);
    let content_digest = mneme_core::ContentDigest::of_source_bytes(document.text.as_bytes());
    let identity = mneme_core::Value::record_named(
        "mneme-semantic-source-binding-v1",
        vec![
            mneme_core::Value::string(context.to_owned()),
            mneme_core::Value::string(document.id.clone()),
            mneme_core::Value::symbol(document.kind.name()),
            mneme_core::Value::string(document.field_path.clone()),
            content_digest.to_value(),
            optional_record_value(document.source),
            optional_revision_value(document.source_revision),
            span,
            optional_record_value(document.assertion),
            optional_record_value(document.episode),
            optional_record_value(document.entity),
            claim_status,
            evidence,
            ancestry_roots,
        ],
    );
    format!(
        "sha256:{}",
        mneme_core::ContentDigest::of_payload(&identity).to_hex()
    )
}

fn rank_candidates(chunks: &[Chunk], query: &[f64]) -> Vec<(String, f64)> {
    let mut scores = std::collections::BTreeMap::<String, f64>::new();
    for chunk in chunks {
        let similarity = chunk
            .vector
            .iter()
            .zip(query)
            .map(|(document, query)| document * query)
            .sum::<f64>()
            .clamp(-1.0, 1.0);
        if similarity <= 0.0 {
            continue;
        }
        scores
            .entry(chunk.candidate_id.clone())
            .and_modify(|score| {
                if similarity.total_cmp(score).is_gt() {
                    *score = similarity;
                }
            })
            .or_insert(similarity);
    }
    let mut entries = scores.into_iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    entries
}

fn hash_field(digest: &mut sha2::Sha256, field: &[u8]) {
    use sha2::Digest as _;
    digest.update(length_bytes(field.len()));
    digest.update(field);
}

fn length_bytes(value: usize) -> [u8; 8] {
    let mut bytes = [0_u8; 8];
    let value_bytes = value.to_le_bytes();
    bytes[..value_bytes.len()].copy_from_slice(&value_bytes);
    bytes
}

fn digest_label_and_fields(label: &[u8], fields: &[&[u8]]) -> String {
    let mut digest = sha2::Sha256::new();
    use sha2::Digest as _;
    digest.update(label);
    for field in fields {
        hash_field(&mut digest, field);
    }
    format_sha256(&digest.finalize())
}

fn format_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(7 + bytes.len().saturating_mul(2));
    text.push_str("sha256:");
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_request() -> SemanticRequest {
        SemanticRequest::from_model(
            SemanticModelIdentity {
                adapter_id: "fixture-runtime".to_owned(),
                adapter_version: "fixture-runtime-v1".to_owned(),
                model_id: "fixture-nomic-embed".to_owned(),
                model_revision: "fixture-revision".to_owned(),
                artifact_digest: format!("sha256:{}", "a".repeat(64)),
                tokenizer_id: "fixture-tokenizer".to_owned(),
                tokenizer_digest: format!("sha256:{}", "b".repeat(64)),
            },
            crate::inference::WorkerCommand {
                executable: std::path::PathBuf::from("/usr/bin/true"),
                args: Vec::new(),
            },
            crate::inference::InvocationLimits {
                max_input_bytes: 4096,
                max_output_bytes: 4096,
                max_wall_time: std::time::Duration::from_secs(2),
            },
            EmbeddingSettings::nomic_embed_text_v1_5(),
        )
    }

    #[test]
    fn output_indices_and_source_order_are_exact() {
        let output = include_bytes!("../tests/fixtures/semantic/valid-two.json");
        let vectors = parse_embeddings(output, "fixture-nomic-embed", 2, 2).expect("valid vectors");
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0], vec![0.6, 0.8]);
        assert_eq!(vectors[1], vec![1.0, 0.0]);

        let reordered = include_bytes!("../tests/fixtures/semantic/reordered-two.json");
        assert!(parse_embeddings(reordered, "fixture-nomic-embed", 2, 2).is_err());
        let duplicate = br#"{"model":"fixture-nomic-embed","data":[{"index":0,"embedding":[1,0]},{"index":0,"embedding":[0,1]}]}"#;
        assert!(parse_embeddings(duplicate, "fixture-nomic-embed", 2, 2).is_err());
        let short = br#"{"model":"fixture-nomic-embed","data":[{"index":0,"embedding":[1,0]}]}"#;
        assert!(parse_embeddings(short, "fixture-nomic-embed", 2, 2).is_err());
    }

    #[test]
    fn vectors_remain_bound_to_the_exact_candidate_chunk_order() {
        let first = "first eligible source chunk";
        let second = "second eligible source chunk";
        let mut chunks = vec![
            PendingChunk {
                candidate_id: "claim:first".to_owned(),
                source_binding: "sha256:first".to_owned(),
                chunk_ordinal: 0,
                byte_start: 0,
                byte_end: first.len(),
                text: first,
                vector: None,
            },
            PendingChunk {
                candidate_id: "episode:second".to_owned(),
                source_binding: "sha256:second".to_owned(),
                chunk_ordinal: 1,
                byte_start: 12,
                byte_end: 12 + second.len(),
                text: second,
                vector: None,
            },
        ];
        assign_vectors(&mut chunks, vec![vec![1.0, 0.0], vec![0.0, 1.0]])
            .expect("one exact vector per ordered source chunk");
        assert_eq!(chunks[0].candidate_id, "claim:first");
        assert_eq!(chunks[0].source_binding, "sha256:first");
        assert_eq!(chunks[0].vector.as_deref(), Some(&[1.0, 0.0][..]));
        assert_eq!(chunks[1].candidate_id, "episode:second");
        assert_eq!(chunks[1].source_binding, "sha256:second");
        assert_eq!(chunks[1].vector.as_deref(), Some(&[0.0, 1.0][..]));
        assert!(assign_vectors(&mut chunks, vec![vec![1.0, 0.0]]).is_err());
    }

    #[test]
    fn malformed_wrong_model_dimension_and_zero_vectors_fail_closed() {
        assert!(parse_embeddings(b"not-json", "fixture-model", 1, 2).is_err());
        let wrong_model = include_bytes!("../tests/fixtures/semantic/wrong-model.json");
        assert!(parse_embeddings(wrong_model, "fixture-nomic-embed", 1, 2).is_err());
        let wrong_dimensions = include_bytes!("../tests/fixtures/semantic/wrong-dimensions.json");
        assert!(parse_embeddings(wrong_dimensions, "fixture-nomic-embed", 1, 2).is_err());
        let zero = include_bytes!("../tests/fixtures/semantic/zero-vector.json");
        assert!(parse_embeddings(zero, "fixture-nomic-embed", 1, 2).is_err());
    }

    #[test]
    fn supervised_timeout_cancellation_and_unavailability_stay_distinct() {
        let semantic = fixture_request();
        let input_digest = format!("sha256:{}", "c".repeat(64));
        for (worker_status, expected_status) in [
            (
                crate::inference::InvocationStatus::Unavailable,
                crate::model::ModeStatus::Unavailable,
            ),
            (
                crate::inference::InvocationStatus::Timeout,
                crate::model::ModeStatus::TimedOut,
            ),
            (
                crate::inference::InvocationStatus::Cancelled,
                crate::model::ModeStatus::Omitted,
            ),
            (
                crate::inference::InvocationStatus::Failed,
                crate::model::ModeStatus::Failed,
            ),
            (
                crate::inference::InvocationStatus::Oversized,
                crate::model::ModeStatus::Failed,
            ),
            (
                crate::inference::InvocationStatus::Malformed,
                crate::model::ModeStatus::Failed,
            ),
        ] {
            let outcome = crate::inference::InvocationOutcome {
                status: worker_status,
                output: None,
                observed_output_bytes: None,
                observed_output_digest: None,
                input_bytes: 1,
                elapsed: std::time::Duration::ZERO,
                usage: crate::inference::UsageTelemetry::Unavailable,
                input_digest: input_digest.clone(),
                configuration_digest: semantic.invocation.invocation_digest(semantic.limits),
                reported_model: None,
                detail: Some("fixture failure".to_owned()),
            };
            let failure = validate_outcome(&outcome, &semantic.invocation, semantic.limits, 1, 2)
                .expect_err("non-complete worker status is never treated as a vector");
            assert_eq!(failure.status().0, expected_status);
        }

        let output = include_bytes!("../tests/fixtures/semantic/valid-two.json").to_vec();
        let observed_output_bytes = output.len();
        let mut substituted = crate::inference::InvocationOutcome {
            status: crate::inference::InvocationStatus::Complete,
            output: Some(output),
            observed_output_bytes: Some(observed_output_bytes),
            observed_output_digest: None,
            input_bytes: 1,
            elapsed: std::time::Duration::from_millis(1),
            usage: crate::inference::UsageTelemetry::Unavailable,
            input_digest,
            configuration_digest: semantic.invocation.invocation_digest(semantic.limits),
            reported_model: Some("substituted-model".to_owned()),
            detail: None,
        };
        assert!(matches!(
            validate_outcome(&substituted, &semantic.invocation, semantic.limits, 2, 2),
            Err(EmbeddingFailure::Failed(_))
        ));
        substituted.configuration_digest = format!("sha256:{}", "d".repeat(64));
        substituted.reported_model = Some(semantic.invocation.descriptor.model_id.clone());
        assert!(matches!(
            validate_outcome(&substituted, &semantic.invocation, semantic.limits, 2, 2),
            Err(EmbeddingFailure::Failed(_))
        ));
    }

    #[test]
    fn non_finite_vectors_fail_and_large_finite_norms_are_stable() {
        assert!(
            parse_embeddings(
                br#"{"model":"fixture-model","data":[{"index":0,"embedding":[1e999,0]}]}"#,
                "fixture-model",
                1,
                2,
            )
            .is_err()
        );
        let large = parse_embeddings(
            br#"{"model":"fixture-model","data":[{"index":0,"embedding":[1e308,1e308]}]}"#,
            "fixture-model",
            1,
            2,
        )
        .expect("finite large vector normalizes without overflowing its norm");
        assert!((large[0][0] - std::f64::consts::FRAC_1_SQRT_2).abs() < 1e-15);
        assert!((large[0][1] - std::f64::consts::FRAC_1_SQRT_2).abs() < 1e-15);
    }

    #[test]
    fn all_settings_change_the_identity() {
        let base = EmbeddingSettings::nomic_embed_text_v1_5();
        let digest = base.settings_digest();
        let mut changed = base.clone();
        changed.query_prefix.push_str("variant:");
        assert_ne!(digest, changed.settings_digest());
        let mut changed = base.clone();
        changed.dimensions = 767;
        assert_ne!(digest, changed.settings_digest());
        let mut changed = base.clone();
        changed.max_chunks = changed.max_chunks.saturating_sub(1);
        assert_ne!(digest, changed.settings_digest());
        let mut changed = base.clone();
        changed.max_raw_float_values -= 1;
        assert_ne!(digest, changed.settings_digest());
        let mut changed = base.clone();
        changed.document_prefix.push_str("variant:");
        assert_ne!(digest, changed.settings_digest());
        let mut changed = base.clone();
        changed.chunking_version.push_str("-variant");
        assert_ne!(digest, changed.settings_digest());
        let mut changed = base.clone();
        changed.chunk_bytes -= 1;
        assert_ne!(digest, changed.settings_digest());
        let mut changed = base.clone();
        changed.max_query_bytes -= 1;
        assert_ne!(digest, changed.settings_digest());
        let mut changed = base.clone();
        changed.max_batch_items -= 1;
        assert_ne!(digest, changed.settings_digest());
        let mut changed = base.clone();
        changed.version.push_str("-variant");
        assert_ne!(digest, changed.settings_digest());
        let mut changed = base.clone();
        changed.max_raw_float_values = changed.dimensions - 1;
        assert!(changed.validate().is_err());
    }

    #[test]
    fn complete_model_identity_and_worker_command_are_validated_and_cached() {
        let mut semantic = fixture_request();
        semantic.validate().expect("pinned semantic config");
        let configuration_digest = semantic.configuration_digest();
        semantic.invocation.worker.args.push("--alternate".into());
        assert_ne!(configuration_digest, semantic.configuration_digest());

        semantic.invocation.descriptor.model_revision.clear();
        assert!(semantic.validate().is_err());
    }

    #[test]
    fn configuration_digest_binds_model_worker_and_limits() {
        let base = fixture_request();
        let digest = base.configuration_digest();
        let mutations: [fn(&mut SemanticRequest); 15] = [
            |request| request.invocation.descriptor.adapter_id.push_str("-other"),
            |request| {
                request
                    .invocation
                    .descriptor
                    .adapter_version
                    .push_str("-other")
            },
            |request| request.invocation.descriptor.model_id.push_str("-other"),
            |request| {
                request
                    .invocation
                    .descriptor
                    .model_revision
                    .push_str("-other")
            },
            |request| {
                request.invocation.descriptor.artifact_digest = format!("sha256:{}", "c".repeat(64))
            },
            |request| {
                request
                    .invocation
                    .descriptor
                    .tokenizer_id
                    .push_str("-other")
            },
            |request| {
                request.invocation.descriptor.tokenizer_digest =
                    format!("sha256:{}", "d".repeat(64))
            },
            |request| {
                request.invocation.descriptor.prompt_template_digest =
                    format!("sha256:{}", "e".repeat(64))
            },
            |request| {
                request.invocation.descriptor.output_schema_digest =
                    format!("sha256:{}", "f".repeat(64))
            },
            |request| {
                request.invocation.descriptor.settings_digest = format!("sha256:{}", "1".repeat(64))
            },
            |request| {
                request.invocation.worker.executable = std::path::PathBuf::from("/usr/bin/env")
            },
            |request| request.invocation.worker.args.push("--other".into()),
            |request| request.limits.max_input_bytes += 1,
            |request| request.limits.max_output_bytes += 1,
            |request| request.limits.max_wall_time += std::time::Duration::from_millis(1),
        ];
        for mutate in mutations {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert_ne!(digest, changed.configuration_digest());
        }
    }

    #[test]
    fn ties_are_stable_and_rankings_never_pad_short_or_empty_corpora() {
        let chunk = |candidate_id: &str| Chunk {
            candidate_id: candidate_id.to_owned(),
            source_binding: "sha256:fixture".to_owned(),
            chunk_ordinal: 0,
            byte_start: 0,
            byte_end: 2,
            vector: vec![1.0, 0.0],
        };
        let tied = rank_candidates(&[chunk("z"), chunk("a")], &[1.0, 0.0]);
        assert_eq!(tied.len(), 2);
        assert_eq!(tied, vec![("a".to_owned(), 1.0), ("z".to_owned(), 1.0)]);
        assert!(rank_candidates(&[], &[1.0, 0.0]).is_empty());
    }

    #[test]
    fn source_bindings_change_with_context_candidate_and_exact_text() {
        let document = crate::model::IndexedDocument {
            id: "claim:fixture".to_owned(),
            kind: crate::model::ContentKind::Claim,
            text: "The fixture claim".to_owned(),
            normalized: "the fixture claim".to_owned(),
            term_counts: std::collections::BTreeMap::new(),
            term_total: 0,
            trigrams: std::collections::BTreeMap::new(),
            trigram_norm: 0.0,
            field_path: "value".to_owned(),
            source: None,
            source_revision: None,
            span: None,
            assertion: None,
            episode: None,
            entity: None,
            claim_status: None,
            evidence: Vec::new(),
            ancestry_roots: std::collections::BTreeSet::new(),
        };
        let original = source_binding("sha256:context-a", &document);
        assert_ne!(original, source_binding("sha256:context-b", &document));
        let mut changed = document.clone();
        changed.id.push_str(":other");
        assert_ne!(original, source_binding("sha256:context-a", &changed));
        let mut changed = document;
        changed.text.push('!');
        assert_ne!(original, source_binding("sha256:context-a", &changed));
    }

    #[test]
    fn unicode_chunking_keeps_complete_boundaries_without_truncation() {
        let text = "abcdéefgh";
        let mut starts = Vec::with_capacity(text.len());
        let mut start = 0_usize;
        while start < text.len() {
            let end = next_utf8_chunk_end(text, start, 5).expect("chunk boundary");
            starts.push((start, end));
            start = end;
        }
        assert_eq!(starts.first().map(|range| range.0), Some(0));
        assert_eq!(starts.last().map(|range| range.1), Some(text.len()));
        assert!(
            starts
                .iter()
                .all(|(start, end)| text.is_char_boundary(*start) && text.is_char_boundary(*end))
        );
        assert_eq!(
            starts
                .iter()
                .map(|(start, end)| &text[*start..*end])
                .collect::<String>(),
            text
        );
        assert_eq!(next_utf8_chunk_end("é", 0, 1), None);
        assert_eq!(next_utf8_chunk_end("é", 0, 2), Some("é".len()));
    }

    #[test]
    fn float_value_ceiling_is_independent_and_exact() {
        let ceiling = 512 * 768;
        assert!(within_raw_float_value_bound(511, 768, ceiling));
        assert!(!within_raw_float_value_bound(512, 768, ceiling));
        assert!(!within_raw_float_value_bound(usize::MAX, 768, usize::MAX));
    }
}
