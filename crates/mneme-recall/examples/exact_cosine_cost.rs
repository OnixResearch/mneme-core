//! Cost of exact semantic ranking at and beyond the recall bound.
//!
//! Semantic recall ranks every eligible chunk exactly: one dot product per
//! chunk against the normalized query, the maximum per candidate, then a sort.
//! This example times exactly those operations on synthetic unit vectors, so
//! the cost of exact ranking can be compared with the embedding call that must
//! precede it and with the corpus sizes where an approximate index would be
//! worth its isolation and maintenance costs.
//!
//! Run with `cargo run --release -p mneme-recall --example exact_cosine_cost`.

/// Chunks per candidate document, as long sources produce.
const CHUNKS_PER_CANDIDATE: usize = 4;
/// Timed repetitions per configuration; the median is reported.
const REPETITIONS: usize = 9;
/// Corpus sizes and dimensions measured. 512 chunks is the recall bound.
const CASES: [(usize, usize); 8] = [
    (512, 768),
    (512, 4_096),
    (2_048, 768),
    (8_192, 768),
    (8_192, 4_096),
    (32_768, 768),
    (131_072, 384),
    (131_072, 768),
];

struct Chunk {
    candidate: usize,
    vector: Vec<f64>,
}

/// A deterministic xorshift generator: the same corpus on every run.
struct Generator(u64);

impl Generator {
    fn next_unit(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        // Map to [-1, 1).
        (self.0 >> 11) as f64 / (1_u64 << 52) as f64 - 1.0
    }

    fn unit_vector(&mut self, dimensions: usize) -> Vec<f64> {
        let mut vector: Vec<f64> = (0..dimensions).map(|_| self.next_unit()).collect();
        let norm = vector.iter().map(|value| value * value).sum::<f64>().sqrt();
        if norm > 0.0 {
            for value in &mut vector {
                *value /= norm;
            }
        }
        vector
    }
}

/// The ranking recall performs: exact cosine per chunk, the best chunk per
/// candidate, candidates sorted by score then identity.
fn rank(chunks: &[Chunk], query: &[f64]) -> Vec<(usize, f64)> {
    let mut best = std::collections::BTreeMap::<usize, f64>::new();
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
        best.entry(chunk.candidate)
            .and_modify(|score| {
                if similarity.total_cmp(score).is_gt() {
                    *score = similarity;
                }
            })
            .or_insert(similarity);
    }
    let mut entries: Vec<(usize, f64)> = best.into_iter().collect();
    entries.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    entries
}

#[allow(unknown_lints, ambient_clock)] // timing is this example's purpose
fn median_micros(chunks: &[Chunk], query: &[f64]) -> (u128, usize) {
    let mut samples = Vec::with_capacity(REPETITIONS);
    let mut ranked = 0;
    for _ in 0..REPETITIONS {
        let started = std::time::Instant::now();
        ranked = std::hint::black_box(rank(chunks, query)).len();
        samples.push(started.elapsed().as_micros());
    }
    samples.sort_unstable();
    (
        samples.get(REPETITIONS / 2).copied().unwrap_or_default(),
        ranked,
    )
}

/// The least any embedding call costs: a worker that reads its request and
/// answers with one fixed vector, run through the real supervisor. A real
/// model adds its own inference time on top. `None` when the worker fails.
#[allow(unknown_lints, ambient_clock)] // timing is this example's purpose
fn noop_embedding_round_trip_micros() -> Option<u128> {
    let mut settings = mneme_recall::semantic::EmbeddingSettings::nomic_embed_text_v1_5();
    settings.dimensions = 2;
    let semantic = mneme_recall::semantic::SemanticRequest::from_model(
        mneme_recall::semantic::SemanticModelIdentity {
            adapter_id: "measurement-runtime".to_owned(),
            adapter_version: "measurement-runtime-v1".to_owned(),
            model_id: "measurement-model".to_owned(),
            model_revision: "measurement-revision".to_owned(),
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
            tokenizer_id: "measurement-tokenizer".to_owned(),
            tokenizer_digest: format!("sha256:{}", "b".repeat(64)),
        },
        mneme_recall::inference::WorkerCommand {
            executable: std::path::PathBuf::from("/bin/sh"),
            args: vec![
                "-c".into(),
                "while IFS= read -r line || [ -n \"$line\" ]; do :; done; \
                 printf '{\"model\":\"measurement-model\",\"data\":[{\"index\":0,\"embedding\":[1,0]}]}'"
                    .into(),
            ],
        },
        mneme_recall::inference::InvocationLimits {
            max_input_bytes: 4_096,
            max_output_bytes: 4_096,
            max_wall_time: std::time::Duration::from_secs(10),
        },
        settings,
    );
    let request = br#"{"model":"measurement-model","input":["search_query: SQLite"],"encoding_format":"float"}"#;
    let mut samples = Vec::with_capacity(REPETITIONS);
    for _ in 0..REPETITIONS {
        let started = std::time::Instant::now();
        let outcome = mneme_recall::inference::invoke_json(
            &semantic.invocation,
            request.to_vec(),
            semantic.limits,
            &mneme_recall::inference::InvocationControl::new(),
        );
        if outcome.status != mneme_recall::inference::InvocationStatus::Complete {
            return None;
        }
        samples.push(started.elapsed().as_micros());
    }
    samples.sort_unstable();
    samples.get(REPETITIONS / 2).copied()
}

fn main() {
    println!("| Chunks | Dimensions | Candidates ranked | Median exact ranking (µs) |");
    println!("|-------:|-----------:|------------------:|--------------------------:|");
    for (count, dimensions) in CASES {
        let mut generator =
            Generator(0x9e37_79b9_7f4a_7c15 ^ (count as u64) ^ ((dimensions as u64) << 32));
        let chunks: Vec<Chunk> = (0..count)
            .map(|index| Chunk {
                candidate: index / CHUNKS_PER_CANDIDATE,
                vector: generator.unit_vector(dimensions),
            })
            .collect();
        let query = generator.unit_vector(dimensions);
        let (micros, ranked) = median_micros(&chunks, &query);
        println!("| {count} | {dimensions} | {ranked} | {micros} |");
    }
    match noop_embedding_round_trip_micros() {
        Some(micros) => println!("\nNo-op embedding worker round trip: {micros} µs median"),
        None => println!("\nNo-op embedding worker round trip: the worker did not complete"),
    }
}
