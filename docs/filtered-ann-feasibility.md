# Filtered approximate nearest-neighbour recall: feasibility (#6)

**Decision: NO-GO.** Semantic recall keeps exact cosine ranking as its only
backend. At the recall bound of 512 chunks, exact ranking costs less than a
tenth of an empty embedding call, so an approximate index would save nothing
the caller could observe, and DYLAN's shared filtered graph would traverse
vectors the caller is not authorized to read. The isolation model and
re-opening criteria below say what a future backend must meet.

## The current exact path

[`crates/mneme-recall/src/semantic.rs`](../crates/mneme-recall/src/semantic.rs)
ranks every eligible chunk exactly. Eligibility is decided before any vector
exists: the semantic index is built from the already-authorized recall index,
which holds only records the request's scope, revision, temporal mode,
retention barriers and status flags admit, and it is cached under that
revision, scope and eligibility generation. Each chunk is embedded by an
operator-configured worker. A query's vector is compared with every chunk by
one dot product of L2-normalized `f64` vectors, the best chunk represents its
candidate (`MaximumChunkCosine`), and candidates are sorted by score and then
identity. A corpus over 512 chunks, or over the profile's float budget, makes
semantic mode unavailable rather than sampled.

`semantic_ranking_embeds_and_returns_only_authorized_current_text` in
[`crates/mneme-recall/tests/recall.rs`](../crates/mneme-recall/tests/recall.rs)
pins this down with a worker that logs everything it is asked to embed.
Another scope's text never reaches the embedder, and a source pruned since the
last ranking is neither embedded nor returned by the next one, because the new
eligibility generation rebuilds the index.

## Measured cost

`cargo run --release -p mneme-recall --example exact_cosine_cost` times the
operations ranking performs, on deterministic synthetic unit vectors with four
chunks per candidate, and the round trip of an embedding worker that does no
inference: it reads its request and returns one fixed vector through the real
supervisor. Medians of nine runs on 2026-11-17 on the development host (AMD
Ryzen AI MAX+ 395, 32 threads, load average about 13 from other work), release
build, Rust 1.99.1:

| Chunks | Dimensions | Median exact ranking |
|-------:|-----------:|---------------------:|
| 512 | 768 | 188 µs |
| 512 | 4,096 | 1.07 ms |
| 2,048 | 768 | 751 µs |
| 8,192 | 768 | 3.04 ms |
| 8,192 | 4,096 | 19.5 ms |
| 32,768 | 768 | 12.4 ms |
| 131,072 | 384 | 27.1 ms |
| 131,072 | 768 | 53.0 ms |

The empty embedding round trip took **5.78 ms**; a real model adds its own
inference to that, once per query, before any ranking can start. Exact ranking
grows linearly and reaches the cost of the empty round trip only near 16,000
chunks at 768 dimensions, thirty times the recall bound. Below that, an
approximate index cannot make a request measurably faster. It would add an
index to build, keep current and purge. Not measured: real model inference,
memory bandwidth contention, and approximate-index build or update times.

## Why not DYLAN's shared filtered graph

[DYLAN](https://arxiv.org/abs/2611.12539) keeps one HNSW-like graph per label
set and answers a filtered query by navigating shared graphs with a label trie.
Its released search computes distances to graph nodes before it checks whether
a node satisfies the filter, so a query traverses, and measures its distance to,
vectors its caller may not read. Label filtering of that kind is a ranking
device, not a security boundary: the distances leak through timing and through
which neighbours are expanded, and a scope that a label does not describe, such
as a revoked grant or a forgotten record, has no label to filter on. Mneme's
authorization, retention barriers and erasure therefore cannot be expressed as
DYLAN labels over one shared graph. The only acceptable shape is a partition per
authorization boundary. With partitions, each one would be no larger than the
corpus a single request may read, and that corpus is what exact ranking already
handles within the bound.

## What a future backend must meet

Re-opening this decision needs a design that keeps every rule the exact path
has:

- **Eligibility before construction.** Only records the caller's
  authorization, scope, revision, temporal mode, status flags, retention and
  erasure generation admit enter the index. Traversal never reaches another
  authorization boundary's vectors, so isolation does not rest on filtering.
- **Labels are not authorization.** Stable external label identifiers, their
  frequency-order mapping, the supported Boolean predicates and the provenance
  of every label are specified. Authorization is never encoded as a
  user-controllable topic tag.
- **A backend-neutral seam with an oracle.** Exact cosine remains the oracle
  and the fallback. The seam keeps maximum-chunk aggregation, source identity,
  the index version, deterministic ties and bounded response packing. An
  approximate result is non-exhaustive: an empty result never establishes
  absence.
- **Change and erasure.** Update, withdrawal, revocation, erasure, tombstone
  reclamation and rebuild are specified. An asynchronous result is
  revalidated against the current eligibility generation before delivery.
- **Numerics, concurrency and bounds.** Equivalence of `f64` normalized
  cosine and `f32` squared L2 is measured, not assumed. Search must not
  mutate shared state, as upstream visit stamps do. Memory and work are
  bounded.
- **Retention before persistence.** No derived vector or index is persisted
  until its retention inventory, purge and crash recovery are specified.

Re-open when all of these hold:

1. The recall bound on semantic chunks is raised to a size where measured exact
   ranking exceeds the measured embedding round trip.
2. [Memory Lab #4](https://github.com/OnixResearch/memory-lab/issues/4)
   establishes a quality-preserving crossover on real workloads.
3. A partitioned design meets the isolation model above.
