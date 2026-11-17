# Mneme Core

Mneme Core is the standalone Rust library workspace for Mneme's typed memory engine and its independently checked decision kernel. This public repository contains eleven libraries and the kernel's preserved Lean proof sources; it does not contain an application binary.

## Crate roles

- **`mneme-kernel`** — small decision functions for bounded arithmetic, identity, scope isolation, publication, cleanup, and related policy; its Rust source is translated and checked by the Lean gate.
- **`mneme-core`** — shared domain types, identifiers, typed records, transport encodings, and schema/version handling.
- **`mneme-store`** — durable workspace history, SQLite ledger, immutable source blobs, and publication/recovery operations.
- **`mneme-memory`** — attributed evidence, assertion lifecycle, support, and bounded explanations over stored snapshots.
- **`mneme-retention`** — scoped retention barriers, dependency-aware withdrawal, and accountable cleanup.
- **`mneme-doc`** — source-first AsciiDoc and Markdown handling, bounded includes, images, and safe previews.
- **`mneme-datalog`** — bounded, explainable relational projections over committed snapshots.
- **`mneme-recall`** — scoped lexical, structured, and local-vector recall. Semantic ranking stays exact; [docs/filtered-ann-feasibility.md](docs/filtered-ann-feasibility.md) records why an approximate index is not used. Entity-seeded expansion is an opt-in structured profile (`mneme_recall::expansion`); [docs/entity-seeded-recall.md](docs/entity-seeded-recall.md) records why it is not used for reader-facing recall yet.
- **`mneme-consolidation`** — evidence-preserving proposal generation and resumable workspace jobs.
- **`mneme-prolog`** — optional bounded Prolog capability contracts and isolated engine execution.
- **`mneme-api`** — transport-neutral local memory commands and queries.

The workspace keeps the original crate names, public Rust APIs, Rust 1.99.1 toolchain pin, lint policy, and release overflow checks. No schema or runtime behavior is changed by this extraction.

Stored records use the canonical binary Preserves profile, whose reader refuses compound nesting deeper than 40 levels and integers wider than 4,096 bytes. Record validation applies the same limits to a record's complete envelope value, retained unknown fields included, so a typed commit or a migration is refused before anything is written unless a fresh handle can read it back.

A model-consolidation job runs under an exclusive claim on its scope and job id, taken before its progress is loaded and held until its last save. The claim is an operating-system lock on a store-owned file under `jobs/`, so a second runner of the same job, from any handle or process, is refused as busy instead of reserving or dispatching the same input; the claim also binds the job to its first progress destination, so naming another one is refused rather than starting a second history. Unrelated jobs, commits and retention keep running during inference. A runner that dies releases its claim with its process, and the next runner resumes the saved progress: charged reservations stay charged and an uncertain attempt is never dispatched again automatically.

## Provenance and preserved history

The source is **`OnixResearch/mneme` at commit `b77325d65aa2904f45234d1d9029081988a9b981`**, titled “Add retained images and verify weighted retrieval fusion.” The repository was filtered from that source history into a core-only history; the filtered starting revision is `7c8fcb894a827baeee75d29cf9f49ba5e31b6ae7`, with 75 source commits preserved. The 11 crate trees and `proofs/kernel` retain their source paths, Git blobs, and file modes from the cited source commit. Root build and developer tooling are adapted for the standalone library workspace.

The kernel proof owner is this repository: `crates/mneme-kernel` and `proofs/kernel` are kept together. Consumers should pin one exact `mneme-core` revision and run that revision's `scripts/verify-kernel-proofs.mjs`; the verifier locates its Rust kernel, proof sources, and lockfile relative to its own checkout.

## Media recognition and schema v5

The production schema registry reads record schema versions 1 through 5. The
v4 schema added `comment`; v5 (`media-recognition`) keeps the earlier
definitions and adds typed media provenance. Existing v1-v4 envelopes keep
their original schema versions and remain readable: the closed acquisition
classes below apply only from v5, so an older source with another acquisition
symbol reads as `imported` and keeps its stored symbol, which pruning and API
output re-emit unchanged. The registry does not
silently rewrite stored records: use the explicit `Migration` API when a
payload transformation is required. A migration produces a new immutable
revision whose predecessor is the input revision; it never invents capture,
recognition, or correction provenance for a historical source.

In v5, `SourceRevision` declares an `Acquisition` (`authored`, `imported`,
`captured`, `machine-recognized`, or `corrected`) and may pin a parent source,
a typed media extent, a transform, and correction provenance. Audio extents
include a rational seconds-per-tick time base and channel count; page and ink
extents declare addressable page counts. A page or ink source may declare its
page frame (`media-frame`), and image import records the decoded pixel size; a
page region must use that frame, or normalized coordinates when the source
declares none. An ink source declares its stroke ids by page and layer
(`ink-strokes`), and a segment's strokes must be among them. A processed
derivative's transform must map its own declared frame onto its parent's. A
`RecognitionRun` pins input and
output source revisions and digests, model/runtime/adapter/preprocessing and
configuration identities, coverage and status, plus optional scores and
alternatives; its machine text is committed in the same batch, and it names
at most 4,096 segments. A run declares the part of its capture it covers
(`covers`): the whole capture, one page, or a half-open audio interval within
the capture's extent. A run that declares none covers the whole capture, and
its segments on the capture itself must lie within its part. Each `RecognitionSegment` pins its text source and inclusive
`SourceSpan` byte offsets, media source revision and digest, and typed audio,
page-region, or ink-stroke location. Text spans remain byte offsets into the
exact UTF-8 source revision; media coordinates never change that contract.

Captured media is separate from its machine-recognized text derivative. A
human correction is another immutable text revision with a predecessor and
edit provenance; alignments must pin that corrected revision or be explicitly
invalidated. Reprocessing creates new recognized text and recognition-run
records rather than replacing corrected text. These records make recognized
text searchable as evidence, but recognition does not accept or promote an
assertion.

A capture recognized more than once may have several texts. `View::capture_texts`
takes them in order of preference:

1. a text whose bytes are retained, before a pruned or erased one;
2. a corrected text, before machine output;
3. a complete run's text, before a partial, failed or cancelled one;
4. the most recently committed.

It selects each text unless the texts already selected cover all of its part.
The rest are alternatives, kept in history. Reprocessing a part replaces older
machine output of that part only, and a part nothing newer covers keeps its
text. Reprocessing never displaces retained text a person corrected, and
choosing a reprocessed result is a correction of it. Where a newer text covers
only some of an older one's part, both are selected and searched. A text that
two runs name appears once, with the part of the run committed first. Current
and historical recall search only selected texts; inspection recall also
returns alternatives. Forgetting an original forgets every derivative, including a
transcript corrected since: a correction's own revision chain is followed back
to the source it was derived from. Exchange bundles carry only current
revisions, so a corrected source, a run or segment pinning a non-current
revision, and everything depending on them are left out of export rather than
failing the receiver's import.

The shared API exposes `recognition.read` with a scoped `{scope, run}` payload.
It returns the run's exact source pins and digests, model/runtime configuration,
bounded recognized text, source acquisition/transform metadata, coverage/status,
and its bounded segment mappings, each with `original-location`: where a region
on a processed image lies on the original. A response holds at most 8 MiB of
encoded text and segments. The service checks caller authorization,
source ancestry and digest identity, and the current retention eligibility
barrier before returning the result.

`mneme_consolidation::recognition` runs durable recognition jobs over a
committed capture, which needs no recognizer to exist: a job can be queued
with the capture and run later. A job divides the capture into units (its
pages, bounded audio intervals, or the whole of an audio or single-page
capture), runs only when its access includes its scope, claims itself through
`Workspace::claim_job`, and keeps content-free progress beside the claim: unit
states, attempts, published run identities and charged resources. Each unit is
reserved durably before its worker starts. The worker reads one JSON header
line and then exactly the capture's bytes on stdin (`invoke_media`, bounded to
256 MiB of media, 4 MiB of answer and 30 minutes per unit), never a path or an
environment, and answers with text, inclusive byte spans and locations within
the unit. The capture is checked again before its bytes reach each worker and
before each publication: it must still be the planned revision, retained,
unchanged and unforgotten. A valid answer is published as its own
recognition run, committed at the revision that check read, and retried
after a fresh check when the workspace moved in between; recognized text
exists only in those records, so forgetting the capture reaches it through
the normal retention rules. Malformed, oversized or misaligned answers are
rejected before publication, a timeout or cancellation reaps the worker, an
unavailable recognizer leaves units waiting without spending their attempts,
and a capture beyond the unit bound is reported unsupported. A runner that
stops after dispatching a unit
leaves it uncertain unless its deterministic run was already committed; an
uncertain unit is never dispatched again automatically, and an explicit retry
is a new, charged attempt.

## Development and verification

The source can be cloned without authentication. The pinned Nix environment
still fetches private OnixResearch verification tooling (Octet and its
dependencies), so those Nix commands require authorized SSH access. The Cargo
library workspace itself uses only local crates and crates.io dependencies.

Enter the pinned development shell to obtain Rust 1.99.1, the pinned Octet runner, the real Scryer Prolog test engine, and—on `x86_64-linux`—the matching Charon/Aeneas/Lean tools:

```sh
nix develop
```

From the repository root:

```sh
just rust-format-check
just rust-lint
just rust-test
just rust-doctest
just rust-check
just octet
just octet-all
just proofs
```

Equivalent Cargo commands are:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --workspace --doc --all-features
```

`just octet` runs the strict required profile in `dylint.toml`, without a baseline. `just octet-all` runs the full-catalog profile from `dylint-all.toml` in an isolated Nix source copy and compares findings with `octet-baseline.json`, keeping the strict profile untouched. Baseline debt does not suppress strict findings.

The all-lint baseline contains 1,574 accepted finding identities in the same
ten lint families as the extracted engine-owned baseline (1,228 identities):
issue-driven additions were refactored until no finding outside those families
remained, and the rest were reviewed before regeneration with the pinned
runner. New or stale identities require that same review; an accepted
baseline is recorded debt, not an all-lint-clean claim. The strict
profile must remain clean without a baseline.

`just proofs` runs the preserved source-to-Lean translation and audits all 128 inventoried kernel theorems against the Rust kernel, checked-in translation, and allowed Lean axioms. It is intentionally a developer/consumer workflow, not a sandboxed Nix check: Lake may fetch proof dependencies. Run it from the pinned development shell on `x86_64-linux`; the shell selects the Charon-matched extraction toolchain. The consumer-side completion gate should execute the verifier from the exact Git revision it compiles.

`nix flake check` provides the standalone Nix Rust build, Rust formatting check, and both Octet profiles. The flake and development shell require no desktop, GUI toolkit, or sibling application checkout.

## Repository status and licensing

This repository is publicly readable. No `LICENSE` or `NOTICE` file existed at the cited source commit, and this extraction adds neither. **Public visibility does not add a license grant.**
