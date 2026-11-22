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
(`covers`): the whole capture, one page, a selected region of one page, or a
half-open audio interval within the capture's extent. A region carries the
caller's 16-byte key for its exact selection (for ink, the selected strokes):
other regions of the page stay selected beside it, the same key replaces only
itself, and a reading of the whole page covers every region of it. A run that
declares none covers the whole capture, and
its segments on the capture itself must lie within its part. Each `RecognitionSegment` pins its text source and inclusive
`SourceSpan` byte offsets, media source revision and digest, and typed audio,
page-region, or ink-stroke location. Optional `block` metadata retains a
bounded backend block identity and label, its reported reading order (or
explicitly unknown order), and one of `literal`, `structure`, or
`interpretation`. A reconstructed equation/table or a diagram description
does not silently become a literal reading. Older segments omit this metadata;
its absence does not invent a reading classification. Text spans remain byte
offsets into the exact UTF-8 source revision; media coordinates never change
that contract.

A run may retain a versioned `page` processing report: input and processed
raster dimensions, an invertible quarter-turn orientation, and up to 128
normalized original-page regions each for missing blocks and detections.
Identities, labels and optional order remain provider metadata, not words or
verified assertions. Declared image frames and the selected original page are
checked before publication. Reported readable/missing block counts must agree
with the run's segments; a no-detection report leaves block coverage unknown,
not an invented 0/0 or evidence that the original is blank. Text-empty reports
remain durable and inspectable. Page-only reruns cannot displace retained
readable text; a person's deliberate empty correction still has precedence.
Older readers retain unknown fields but do not provide these page-aware
selection/inspection semantics, so upgrade every participating device.

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
3. among machine output, a complete run's text before a partial, failed or
   cancelled one;
4. the most recently committed.

It selects each text unless the texts already selected cover all of its part.
The rest are alternatives, kept in history. Reprocessing a part replaces older
machine output of that part only, and a part nothing newer covers keeps its
text. Reprocessing never displaces retained text a person corrected, and
choosing a reprocessed result is a correction of it. Where a newer text covers
only some of an older one's part, both are selected and searched. A text that
two runs name appears once, with the part of the run committed first. A
pruned capture keeps its extent, so its texts are selected the same way after
pruning. Current
and historical recall search only selected texts; inspection recall also
returns alternatives. Forgetting an original forgets every derivative, including a
transcript corrected since: a correction's own revision chain is followed back
to the source it was derived from. Exchange bundles carry only current
revisions, so a corrected source, a run or segment pinning a non-current
revision, and everything depending on them are left out of export rather than
failing the receiver's import.

An exchange bundle carries sources of up to 1 MiB inside it, within 2 MiB.
An export that does not fit is a version 2 bundle (`mneme-record-exchange-v2`),
and each of its retained sources over 64 KiB travels beside it as an asset of
at most 256 MiB, cut into 1 MiB chunks. The bundle signs each asset's source
revision, scope, digest, length and media type, the digest of every chunk, and
the bundle records that depend on the source; authentication refuses an entry
that differs from its signed source record. `asset_chunk` reads a chunk for
sending. `grant_asset` selects one current, shared, unforgotten source by its
record and revision, never by digest, and refuses every other request in the
same way. A receiver checks each chunk against the digest signed for its place
and keeps it under `transfers/<signer key id>/<digest>/`, beside the blob store
and never in it. Chunks may arrive in any order, more than once and across
restarts, within 1 GiB for all pending transfers: a transfer starts only when
its whole asset fits beside the room every started transfer holds, and a
started transfer keeps every chunk, so it always finishes. Until every chunk
is here and the whole asset hashes to its digest, `import_records` defers the
source and everything that depends on it, including text recognized from it,
and reports them; a later import of the same bundle publishes them, parents
before what needs them, up to 512 MiB of assets per import. A derived asset's
transfer starts only once every asset it needs is here whole (`AssetWaiting`
until then), so it never takes room its parent needs. What waits for an asset
still arriving is decided before any bytes are read, and keeps its own chunks.
Bytes a source of the asset's own scope already holds are used without
chunks; bytes held in another scope never are. `wanted_chunks` names the
chunks a transport still needs to send, parents first; `pending_assets`,
`transfer_usage` and `media_arrival` report what is arriving, and a pending
source is never in the ledger. `release_untrusted` removes transfers from keys
no longer trusted, and `release_unnamed` those none of an issuer's current
bundles names; a manifest that cannot be read names nothing arriving. A
chunk of a forgotten source, or of bytes whose replay a forget blocks, is
refused and its transfer removed; applying a barrier the first time removes
what arrived of its source or bytes, an import refuses the asset, and a local
forget searches pending transfers as one of its cleanup locations. A small
export is still a version 1 bundle. A reader that knows only version 1 refuses
a version 2 bundle as malformed, so every device exchanging larger originals
must be upgraded; this reader refuses later versions as an unsupported profile.

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
the unit. A segment may supply a `block` object with `reading`, `identity`,
`label` and optional `order`; identities/labels are bounded to 128 UTF-8 bytes,
and labels contain ASCII letters, digits, underscores or hyphens. An answer
may report up to 128 provider `scores` (`provider`, `metric`, finite `value`)
and 128 `alternatives` (`text`, optional finite `score`). These remain raw
provider telemetry, not calibrated confidence; a missing value is not zero.
Publication and `recognition.read` retain these fields, and unknown reading
kinds or malformed metadata reject the unit before any text is published.
The capture is checked again before its bytes reach each worker and
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

`UnitPlan::Page { page }` dispatches only that original page, without renumbering
it or repeatedly recognizing one selection as if it covered every page;
`UnitPlan::Region { page, key }` dispatches only that page and publishes a run
covering the region, never the page. Worker
answers may explicitly report `partial` plus `coverage:{completed,total}`;
partial answers require those counts. Legacy complete answers without counts
retain their unit-level 1/1 behavior. When a page report omits block coverage,
that unit-level completion is not detected-block or exhaustive-page coverage.

## Development and verification

The source can be cloned without authentication. Every pinned flake input,
including Octet and its Cairn, Valence and artifact dependencies, is fetched
over HTTPS from its public repository, so the Nix commands need no SSH key,
token, or other credential. The Cargo library workspace itself uses only local
crates and crates.io dependencies.

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

The all-lint baseline contains 1,946 accepted finding identities in the same
ten lint families as the extracted engine-owned baseline (1,228 identities):
issue-driven additions were refactored until no finding outside those families
remained, and the rest were reviewed before regeneration with the pinned
runner. New or stale identities require that same review; an accepted
baseline is recorded debt, not an all-lint-clean claim. The strict
profile must remain clean without a baseline.

`just proofs` runs the preserved source-to-Lean translation and audits all 128 inventoried kernel theorems against the Rust kernel, checked-in translation, and allowed Lean axioms. It is intentionally a developer/consumer workflow, not a sandboxed Nix check: Lake may fetch proof dependencies. Run it from the pinned development shell on `x86_64-linux`; the shell selects the Charon-matched extraction toolchain. The consumer-side completion gate should execute the verifier from the exact Git revision it compiles.

`nix flake check` provides the standalone Nix Rust build, Rust formatting check, and both Octet profiles. The flake and development shell require no desktop, GUI toolkit, or sibling application checkout.

### Continuous integration

[`.github/workflows/verify.yml`](.github/workflows/verify.yml) runs on every
push to `main`, every pull request, and on demand. It asks for `contents: read`
only, uses no repository secret, persists no checkout credential, and has no
`pull_request_target` workflow. The checkout and Nix installer actions are
pinned to full commits, and every flake input is pinned in `flake.lock`.
The pinned Octet UI library also fetches a public `bounded-exec` revision
directly over SSH. The workflow rewrites that one URL to anonymous HTTPS
in the runner's Git configuration; it does not change the revision or hash.

The job runs the same gate as a local checkout:

```sh
nix flake check --no-update-lock-file --keep-going --max-jobs 2
```

That is the standalone Nix Rust build, Rust formatting check, and both Octet
profiles, including the workspace's own Clippy, test, and doctest commands. It
installs Nix 2.36.0 on `ubuntu-24.04` and runs with a 240-minute timeout after
reclaiming disk from preinstalled toolchains the job does not use. A failing
check fails the job.

The proof gate is not run by CI: `just proofs` needs the Charon, Aeneas and Lean
tools from the `x86_64-linux` development shell, builds the Lean proofs, and
Lake may fetch proof dependencies, so it remains a separate
developer/consumer workflow rather than a sandboxed flake check. Run it from
the pinned shell with `nix develop --command just proofs`, as described above;
the consumer-side completion gate should execute
`scripts/verify-kernel-proofs.mjs` from the exact revision it compiles.

To reproduce the CI gate locally without an SSH key, use the same transport
rewrite in your Git configuration and the command above. No repository secret
or SSH agent is needed.

## Repository status and licensing

This repository is publicly readable. Except where otherwise noted, Mneme Core
is dual-licensed under the MIT License or Apache License 2.0, at your option.
See [LICENSE](LICENSE), [MIT](LICENSE-MIT), and [Apache-2.0](LICENSE-APACHE).
Separate dependencies and third-party material keep their own license terms.
