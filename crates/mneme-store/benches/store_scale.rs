//! Criterion micro-benchmarks for `mneme-store` 10k-note save and
//! SQLite metadata-projection lookup latency (`query_entities` / `query_documents`).

#![allow(
    unknown_lints,
    no_unwrap,
    function_length,
    allocation_in_loop,
    unbounded_collection_growth,
    platform_dependent_cast,
    raw_arithmetic_overflow,
    magic_number,
    explicit_defaults,
    non_trait_imports
)] // benchmark harness constructs 10k-note fixtures, uses criterion macros, and asserts via expect
#![allow(clippy::expect_used, clippy::unwrap_used)] // benchmark harness asserts via expect

use criterion::{Criterion, black_box, criterion_group, criterion_main};

const NOTE_COUNT: u32 = 10_000;

fn bench_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "bench-scale").expect("scope")
}

fn note_record_id(tag: u8, idx: u32) -> mneme_core::RecordId {
    let mut raw = [0_u8; 16];
    raw[0] = tag;
    raw[1..5].copy_from_slice(&idx.to_be_bytes());
    mneme_core::RecordId::from_bytes(raw)
}

fn note_revision_id(tag: u8, idx: u32, generation: u32) -> mneme_core::RevisionId {
    let mut raw = [0_u8; 16];
    raw[0] = tag;
    raw[1..5].copy_from_slice(&idx.to_be_bytes());
    raw[5..9].copy_from_slice(&generation.to_be_bytes());
    mneme_core::RevisionId::from_bytes(raw)
}

fn seed_ten_thousand_notes() -> (
    tempfile::TempDir,
    mneme_store::Workspace,
    mneme_core::RevisionId,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ws = mneme_store::Workspace::create(
        dir.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_000),
            )),
            faults: Box::new(mneme_store::NoFaults),
        },
    )
    .expect("create workspace");
    let genesis = ws.current_revision().expect("genesis");

    let mut records = Vec::with_capacity(NOTE_COUNT as usize);
    for idx in 0..NOTE_COUNT {
        records.push(mneme_store::RecordDraft {
            schema_version: 3,
            kind: mneme_core::RecordKind::Entity,
            record_id: note_record_id(0x10, idx),
            revision_id: note_revision_id(0x10, idx, 0),
            predecessor: None,
            scope: bench_scope(),
            payload: mneme_core::Payload::new([
                (
                    mneme_core::Symbol::from("entity-type"),
                    mneme_core::Value::symbol("note"),
                ),
                (
                    mneme_core::Symbol::from("label"),
                    mneme_core::Value::string(format!("Note {idx:05}")),
                ),
                (
                    mneme_core::Symbol::from("properties"),
                    mneme_core::Value::symbol_dictionary([(
                        mneme_core::Symbol::from("external-id"),
                        mneme_core::Value::string(format!("note/{idx:05}.adoc")),
                    )]),
                ),
            ]),
        });
    }

    ws.commit(mneme_store::CommitCommand {
        base: genesis,
        actor: "bench".to_owned(),
        scope: bench_scope(),
        idempotency_key: "seed-10k-notes".to_owned(),
        records,
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })
    .expect("commit 10k notes");

    (dir, ws, note_revision_id(0x10, 0, 0))
}

fn bench_store_10k_scale(c: &mut Criterion) {
    let (_dir, mut ws, mut last_rev) = seed_ten_thousand_notes();
    let scope = bench_scope();
    let target_ext = "note/05000.adoc".to_owned();

    let mut group = c.benchmark_group("store_10k_notes");

    group.bench_function("metadata_entity_lookup_by_external_id", |b| {
        b.iter(|| {
            let page = ws
                .query_entities(black_box(&mneme_store::EntityQuery {
                    scope: Some(scope.clone()),
                    entity_type: Some("note".to_owned()),
                    external_id: Some(target_ext.clone()),
                    after: None,
                    limit: Some(10),
                }))
                .expect("query entity");
            assert_eq!(page.items.len(), 1);
            black_box(page.items.len())
        });
    });

    group.bench_function("metadata_paged_scan_100", |b| {
        b.iter(|| {
            let page = ws
                .query_entities(black_box(&mneme_store::EntityQuery {
                    scope: Some(scope.clone()),
                    entity_type: Some("note".to_owned()),
                    external_id: None,
                    after: None,
                    limit: Some(100),
                }))
                .expect("paged entity query");
            assert_eq!(page.items.len(), 100);
            black_box(page.items.len())
        });
    });

    let mut save_gen: u32 = 1;
    group.bench_function("single_note_save_in_10k_vault", |b| {
        b.iter(|| {
            let base = ws.current_revision().expect("head");
            let next_rev = note_revision_id(0x10, 0, save_gen);
            let outcome = ws
                .commit(mneme_store::CommitCommand {
                    base,
                    actor: "bench".to_owned(),
                    scope: scope.clone(),
                    idempotency_key: format!("save-note-gen-{save_gen}"),
                    records: vec![mneme_store::RecordDraft {
                        schema_version: 3,
                        kind: mneme_core::RecordKind::Entity,
                        record_id: note_record_id(0x10, 0),
                        revision_id: next_rev,
                        predecessor: Some(last_rev),
                        scope: scope.clone(),
                        payload: mneme_core::Payload::new([
                            (
                                mneme_core::Symbol::from("entity-type"),
                                mneme_core::Value::symbol("note"),
                            ),
                            (
                                mneme_core::Symbol::from("label"),
                                mneme_core::Value::string(format!("Note 00000 v{save_gen}")),
                            ),
                            (
                                mneme_core::Symbol::from("properties"),
                                mneme_core::Value::symbol_dictionary([(
                                    mneme_core::Symbol::from("external-id"),
                                    mneme_core::Value::string("note/00000.adoc"),
                                )]),
                            ),
                        ]),
                    }],
                    source_blobs: Vec::new(),
                    publications: Vec::new(),
                    import_candidates: Vec::new(),
                    retention: None,
                })
                .expect("save single note");
            last_rev = next_rev;
            save_gen = save_gen.saturating_add(1);
            black_box(outcome.revision)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_store_10k_scale);
criterion_main!(benches);
