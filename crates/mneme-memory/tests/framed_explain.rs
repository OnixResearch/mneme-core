//! End-to-end tests verifying `View::explain` succeeds on Zstd (`MNZSTD01`),
//! Zstd-dictionary (`MNZSTD02`), and FastCDC (`MNCDC01\0`) source blobs.
#![allow(
    unknown_lints,
    no_unwrap,
    assertion_density,
    function_length,
    allocation_in_loop,
    too_many_parameters,
    numeric_units,
    platform_dependent_cast,
    raw_arithmetic_overflow,
    magic_number
)] // integration tests assert via expect
#![allow(clippy::expect_used, clippy::unwrap_used)] // integration tests assert via expect

fn test_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn draft(envelope: &mneme_core::RecordEnvelope) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: envelope.schema_version,
        kind: envelope.kind,
        record_id: envelope.record_id,
        revision_id: envelope.revision_id,
        predecessor: envelope.predecessor,
        scope: envelope.scope.clone(),
        payload: envelope.payload.clone(),
    }
}

fn batch(
    scope: &mneme_core::ScopeId,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    sources: Vec<mneme_store::SourceBlobDraft>,
) -> mneme_memory::Batch {
    mneme_memory::Batch {
        actor: "test-author".to_owned(),
        scope: scope.clone(),
        idempotency_key: key.to_owned(),
        records,
        source_blobs: sources,
        publications: Vec::new(),
    }
}

fn synthetic_large_note(lines: usize, needle: &str) -> (Vec<u8>, u64, u64) {
    let mut out = Vec::with_capacity(lines.saturating_mul(80));
    let mut needle_start = 0_u64;
    let mut needle_end = 0_u64;
    let target_line = lines / 2;
    for index in 0..lines {
        if index == target_line {
            needle_start = out.len() as u64;
            out.extend_from_slice(needle.as_bytes());
            needle_end = out.len() as u64;
            out.push(b'\n');
            continue;
        }
        let mixed = (index as u64)
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let line = format!(
            "== Section {index:05} ({mixed:016x})\nParagraph body for line {index} token={:08x}.\n",
            (mixed >> 32) & 0xffff_ffff
        );
        out.extend_from_slice(line.as_bytes());
    }
    (out, needle_start, needle_end)
}

fn train_dict() -> Vec<u8> {
    let samples: Vec<Vec<u8>> = (0..64)
        .map(|i| {
            format!("== Section {i:05} (0123456789abcdef)\nParagraph body for line {i} token=deadbeef.\n")
                .into_bytes()
        })
        .collect();
    let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
    mneme_store::dedup::train_zstd_dictionary(&slices, 8 * 1024).expect("train dict")
}

fn explain_policy() -> mneme_memory::Policy {
    mneme_memory::Policy {
        max_explanation_nodes: 64,
        max_excerpt_bytes: 512,
    }
}

fn check_explain_with_framing(
    label: &str,
    expected_magic: &[u8; 8],
    configure: impl FnOnce(&mut mneme_store::Workspace),
) {
    let temp = tempfile::tempdir().expect("temp");
    let scope = test_scope();
    let mut workspace = mneme_store::Workspace::create(
        temp.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_000),
            )),
            faults: Box::new(mneme_store::NoFaults),
        },
    )
    .expect("create");
    configure(&mut workspace);

    let needle = "The framed blob verified excerpt is readable via View::explain.";
    let (source_bytes, start, end) = synthetic_large_note(3_500, needle);
    let source_digest = mneme_core::ContentDigest::of_source_bytes(&source_bytes);
    let source_id = rid(0x41);
    let source_rev = rev(0x42);
    let evidence_id = rid(0x43);
    let evidence_rev = rev(0x44);
    let assertion_id = rid(0x45);
    let assertion_rev = rev(0x46);

    {
        let mut memory = mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator);
        memory
            .commit(batch(
                &scope,
                "entity",
                vec![draft(&mneme_core::fixtures::entity())],
                Vec::new(),
            ))
            .expect("commit entity");
        let (source, blob) = mneme_memory::build_source(
            source_id,
            source_rev,
            &scope,
            mneme_memory::SourceOptions {
                bytes: &source_bytes,
                media_type: "text/asciidoc",
                entity: Some(mneme_core::fixtures::entity_id()),
                path_hint: Some("framed.adoc"),
            },
        )
        .expect("build source");
        memory
            .commit(batch(&scope, "source", vec![source], vec![blob]))
            .expect("commit source");

        let span = mneme_core::SourceSpan::new(start, end.saturating_sub(1)).expect("span");
        let evidence = mneme_memory::build_evidence(
            evidence_id,
            evidence_rev,
            &scope,
            mneme_memory::EvidenceOptions {
                assertion: assertion_id,
                source: source_id,
                source_revision: source_rev,
                span: Some(span),
                anchor: Some("framed-anchor"),
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        let assertion = mneme_memory::build_proposed_assertion(
            assertion_id,
            assertion_rev,
            &scope,
            mneme_memory::ProposedAssertionOptions {
                subject: mneme_core::fixtures::entity_id(),
                predicate: "framed-check",
                value: mneme_core::Value::string(label),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "test-author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    evidence_id,
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        memory
            .commit(batch(
                &scope,
                "assertion",
                vec![evidence, assertion],
                Vec::new(),
            ))
            .expect("commit assertion");
    }

    let blob_path = mneme_store::payload::blob_path(temp.path(), source_digest);
    let disk = std::fs::read(&blob_path).expect("read on-disk blob");
    assert!(
        disk.starts_with(expected_magic),
        "{label}: expected blob on disk to start with {expected_magic:?}"
    );
    assert!(
        !mneme_store::outboard::path(temp.path(), source_digest).exists(),
        "{label}: framed blob must not write .obao4"
    );

    let snapshot = workspace.snapshot().expect("snapshot");
    let view = mneme_memory::View::new(snapshot, temp.path());
    let explanation = view
        .explain(assertion_id, explain_policy())
        .expect("explain framed blob");
    assert_eq!(explanation.evidence.len(), 1);
    let item = &explanation.evidence[0];
    assert_eq!(
        item.availability,
        mneme_memory::SourceAvailability::Retained,
        "{label}: expected Retained availability"
    );
    let excerpt = item.excerpt.as_ref().expect("excerpt present");
    let excerpt_str = std::str::from_utf8(&excerpt.bytes).expect("utf8 excerpt");
    assert!(
        excerpt_str.contains(needle),
        "{label}: excerpt {excerpt_str:?} did not contain {needle:?}"
    );
}

#[test]
fn view_explain_succeeds_on_zstd_zstd_dict_and_fastcdc_blobs() {
    check_explain_with_framing("zstd-plain", b"MNZSTD01", |ws| {
        ws.set_blob_compression(mneme_store::BlobCompression::Zstd);
    });

    let dict = train_dict();
    check_explain_with_framing("zstd-dict", b"MNZSTD02", |ws| {
        let digest = ws.stage_zstd_dictionary(&dict).expect("stage dict");
        ws.set_blob_compression(mneme_store::BlobCompression::ZstdDictionary {
            dictionary: digest,
        });
    });

    check_explain_with_framing("fastcdc", b"MNCDC01\0", |ws| {
        let digest = ws.stage_zstd_dictionary(&dict).expect("stage dict");
        ws.set_blob_compression(mneme_store::BlobCompression::ZstdDictionary {
            dictionary: digest,
        });
        ws.set_blob_chunking(mneme_store::BlobChunking::FastCdc(
            mneme_store::FastCdcConfig::default(),
        ));
    });
}
