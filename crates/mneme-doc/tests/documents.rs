//! Source-first document behavior over real workspace blobs and commits.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::expect_used)]

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn entity_draft() -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Entity,
        record_id: mneme_core::fixtures::entity_id(),
        revision_id: rev(0x0b),
        predecessor: None,
        scope: scope(),
        payload: mneme_core::fixtures::entity().payload,
    }
}

fn entity_source_id() -> mneme_core::RecordId {
    mneme_core::fixtures::entity_id()
}

/// A second committed entity, so a binding test can name two real identities.
fn other_entity_id() -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([0x88; 16])
}

struct Harness {
    temp: tempfile::TempDir,
    workspace: mneme_store::Workspace,
}

impl Harness {
    fn new() -> Self {
        Self::with_faults(Box::new(mneme_store::NoFaults))
    }

    fn with_faults(faults: Box<dyn mneme_store::FaultInjector>) -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let mut workspace = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig {
                clock: Box::new(mneme_store::FixedClock::new(
                    mneme_core::Timestamp::from_nanos(1_000),
                )),
                faults,
            },
        )
        .expect("create");
        let base = workspace.current_revision().expect("base");
        workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "doc-test".to_owned(),
                scope: scope(),
                idempotency_key: "entity".to_owned(),
                records: vec![entity_draft()],
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("entity");
        Harness { temp, workspace }
    }

    fn reopen_with(&mut self, faults: Box<dyn mneme_store::FaultInjector>) {
        self.workspace = mneme_store::Workspace::open(
            self.temp.path(),
            mneme_store::WorkspaceConfig {
                clock: Box::new(mneme_store::FixedClock::new(
                    mneme_core::Timestamp::from_nanos(2_000),
                )),
                faults,
            },
        )
        .expect("open");
    }

    fn write_file(&self, path: &str, bytes: &[u8]) {
        mneme_store::payload::publish_working_file(self.temp.path(), path, bytes)
            .expect("working file");
    }

    fn request(
        &self,
        key: &str,
        document_id: Option<mneme_core::RecordId>,
        path: &str,
        title: Option<&str>,
    ) -> mneme_doc::ImportRequest {
        mneme_doc::ImportRequest {
            actor: "doc-author".to_owned(),
            scope: scope(),
            base_revision: self.workspace.current_revision().expect("base"),
            idempotency_key: key.to_owned(),
            document_id,
            path: path.to_owned(),
            title: title.map(str::to_owned),
            policy: mneme_doc::DocumentPolicy {
                allowed_roots: vec![String::new()],
                max_depth: 8,
                max_inputs: 64,
                max_total_source_bytes: 4 * 1024 * 1024,
                max_expanded_bytes: 8 * 1024 * 1024,
                max_time_ms: 1_000,
            },
            render_config: mneme_doc::RenderConfig {
                version: mneme_doc::RENDER_CONFIG_VERSION.to_owned(),
                include_entity_metadata: true,
                max_output_bytes: 8 * 1024 * 1024,
                max_time_ms: 1_000,
            },
        }
    }

    fn import(&mut self, request: mneme_doc::ImportRequest) -> mneme_doc::DocumentRevision {
        let mut documents = mneme_doc::Documents::new(&mut self.workspace);
        documents.import_working_file(request).expect("import")
    }

    fn commit_other_entity(&mut self) {
        let mut draft = entity_draft();
        draft.record_id = other_entity_id();
        draft.revision_id = rev(0x0d);
        let base = self.workspace.current_revision().expect("base");
        self.workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "doc-test".to_owned(),
                scope: scope(),
                idempotency_key: "entity-other".to_owned(),
                records: vec![draft],
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("other entity");
    }

    fn anchor_records(&self) -> Vec<mneme_core::RecordEnvelope> {
        self.workspace
            .snapshot()
            .expect("snapshot")
            .records
            .into_iter()
            .filter(|record| record.kind == mneme_core::RecordKind::DocumentAnchor)
            .collect()
    }

    fn binding_records(&self) -> Vec<mneme_core::RecordEnvelope> {
        self.workspace
            .snapshot()
            .expect("snapshot")
            .records
            .into_iter()
            .filter(|record| record.kind == mneme_core::RecordKind::DocumentBinding)
            .collect()
    }

    fn document_records(&self) -> Vec<mneme_core::RecordEnvelope> {
        self.workspace
            .snapshot()
            .expect("snapshot")
            .records
            .into_iter()
            .filter(|record| record.kind == mneme_core::RecordKind::Document)
            .collect()
    }

    fn working_file(&self, path: &str) -> Option<Vec<u8>> {
        mneme_store::payload::read_working_file(self.temp.path(), path).expect("working file")
    }

    fn entity_record(&self, entity: mneme_core::RecordId) -> mneme_core::RecordEnvelope {
        self.workspace
            .snapshot()
            .expect("snapshot")
            .records
            .into_iter()
            .find(|record| record.record_id == entity)
            .expect("entity record")
    }

    fn binding_request(
        &self,
        key: &str,
        document_id: mneme_core::RecordId,
        path: &str,
        entity: Option<mneme_core::RecordId>,
        publish: bool,
    ) -> mneme_doc::BindingRequest {
        mneme_doc::BindingRequest {
            import: self.request(key, Some(document_id), path, None),
            entity,
            publish,
        }
    }
}

fn bound_source(body: &str) -> String {
    format!(
        "= Cedar Notes\n:entity-id: {}\n\n{body}",
        entity_source_id().to_hex()
    )
}

#[test]
fn import_move_and_property_edit_preserve_identity_and_source_bytes() {
    let mut harness = Harness::new();
    let source =
        bound_source("The source keeps exact bytes.\n\n[[intro,Intro anchor]]\nIntroduction.\n");
    harness.write_file("docs/notes.adoc", source.as_bytes());
    let imported = harness.import(harness.request("import", None, "docs/notes.adoc", None));
    assert_eq!(imported.entity, Some(entity_source_id()));
    assert!(!imported.anchors.is_empty());
    assert_eq!(
        mneme_doc::Documents::new(&mut harness.workspace)
            .source_bytes(imported.document_id)
            .expect("source"),
        source.as_bytes()
    );
    let anchors = mneme_doc::Documents::new(&mut harness.workspace)
        .anchors(imported.document_id)
        .expect("anchors");
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].anchor, "intro");
    assert_eq!(
        &source[usize::try_from(anchors[0].span.expect("span").start()).expect("span start")
            ..=usize::try_from(anchors[0].span.expect("span").end()).expect("span end")],
        "[[intro,Intro anchor]]"
    );

    let move_base = harness.workspace.current_revision().expect("base");
    let moved = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .move_document(mneme_doc::MoveRequest {
                actor: "doc-author".to_owned(),
                scope: scope(),
                base_revision: move_base,
                idempotency_key: "move".to_owned(),
                document_id: imported.document_id,
                title: None,
                path: "docs/renamed.adoc".to_owned(),
            })
            .expect("move")
    };
    assert_eq!(moved.document_id, imported.document_id);
    assert_eq!(moved.source, imported.source);
    assert_eq!(moved.path, "docs/renamed.adoc");

    let entity_before = harness
        .workspace
        .snapshot()
        .expect("snapshot")
        .records
        .into_iter()
        .find(|record| record.record_id == entity_source_id())
        .expect("entity");
    let property_base = harness.workspace.current_revision().expect("base");
    mneme_doc::Documents::new(&mut harness.workspace)
        .edit_entity_property(mneme_doc::EntityPropertyEditRequest {
            actor: "doc-author",
            scope: &scope(),
            base_revision: property_base,
            idempotency_key: "property",
            entity_id: entity_source_id(),
            property: "status",
            value: Some(mneme_core::Value::string("reviewed")),
        })
        .expect("property edit");
    let entity_after = harness
        .workspace
        .snapshot()
        .expect("snapshot")
        .records
        .into_iter()
        .find(|record| record.record_id == entity_source_id())
        .expect("entity");
    assert_ne!(entity_before.revision_id, entity_after.revision_id);
    assert_eq!(
        mneme_doc::Documents::new(&mut harness.workspace)
            .source_bytes(imported.document_id)
            .expect("source"),
        source.as_bytes()
    );
    let _ = imported;
}

#[test]
fn conflicting_and_conditional_bindings_are_rejected_without_commit() {
    let mut harness = Harness::new();
    harness.commit_other_entity();
    let conflicting = format!(
        "= Cedar\n:entity-id: {}\n:entity-id: {}\n\nBody.\n",
        entity_source_id().to_hex(),
        other_entity_id().to_hex()
    );
    harness.write_file("docs/conflict.adoc", conflicting.as_bytes());
    let conflict_request = harness.request("conflict", None, "docs/conflict.adoc", None);
    let validation = {
        let documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .validate_working_file(conflict_request)
            .expect("conflict draft")
    };
    assert!(!validation.valid);
    assert!(
        validation
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "binding-conflict"),
        "two committed entities in one header are a binding conflict"
    );
    let retry_request = harness.request("conflict", None, "docs/conflict.adoc", None);
    let error = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .import_working_file(retry_request)
            .expect_err("conflict")
    };
    assert!(matches!(error, mneme_doc::DocumentError::Diagnostics(_)));
    assert!(harness.document_records().is_empty());

    let conditional = format!(
        "= Cedar\nifdef::flag[]\n:entity-id: {}\nendif::[]\n\nBody.\n",
        entity_source_id().to_hex()
    );
    harness.write_file("docs/conditional.adoc", conditional.as_bytes());
    let conditional_request = harness.request("conditional", None, "docs/conditional.adoc", None);
    let validation = {
        let documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .validate_working_file(conditional_request)
            .expect("validation")
    };
    assert!(!validation.valid);
    assert!(
        validation
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "binding-conditional")
    );
}

#[test]
fn invalid_external_edit_leaves_prior_revision_authoritative() {
    let mut harness = Harness::new();
    harness.write_file(
        "docs/edit.adoc",
        bound_source("Exact retained prose.\r\n").as_bytes(),
    );
    let imported = harness.import(harness.request("initial", None, "docs/edit.adoc", None));
    harness.write_file("docs/edit.adoc", b"= Cedar\n:entity-id: not-hex\n\nBroken");
    let bad_edit_request = harness.request(
        "bad-edit",
        Some(imported.document_id),
        "docs/edit.adoc",
        None,
    );
    let error = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .import_working_file(bad_edit_request)
            .expect_err("invalid edit")
    };
    assert!(matches!(error, mneme_doc::DocumentError::Diagnostics(_)));
    assert_eq!(
        mneme_doc::Documents::new(&mut harness.workspace)
            .source_bytes(imported.document_id)
            .expect("prior source"),
        bound_source("Exact retained prose.\r\n").as_bytes()
    );
}

#[test]
fn draft_validation_reports_candidate_without_mutating() {
    let mut harness = Harness::new();
    harness.write_file("docs/draft.adoc", b"= Draft\n\nCandidate body.\n");
    let before = harness.workspace.current_revision().expect("before");
    let draft_request = harness.request("draft", None, "docs/draft.adoc", None);
    let draft = {
        let documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .validate_working_file(draft_request)
            .expect("draft")
    };
    assert!(draft.valid);
    assert!(draft.preview_html.contains("Candidate body."));
    assert_eq!(harness.workspace.current_revision().expect("after"), before);
    assert!(draft.base_revision == before);
}

#[test]
fn stale_candidate_conflicts_and_preserves_newer_document() {
    let mut harness = Harness::new();
    harness.write_file("docs/stable.adoc", b"= Stable\n\nfirst\n");
    let first = harness.import(harness.request("first", None, "docs/stable.adoc", None));
    let stale_base = first.workspace_revision;
    harness.write_file("docs/stable.adoc", b"= Stable\n\nsecond\n");
    let second = harness.import(harness.request(
        "second",
        Some(first.document_id),
        "docs/stable.adoc",
        None,
    ));
    let mut stale_request =
        harness.request("stale", Some(first.document_id), "docs/stable.adoc", None);
    stale_request.base_revision = stale_base;
    let error = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .import_working_file(stale_request)
            .expect_err("stale")
    };
    assert!(matches!(
        error,
        mneme_doc::DocumentError::Store(mneme_store::Failure::StaleBase { .. })
    ));
    assert_eq!(
        mneme_doc::Documents::new(&mut harness.workspace)
            .source_bytes(first.document_id)
            .expect("source"),
        b"= Stable\n\nsecond\n"
    );
    let _ = second;
}

#[test]
fn includes_pin_dependencies_and_historical_preview_uses_the_old_closure() {
    let mut harness = Harness::new();
    harness.write_file("docs/part.adoc", b"= Part\n\nThe old included sentence.\n");
    let part = harness.import(harness.request("part", None, "docs/part.adoc", None));
    harness.write_file(
        "docs/root.adoc",
        b"= Root\n\nBefore include.\n\ninclude::part.adoc[]\n\nAfter include.\n",
    );
    let root = harness.import(harness.request("root", None, "docs/root.adoc", None));
    assert_eq!(root.includes.len(), 1);
    assert_eq!(root.includes[0].path, "docs/part.adoc");
    let old_root_revision = root.workspace_revision;
    {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        let preview = documents
            .preview(
                root.document_id,
                None,
                mneme_doc::RenderConfig {
                    version: mneme_doc::RENDER_CONFIG_VERSION.to_owned(),
                    include_entity_metadata: true,
                    max_output_bytes: 8 * 1024 * 1024,
                    max_time_ms: 1_000,
                },
            )
            .expect("preview");
        assert!(preview.source_available);
        assert!(preview.html.contains("old included sentence"));
        assert!(preview.html.contains("Before include"));
        assert_eq!(preview.occurrences.len(), 1);
        assert_eq!(preview.occurrences[0].target_path, "docs/part.adoc");
    }
    // Change the include source and import it; the old root closure is pinned.
    harness.write_file("docs/part.adoc", b"= Part\n\nThe new included sentence.\n");
    let new_part =
        harness.import(harness.request("part-2", Some(part.document_id), "docs/part.adoc", None));
    assert_ne!(new_part.source.revision, part.source.revision);
    {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        let historical = documents
            .preview(
                root.document_id,
                Some(old_root_revision),
                mneme_doc::RenderConfig {
                    version: mneme_doc::RENDER_CONFIG_VERSION.to_owned(),
                    include_entity_metadata: true,
                    max_output_bytes: 8 * 1024 * 1024,
                    max_time_ms: 1_000,
                },
            )
            .expect("historical preview");
        assert!(historical.html.contains("old included sentence"));
        assert!(!historical.html.contains("new included sentence"));
    }
    // Re-importing the root updates its closure to the new include revision.
    let new_root =
        harness.import(harness.request("root-2", Some(root.document_id), "docs/root.adoc", None));
    assert_eq!(new_root.includes[0].pin, new_part.source);
    {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        let current = documents
            .preview(
                root.document_id,
                None,
                mneme_doc::RenderConfig {
                    version: mneme_doc::RENDER_CONFIG_VERSION.to_owned(),
                    include_entity_metadata: true,
                    max_output_bytes: 8 * 1024 * 1024,
                    max_time_ms: 1_000,
                },
            )
            .expect("current preview");
        assert!(current.html.contains("new included sentence"));
        assert!(!current.html.contains("old included sentence"));
    }
}

#[test]
fn include_traversal_remote_cycle_and_limits_fail_closed() {
    let mut harness = Harness::new();
    harness.write_file("docs/part.adoc", b"= Part\n\nshared\n");
    harness.import(harness.request("part", None, "docs/part.adoc", None));
    for (key, body) in [
        ("traversal", "= Root\n\ninclude::../outside.adoc[]\n"),
        (
            "remote",
            "= Root\n\ninclude::https://example.invalid/x.adoc[]\n",
        ),
    ] {
        harness.write_file("bad.adoc", body.as_bytes());
        let request = harness.request(key, None, "bad.adoc", None);
        let validation = {
            let documents = mneme_doc::Documents::new(&mut harness.workspace);
            documents
                .validate_working_file(request)
                .expect("diagnostic draft")
        };
        assert!(!validation.valid);
        assert!(
            validation
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.fatal)
        );
    }
    // A missing required include is fatal; an optional one is diagnostic-only.
    harness.write_file("docs/required.adoc", b"= Root\n\ninclude::missing.adoc[]\n");
    let required_request = harness.request("required", None, "docs/required.adoc", None);
    let required = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .import_working_file(required_request)
            .expect_err("missing include")
    };
    assert!(matches!(required, mneme_doc::DocumentError::Diagnostics(_)));
    harness.write_file(
        "docs/optional.adoc",
        b"= Root\n\ninclude::missing.adoc[opts=optional]\n",
    );
    let optional_request = harness.request("optional", None, "docs/optional.adoc", None);
    let optional = {
        let documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .validate_working_file(optional_request)
            .expect("optional import")
    };
    assert!(optional.valid);
    assert!(
        optional
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "include-optional-missing")
    );

    // Two inputs exceed a one-input policy.
    let policy = mneme_doc::DocumentPolicy {
        max_inputs: 1,
        ..mneme_doc::DocumentPolicy {
            allowed_roots: vec![String::new()],
            max_depth: 8,
            max_inputs: 64,
            max_total_source_bytes: 4 * 1024 * 1024,
            max_expanded_bytes: 8 * 1024 * 1024,
            max_time_ms: 1_000,
        }
    };
    harness.write_file("docs/other.adoc", b"= Other\n\nother\n");
    harness.import(harness.request("other", None, "docs/other.adoc", None));
    harness.write_file(
        "docs/two.adoc",
        b"= Root\n\ninclude::part.adoc[]\n\ninclude::other.adoc[]\n",
    );
    let mut request = harness.request("two", None, "docs/two.adoc", None);
    request.policy = policy;
    let error = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .import_working_file(request)
            .expect_err("input limit")
    };
    assert!(matches!(error, mneme_doc::DocumentError::Diagnostics(_)));
}

#[test]
fn include_cycles_are_rejected() {
    let mut harness = Harness::new();
    harness.write_file("docs/a.adoc", b"= A\n\ninclude::b.adoc[]\n");
    // A is not importable until B exists.
    harness.write_file("docs/b.adoc", b"= B\n\nplain\n");
    harness.import(harness.request("b", None, "docs/b.adoc", None));
    harness.import(harness.request("a", None, "docs/a.adoc", None));
    harness.write_file("docs/b.adoc", b"= B\n\ninclude::a.adoc[]\n");
    let cycle_request = harness.request("b-cycle", None, "docs/b.adoc", None);
    let error = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .import_working_file(cycle_request)
            .expect_err("cycle")
    };
    assert!(matches!(error, mneme_doc::DocumentError::Diagnostics(_)));
}

#[test]
fn preview_escapes_active_content_and_unregistered_constructs() {
    let mut harness = Harness::new();
    let body = format!(
        "= Unsafe\n:entity-id: {}\n\n<script>alert(1)</script>\n\nlink:javascript:alert(1)[bad link]\n\nimage:https://example.invalid/x.png[alt]\n\npass:[secret]\n\nevil:target[]\n\n++++\n<img src=x onerror=alert(1)>\n++++\n",
        entity_source_id().to_hex()
    );
    harness.write_file("docs/unsafe.adoc", body.as_bytes());
    let imported = harness.import(harness.request("unsafe", None, "docs/unsafe.adoc", None));
    let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
    let preview = documents
        .preview(
            imported.document_id,
            None,
            mneme_doc::RenderConfig {
                version: mneme_doc::RENDER_CONFIG_VERSION.to_owned(),
                include_entity_metadata: true,
                max_output_bytes: 8 * 1024 * 1024,
                max_time_ms: 1_000,
            },
        )
        .expect("preview");
    assert!(!preview.html.contains("<script"));
    assert!(!preview.html.contains("<img"));
    assert!(preview.html.contains("&lt;img"));
    assert!(!preview.html.contains("href=\"javascript:"));
    assert!(preview.html.contains("&lt;script&gt;"));
    assert!(preview.html.contains("alt"));
    let codes = preview
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(codes.contains("raw-html-escaped"));
    assert!(codes.contains("external-navigation-not-automatic"));
    assert!(codes.contains("external-asset-not-fetched"));
    assert!(codes.contains("passthrough-inline-escaped"));
    assert!(codes.contains("unsupported-macro"));
    assert!(codes.contains("raw-passthrough-escaped"));
    assert!(preview.html.contains("data-projection=\"entity-metadata\""));
}

#[test]
fn repeated_includes_share_extraction_provenance() {
    let mut harness = Harness::new();
    harness.write_file("docs/part.adoc", b"= Part\n\nOne repeated sentence.\n");
    let part = harness.import(harness.request("part", None, "docs/part.adoc", None));
    harness.write_file(
        "docs/root.adoc",
        b"= Root\n\ninclude::part.adoc[]\n\ninclude::part.adoc[]\n\nRoot sentence.\n",
    );
    let root = harness.import(harness.request("root", None, "docs/root.adoc", None));
    let candidates = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .extract_proposals(root.document_id)
            .expect("extract")
    };
    let repeated = candidates
        .iter()
        .filter(|candidate| candidate.text.contains("One repeated sentence"))
        .collect::<Vec<_>>();
    assert_eq!(repeated.len(), 1);
    assert_eq!(repeated[0].source, part.source);
    assert_eq!(repeated[0].occurrences.len(), 2);
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.text.contains("Root sentence"))
    );
}

#[test]
fn binding_patch_changes_only_the_header_attribute() {
    let mut harness = Harness::new();
    let before = b"= Notes\n\nKeep this body byte-for-byte.\n";
    harness.write_file("docs/binding.adoc", before);
    let imported = harness.import(harness.request("binding", None, "docs/binding.adoc", None));
    let base = harness.workspace.current_revision().expect("base");
    let patched = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .patch_binding(mneme_doc::BindingRequest {
                import: mneme_doc::ImportRequest {
                    actor: "doc-author".to_owned(),
                    scope: scope(),
                    base_revision: base,
                    idempotency_key: "bind".to_owned(),
                    document_id: Some(imported.document_id),
                    path: "docs/binding.adoc".to_owned(),
                    title: None,
                    policy: mneme_doc::DocumentPolicy {
                        allowed_roots: vec![String::new()],
                        max_depth: 8,
                        max_inputs: 64,
                        max_total_source_bytes: 4 * 1024 * 1024,
                        max_expanded_bytes: 8 * 1024 * 1024,
                        max_time_ms: 1_000,
                    },
                    render_config: mneme_doc::RenderConfig {
                        version: mneme_doc::RENDER_CONFIG_VERSION.to_owned(),
                        include_entity_metadata: true,
                        max_output_bytes: 8 * 1024 * 1024,
                        max_time_ms: 1_000,
                    },
                },
                entity: Some(entity_source_id()),
                publish: false,
            })
            .expect("bind")
    };
    assert_eq!(patched.entity, Some(entity_source_id()));
    let bytes = mneme_doc::Documents::new(&mut harness.workspace)
        .source_bytes(imported.document_id)
        .expect("source");
    let expected = format!(
        "= Notes\n:entity-id: {}\n\nKeep this body byte-for-byte.\n",
        entity_source_id().to_hex()
    );
    assert_eq!(bytes, expected.as_bytes());
}

#[test]
fn publication_recovery_does_not_overwrite_an_external_edit() {
    let mut harness = Harness::new();
    harness.reopen_with(Box::new(mneme_store::FaultAt(
        mneme_store::FaultPoint::AfterCommit,
    )));
    let request = harness.request("publish", None, "docs/publish.adoc", None);
    let error = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .save_source(request, b"= Publish\n\ncommitted source\n")
            .expect_err("fault after commit")
    };
    assert!(matches!(
        error,
        mneme_doc::DocumentError::Store(mneme_store::Failure::InjectedFault(_))
    ));
    harness.reopen_with(Box::new(mneme_store::NoFaults));
    let committed = harness
        .workspace
        .snapshot()
        .expect("snapshot")
        .records
        .into_iter()
        .find(|record| record.kind == mneme_core::RecordKind::Document)
        .expect("document committed");
    let external = b"= Publish\n\nexternal edit\n";
    harness.write_file("docs/publish.adoc", external);
    let revision = harness.workspace.current_revision().expect("revision");
    let report = harness.workspace.recover().expect("recover");
    assert_eq!(
        harness.workspace.current_revision().expect("revision"),
        revision
    );
    assert_eq!(report.publications.len(), 1);
    assert_eq!(
        report.publications[0].state,
        mneme_store::PublicationState::Diverged
    );
    assert_eq!(
        mneme_store::payload::read_working_file(harness.temp.path(), "docs/publish.adoc")
            .expect("file"),
        Some(external.to_vec())
    );
    let _ = committed;
}

#[cfg(unix)]
#[test]
fn symlinked_working_file_cannot_escape_the_workspace() {
    let mut harness = Harness::new();
    let outside = harness.temp.path().join("outside.adoc");
    std::fs::write(&outside, b"= Outside\n\nsecret\n").expect("outside");
    let link = harness.temp.path().join("working/link.adoc");
    std::os::unix::fs::symlink(&outside, &link).expect("symlink");
    let request = harness.request("link", None, "link.adoc", None);
    let error = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .import_working_file(request)
            .expect_err("symlink escape")
    };
    assert!(matches!(error, mneme_doc::DocumentError::Store(_)));
}

#[test]
fn preview_cache_keys_cover_configuration_processor_dependencies_and_generation() {
    let mut harness = Harness::new();
    harness.write_file("docs/cache.adoc", b"= Cache\n\ncached\n");
    let imported = harness.import(harness.request("cache", None, "docs/cache.adoc", None));
    let artifact = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .preview(
                imported.document_id,
                None,
                mneme_doc::RenderConfig {
                    version: mneme_doc::RENDER_CONFIG_VERSION.to_owned(),
                    include_entity_metadata: true,
                    max_output_bytes: 8 * 1024 * 1024,
                    max_time_ms: 1_000,
                },
            )
            .expect("preview")
    };
    let key = artifact.key();
    let mut cache = mneme_doc::PreviewCache::new();
    assert!(cache.insert(artifact.clone()) == key);
    assert!(cache.get(&key).is_some());
    let mut changed = key.clone();
    changed.config_version.push_str("-other");
    assert!(cache.get(&changed).is_none());
    changed = key.clone();
    changed.processor_version.push_str("-other");
    assert!(cache.get(&changed).is_none());
    changed = key.clone();
    changed.generation += 1;
    assert!(cache.get(&changed).is_none());
    changed = key.clone();
    changed
        .includes
        .push(("docs/part.adoc".to_owned(), rid(0x70), rev(0x71)));
    assert!(cache.get(&changed).is_none());
    cache.invalidate_document(imported.document_id);
    assert!(cache.get(&key).is_none());
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

#[test]
fn unavailable_root_and_include_sources_are_reported_without_substitution() {
    let mut harness = Harness::new();
    harness.write_file("docs/part.adoc", b"= Part\n\nincluded text\n");
    let part = harness.import(harness.request("part", None, "docs/part.adoc", None));
    harness.write_file("docs/root.adoc", b"= Root\n\ninclude::part.adoc[]\n");
    let root = harness.import(harness.request("root", None, "docs/root.adoc", None));
    let part_view = mneme_doc::Documents::new(&mut harness.workspace)
        .document_by_path("docs/part.adoc")
        .expect("lookup")
        .expect("part");
    let digest = mneme_core::ContentDigest::of_source_bytes(b"= Part\n\nincluded text\n");
    assert!(mneme_store::payload::blob_path(harness.temp.path(), digest).exists());
    // Mark the included source unavailable while the root remains committed.
    let mut unavailable = mneme_memory::build_unavailable_source_with_digest(
        part_view.source.source,
        rev(0x72),
        &scope(),
        mneme_memory::UnavailableSourceWithDigestOptions {
            reason: "source bytes pruned under retention policy",
            availability: "pruned",
            prior_digest: Some(digest),
            entity: None,
            path_hint: Some("docs/part.adoc"),
        },
    );
    unavailable.predecessor = Some(part.source.revision);
    let base = harness.workspace.current_revision().expect("base");
    harness
        .workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "doc-test".to_owned(),
            scope: scope(),
            idempotency_key: "prune-part".to_owned(),
            records: vec![unavailable],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("unavailable source");
    let preview = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .preview(
                root.document_id,
                None,
                mneme_doc::RenderConfig {
                    version: mneme_doc::RENDER_CONFIG_VERSION.to_owned(),
                    include_entity_metadata: true,
                    max_output_bytes: 8 * 1024 * 1024,
                    max_time_ms: 1_000,
                },
            )
            .expect("preview")
    };
    assert!(preview.source_available);
    assert!(
        preview
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "include-unavailable")
    );
    assert!(!preview.html.contains("included text"));
    let _ = part;
}

#[test]
fn include_policy_depth_byte_roots_and_time_limits_fail_closed() {
    let mut harness = Harness::new();
    harness.write_file("docs/part.adoc", b"= Part\n\nincluded\n");
    harness.import(harness.request("part", None, "docs/part.adoc", None));
    harness.write_file("docs/root.adoc", b"= Root\n\ninclude::part.adoc[]\n");
    for policy in [
        mneme_doc::DocumentPolicy {
            max_depth: 0,
            ..mneme_doc::DocumentPolicy {
                allowed_roots: vec![String::new()],
                max_depth: 8,
                max_inputs: 64,
                max_total_source_bytes: 4 * 1024 * 1024,
                max_expanded_bytes: 8 * 1024 * 1024,
                max_time_ms: 1_000,
            }
        },
        mneme_doc::DocumentPolicy {
            max_total_source_bytes: 10,
            ..mneme_doc::DocumentPolicy {
                allowed_roots: vec![String::new()],
                max_depth: 8,
                max_inputs: 64,
                max_total_source_bytes: 4 * 1024 * 1024,
                max_expanded_bytes: 8 * 1024 * 1024,
                max_time_ms: 1_000,
            }
        },
        mneme_doc::DocumentPolicy {
            max_time_ms: 0,
            ..mneme_doc::DocumentPolicy {
                allowed_roots: vec![String::new()],
                max_depth: 8,
                max_inputs: 64,
                max_total_source_bytes: 4 * 1024 * 1024,
                max_expanded_bytes: 8 * 1024 * 1024,
                max_time_ms: 1_000,
            }
        },
        mneme_doc::DocumentPolicy {
            allowed_roots: vec!["other".to_owned()],
            ..mneme_doc::DocumentPolicy {
                allowed_roots: vec![String::new()],
                max_depth: 8,
                max_inputs: 64,
                max_total_source_bytes: 4 * 1024 * 1024,
                max_expanded_bytes: 8 * 1024 * 1024,
                max_time_ms: 1_000,
            }
        },
    ] {
        let mut request = harness.request("limits", None, "docs/root.adoc", None);
        request.policy = policy;
        let validation = {
            let documents = mneme_doc::Documents::new(&mut harness.workspace);
            documents
                .validate_working_file(request)
                .expect("diagnostic draft")
        };
        assert!(!validation.valid);
        assert!(
            validation
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.fatal)
        );
    }
}

#[test]
fn evidence_keeps_a_pinned_document_span_after_the_document_changes() {
    let mut harness = Harness::new();
    let first_source = b"= Evidence\n\nOriginal cited sentence.\n";
    harness.write_file("docs/evidence.adoc", first_source);
    let imported =
        harness.import(harness.request("evidence-doc", None, "docs/evidence.adoc", None));
    let span = mneme_core::SourceSpan::new(12, 35).expect("span");
    let evidence = mneme_memory::build_evidence(
        rid(0x40),
        rev(0x41),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x42),
            source: imported.source.source,
            source_revision: imported.source.revision,
            span: Some(span),
            anchor: Some("evidence"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        rid(0x42),
        rev(0x43),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: entity_source_id(),
            predicate: "citation",
            value: mneme_core::Value::string("original"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x40),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator)
        .commit(mneme_memory::Batch {
            actor: "doc-author".to_owned(),
            scope: scope(),
            idempotency_key: "evidence".to_owned(),
            records: vec![evidence, assertion],
            source_blobs: Vec::new(),
            publications: Vec::new(),
        })
        .expect("evidence commit");

    harness.write_file("docs/evidence.adoc", b"= Evidence\n\nRewritten sentence.\n");
    harness.import(harness.request(
        "evidence-doc-2",
        Some(imported.document_id),
        "docs/evidence.adoc",
        None,
    ));
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    let view = memory.view().expect("view");
    let old_source = view
        .source_at(imported.source.source, imported.source.revision)
        .expect("pinned source");
    match view.source_status_for(&old_source).expect("status") {
        mneme_memory::SourceStatus::Retained(bytes) => {
            assert_eq!(bytes, first_source);
        }
        other => {
            assert_eq!(other.availability().name(), "retained");
        }
    }
    let explanation = view
        .explain(rid(0x42), Default::default())
        .expect("explain");
    assert_eq!(
        explanation.evidence[0]
            .excerpt
            .as_ref()
            .expect("excerpt")
            .bytes,
        b"Original cited sentence."
    );
}

#[test]
fn substituted_binding_and_invalid_utf8_are_rejected() {
    let mut harness = Harness::new();
    harness.write_file(
        "docs/substituted.adoc",
        b"= Substitute\n:entity-id: {entity}\n\nbody\n",
    );
    let substituted_request = harness.request("substituted", None, "docs/substituted.adoc", None);
    let substituted = mneme_doc::Documents::new(&mut harness.workspace)
        .validate_working_file(substituted_request)
        .expect("diagnostic draft");
    assert!(!substituted.valid);
    assert!(
        substituted
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "binding-substitution")
    );

    harness.write_file("docs/utf8.adoc", &[0xff, 0xfe, b'r', b'o', b'o', b't']);
    let utf8_request = harness.request("utf8", None, "docs/utf8.adoc", None);
    let invalid = mneme_doc::Documents::new(&mut harness.workspace)
        .validate_working_file(utf8_request)
        .expect("diagnostic draft");
    assert!(!invalid.valid);
    assert!(
        invalid
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "invalid-utf8")
    );
}

#[test]
fn repeated_save_with_the_same_key_returns_the_same_revision() {
    let mut harness = Harness::new();
    let request = harness.request("save", None, "docs/save.adoc", None);
    let first = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .save_source(request.clone(), b"= Save\n\nsaved body\n")
            .expect("first save")
    };
    let generation = harness
        .workspace
        .snapshot()
        .expect("snapshot")
        .records
        .len();
    let second = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .save_source(request, b"= Save\n\nsaved body\n")
            .expect("retry save")
    };
    assert_eq!(first.document_id, second.document_id);
    assert_eq!(first.document_revision, second.document_revision);
    assert_eq!(
        harness
            .workspace
            .snapshot()
            .expect("snapshot")
            .records
            .len(),
        generation
    );
}

#[test]
fn anchors_are_scoped_to_the_current_document_source_revision() {
    let mut harness = Harness::new();
    harness.write_file("docs/anchor-v1.adoc", b"= A\n\n[[first]]\nbody\n");
    let first = harness.import(harness.request("a1", None, "docs/anchor-v1.adoc", None));
    assert_eq!(
        mneme_doc::Documents::new(&mut harness.workspace)
            .anchors(first.document_id)
            .expect("anchors")
            .len(),
        1
    );
    harness.write_file("docs/anchor-v1.adoc", b"= A\n\n[[second]]\nnew body\n");
    harness.import(harness.request("a2", Some(first.document_id), "docs/anchor-v1.adoc", None));
    let anchors = mneme_doc::Documents::new(&mut harness.workspace)
        .anchors(first.document_id)
        .expect("anchors");
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].anchor, "second");
}

#[test]
fn document_listing_is_deterministic_and_carries_scope() {
    let mut harness = Harness::new();
    for (key, path, title) in [
        ("zeta", "notes/zeta.adoc", "zeta"),
        ("alpha", "notes/alpha.adoc", "Alpha"),
        ("beta", "notes/alpha-beta.adoc", "alpha beta"),
    ] {
        harness.write_file(path, format!("= {title}\n\nbody\n").as_bytes());
        harness.import(harness.request(key, None, path, Some(title)));
    }
    let mut request = harness.request("birch", None, "notes/birch.adoc", Some("Birch"));
    request.scope =
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "birch").expect("scope");
    harness.write_file("notes/birch.adoc", b"= Birch\n\nother scope\n");
    harness.import(request);

    let first = mneme_doc::Documents::new(&mut harness.workspace)
        .list_documents()
        .expect("list");
    let second = mneme_doc::Documents::new(&mut harness.workspace)
        .list_documents()
        .expect("list");
    assert_eq!(first, second);
    assert_eq!(
        first
            .iter()
            .map(|summary| summary.title.as_str())
            .collect::<Vec<_>>(),
        vec!["Alpha", "alpha beta", "Birch", "zeta"]
    );
    assert_eq!(
        first
            .iter()
            .filter(|summary| summary.scope == scope())
            .count(),
        3
    );
    assert!(first.iter().all(|summary| summary.path.is_some()));
    assert!(first.iter().all(|summary| summary.revision != rev(0)));
}

#[test]
fn move_can_rename_title_without_changing_identity_or_source() {
    let mut harness = Harness::new();
    let source = b"= Original\n\nBody stays exact.\n";
    harness.write_file("docs/original.adoc", source);
    let imported = harness.import(harness.request(
        "rename-import",
        None,
        "docs/original.adoc",
        Some("Original"),
    ));
    let base = harness.workspace.current_revision().expect("base");
    let moved = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .move_document(mneme_doc::MoveRequest {
                actor: "doc-author".to_owned(),
                scope: scope(),
                base_revision: base,
                idempotency_key: "rename".to_owned(),
                document_id: imported.document_id,
                path: "docs/renamed.adoc".to_owned(),
                title: Some("Renamed".to_owned()),
            })
            .expect("rename")
    };
    assert_eq!(moved.document_id, imported.document_id);
    assert_eq!(moved.source, imported.source);
    assert_eq!(moved.path, "docs/renamed.adoc");
    let documents = mneme_doc::Documents::new(&mut harness.workspace);
    let view = documents.document(moved.document_id).expect("document");
    assert_eq!(view.title, "Renamed");
    assert_eq!(
        documents
            .source_bytes(moved.document_id)
            .expect("source bytes"),
        source
    );
}

#[test]
fn move_refuses_an_empty_title_without_a_commit() {
    let mut harness = Harness::new();
    harness.write_file("docs/keep.adoc", b"= Keep\n\nbody\n");
    let imported = harness.import(harness.request("keep", None, "docs/keep.adoc", Some("Keep")));
    let revision = harness.workspace.current_revision().expect("revision");
    let error = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .move_document(mneme_doc::MoveRequest {
                actor: "doc-author".to_owned(),
                scope: scope(),
                base_revision: revision,
                idempotency_key: "empty-title".to_owned(),
                document_id: imported.document_id,
                path: "docs/keep.adoc".to_owned(),
                title: Some("   ".to_owned()),
            })
            .expect_err("empty title")
    };
    assert!(matches!(error, mneme_doc::DocumentError::Invalid(_)));
    assert_eq!(
        harness.workspace.current_revision().expect("revision"),
        revision
    );
}

#[test]
fn import_key_reuse_with_changed_bytes_conflicts_instead_of_replaying() {
    let mut harness = Harness::new();
    harness.write_file("docs/idem.adoc", b"= Idem\n\nfirst body\n");
    let first = harness.import(harness.request("same-key", None, "docs/idem.adoc", None));
    let replay = harness.import(harness.request("same-key", None, "docs/idem.adoc", None));
    assert_eq!(replay.workspace_revision, first.workspace_revision);
    assert_eq!(replay.sequence, first.sequence);
    assert_eq!(replay.document_revision, first.document_revision);
    assert_eq!(
        harness.workspace.current_revision().expect("revision"),
        first.workspace_revision
    );

    harness.write_file("docs/idem.adoc", b"= Idem\n\nchanged body\n");
    let retry = harness.request("same-key", None, "docs/idem.adoc", None);
    let error = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .import_working_file(retry)
            .expect_err("changed content under one key")
    };
    assert!(matches!(
        error,
        mneme_doc::DocumentError::Store(mneme_store::Failure::IdempotencyConflict { .. })
    ));
    assert_eq!(
        harness.workspace.current_revision().expect("revision"),
        first.workspace_revision,
        "the refused retry committed nothing"
    );
    assert_eq!(
        mneme_doc::Documents::new(&mut harness.workspace)
            .source_bytes(first.document_id)
            .expect("source"),
        b"= Idem\n\nfirst body\n"
    );
}

#[test]
fn a_move_retry_replays_the_first_outcome_without_mixing_revisions() {
    let mut harness = Harness::new();
    harness.write_file("docs/retry.adoc", b"= Retry\n\nbody\n");
    let imported = harness.import(harness.request("retry-import", None, "docs/retry.adoc", None));
    let first_base = harness.workspace.current_revision().expect("base");
    let first_move = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .move_document(mneme_doc::MoveRequest {
                actor: "doc-author".to_owned(),
                scope: scope(),
                base_revision: first_base,
                idempotency_key: "k-move".to_owned(),
                document_id: imported.document_id,
                path: "docs/b.adoc".to_owned(),
                title: None,
            })
            .expect("first move")
    };
    let second_base = harness.workspace.current_revision().expect("base");
    let second_move = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .move_document(mneme_doc::MoveRequest {
                actor: "doc-author".to_owned(),
                scope: scope(),
                base_revision: second_base,
                idempotency_key: "k-move-2".to_owned(),
                document_id: imported.document_id,
                path: "docs/c.adoc".to_owned(),
                title: None,
            })
            .expect("second move")
    };
    assert_eq!(second_move.path, "docs/c.adoc");
    let retry_base = harness.workspace.current_revision().expect("base");
    let replayed = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .move_document(mneme_doc::MoveRequest {
                actor: "doc-author".to_owned(),
                scope: scope(),
                base_revision: retry_base,
                idempotency_key: "k-move".to_owned(),
                document_id: imported.document_id,
                path: "docs/b.adoc".to_owned(),
                title: None,
            })
            .expect("replayed move")
    };
    assert_eq!(replayed.path, "docs/b.adoc");
    assert_eq!(replayed.document_revision, first_move.document_revision);
    assert_eq!(replayed.workspace_revision, first_move.workspace_revision);
    assert_eq!(replayed.sequence, first_move.sequence);
    assert_ne!(replayed.document_revision, second_move.document_revision);
    assert_eq!(
        harness.workspace.current_revision().expect("revision"),
        second_move.workspace_revision,
        "a replay never commits or moves again"
    );
    assert_eq!(
        mneme_doc::Documents::new(&mut harness.workspace)
            .document(imported.document_id)
            .expect("document")
            .path
            .as_deref(),
        Some("docs/c.adoc")
    );
}

#[test]
fn a_property_edit_retry_returns_the_original_revision() {
    let mut harness = Harness::new();
    let scope = scope();
    let first_base = harness.workspace.current_revision().expect("base");
    let first = mneme_doc::Documents::new(&mut harness.workspace)
        .edit_entity_property(mneme_doc::EntityPropertyEditRequest {
            actor: "doc-author",
            scope: &scope,
            base_revision: first_base,
            idempotency_key: "prop-retry",
            entity_id: entity_source_id(),
            property: "status",
            value: Some(mneme_core::Value::string("reviewed")),
        })
        .expect("property edit");
    assert_eq!(
        harness.workspace.current_revision().expect("revision"),
        first
    );
    let retry_base = harness.workspace.current_revision().expect("base");
    let retried = mneme_doc::Documents::new(&mut harness.workspace)
        .edit_entity_property(mneme_doc::EntityPropertyEditRequest {
            actor: "doc-author",
            scope: &scope,
            base_revision: retry_base,
            idempotency_key: "prop-retry",
            entity_id: entity_source_id(),
            property: "status",
            value: Some(mneme_core::Value::string("reviewed")),
        })
        .expect("property retry");
    assert_eq!(retried, first);
    assert_eq!(
        harness.workspace.current_revision().expect("revision"),
        first,
        "the retry reused the recorded outcome instead of committing"
    );
    let conflict_base = harness.workspace.current_revision().expect("base");
    let conflict = mneme_doc::Documents::new(&mut harness.workspace)
        .edit_entity_property(mneme_doc::EntityPropertyEditRequest {
            actor: "doc-author",
            scope: &scope,
            base_revision: conflict_base,
            idempotency_key: "prop-retry",
            entity_id: entity_source_id(),
            property: "status",
            value: Some(mneme_core::Value::string("published")),
        })
        .expect_err("a reused key with another value must conflict");
    assert!(matches!(
        conflict,
        mneme_doc::DocumentError::Store(mneme_store::Failure::IdempotencyConflict { .. })
    ));
}

#[test]
fn publishing_a_binding_does_not_overwrite_an_unimported_edit() {
    let mut harness = Harness::new();
    harness.write_file("docs/bind-publish.adoc", b"= Alpha\n\nCommitted body.\n");
    let imported =
        harness.import(harness.request("bp-import", None, "docs/bind-publish.adoc", None));
    let external = b"= Alpha\n\nUnimported external edit.\n";
    harness.write_file("docs/bind-publish.adoc", external);
    let request = harness.binding_request(
        "bp-bind",
        imported.document_id,
        "docs/bind-publish.adoc",
        Some(entity_source_id()),
        true,
    );
    let bound = mneme_doc::Documents::new(&mut harness.workspace)
        .patch_binding(request)
        .expect("binding commit");
    assert_eq!(bound.entity, Some(entity_source_id()));
    assert_eq!(bound.publications.len(), 1);
    assert_eq!(
        bound.publications[0].state,
        mneme_store::PublicationState::Diverged,
        "the unimported edit is reported instead of being replaced"
    );
    assert_eq!(
        harness.working_file("docs/bind-publish.adoc"),
        Some(external.to_vec())
    );
    let committed = mneme_doc::Documents::new(&mut harness.workspace)
        .source_bytes(imported.document_id)
        .expect("committed source");
    let expected = format!(
        "= Alpha\n:entity-id: {}\n\nCommitted body.\n",
        entity_source_id().to_hex()
    );
    assert_eq!(committed, expected.as_bytes());
}

#[test]
fn binding_a_crlf_document_patches_only_the_header() {
    let mut harness = Harness::new();
    let source = "= Binding guide\r\n\r\nTo bind a note, add this header line:\r\n\r\n----\r\n:entity-id: 08080808080808080808080808080808\r\n----\r\n";
    harness.write_file("docs/crlf.adoc", source.as_bytes());
    let imported = harness.import(harness.request("crlf", None, "docs/crlf.adoc", None));
    let request = harness.binding_request(
        "crlf-bind",
        imported.document_id,
        "docs/crlf.adoc",
        Some(entity_source_id()),
        false,
    );
    let bound = mneme_doc::Documents::new(&mut harness.workspace)
        .patch_binding(request)
        .expect("crlf bind");
    assert_eq!(bound.entity, Some(entity_source_id()));
    let expected = format!(
        "= Binding guide\r\n:entity-id: {}\r\n\r\nTo bind a note, add this header line:\r\n\r\n----\r\n:entity-id: 08080808080808080808080808080808\r\n----\r\n",
        entity_source_id().to_hex()
    );
    assert_eq!(
        mneme_doc::Documents::new(&mut harness.workspace)
            .source_bytes(imported.document_id)
            .expect("source"),
        expected.as_bytes(),
        "the header entry is inserted and the prose is untouched"
    );
}

#[test]
fn binding_a_title_only_document_keeps_the_title() {
    let mut harness = Harness::new();
    harness.write_file("docs/title-only.adoc", b"= Title only");
    let imported =
        harness.import(harness.request("title-only", None, "docs/title-only.adoc", None));
    let request = harness.binding_request(
        "title-only-bind",
        imported.document_id,
        "docs/title-only.adoc",
        Some(entity_source_id()),
        false,
    );
    let bound = mneme_doc::Documents::new(&mut harness.workspace)
        .patch_binding(request)
        .expect("title-only bind");
    assert_eq!(bound.entity, Some(entity_source_id()));
    let expected = format!(
        "= Title only\n:entity-id: {}\n",
        entity_source_id().to_hex()
    );
    assert_eq!(
        mneme_doc::Documents::new(&mut harness.workspace)
            .source_bytes(imported.document_id)
            .expect("source"),
        expected.as_bytes()
    );
    let document = mneme_doc::Documents::new(&mut harness.workspace)
        .document(imported.document_id)
        .expect("document");
    assert_eq!(document.title, "Title only");
    assert_eq!(document.entity, Some(entity_source_id()));
}

#[test]
fn a_moved_document_previews_its_pinned_include_closure() {
    let mut harness = Harness::new();
    harness.write_file(
        "swap/x/a.adoc",
        b"= Inner A\n\nINNER sentence from swap/x/a.adoc.\n",
    );
    harness.import(harness.request("swap-inner", None, "swap/x/a.adoc", None));
    harness.write_file(
        "swap/a.adoc",
        b"= Outer A\n\nOUTER sentence from swap/a.adoc.\n",
    );
    harness.import(harness.request("swap-outer", None, "swap/a.adoc", None));
    harness.write_file(
        "swap/x/root.adoc",
        b"= Root\n\ninclude::a.adoc[]\n\ninclude::../a.adoc[]\n",
    );
    let root = harness.import(harness.request("swap-root", None, "swap/x/root.adoc", None));
    assert_eq!(root.includes.len(), 2);
    let move_base = harness.workspace.current_revision().expect("base");
    let moved = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .move_document(mneme_doc::MoveRequest {
                actor: "doc-author".to_owned(),
                scope: scope(),
                base_revision: move_base,
                idempotency_key: "swap-move".to_owned(),
                document_id: root.document_id,
                path: "swap/root.adoc".to_owned(),
                title: None,
            })
            .expect("move out of the subdirectory")
    };
    assert_eq!(moved.path, "swap/root.adoc");
    let preview = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .preview(
                root.document_id,
                None,
                mneme_doc::RenderConfig {
                    version: mneme_doc::RENDER_CONFIG_VERSION.to_owned(),
                    include_entity_metadata: true,
                    max_output_bytes: 8 * 1024 * 1024,
                    max_time_ms: 1_000,
                },
            )
            .expect("preview")
    };
    assert_eq!(preview.path, "swap/root.adoc");
    assert!(
        preview.html.contains("INNER sentence from swap/x/a.adoc."),
        "the directive pinned to swap/x/a.adoc still resolves there"
    );
    assert!(preview.html.contains("OUTER sentence from swap/a.adoc."));
    assert_eq!(preview.occurrences.len(), 2);
    assert!(
        preview
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != "include-unavailable")
    );
    let candidates = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .extract_proposals(root.document_id)
            .expect("extract")
    };
    let inner = candidates
        .iter()
        .find(|candidate| candidate.text.contains("INNER sentence"))
        .expect("inner candidate");
    assert_eq!(inner.origin_path, "swap/x/a.adoc");
    assert_eq!(inner.occurrences.len(), 1);
}

#[test]
fn non_canonical_logical_paths_are_refused() {
    let mut harness = Harness::new();
    harness.write_file("alias/x.adoc", b"= Alias\n\nbody\n");
    let revision = harness.workspace.current_revision().expect("revision");
    for path in [
        "alias//x.adoc",
        "alias/./x.adoc",
        "/alias/x.adoc",
        "alias/../x.adoc",
    ] {
        let request = harness.request("alias", None, path, None);
        let error = {
            let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
            documents
                .import_working_file(request)
                .expect_err("non-canonical logical path")
        };
        assert!(
            matches!(error, mneme_doc::DocumentError::Invalid(_)),
            "{path} must be refused"
        );
    }
    assert_eq!(
        harness.workspace.current_revision().expect("revision"),
        revision
    );
    let imported = harness.import(harness.request("alias-ok", None, "alias/x.adoc", None));
    let move_base = harness.workspace.current_revision().expect("base");
    let error = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .move_document(mneme_doc::MoveRequest {
                actor: "doc-author".to_owned(),
                scope: scope(),
                base_revision: move_base,
                idempotency_key: "alias-move".to_owned(),
                document_id: imported.document_id,
                path: "alias//moved.adoc".to_owned(),
                title: None,
            })
            .expect_err("non-canonical destination")
    };
    assert!(matches!(error, mneme_doc::DocumentError::Invalid(_)));
}

#[test]
fn re_import_supersedes_anchor_and_binding_records() {
    let mut harness = Harness::new();
    let source = bound_source("Intro.\n\n[[intro,Intro anchor]]\nBody.\n");
    harness.write_file("docs/grow.adoc", source.as_bytes());
    let imported = harness.import(harness.request("grow-1", None, "docs/grow.adoc", None));
    let anchors = harness.anchor_records();
    let bindings = harness.binding_records();
    assert_eq!(anchors.len(), 1);
    assert_eq!(bindings.len(), 1);
    let anchor_id = anchors[0].record_id;
    let anchor_revision = anchors[0].revision_id;
    let binding_id = bindings[0].record_id;
    let binding_revision = bindings[0].revision_id;

    harness.import(harness.request("grow-2", Some(imported.document_id), "docs/grow.adoc", None));
    let anchors_second = harness.anchor_records();
    assert_eq!(
        anchors_second.len(),
        1,
        "a save supersedes the anchor record instead of minting another"
    );
    assert_eq!(anchors_second[0].record_id, anchor_id);
    assert_eq!(anchors_second[0].predecessor, Some(anchor_revision));
    let bindings_second = harness.binding_records();
    assert_eq!(bindings_second.len(), 1);
    assert_eq!(bindings_second[0].record_id, binding_id);
    assert_eq!(bindings_second[0].predecessor, Some(binding_revision));

    harness.import(harness.request("grow-3", Some(imported.document_id), "docs/grow.adoc", None));
    let anchors_third = harness.anchor_records();
    assert_eq!(anchors_third.len(), 1);
    assert_eq!(anchors_third[0].record_id, anchor_id);
    assert_eq!(
        anchors_third[0].predecessor,
        Some(anchors_second[0].revision_id)
    );
    let listed = mneme_doc::Documents::new(&mut harness.workspace)
        .anchors(imported.document_id)
        .expect("anchors");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].record_id, anchor_id);
    assert_eq!(harness.binding_records().len(), 1);
}

#[test]
fn retained_extension_fields_survive_document_and_property_edits() {
    let mut harness = Harness::new();
    harness.write_file("docs/ext.adoc", b"= Ext\n\nfirst body\n");
    let imported = harness.import(harness.request("ext-1", None, "docs/ext.adoc", None));
    let document = harness
        .document_records()
        .into_iter()
        .find(|record| record.record_id == imported.document_id)
        .expect("document");
    let mut payload = document.payload.clone();
    payload.insert(
        mneme_core::Symbol::from("x-ext"),
        mneme_core::Value::string("keep me"),
    );
    let base = harness.workspace.current_revision().expect("base");
    harness
        .workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "ext-tool".to_owned(),
            scope: scope(),
            idempotency_key: "ext-document".to_owned(),
            records: vec![mneme_store::RecordDraft {
                schema_version: mneme_doc::DOCUMENT_SCHEMA_VERSION,
                kind: mneme_core::RecordKind::Document,
                record_id: document.record_id,
                revision_id: rev(0x51),
                predecessor: Some(document.revision_id),
                scope: scope(),
                payload,
            }],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("document extension commit");
    harness.write_file("docs/ext.adoc", b"= Ext\n\nsecond body\n");
    harness.import(harness.request("ext-2", Some(imported.document_id), "docs/ext.adoc", None));
    let after = harness
        .document_records()
        .into_iter()
        .find(|record| record.record_id == imported.document_id)
        .expect("document");
    assert_eq!(
        after
            .payload
            .get("x-ext")
            .and_then(mneme_core::Value::as_string),
        Some("keep me"),
        "a re-import preserves a retained extension field"
    );
    assert_eq!(
        mneme_doc::Documents::new(&mut harness.workspace)
            .source_bytes(imported.document_id)
            .expect("source"),
        b"= Ext\n\nsecond body\n"
    );

    let entity = harness.entity_record(entity_source_id());
    let mut entity_payload = entity.payload.clone();
    entity_payload.insert(
        mneme_core::Symbol::from("x-ext"),
        mneme_core::Value::string("entity keep"),
    );
    let base = harness.workspace.current_revision().expect("base");
    harness
        .workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "ext-tool".to_owned(),
            scope: scope(),
            idempotency_key: "ext-entity".to_owned(),
            records: vec![mneme_store::RecordDraft {
                schema_version: entity.schema_version,
                kind: mneme_core::RecordKind::Entity,
                record_id: entity.record_id,
                revision_id: rev(0x52),
                predecessor: Some(entity.revision_id),
                scope: scope(),
                payload: entity_payload,
            }],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("entity extension commit");
    let scope = scope();
    let property_base = harness.workspace.current_revision().expect("base");
    mneme_doc::Documents::new(&mut harness.workspace)
        .edit_entity_property(mneme_doc::EntityPropertyEditRequest {
            actor: "doc-author",
            scope: &scope,
            base_revision: property_base,
            idempotency_key: "ext-property",
            entity_id: entity_source_id(),
            property: "status",
            value: Some(mneme_core::Value::string("reviewed")),
        })
        .expect("property edit");
    let entity_after = harness.entity_record(entity_source_id());
    assert_eq!(
        entity_after
            .payload
            .get("x-ext")
            .and_then(mneme_core::Value::as_string),
        Some("entity keep"),
        "a property edit preserves a retained extension field"
    );
    let properties = entity_after
        .payload
        .get("properties")
        .and_then(mneme_core::Value::as_dictionary)
        .expect("properties");
    assert_eq!(
        properties.get(&mneme_core::Value::symbol("status")),
        Some(&mneme_core::Value::string("reviewed"))
    );
}

#[cfg(unix)]
#[test]
fn a_fifo_working_file_is_refused_promptly() {
    let mut harness = Harness::new();
    let fifo = harness.temp.path().join("working/pipe.adoc");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "mkfifo creates the special file");
    let request = harness.request("fifo", None, "pipe.adoc", None);
    let error = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .import_working_file(request)
            .expect_err("a FIFO is not a document source")
    };
    assert!(matches!(error, mneme_doc::DocumentError::Store(_)));
}

#[test]
fn a_draft_of_a_new_document_reports_no_committed_identity() {
    let mut harness = Harness::new();
    harness.write_file("docs/new.adoc", b"= New\n\nbody\n");
    let draft_request = harness.request("new-draft", None, "docs/new.adoc", None);
    let draft = {
        let documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .validate_working_file(draft_request)
            .expect("draft")
    };
    assert!(draft.valid);
    assert_eq!(
        draft.document_id, None,
        "a new candidate has no committed identity yet"
    );
    let committed = harness.import(harness.request("new-import", None, "docs/new.adoc", None));
    assert!(
        harness
            .document_records()
            .iter()
            .any(|record| record.record_id == committed.document_id)
    );
    let existing_request = harness.request(
        "new-draft-2",
        Some(committed.document_id),
        "docs/new.adoc",
        None,
    );
    let existing = {
        let documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .validate_working_file(existing_request)
            .expect("existing draft")
    };
    assert_eq!(existing.document_id, Some(committed.document_id));
}

#[test]
fn the_root_source_is_charged_against_the_byte_budget() {
    let mut harness = Harness::new();
    harness.write_file(
        "docs/big.adoc",
        b"= Big\n\nA body long enough to exceed ten bytes.\n",
    );
    let mut request = harness.request("big", None, "docs/big.adoc", None);
    let mut policy = request.policy.clone();
    policy.max_total_source_bytes = 10;
    request.policy = policy;
    let validation = {
        let documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .validate_working_file(request)
            .expect("diagnostic draft")
    };
    assert!(!validation.valid);
    assert!(
        validation
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "source-byte-limit" && diagnostic.fatal)
    );
}

fn preview_config() -> mneme_doc::RenderConfig {
    mneme_doc::RenderConfig {
        version: mneme_doc::RENDER_CONFIG_VERSION.to_owned(),
        include_entity_metadata: true,
        max_output_bytes: 8 * 1024 * 1024,
        max_time_ms: 1_000,
    }
}

#[test]
fn include_fan_out_stops_at_the_include_expansion_budget() {
    let mut harness = Harness::new();
    harness.write_file("docs/leaf.adoc", b"Leaf paragraph.\n");
    harness.import(harness.request("fanout-leaf", None, "docs/leaf.adoc", None));
    let shared = "include::leaf.adoc[]\n".repeat(10);
    harness.write_file("docs/shared.adoc", shared.as_bytes());
    harness.import(harness.request("fanout-shared", None, "docs/shared.adoc", None));
    let level = "include::shared.adoc[]\n".repeat(10);
    let mut root = String::new();
    for index in 0..10 {
        let path = format!("docs/level1-{index}.adoc");
        harness.write_file(&path, level.as_bytes());
        let key = format!("fanout-level-{index}");
        harness.import(harness.request(&key, None, &path, None));
        root.push_str(&format!("include::level1-{index}.adoc[]\n"));
    }
    harness.write_file("docs/fanout.adoc", root.as_bytes());
    let mut request = harness.request("fanout-root", None, "docs/fanout.adoc", None);
    request.policy.max_time_ms = 30_000;
    request.render_config.max_time_ms = 30_000;
    let validation = {
        let documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .validate_working_file(request)
            .expect("fan-out draft")
    };
    assert!(validation.valid);
    assert!(validation.includes.len() < 14);
    let budget = validation
        .preview_diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "render-budget-exhausted")
        .count();
    assert_eq!(budget, 1);
    // Ten-by-ten-by-ten fan-out is 1,110 expansions; the preview stops at the
    // include budget instead of expanding every level.
    let rendered = validation
        .preview_html
        .matches("<p>Leaf paragraph.</p>")
        .count();
    assert!(rendered > 0);
    assert!(rendered < 1_110);
}

#[test]
fn crlf_and_title_only_documents_parse_like_lf_documents() {
    let entity = entity_source_id().to_hex();
    let lf = format!("= Notes\n:entity-id: {entity}\n\nBody\n");
    let crlf = format!("= Notes\r\n:entity-id: {entity}\r\n\r\nBody\r\n");
    let lf_header = mneme_doc::asciidoc::parse_header(&lf).expect("lf header");
    let crlf_header = mneme_doc::asciidoc::parse_header(&crlf).expect("crlf header");
    assert_eq!(lf_header.title, crlf_header.title);
    assert_eq!(lf_header.entity_id, crlf_header.entity_id);
    assert_eq!(crlf_header.title.as_deref(), Some("Notes"));
    assert_eq!(crlf_header.entity_id, Some(entity_source_id()));
    let span = crlf_header.span.expect("header span");
    assert_eq!(span.start(), 0);
    let end = usize::try_from(span.end()).expect("span end");
    assert!(crlf[..=end].ends_with(&entity));
    let title_only = mneme_doc::asciidoc::parse_header("= Title only").expect("title only");
    assert_eq!(title_only.title.as_deref(), Some("Title only"));
    assert!(title_only.entity_id.is_none());
    let title_span = title_only.span.expect("title span");
    assert_eq!(title_span.end(), 11);
}

#[test]
fn commented_out_anchors_and_includes_are_ignored() {
    let mut harness = Harness::new();
    let source = "= Blocks\n\n////\n[[ghost]]\ninclude::never-written.adoc[]\nwithdrawn claim\n////\n\n----\n[[fake]]\ninclude::also-never-written.adoc[]\n[[real]]\n----\n\n[[real]]\nReal paragraph.\n";
    harness.write_file("docs/blocks.adoc", source.as_bytes());
    let imported = harness.import(harness.request("blocks", None, "docs/blocks.adoc", None));
    assert_eq!(imported.anchors.len(), 1);
    let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
    let anchors = documents.anchors(imported.document_id).expect("anchors");
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].anchor, "real");
    let preview = documents
        .preview(imported.document_id, None, preview_config())
        .expect("preview");
    assert!(!preview.html.contains("withdrawn claim"));
    assert!(preview.html.contains("Real paragraph."));
    let candidates = documents
        .extract_proposals(imported.document_id)
        .expect("extract");
    assert!(
        !candidates
            .iter()
            .any(|candidate| candidate.text.contains("withdrawn claim"))
    );
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.text.contains("Real paragraph."))
    );
}

#[test]
fn an_unterminated_block_is_reported_and_keeps_the_following_content() {
    let mut harness = Harness::new();
    let source =
        "= Open\n\nBefore.\n\n----\nlisting that is never closed\n\nimportant trailing prose\n";
    harness.write_file("docs/open.adoc", source.as_bytes());
    let imported = harness.import(harness.request("open", None, "docs/open.adoc", None));
    let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
    let preview = documents
        .preview(imported.document_id, None, preview_config())
        .expect("preview");
    assert!(preview.html.contains("listing that is never closed"));
    assert!(preview.html.contains("important trailing prose"));
    assert!(
        preview
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "unterminated-block")
    );
}

#[test]
fn include_selection_attributes_are_refused_instead_of_silently_expanded() {
    let mut harness = Harness::new();
    let tagged = "// tag::public[]\nPublic sentence.\n// end::public[]\n\nPRIVATE salary figure.\n";
    harness.write_file("docs/notes.adoc", tagged.as_bytes());
    harness.import(harness.request("notes", None, "docs/notes.adoc", None));
    for (key, directive) in [
        ("tag", "include::notes.adoc[tag=public]"),
        ("lines", "include::notes.adoc[lines=4]"),
    ] {
        let path = format!("docs/{key}.adoc");
        let source = format!("= Report\n\n{directive}\n");
        harness.write_file(&path, source.as_bytes());
        let request_key = format!("{key}-request");
        let request = harness.request(&request_key, None, &path, None);
        let validation = {
            let documents = mneme_doc::Documents::new(&mut harness.workspace);
            documents
                .validate_working_file(request)
                .expect("attribute draft")
        };
        assert!(!validation.valid);
        assert!(validation.includes.is_empty());
        assert!(
            validation
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "include-attribute-unsupported")
                .all(|diagnostic| diagnostic.fatal)
        );
        assert!(
            validation
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "include-attribute-unsupported")
        );
        assert!(!validation.preview_html.contains("PRIVATE salary figure"));
        assert!(!validation.preview_html.contains("Public sentence"));
    }
}

fn assert_binding_diagnostic(harness: &mut Harness, key: &str, body: &str, code: &str) {
    let path = format!("docs/{key}.adoc");
    harness.write_file(&path, body.as_bytes());
    let request_key = format!("{key}-binding");
    let request = harness.request(&request_key, None, &path, None);
    let validation = {
        let documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .validate_working_file(request)
            .expect("binding draft")
    };
    assert!(!validation.valid);
    assert!(
        validation
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == code),
        "{key} must report {code}"
    );
}

#[test]
fn entity_id_declarations_outside_the_header_and_unset_forms_are_rejected() {
    let mut harness = Harness::new();
    let entity = entity_source_id().to_hex();
    let other = mneme_core::RecordId::from_bytes([0x88; 16]).to_hex();
    assert_binding_diagnostic(
        &mut harness,
        "unset",
        "= T\n:!entity-id:\n\nBody.\n",
        "binding-unset",
    );
    assert_binding_diagnostic(
        &mut harness,
        "bang",
        "= T\n:entity-id!:\n\nBody.\n",
        "binding-unset",
    );
    let case_variant = format!("= T\n:entity-id: {entity}\n:Entity-ID: {other}\n\nBody.\n");
    assert_binding_diagnostic(
        &mut harness,
        "case-variant",
        &case_variant,
        "binding-conflict",
    );
    let body_declaration = format!("= T\n:entity-id: {entity}\n\n:entity-id: {other}\n\nBody.\n");
    assert_binding_diagnostic(
        &mut harness,
        "body",
        &body_declaration,
        "binding-outside-header",
    );
    let commented = format!("= T\n////\n:entity-id: {entity}\n////\n\nBody.\n");
    harness.write_file("docs/commented.adoc", commented.as_bytes());
    let request = harness.request("commented-binding", None, "docs/commented.adoc", None);
    let validation = {
        let documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .validate_working_file(request)
            .expect("commented binding draft")
    };
    assert!(validation.valid);
    assert!(validation.entity.is_none());
}

#[test]
fn preview_does_not_render_header_attribute_entries_as_prose() {
    let mut harness = Harness::new();
    let source = format!(
        "= Probe\n:entity-id: {}\n\nBody prose.\n",
        entity_source_id().to_hex()
    );
    harness.write_file("docs/probe.adoc", source.as_bytes());
    let imported = harness.import(harness.request("probe", None, "docs/probe.adoc", None));
    let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
    let preview = documents
        .preview(imported.document_id, None, preview_config())
        .expect("preview");
    assert!(preview.html.contains("<h1>Probe</h1>"));
    assert!(preview.html.contains("Body prose."));
    assert!(!preview.html.contains("entity-id"));
}

#[test]
fn preview_refuses_an_unsupported_configuration() {
    let mut harness = Harness::new();
    harness.write_file("docs/config.adoc", b"= Config\n\nBody.\n");
    let imported = harness.import(harness.request("config", None, "docs/config.adoc", None));
    let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
    let artifact = documents
        .preview(
            imported.document_id,
            None,
            mneme_doc::RenderConfig {
                version: "mneme-preview/v99-strict".to_owned(),
                ..preview_config()
            },
        )
        .expect("preview");
    assert!(!artifact.html.contains("<p>"));
    assert!(artifact.html.contains("preview is partial"));
    assert!(
        artifact
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "unsupported-render-config")
    );
}

#[test]
fn extraction_keeps_the_first_paragraph_of_a_header_less_source() {
    let mut harness = Harness::new();
    let fragment = "The audit deadline is 2026-12-01.\n\nSecond shared paragraph.\n";
    harness.write_file("docs/shared.adoc", fragment.as_bytes());
    harness.import(harness.request("shared-fragment", None, "docs/shared.adoc", None));
    let host = "Host first paragraph without a header.\n\ninclude::shared.adoc[]\n\nHost last paragraph.\n";
    harness.write_file("docs/host.adoc", host.as_bytes());
    let imported = harness.import(harness.request("host", None, "docs/host.adoc", None));
    let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
    let candidates = documents
        .extract_proposals(imported.document_id)
        .expect("extract");
    for expected in [
        "Host first paragraph without a header.",
        "The audit deadline is 2026-12-01.",
        "Second shared paragraph.",
        "Host last paragraph.",
    ] {
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.text.contains(expected)),
            "missing extracted paragraph {expected:?}"
        );
    }
}

#[test]
fn commented_text_and_block_macros_are_reported_and_not_rendered() {
    let mut harness = Harness::new();
    let source = "= Macro\n\n// a comment line that should not render\n\ngist::12345[]\n\nplantuml::diagram.puml[format=svg]\n\n//////\nComment block content.\n//////\n\n------\nListing content.\n------\n\nTail paragraph.\n";
    harness.write_file("docs/macro.adoc", source.as_bytes());
    let imported = harness.import(harness.request("macro", None, "docs/macro.adoc", None));
    let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
    let preview = documents
        .preview(imported.document_id, None, preview_config())
        .expect("preview");
    assert!(
        !preview
            .html
            .contains("a comment line that should not render")
    );
    assert!(!preview.html.contains("Comment block content"));
    assert!(preview.html.contains("Listing content."));
    assert!(preview.html.contains("Tail paragraph."));
    let macros = preview
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "unsupported-block-macro")
        .count();
    assert_eq!(macros, 2);
    let candidates = documents
        .extract_proposals(imported.document_id)
        .expect("extract");
    assert!(
        !candidates
            .iter()
            .any(|candidate| candidate.text.contains("Comment block content"))
    );
    assert!(
        !candidates
            .iter()
            .any(|candidate| candidate.text.contains("Listing content"))
    );
}

#[test]
fn a_long_unclosed_macro_line_previews_in_one_pass() {
    let mut harness = Harness::new();
    let mut source = String::from("= Long\n\n");
    for _ in 0..20_000 {
        source.push_str("link:");
    }
    source.push('\n');
    harness.write_file("docs/long.adoc", source.as_bytes());
    let mut request = harness.request("long", None, "docs/long.adoc", None);
    request.policy.max_time_ms = 30_000;
    request.render_config.max_time_ms = 30_000;
    let imported = harness.import(request);
    let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
    let preview = documents
        .preview(
            imported.document_id,
            None,
            mneme_doc::RenderConfig {
                max_time_ms: 30_000,
                ..preview_config()
            },
        )
        .expect("preview");
    assert_eq!(preview.html.matches("link:").count(), 20_000);
}

#[test]
fn a_binding_retry_returns_the_original_revision() {
    let mut harness = Harness::new();
    harness.write_file("docs/bind-retry.adoc", b"= Bind\n\nbody\n");
    let imported =
        harness.import(harness.request("bind-retry-import", None, "docs/bind-retry.adoc", None));
    let first = {
        let request = harness.binding_request(
            "bind-retry",
            imported.document_id,
            "docs/bind-retry.adoc",
            Some(entity_source_id()),
            false,
        );
        mneme_doc::Documents::new(&mut harness.workspace)
            .patch_binding(request)
            .expect("bind")
    };
    assert_eq!(first.entity, Some(entity_source_id()));
    let committed = harness.workspace.current_revision().expect("revision");
    let retried = {
        let request = harness.binding_request(
            "bind-retry",
            imported.document_id,
            "docs/bind-retry.adoc",
            Some(entity_source_id()),
            false,
        );
        mneme_doc::Documents::new(&mut harness.workspace)
            .patch_binding(request)
            .expect("binding retry")
    };
    assert_eq!(retried.document_revision, first.document_revision);
    assert_eq!(retried.workspace_revision, first.workspace_revision);
    assert_eq!(retried.sequence, first.sequence);
    assert_eq!(
        harness.workspace.current_revision().expect("revision"),
        committed,
        "the retry reused the recorded outcome instead of committing"
    );
}

#[test]
fn a_move_publishes_the_committed_bytes_and_retires_the_old_copy() {
    let mut harness = Harness::new();
    let source = b"= Move\n\ncommitted body\n";
    harness.write_file("docs/move-src.adoc", source);
    let imported = harness.import(harness.request("move-src", None, "docs/move-src.adoc", None));
    let base = harness.workspace.current_revision().expect("base");
    let moved = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .move_document(mneme_doc::MoveRequest {
                actor: "doc-author".to_owned(),
                scope: scope(),
                base_revision: base,
                idempotency_key: "move-src-move".to_owned(),
                document_id: imported.document_id,
                path: "docs/move-dst.adoc".to_owned(),
                title: None,
            })
            .expect("move")
    };
    assert_eq!(moved.publications.len(), 1);
    assert_eq!(moved.publications[0].path, "docs/move-dst.adoc");
    assert_eq!(
        moved.publications[0].state,
        mneme_store::PublicationState::Published
    );
    assert_eq!(
        harness.working_file("docs/move-dst.adoc"),
        Some(source.to_vec())
    );
    assert_eq!(harness.working_file("docs/move-src.adoc"), None);
    assert_eq!(
        moved.retired_working_copy,
        Some(mneme_doc::WorkingCopyRetirement::Removed)
    );
}

#[test]
fn a_move_keeps_an_edited_old_working_copy() {
    let mut harness = Harness::new();
    let source = b"= Move\n\ncommitted body\n";
    harness.write_file("docs/move-src.adoc", source);
    let imported = harness.import(harness.request("move-src", None, "docs/move-src.adoc", None));
    let edited = b"= Move\n\nunimported edit\n";
    harness.write_file("docs/move-src.adoc", edited);
    let base = harness.workspace.current_revision().expect("base");
    let moved = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .move_document(mneme_doc::MoveRequest {
                actor: "doc-author".to_owned(),
                scope: scope(),
                base_revision: base,
                idempotency_key: "move-edited".to_owned(),
                document_id: imported.document_id,
                path: "docs/move-dst.adoc".to_owned(),
                title: None,
            })
            .expect("move")
    };
    assert_eq!(
        moved.publications[0].state,
        mneme_store::PublicationState::Published
    );
    assert_eq!(
        moved.retired_working_copy,
        Some(mneme_doc::WorkingCopyRetirement::Diverged)
    );
    assert_eq!(
        harness.working_file("docs/move-src.adoc"),
        Some(edited.to_vec()),
        "an edited old copy is kept, never deleted"
    );
    assert_eq!(
        harness.working_file("docs/move-dst.adoc"),
        Some(source.to_vec())
    );
}

#[test]
fn a_move_publication_is_completed_by_publish_pending_after_a_crash() {
    let mut harness = Harness::new();
    let source = b"= Journal\n\nentry\n";
    harness.write_file("docs/journal.adoc", source);
    let imported = harness.import(harness.request("journal", None, "docs/journal.adoc", None));
    harness.reopen_with(Box::new(mneme_store::FaultAt(
        mneme_store::FaultPoint::AfterCommit,
    )));
    let base = harness.workspace.current_revision().expect("base");
    let error = {
        let mut documents = mneme_doc::Documents::new(&mut harness.workspace);
        documents
            .move_document(mneme_doc::MoveRequest {
                actor: "doc-author".to_owned(),
                scope: scope(),
                base_revision: base,
                idempotency_key: "journal-move".to_owned(),
                document_id: imported.document_id,
                path: "docs/diary.adoc".to_owned(),
                title: None,
            })
            .expect_err("fault after commit")
    };
    assert!(matches!(
        error,
        mneme_doc::DocumentError::Store(mneme_store::Failure::InjectedFault(_))
    ));
    harness.reopen_with(Box::new(mneme_store::NoFaults));
    assert_eq!(harness.working_file("docs/diary.adoc"), None);
    let outcomes = harness.workspace.publish_pending().expect("publish");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].state, mneme_store::PublicationState::Published);
    assert_eq!(
        harness.working_file("docs/diary.adoc"),
        Some(source.to_vec())
    );
    let document = mneme_doc::Documents::new(&mut harness.workspace)
        .document(imported.document_id)
        .expect("document");
    assert_eq!(document.path.as_deref(), Some("docs/diary.adoc"));
}
