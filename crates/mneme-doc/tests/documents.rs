//! Source-first document behavior over real workspace blobs and commits.

#![allow(clippy::expect_used)]

use mneme_core::{RecordId, RevisionId, ScopeClass, ScopeId, Timestamp, Value};
use mneme_doc::{
    BindingRequest, DocumentError, DocumentPolicy, Documents, ImportRequest, MoveRequest,
    RenderConfig,
};
use mneme_store::{
    CommitCommand, FaultAt, FaultPoint, FixedClock, NoFaults, Workspace, WorkspaceConfig, blob,
};
use tempfile::TempDir;

fn scope() -> ScopeId {
    ScopeId::new(ScopeClass::Project, "cedar").expect("scope")
}

fn rev(byte: u8) -> RevisionId {
    RevisionId::from_bytes([byte; 16])
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

fn entity_source_id() -> RecordId {
    mneme_core::fixtures::entity_id()
}

struct Harness {
    temp: TempDir,
    workspace: Workspace,
}

impl Harness {
    fn new() -> Self {
        Self::with_faults(Box::new(NoFaults))
    }

    fn with_faults(faults: Box<dyn mneme_store::FaultInjector>) -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let mut workspace = Workspace::create(
            temp.path(),
            WorkspaceConfig {
                clock: Box::new(FixedClock::new(Timestamp::from_nanos(1_000))),
                faults,
            },
        )
        .expect("create");
        let base = workspace.current_revision().expect("base");
        workspace
            .commit(CommitCommand {
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
        self.workspace = Workspace::open(
            self.temp.path(),
            WorkspaceConfig {
                clock: Box::new(FixedClock::new(Timestamp::from_nanos(2_000))),
                faults,
            },
        )
        .expect("open");
    }

    fn write_file(&self, path: &str, bytes: &[u8]) {
        blob::publish_working_file(self.temp.path(), path, bytes).expect("working file");
    }

    fn request(
        &self,
        key: &str,
        document_id: Option<RecordId>,
        path: &str,
        title: Option<&str>,
    ) -> ImportRequest {
        ImportRequest {
            actor: "doc-author".to_owned(),
            scope: scope(),
            base_revision: self.workspace.current_revision().expect("base"),
            idempotency_key: key.to_owned(),
            document_id,
            path: path.to_owned(),
            title: title.map(str::to_owned),
            policy: DocumentPolicy::default(),
            render_config: RenderConfig::default(),
        }
    }

    fn import(&mut self, request: ImportRequest) -> mneme_doc::DocumentRevision {
        let mut documents = Documents::new(&mut self.workspace);
        documents.import_working_file(request).expect("import")
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
        Documents::new(&mut harness.workspace)
            .source_bytes(imported.document_id)
            .expect("source"),
        source.as_bytes()
    );
    let anchors = Documents::new(&mut harness.workspace)
        .anchors(imported.document_id)
        .expect("anchors");
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].anchor, "intro");
    assert_eq!(
        &source[anchors[0].span.expect("span").start() as usize
            ..=anchors[0].span.expect("span").end() as usize],
        "[[intro,Intro anchor]]"
    );

    let move_base = harness.workspace.current_revision().expect("base");
    let moved = {
        let mut documents = Documents::new(&mut harness.workspace);
        documents
            .move_document(MoveRequest {
                actor: "doc-author".to_owned(),
                scope: scope(),
                base_revision: move_base,
                idempotency_key: "move".to_owned(),
                document_id: imported.document_id,
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
    Documents::new(&mut harness.workspace)
        .edit_entity_property(
            "doc-author",
            &scope(),
            property_base,
            "property",
            entity_source_id(),
            "status",
            Some(Value::string("reviewed")),
        )
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
        Documents::new(&mut harness.workspace)
            .source_bytes(imported.document_id)
            .expect("source"),
        source.as_bytes()
    );
    let _ = imported;
}

#[test]
fn conflicting_and_conditional_bindings_are_rejected_without_commit() {
    let mut harness = Harness::new();
    let conflicting = format!(
        "= Cedar\n:entity-id: {}\n:entity-id: {}\n\nBody.\n",
        entity_source_id().to_hex(),
        RecordId::from_bytes([0x99; 16]).to_hex()
    );
    harness.write_file("docs/conflict.adoc", conflicting.as_bytes());
    let conflict_request = harness.request("conflict", None, "docs/conflict.adoc", None);
    let error = {
        let mut documents = Documents::new(&mut harness.workspace);
        documents
            .import_working_file(conflict_request)
            .expect_err("conflict")
    };
    assert!(matches!(error, DocumentError::Diagnostics(_)));
    assert!(
        harness
            .workspace
            .snapshot()
            .expect("snapshot")
            .records
            .iter()
            .all(|record| record.kind != mneme_core::RecordKind::Document)
    );

    let conditional = format!(
        "= Cedar\nifdef::flag[]\n:entity-id: {}\nendif::[]\n\nBody.\n",
        entity_source_id().to_hex()
    );
    harness.write_file("docs/conditional.adoc", conditional.as_bytes());
    let conditional_request = harness.request("conditional", None, "docs/conditional.adoc", None);
    let validation = {
        let documents = Documents::new(&mut harness.workspace);
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
        let mut documents = Documents::new(&mut harness.workspace);
        documents
            .import_working_file(bad_edit_request)
            .expect_err("invalid edit")
    };
    assert!(matches!(error, DocumentError::Diagnostics(_)));
    assert_eq!(
        Documents::new(&mut harness.workspace)
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
        let documents = Documents::new(&mut harness.workspace);
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
        let mut documents = Documents::new(&mut harness.workspace);
        documents
            .import_working_file(stale_request)
            .expect_err("stale")
    };
    assert!(matches!(
        error,
        DocumentError::Store(mneme_store::StoreError::StaleBase { .. })
    ));
    assert_eq!(
        Documents::new(&mut harness.workspace)
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
        let mut documents = Documents::new(&mut harness.workspace);
        let preview = documents
            .preview(root.document_id, None, RenderConfig::default())
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
        let mut documents = Documents::new(&mut harness.workspace);
        let historical = documents
            .preview(
                root.document_id,
                Some(old_root_revision),
                RenderConfig::default(),
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
        let mut documents = Documents::new(&mut harness.workspace);
        let current = documents
            .preview(root.document_id, None, RenderConfig::default())
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
            let documents = Documents::new(&mut harness.workspace);
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
        let mut documents = Documents::new(&mut harness.workspace);
        documents
            .import_working_file(required_request)
            .expect_err("missing include")
    };
    assert!(matches!(required, DocumentError::Diagnostics(_)));
    harness.write_file(
        "docs/optional.adoc",
        b"= Root\n\ninclude::missing.adoc[opts=optional]\n",
    );
    let optional_request = harness.request("optional", None, "docs/optional.adoc", None);
    let optional = {
        let documents = Documents::new(&mut harness.workspace);
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
    let policy = DocumentPolicy {
        max_inputs: 1,
        ..DocumentPolicy::default()
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
        let mut documents = Documents::new(&mut harness.workspace);
        documents
            .import_working_file(request)
            .expect_err("input limit")
    };
    assert!(matches!(error, DocumentError::Diagnostics(_)));
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
        let mut documents = Documents::new(&mut harness.workspace);
        documents
            .import_working_file(cycle_request)
            .expect_err("cycle")
    };
    assert!(matches!(error, DocumentError::Diagnostics(_)));
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
    let mut documents = Documents::new(&mut harness.workspace);
    let preview = documents
        .preview(imported.document_id, None, RenderConfig::default())
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
        let mut documents = Documents::new(&mut harness.workspace);
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
        let mut documents = Documents::new(&mut harness.workspace);
        documents
            .patch_binding(BindingRequest {
                import: ImportRequest {
                    actor: "doc-author".to_owned(),
                    scope: scope(),
                    base_revision: base,
                    idempotency_key: "bind".to_owned(),
                    document_id: Some(imported.document_id),
                    path: "docs/binding.adoc".to_owned(),
                    title: None,
                    policy: DocumentPolicy::default(),
                    render_config: RenderConfig::default(),
                },
                entity: Some(entity_source_id()),
                publish: false,
            })
            .expect("bind")
    };
    assert_eq!(patched.entity, Some(entity_source_id()));
    let bytes = Documents::new(&mut harness.workspace)
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
    harness.reopen_with(Box::new(FaultAt(FaultPoint::AfterCommit)));
    let request = harness.request("publish", None, "docs/publish.adoc", None);
    let error = {
        let mut documents = Documents::new(&mut harness.workspace);
        documents
            .save_source(request, b"= Publish\n\ncommitted source\n")
            .expect_err("fault after commit")
    };
    assert!(matches!(
        error,
        DocumentError::Store(mneme_store::StoreError::InjectedFault(_))
    ));
    harness.reopen_with(Box::new(NoFaults));
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
        blob::read_working_file(harness.temp.path(), "docs/publish.adoc").expect("file"),
        Some(external.to_vec())
    );
    let _ = committed;
}

#[cfg(unix)]
#[test]
fn symlinked_working_file_cannot_escape_the_workspace() {
    use std::os::unix::fs::symlink;
    let mut harness = Harness::new();
    let outside = harness.temp.path().join("outside.adoc");
    std::fs::write(&outside, b"= Outside\n\nsecret\n").expect("outside");
    let link = harness.temp.path().join("working/link.adoc");
    symlink(&outside, &link).expect("symlink");
    let request = harness.request("link", None, "link.adoc", None);
    let error = {
        let mut documents = Documents::new(&mut harness.workspace);
        documents
            .import_working_file(request)
            .expect_err("symlink escape")
    };
    assert!(matches!(error, DocumentError::Store(_)));
}

#[test]
fn preview_cache_keys_cover_configuration_processor_dependencies_and_generation() {
    let mut harness = Harness::new();
    harness.write_file("docs/cache.adoc", b"= Cache\n\ncached\n");
    let imported = harness.import(harness.request("cache", None, "docs/cache.adoc", None));
    let artifact = {
        let mut documents = Documents::new(&mut harness.workspace);
        documents
            .preview(imported.document_id, None, RenderConfig::default())
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

fn rid(byte: u8) -> RecordId {
    RecordId::from_bytes([byte; 16])
}

#[test]
fn unavailable_root_and_include_sources_are_reported_without_substitution() {
    let mut harness = Harness::new();
    harness.write_file("docs/part.adoc", b"= Part\n\nincluded text\n");
    let part = harness.import(harness.request("part", None, "docs/part.adoc", None));
    harness.write_file("docs/root.adoc", b"= Root\n\ninclude::part.adoc[]\n");
    let root = harness.import(harness.request("root", None, "docs/root.adoc", None));
    let part_view = Documents::new(&mut harness.workspace)
        .document_by_path("docs/part.adoc")
        .expect("lookup")
        .expect("part");
    let digest = mneme_core::ContentDigest::of_source_bytes(b"= Part\n\nincluded text\n");
    assert!(blob::blob_path(harness.temp.path(), digest).exists());
    // Mark the included source unavailable while the root remains committed.
    let mut unavailable = mneme_memory::build_unavailable_source_with_digest(
        part_view.source.source,
        rev(0x72),
        &scope(),
        "source bytes pruned under retention policy",
        "pruned",
        Some(digest),
        None,
        Some("docs/part.adoc"),
    );
    unavailable.predecessor = Some(part.source.revision);
    let base = harness.workspace.current_revision().expect("base");
    harness
        .workspace
        .commit(CommitCommand {
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
        let mut documents = Documents::new(&mut harness.workspace);
        documents
            .preview(root.document_id, None, RenderConfig::default())
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
        DocumentPolicy {
            max_depth: 0,
            ..DocumentPolicy::default()
        },
        DocumentPolicy {
            max_total_source_bytes: 10,
            ..DocumentPolicy::default()
        },
        DocumentPolicy {
            max_time_ms: 0,
            ..DocumentPolicy::default()
        },
        DocumentPolicy {
            allowed_roots: vec!["other".to_owned()],
            ..DocumentPolicy::default()
        },
    ] {
        let mut request = harness.request("limits", None, "docs/root.adoc", None);
        request.policy = policy;
        let validation = {
            let documents = Documents::new(&mut harness.workspace);
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
    use mneme_core::{Origin, SourceSpan};
    use mneme_memory::{Memory, MemoryBatch, Stance, build_evidence, build_proposed_assertion};

    let mut harness = Harness::new();
    let first_source = b"= Evidence\n\nOriginal cited sentence.\n";
    harness.write_file("docs/evidence.adoc", first_source);
    let imported =
        harness.import(harness.request("evidence-doc", None, "docs/evidence.adoc", None));
    let span = SourceSpan::new(12, 35).expect("span");
    let evidence = build_evidence(
        rid(0x40),
        rev(0x41),
        &scope(),
        rid(0x42),
        imported.source.source,
        imported.source.revision,
        Some(span),
        Some("evidence"),
        mneme_memory::SupportRelation::Supports,
        Origin::AuthoredStatement,
        &[],
    );
    let assertion = build_proposed_assertion(
        rid(0x42),
        rev(0x43),
        &scope(),
        entity_source_id(),
        "citation",
        Value::string("original"),
        Stance::Affirm,
        Origin::AuthoredStatement,
        "author",
        mneme_core::ValidTime::always(),
        &[mneme_core::Reference::local(
            rid(0x40),
            mneme_core::RecordKind::Evidence,
        )],
        None,
        None,
    );
    Memory::new(&mut harness.workspace)
        .commit(MemoryBatch {
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
    let memory = Memory::new(&mut harness.workspace);
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
    let substituted = Documents::new(&mut harness.workspace)
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
    let invalid = Documents::new(&mut harness.workspace)
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
        let mut documents = Documents::new(&mut harness.workspace);
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
        let mut documents = Documents::new(&mut harness.workspace);
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
        Documents::new(&mut harness.workspace)
            .anchors(first.document_id)
            .expect("anchors")
            .len(),
        1
    );
    harness.write_file("docs/anchor-v1.adoc", b"= A\n\n[[second]]\nnew body\n");
    harness.import(harness.request("a2", Some(first.document_id), "docs/anchor-v1.adoc", None));
    let anchors = Documents::new(&mut harness.workspace)
        .anchors(first.document_id)
        .expect("anchors");
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].anchor, "second");
}
