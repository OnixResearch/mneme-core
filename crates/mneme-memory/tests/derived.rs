//! Regression tests for the `derived` acquisition on source revisions.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

mod common;

fn text_options(bytes: &[u8]) -> mneme_memory::SourceOptions<'_> {
    mneme_memory::SourceOptions {
        bytes,
        media_type: "text/plain; charset=utf-8",
        entity: None,
        path_hint: None,
    }
}

fn commit_original(workspace: &mut mneme_store::Workspace) -> mneme_core::SourcePin {
    let pin = mneme_core::SourcePin::new(common::rid(0xd1), common::rev(0xe1));
    let (record, blob) = mneme_memory::build_captured_source(
        pin.source(),
        pin.revision(),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: b"%PDF original",
            media_type: "application/pdf",
            entity: None,
            path_hint: None,
        },
        mneme_core::MediaExtent::Pages { page_count: 1 },
    )
    .expect("original");
    common::engine(workspace)
        .commit(common::batch("original", vec![record], vec![blob]))
        .expect("commit original");
    pin
}

fn derive(
    upstream: mneme_core::SourcePin,
    id: u8,
) -> (mneme_store::RecordDraft, mneme_store::SourceBlobDraft) {
    let derivation =
        mneme_core::DerivedAcquisition::new(upstream, "pdftotext", "24.02.0").expect("derivation");
    mneme_memory::build_derived_source(
        common::rid(id),
        common::rev(id),
        &common::scope(),
        text_options(b"companion text"),
        &derivation,
    )
    .expect("derived draft")
}

#[test]
fn a_derived_source_commits_and_reads_back_its_upstream_and_backend() {
    let (_temp, mut workspace) = common::setup();
    let upstream = commit_original(&mut workspace);
    let (record, blob) = derive(upstream, 0xd2);
    assert_eq!(
        record.schema_version,
        mneme_core::DERIVED_ACQUISITION_SCHEMA_VERSION
    );
    common::engine(&mut workspace)
        .commit(common::batch("derived", vec![record], vec![blob]))
        .expect("a derived source over an existing source commits");
    let stored = common::latest(&workspace, common::rid(0xd2));
    let view = mneme_memory::SourceView::parse(stored).expect("derived view");
    assert_eq!(view.acquisition, mneme_core::Acquisition::Derived);
    let derivation = view.derivation.as_ref().expect("derivation");
    assert_eq!(derivation.source(), upstream);
    assert_eq!(derivation.backend().as_str(), "pdftotext");
    assert_eq!(derivation.backend_version(), "24.02.0");
    assert_eq!(view.derived_from, Some(upstream));
    let pruned = mneme_memory::build_unavailable_source_preserving(
        &view,
        common::rev(0xee),
        "pruned for the test",
        "pruned",
    );
    assert_eq!(
        pruned.schema_version,
        mneme_core::DERIVED_ACQUISITION_SCHEMA_VERSION
    );
    assert_eq!(
        pruned.payload.get("acquisition"),
        Some(&derivation.to_value())
    );
}

#[test]
fn a_dangling_or_self_referencing_derived_source_is_refused() {
    let (_temp, mut workspace) = common::setup();
    let dangling = mneme_core::SourcePin::new(common::rid(0xdf), common::rev(0xef));
    let (record, blob) = derive(dangling, 0xd3);
    assert!(
        common::engine(&mut workspace)
            .commit(common::batch("dangling", vec![record], vec![blob]))
            .is_err(),
        "a missing upstream source must be refused"
    );
    let upstream = commit_original(&mut workspace);
    let wrong_revision = mneme_core::SourcePin::new(upstream.source(), common::rev(0xe9));
    let (record, blob) = derive(wrong_revision, 0xd4);
    assert!(
        common::engine(&mut workspace)
            .commit(common::batch("wrong-revision", vec![record], vec![blob]))
            .is_err(),
        "an unknown upstream revision must be refused"
    );
    let own = mneme_core::SourcePin::new(common::rid(0xd5), common::rev(0xe5));
    let (record, blob) = derive(own, 0xd5);
    assert!(
        common::engine(&mut workspace)
            .commit(common::batch("self", vec![record], vec![blob]))
            .is_err(),
        "a derivative cannot name itself as upstream"
    );
}

#[test]
fn a_derived_record_needs_schema_six_and_a_matching_pin() {
    let registry = mneme_core::SchemaRegistry::production();
    let upstream = mneme_core::SourcePin::new(common::rid(0xd1), common::rev(0xe1));
    let (draft, _) = derive(upstream, 0xd6);
    let envelope = |draft: &mneme_store::RecordDraft, version: u32, payload| {
        let mut record = mneme_core::fixtures::source_revision();
        record.schema_version = version;
        record.payload = payload;
        let _ = draft;
        record
    };
    let ok = envelope(&draft, 6, draft.payload.clone());
    mneme_core::validate_record_value(&ok.to_value(), &registry, None)
        .expect("a v6 derived source validates");
    let old = envelope(&draft, 5, draft.payload.clone());
    assert!(
        mneme_core::validate_record_value(&old.to_value(), &registry, None).is_err(),
        "schema 5 keeps a closed symbol acquisition"
    );
    let mut payload = draft.payload.as_map().clone();
    payload.remove(&mneme_core::Symbol::from("derived-from"));
    let unpinned = envelope(&draft, 6, mneme_core::Payload::new(payload.clone()));
    assert!(mneme_core::validate_record_value(&unpinned.to_value(), &registry, None).is_err());
    payload.insert(
        mneme_core::Symbol::from("derived-from"),
        mneme_core::SourcePin::new(common::rid(0xaa), common::rev(0xbb)).to_value(),
    );
    let mismatched = envelope(&draft, 6, mneme_core::Payload::new(payload));
    assert!(mneme_core::validate_record_value(&mismatched.to_value(), &registry, None).is_err());
    let bare = mneme_core::Acquisition::from_value(
        &mneme_core::Value::symbol("derived"),
        &mneme_core::Path::root(),
    );
    assert!(bare.is_err(), "the bare symbol carries no upstream");
}

#[test]
fn authored_and_imported_sources_still_decode_unchanged() {
    for symbol in ["authored", "imported"] {
        let mut source = mneme_core::fixtures::source_revision();
        let mut payload = source.payload.as_map().clone();
        payload.insert(
            mneme_core::Symbol::from("acquisition"),
            mneme_core::Value::symbol(symbol),
        );
        source.payload = mneme_core::Payload::new(payload);
        let registry = mneme_core::SchemaRegistry::production();
        for version in [1, 5, 6] {
            source.schema_version = version;
            mneme_core::validate_record_value(&source.to_value(), &registry, None)
                .expect("authored and imported validate at prior and current schema versions");
        }
        let view = mneme_memory::SourceView::parse(source).expect("view");
        assert!(view.derivation.is_none());
        assert!(!view.acquisition.is_reproducible());
    }
}
