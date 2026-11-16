//! Signed workspace exchange over the durable memory admission path.
#![allow(unknown_lints, no_unwrap)] // test inputs are deterministic fixtures
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
mod common;

fn receiver() -> (tempfile::TempDir, mneme_store::Workspace) {
    let temp = tempfile::tempdir().expect("receiver directory");
    let workspace = mneme_store::Workspace::create(
        temp.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(2_000),
            )),
            faults: Box::new(mneme_store::NoFaults),
        },
    )
    .expect("receiver workspace");
    (temp, workspace)
}

fn trusted_policy(issuer: &str, secret: &[u8; 32]) -> mneme_memory::exchange::Policy {
    mneme_memory::exchange::Policy::new([mneme_memory::exchange::Peer {
        issuer: issuer.to_owned(),
        public_key: mneme_memory::exchange::public_key(secret),
    }])
    .expect("trusted device policy")
}

fn proposal(workspace: &mut mneme_store::Workspace) -> mneme_core::RecordId {
    common::propose(
        workspace,
        "exchange-proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x80),
            evidence_revision: common::rev(0x81),
            assertion_id: common::rid(0x82),
            assertion_revision: common::rev(0x83),
            predicate: "exchange-test",
            value: mneme_core::Value::string("signed claim"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    )
}

#[test]
fn signed_import_is_trusted_reviewable_and_idempotent() {
    let (_origin_temp, mut origin) = common::setup();
    let assertion = proposal(&mut origin);
    let secret = [0x91; 32];
    let document = mneme_memory::exchange::export_workspace(&origin, "device-a", &secret)
        .expect("signed export");
    let policy = trusted_policy("device-a", &secret);
    let authenticated = mneme_memory::exchange::authenticate_json(document.as_bytes(), &policy)
        .expect("trusted signature");
    let (_receiver_temp, mut receiver) = receiver();
    let first =
        mneme_memory::exchange::import_records(&mut receiver, authenticated, "local-reviewer")
            .expect("import through memory validation");
    assert!(first.imported.contains(&assertion));
    assert!(first.already_present.is_empty());
    assert!(first.decisions.is_empty());
    let view = common::engine(&mut receiver).view().expect("imported view");
    let imported = view.assertion(assertion).expect("imported assertion");
    assert_eq!(imported.lifecycle, mneme_core::Lifecycle::Proposed);
    assert_eq!(imported.origin, mneme_core::Origin::Import);
    assert_eq!(
        view.source_status(common::SOURCE_ID)
            .expect("imported source"),
        mneme_memory::SourceStatus::Retained(mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec())
    );
    let replay = mneme_memory::exchange::authenticate_json(document.as_bytes(), &policy)
        .expect("replayed trusted signature");
    let second = mneme_memory::exchange::import_records(&mut receiver, replay, "local-reviewer")
        .expect("idempotent replay");
    assert!(second.imported.is_empty());
    assert!(second.already_present.contains(&assertion));
}

#[test]
fn exchange_authentication_rejects_untrusted_and_tampered_signers() {
    let (_origin_temp, mut origin) = common::setup();
    proposal(&mut origin);
    let secret = [0xa2; 32];
    let document = mneme_memory::exchange::export_workspace(&origin, "device-a", &secret)
        .expect("signed export");
    let untrusted =
        mneme_memory::exchange::Policy::new(std::iter::empty()).expect("empty local trust policy");
    assert!(matches!(
        mneme_memory::exchange::authenticate_json(document.as_bytes(), &untrusted),
        Err(mneme_memory::exchange::Error::UntrustedIssuer)
    ));
    let policy = trusted_policy("device-b", &secret);
    let altered = document.replace("device-a", "device-b");
    assert_ne!(altered, document);
    assert!(matches!(
        mneme_memory::exchange::authenticate_json(altered.as_bytes(), &policy),
        Err(mneme_memory::exchange::Error::InvalidSignature)
    ));
}

#[test]
fn signed_import_turns_open_comment_into_proposed() {
    let (_origin_temp, mut origin) = common::setup();
    let source_reference = mneme_core::Reference::pinned(
        common::SOURCE_ID,
        common::SOURCE_REV,
        mneme_core::RecordKind::SourceRevision,
    );
    let origin_document = mneme_store::RecordDraft {
        schema_version: 3,
        kind: mneme_core::RecordKind::Document,
        record_id: common::rid(0x60),
        revision_id: common::rev(0x61),
        predecessor: None,
        scope: common::scope(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("title"),
                mneme_core::Value::string("note"),
            ),
            (
                mneme_core::Symbol::from("source-revision"),
                source_reference.to_value(),
            ),
            (
                mneme_core::Symbol::from("path"),
                mneme_core::Value::string("project.adoc"),
            ),
            (
                mneme_core::Symbol::from("entity"),
                mneme_core::Reference::local(
                    mneme_core::fixtures::entity_id(),
                    mneme_core::RecordKind::Entity,
                )
                .to_value(),
            ),
        ]),
    };
    {
        let mut memory = common::engine(&mut origin);
        memory
            .commit(common::batch("document", vec![origin_document], Vec::new()))
            .expect("origin document");
    }
    let comment_id = common::rid(0x70);
    let comment = mneme_memory::build_comment(
        comment_id,
        common::rev(0x71),
        &common::scope(),
        mneme_memory::CommentOptions {
            actor: "alice",
            document: common::rid(0x60),
            source_revision: common::SOURCE_ID,
            span: None,
            block: None,
            text: "hello",
            reply_to: None,
            mentions: &[],
            status: "open",
            resolves: None,
        },
    );
    {
        let mut memory = common::engine(&mut origin);
        memory
            .commit(common::batch("comment", vec![comment], Vec::new()))
            .expect("comment commit");
    }
    let secret = [0x91; 32];
    let bundle_json = mneme_memory::exchange::export_workspace(&origin, "device-a", &secret)
        .expect("signed export");
    let policy = trusted_policy("device-a", &secret);
    let authenticated = mneme_memory::exchange::authenticate_json(bundle_json.as_bytes(), &policy)
        .expect("trusted signature");
    let (_receiver_temp, mut receiver) = common::setup();
    let receiver_document = mneme_store::RecordDraft {
        schema_version: 3,
        kind: mneme_core::RecordKind::Document,
        record_id: common::rid(0x69),
        revision_id: common::rev(0x6a),
        predecessor: None,
        scope: common::scope(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("title"),
                mneme_core::Value::string("note"),
            ),
            (
                mneme_core::Symbol::from("source-revision"),
                source_reference.to_value(),
            ),
            (
                mneme_core::Symbol::from("path"),
                mneme_core::Value::string("project.adoc"),
            ),
            (
                mneme_core::Symbol::from("entity"),
                mneme_core::Reference::local(
                    mneme_core::fixtures::entity_id(),
                    mneme_core::RecordKind::Entity,
                )
                .to_value(),
            ),
        ]),
    };
    {
        let mut memory = common::engine(&mut receiver);
        memory
            .commit(common::batch(
                "document",
                vec![receiver_document],
                Vec::new(),
            ))
            .expect("receiver document");
    }
    let first =
        mneme_memory::exchange::import_records(&mut receiver, authenticated, "local-reviewer")
            .expect("import through memory validation");
    assert!(first.imported.contains(&comment_id));
    let imported = mneme_memory::CommentView::parse(common::latest(&receiver, comment_id))
        .expect("imported comment");
    assert_eq!(imported.status, "proposed");
}
