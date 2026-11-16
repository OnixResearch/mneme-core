#![allow(unknown_lints, no_unwrap)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
mod common;

#[test]
fn build_comment_round_trips_through_comment_view() {
    let (_temp, mut workspace) = common::setup();
    // Create a document record so the comment's document reference resolves.
    let source_reference = mneme_core::Reference::pinned(
        common::SOURCE_ID,
        common::SOURCE_REV,
        mneme_core::RecordKind::SourceRevision,
    );
    let document = mneme_store::RecordDraft {
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
        ]),
    };
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("document", vec![document], Vec::new()))
            .expect("document commit");
    }
    let span = mneme_core::SourceSpan::new(0, 5).expect("span");
    // First comment, referenced by reply-to/resolves below.
    let first = mneme_memory::build_comment(
        common::rid(0x32),
        common::rev(0x33),
        &common::scope(),
        mneme_memory::CommentOptions {
            actor: "bob",
            document: common::rid(0x60),
            source_revision: common::SOURCE_ID,
            source_pin: common::SOURCE_REV,
            span: None,
            block: None,
            text: "first",
            reply_to: None,
            mentions: &[],
            status: "open",
            resolves: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("first-comment", vec![first], Vec::new()))
            .expect("first comment commit");
    }
    let second = mneme_memory::build_comment(
        common::rid(0x30),
        common::rev(0x31),
        &common::scope(),
        mneme_memory::CommentOptions {
            actor: "alice",
            document: common::rid(0x60),
            source_revision: common::SOURCE_ID,
            source_pin: common::SOURCE_REV,
            span: Some(span),
            block: Some("blk-1"),
            text: "hello comment",
            reply_to: Some(common::rid(0x32)),
            mentions: &["bob", "carol"],
            status: "open",
            resolves: Some(common::rid(0x32)),
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("comment", vec![second], Vec::new()))
            .expect("commit");
    }
    let parsed = mneme_memory::CommentView::parse(common::latest(&workspace, common::rid(0x30)))
        .expect("parse");
    assert_eq!(parsed.actor, "alice");
    assert_eq!(parsed.document, common::rid(0x60));
    assert_eq!(parsed.source_revision, common::SOURCE_ID);
    assert_eq!(
        parsed.source_pin,
        Some(common::SOURCE_REV),
        "the comment names the source revision it is about"
    );
    assert_eq!(parsed.span, Some(span));
    assert_eq!(parsed.block.as_deref(), Some("blk-1"));
    assert_eq!(parsed.text, "hello comment");
    assert_eq!(parsed.reply_to, Some(common::rid(0x32)));
    assert!(parsed.mentions.contains("bob"));
    assert!(parsed.mentions.contains("carol"));
    assert_eq!(parsed.status, "open");
    assert_eq!(parsed.resolves, Some(common::rid(0x32)));
}
