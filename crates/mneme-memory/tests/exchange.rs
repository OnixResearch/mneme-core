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

fn trusted_policy(issuer: &str, secret: &[u8; 32]) -> mneme_memory::exchange::ExchangePolicy {
    mneme_memory::exchange::ExchangePolicy::new([mneme_memory::exchange::ExchangePeer {
        issuer: issuer.to_owned(),
        public_key: mneme_memory::exchange::exchange_public_key(secret),
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
    let authenticated =
        mneme_memory::exchange::authenticate_exchange_json(document.as_bytes(), &policy)
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
    let replay = mneme_memory::exchange::authenticate_exchange_json(document.as_bytes(), &policy)
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
    let untrusted = mneme_memory::exchange::ExchangePolicy::new(std::iter::empty())
        .expect("empty local trust policy");
    assert!(matches!(
        mneme_memory::exchange::authenticate_exchange_json(document.as_bytes(), &untrusted),
        Err(mneme_memory::exchange::ExchangeError::UntrustedIssuer)
    ));
    let policy = trusted_policy("device-b", &secret);
    let altered = document.replace("device-a", "device-b");
    assert_ne!(altered, document);
    assert!(matches!(
        mneme_memory::exchange::authenticate_exchange_json(altered.as_bytes(), &policy),
        Err(mneme_memory::exchange::ExchangeError::InvalidSignature)
    ));
}
