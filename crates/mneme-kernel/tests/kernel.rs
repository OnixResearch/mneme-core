//! Behavioural checks for the decision kernel. The Lean proofs in
//! `proofs/kernel` state the general properties; these tests pin concrete
//! boundaries and keep the crate honest under the product toolchain.

fn digest(byte: u128) -> mneme_kernel::hashing::Digest {
    mneme_kernel::hashing::Digest {
        hi: byte,
        lo: !byte,
    }
}

#[test]
fn retry_of_a_committed_command_replays_even_after_the_base_moved() {
    let stored = mneme_kernel::admission::StoredCommand {
        command: digest(1),
        fingerprint: None,
    };
    let facts = mneme_kernel::admission::CommitFacts {
        stored: Some(stored),
        command: digest(1),
        fingerprint: None,
        base_is_current: false,
        generation_is_pinned: false,
    };
    assert_eq!(
        mneme_kernel::admission::decide_commit(&facts),
        mneme_kernel::admission::CommitDecision::Replay
    );
}

#[test]
fn same_key_with_other_content_conflicts() {
    let stored = mneme_kernel::admission::StoredCommand {
        command: digest(1),
        fingerprint: Some(digest(7)),
    };
    let changed_fingerprint = mneme_kernel::admission::CommitFacts {
        stored: Some(stored),
        command: digest(1),
        fingerprint: Some(digest(8)),
        base_is_current: true,
        generation_is_pinned: true,
    };
    assert_eq!(
        mneme_kernel::admission::decide_commit(&changed_fingerprint),
        mneme_kernel::admission::CommitDecision::IdempotencyConflict
    );
    let rebuilt_command = mneme_kernel::admission::CommitFacts {
        stored: Some(stored),
        command: digest(2),
        fingerprint: Some(digest(7)),
        base_is_current: false,
        generation_is_pinned: true,
    };
    assert_eq!(
        mneme_kernel::admission::decide_commit(&rebuilt_command),
        mneme_kernel::admission::CommitDecision::Replay
    );
    assert_eq!(
        mneme_kernel::admission::decide_replay(&Some(stored), &digest(8)),
        mneme_kernel::admission::ReplayDecision::Conflict
    );
    assert_eq!(
        mneme_kernel::admission::decide_replay(&Some(stored), &digest(7)),
        mneme_kernel::admission::ReplayDecision::Replay
    );
    assert_eq!(
        mneme_kernel::admission::decide_replay(&None, &digest(7)),
        mneme_kernel::admission::ReplayDecision::Fresh
    );
}

#[test]
fn fresh_command_checks_base_then_barrier() {
    let mut facts = mneme_kernel::admission::CommitFacts {
        stored: None,
        command: digest(1),
        fingerprint: None,
        base_is_current: false,
        generation_is_pinned: false,
    };
    assert_eq!(
        mneme_kernel::admission::decide_commit(&facts),
        mneme_kernel::admission::CommitDecision::StaleBase
    );
    facts.base_is_current = true;
    assert_eq!(
        mneme_kernel::admission::decide_commit(&facts),
        mneme_kernel::admission::CommitDecision::BarrierAdvanced
    );
    facts.generation_is_pinned = true;
    assert_eq!(
        mneme_kernel::admission::decide_commit(&facts),
        mneme_kernel::admission::CommitDecision::Proceed
    );
}

#[test]
fn publication_replaces_only_the_expected_content() {
    let decide = |observed, expected| {
        mneme_kernel::publish::decide_publication(&mneme_kernel::publish::PublicationFacts {
            observed,
            expected,
            desired: digest(9),
        })
    };
    assert_eq!(
        decide(None, None),
        mneme_kernel::publish::PublicationDecision::Replace
    );
    assert_eq!(
        decide(Some(digest(3)), Some(digest(3))),
        mneme_kernel::publish::PublicationDecision::Replace
    );
    assert_eq!(
        decide(Some(digest(4)), Some(digest(3))),
        mneme_kernel::publish::PublicationDecision::Diverged
    );
    assert_eq!(
        decide(Some(digest(4)), None),
        mneme_kernel::publish::PublicationDecision::Diverged
    );
    assert_eq!(
        decide(None, Some(digest(3))),
        mneme_kernel::publish::PublicationDecision::Diverged
    );
    assert_eq!(
        decide(Some(digest(9)), Some(digest(3))),
        mneme_kernel::publish::PublicationDecision::AlreadyPublished
    );
    assert!(mneme_kernel::publish::should_attempt(
        mneme_kernel::publish::PublicationPhase::Failed
    ));
    assert!(!mneme_kernel::publish::should_attempt(
        mneme_kernel::publish::PublicationPhase::Diverged
    ));
}

#[test]
fn purge_deletes_only_planned_regular_files_and_unneeded_blobs() {
    let working = |kind, observed| {
        mneme_kernel::purge::decide_working(&mneme_kernel::purge::WorkingFacts {
            kind,
            observed,
            planned: digest(5),
        })
    };
    assert_eq!(
        working(mneme_kernel::purge::EntryKind::Regular, Some(digest(5))),
        mneme_kernel::purge::WorkingDecision::Purge
    );
    assert_eq!(
        working(mneme_kernel::purge::EntryKind::Regular, Some(digest(6))),
        mneme_kernel::purge::WorkingDecision::ExternalEdit
    );
    assert_eq!(
        working(mneme_kernel::purge::EntryKind::Other, Some(digest(5))),
        mneme_kernel::purge::WorkingDecision::Unsupported
    );
    assert_eq!(
        working(mneme_kernel::purge::EntryKind::Absent, None),
        mneme_kernel::purge::WorkingDecision::AlreadyAbsent
    );
    let blob = |required, present| {
        mneme_kernel::purge::decide_blob(&mneme_kernel::purge::BlobFacts { required, present })
    };
    assert_eq!(
        blob(true, true),
        mneme_kernel::purge::BlobDecision::RetainShared
    );
    assert_eq!(blob(false, true), mneme_kernel::purge::BlobDecision::Purge);
    assert_eq!(
        blob(false, false),
        mneme_kernel::purge::BlobDecision::AlreadyAbsent
    );
}

#[test]
fn cleanup_is_complete_only_when_every_location_is_settled() {
    let settled = [
        mneme_kernel::cleanup::LocationState::Purged,
        mneme_kernel::cleanup::LocationState::Absent,
        mneme_kernel::cleanup::LocationState::Verified,
    ];
    assert!(mneme_kernel::cleanup::physically_complete(&settled));
    assert_eq!(
        mneme_kernel::cleanup::summarize(&settled),
        mneme_kernel::cleanup::JobSummary::Complete
    );
    assert!(!mneme_kernel::cleanup::physically_complete(&[]));
    assert_eq!(
        mneme_kernel::cleanup::summarize(&[]),
        mneme_kernel::cleanup::JobSummary::Partial
    );
    for (state, summary) in [
        (
            mneme_kernel::cleanup::LocationState::Failed,
            mneme_kernel::cleanup::JobSummary::Failed,
        ),
        (
            mneme_kernel::cleanup::LocationState::Pending,
            mneme_kernel::cleanup::JobSummary::Pending,
        ),
        (
            mneme_kernel::cleanup::LocationState::RetainedShared,
            mneme_kernel::cleanup::JobSummary::Partial,
        ),
        (
            mneme_kernel::cleanup::LocationState::Unavailable,
            mneme_kernel::cleanup::JobSummary::Partial,
        ),
    ] {
        let states = [mneme_kernel::cleanup::LocationState::Purged, state];
        assert!(!mneme_kernel::cleanup::physically_complete(&states));
        assert_eq!(mneme_kernel::cleanup::summarize(&states), summary);
        assert!(mneme_kernel::cleanup::needs_attempt(state));
    }
}

#[test]
fn restore_serves_nothing_until_a_current_ledger_of_this_workspace_arrives() {
    assert!(!mneme_kernel::restore::may_serve(
        mneme_kernel::restore::Marker::Pending
    ));
    assert!(mneme_kernel::restore::may_serve(
        mneme_kernel::restore::Marker::Clear
    ));
    let decide = |same_workspace, ledger_generation| {
        mneme_kernel::restore::decide_ledger(&mneme_kernel::restore::LedgerFacts {
            same_workspace,
            ledger_generation,
            restored_generation: 4,
        })
    };
    assert_eq!(
        decide(false, 9),
        mneme_kernel::restore::LedgerDecision::ForeignWorkspace
    );
    assert_eq!(
        decide(true, 3),
        mneme_kernel::restore::LedgerDecision::Stale
    );
    assert_eq!(
        decide(true, 4),
        mneme_kernel::restore::LedgerDecision::Apply
    );
}

#[test]
fn scope_rules_refuse_unauthorized_and_downward_references() {
    let reference = |same_scope, source_class, target_class, target_authorized| {
        mneme_kernel::isolation::reference_allowed(&mneme_kernel::isolation::ReferenceFacts {
            same_scope,
            source_class,
            target_class,
            target_authorized,
        })
    };
    let operational = mneme_kernel::isolation::ScopeClass::Operational;
    let hypothesis = mneme_kernel::isolation::ScopeClass::Hypothesis;
    assert!(reference(true, operational, operational, false));
    assert!(!reference(false, operational, operational, false));
    assert!(reference(false, operational, operational, true));
    assert!(!reference(false, operational, hypothesis, true));
    assert!(reference(false, hypothesis, operational, true));

    let visible = |same_scope, record_class, include_hypothetical, record_scope_authorized| {
        mneme_kernel::isolation::record_visible(&mneme_kernel::isolation::VisibilityFacts {
            same_scope,
            record_class,
            include_hypothetical,
            record_scope_authorized,
        })
    };
    assert!(visible(true, operational, false, false));
    assert!(!visible(false, hypothesis, true, false));
    assert!(!visible(false, operational, true, true));
    assert!(visible(false, hypothesis, true, true));

    let promotion = mneme_kernel::isolation::RevisionFacts {
        same_scope: false,
        prior_class: hypothesis,
        next_class: operational,
        carries_acceptance: true,
        both_authorized: true,
    };
    assert!(mneme_kernel::isolation::revision_scope_allowed(&promotion));
    assert!(!mneme_kernel::isolation::revision_scope_allowed(
        &mneme_kernel::isolation::RevisionFacts {
            both_authorized: false,
            ..promotion
        }
    ));
    assert!(!mneme_kernel::isolation::revision_scope_structural(
        &mneme_kernel::isolation::ScopeChange {
            same_scope: false,
            prior_class: operational,
            next_class: operational,
        }
    ));
    assert!(mneme_kernel::isolation::content_readable(
        &mneme_kernel::isolation::ContentFacts {
            same_scope: false,
            target_authorized: true,
        }
    ));
    assert!(!mneme_kernel::isolation::content_readable(
        &mneme_kernel::isolation::ContentFacts {
            same_scope: false,
            target_authorized: false,
        }
    ));
    assert!(!mneme_kernel::isolation::blob_claim_allowed(
        &mneme_kernel::isolation::BlobClaimFacts {
            bytes_supplied: false,
            bound_in_scope: false,
        }
    ));
}

#[test]
fn nothing_aggregates_to_passed_from_an_empty_set() {
    let passed = mneme_kernel::verdict::Status::Passed;
    let failed = mneme_kernel::verdict::Status::Failed;
    let skipped = mneme_kernel::verdict::Status::Skipped;
    let unimplemented = mneme_kernel::verdict::Status::Unimplemented;
    assert_eq!(mneme_kernel::verdict::aggregate(&[]), unimplemented);
    assert!(!mneme_kernel::verdict::acceptance_satisfied(&[]));
    assert!(mneme_kernel::verdict::acceptance_satisfied(&[
        passed, passed
    ]));
    assert!(!mneme_kernel::verdict::acceptance_satisfied(&[
        passed, skipped
    ]));
    assert_eq!(
        mneme_kernel::verdict::aggregate(&[passed, skipped, unimplemented]),
        unimplemented
    );
    assert_eq!(
        mneme_kernel::verdict::aggregate(&[unimplemented, failed, passed]),
        failed
    );
    let declared = mneme_kernel::verdict::SkipDeclaration::Declared;
    let not_declared = mneme_kernel::verdict::SkipDeclaration::NotDeclared;
    assert_eq!(mneme_kernel::verdict::case_status(declared, failed), failed);
    assert_eq!(
        mneme_kernel::verdict::case_status(declared, passed),
        skipped
    );
    assert_eq!(
        mneme_kernel::verdict::case_status(not_declared, passed),
        passed
    );
}

#[test]
fn absence_needs_an_exhaustive_complete_unbounded_current_answer() {
    let complete = mneme_kernel::completeness::AnswerFacts {
        rows: 0,
        exhaustive: true,
        coverage: mneme_kernel::completeness::Coverage::Complete,
        limit_reached: false,
        declaration_valid: true,
        generation_current: true,
    };
    assert!(mneme_kernel::completeness::absence_established(&complete));
    for weakened in [
        mneme_kernel::completeness::AnswerFacts {
            rows: 1,
            ..complete
        },
        mneme_kernel::completeness::AnswerFacts {
            exhaustive: false,
            ..complete
        },
        mneme_kernel::completeness::AnswerFacts {
            coverage: mneme_kernel::completeness::Coverage::Incomplete,
            ..complete
        },
        mneme_kernel::completeness::AnswerFacts {
            coverage: mneme_kernel::completeness::Coverage::Unknown,
            ..complete
        },
        mneme_kernel::completeness::AnswerFacts {
            limit_reached: true,
            ..complete
        },
        mneme_kernel::completeness::AnswerFacts {
            declaration_valid: false,
            ..complete
        },
        mneme_kernel::completeness::AnswerFacts {
            generation_current: false,
            ..complete
        },
    ] {
        assert!(!mneme_kernel::completeness::absence_established(&weakened));
    }
}

#[test]
fn budgets_refuse_overflow_and_excess() {
    assert_eq!(mneme_kernel::budget::charge(3, 4, 7), Some(7));
    assert_eq!(mneme_kernel::budget::charge(3, 5, 7), None);
    assert_eq!(mneme_kernel::budget::charge(u64::MAX, 1, u64::MAX), None);
}

#[test]
fn excerpt_windows_stay_inside_the_text() {
    let window = |start, stop, text_len, max_bytes| {
        mneme_kernel::extent::excerpt_window(&mneme_kernel::extent::ExcerptRequest {
            start,
            stop,
            text_len,
            max_bytes,
        })
    };
    assert_eq!(window(5, 4, 10, 8), None);
    assert_eq!(window(0, 11, 10, 8), None);
    assert_eq!(
        window(2, 6, 10, 8),
        Some(mneme_kernel::extent::Window {
            start: 2,
            stop: 6,
            truncated: false
        })
    );
    assert_eq!(
        window(2, 10, 10, 3),
        Some(mneme_kernel::extent::Window {
            start: 2,
            stop: 5,
            truncated: true
        })
    );
    assert_eq!(
        window(u64::MAX, u64::MAX, u64::MAX, 0),
        Some(mneme_kernel::extent::Window {
            start: u64::MAX,
            stop: u64::MAX,
            truncated: false
        })
    );
    assert_eq!(mneme_kernel::extent::span_length(9, 3), None);
    let text = "aé€b".as_bytes();
    assert_eq!(mneme_kernel::extent::floor_boundary(text, 2), 1);
    assert_eq!(mneme_kernel::extent::floor_boundary(text, 5), 3);
    assert_eq!(mneme_kernel::extent::floor_boundary(text, 99), text.len());
    for index in 0..=text.len() {
        let floored = mneme_kernel::extent::floor_boundary(text, index);
        assert!(std::str::from_utf8(&text[..floored]).is_ok());
    }
}

#[test]
fn text_checks_refuse_injection_and_aliases() {
    assert!(mneme_kernel::text::is_safe_atom(b"path_2B"));
    for unsafe_text in [
        &b""[..],
        b"Path",
        b"_x",
        b"a), consult(other_file",
        b"a b",
        b"a.",
        b"a'b",
        "\u{e9}".as_bytes(),
    ] {
        assert!(!mneme_kernel::text::is_safe_atom(unsafe_text));
    }
    assert!(mneme_kernel::text::is_lower_hex(b"00ff9a"));
    assert!(!mneme_kernel::text::is_lower_hex(b"00FF9a"));
    for canonical in [
        &b"a"[..],
        b"notes/alpha.adoc",
        b"a/..b/c",
        b"...",
        b".hidden",
    ] {
        assert!(mneme_kernel::text::is_canonical_relative_path(canonical));
    }
    for alias in [
        &b""[..],
        b"/a",
        b"a/",
        b"a//b",
        b"a/./b",
        b"a/../b",
        b"..",
        b".",
        b"a\\b",
        b"a\0b",
    ] {
        assert!(!mneme_kernel::text::is_canonical_relative_path(alias));
    }
}

#[test]
fn lifecycle_is_born_proposed_and_retraction_is_final() {
    let proposed = mneme_kernel::claim::Lifecycle::Proposed;
    let accepted = mneme_kernel::claim::Lifecycle::Accepted;
    let retracted = mneme_kernel::claim::Lifecycle::Retracted;
    let superseded = mneme_kernel::claim::Lifecycle::Superseded;
    assert!(mneme_kernel::claim::transition_allowed(None, proposed));
    assert!(!mneme_kernel::claim::transition_allowed(None, accepted));
    assert!(!mneme_kernel::claim::transition_allowed(
        Some(retracted),
        accepted
    ));
    assert!(!mneme_kernel::claim::transition_allowed(
        Some(superseded),
        accepted
    ));
    assert!(mneme_kernel::claim::transition_allowed(
        Some(superseded),
        retracted
    ));
    assert!(!mneme_kernel::claim::transition_allowed(
        Some(accepted),
        proposed
    ));

    let decision = mneme_kernel::claim::CitedDecision {
        kind: mneme_kernel::claim::DecisionKind::Acceptance,
        outcome_matches: true,
        targets_assertion: true,
        binds_replaced_revision: true,
    };
    let commit = mneme_kernel::claim::CommitTimeFacts {
        decision_in_batch: true,
        actor_is_committer: true,
    };
    assert!(mneme_kernel::claim::revision_admissible(
        Some(proposed),
        accepted,
        &Some(decision),
        &commit
    ));
    let reused = mneme_kernel::claim::CitedDecision {
        binds_replaced_revision: false,
        ..decision
    };
    assert!(!mneme_kernel::claim::decision_backs(
        accepted,
        &Some(reused)
    ));
    assert!(!mneme_kernel::claim::revision_admissible(
        Some(proposed),
        accepted,
        &Some(decision),
        &mneme_kernel::claim::CommitTimeFacts {
            decision_in_batch: true,
            actor_is_committer: false,
        }
    ));
    assert!(!mneme_kernel::claim::revision_admissible(
        Some(proposed),
        accepted,
        &None,
        &commit
    ));
    assert!(mneme_kernel::claim::revision_admissible(
        None, proposed, &None, &commit
    ));
}

#[test]
fn epistemic_semiring_laws_and_annihilator_exclusion() {
    use mneme_kernel::epistemic::{EpistemicStatus, is_active, join, negation_blocks, rank, union};

    let all = [
        EpistemicStatus::Rejected,
        EpistemicStatus::Proposed,
        EpistemicStatus::Accepted,
    ];
    for a in all {
        assert_eq!(join(a, a), a);
        assert_eq!(union(a, a), a);
        assert_eq!(join(EpistemicStatus::Accepted, a), a);
        assert_eq!(join(a, EpistemicStatus::Accepted), a);
        assert_eq!(
            join(EpistemicStatus::Rejected, a),
            EpistemicStatus::Rejected
        );
        assert_eq!(
            join(a, EpistemicStatus::Rejected),
            EpistemicStatus::Rejected
        );
        assert_eq!(union(EpistemicStatus::Rejected, a), a);
        assert_eq!(union(a, EpistemicStatus::Rejected), a);
        assert_eq!(
            union(EpistemicStatus::Accepted, a),
            EpistemicStatus::Accepted
        );
        assert_eq!(
            union(a, EpistemicStatus::Accepted),
            EpistemicStatus::Accepted
        );
        assert_eq!(is_active(a), a != EpistemicStatus::Rejected);
        assert_eq!(negation_blocks(a), a != EpistemicStatus::Rejected);
        for b in all {
            assert_eq!(join(a, b), join(b, a));
            assert_eq!(union(a, b), union(b, a));
            assert!(rank(join(a, b)) <= rank(a));
            assert!(rank(join(a, b)) <= rank(b));
            for c in all {
                assert_eq!(join(join(a, b), c), join(a, join(b, c)));
                assert_eq!(union(union(a, b), c), union(a, union(b, c)));
                assert_eq!(join(a, union(b, c)), union(join(a, b), join(a, c)));
            }
        }
    }
}

#[test]
fn assertion_and_non_monotonic_admission_gates() {
    for has_accepted_decision in [false, true] {
        for has_current_basis in [false, true] {
            for suppressed in [false, true] {
                for subject_live in [false, true] {
                    let input = mneme_kernel::admission::AssertionAdmissionInput {
                        has_accepted_decision,
                        has_current_basis,
                        suppressed,
                        subject_live,
                    };
                    let expected =
                        has_accepted_decision && has_current_basis && !suppressed && subject_live;
                    assert_eq!(
                        mneme_kernel::admission::assertion_admissible(&input),
                        expected
                    );
                }
            }
        }
    }

    assert!(mneme_kernel::admission::non_monotonic_rule_admissible(
        mneme_kernel::completeness::Coverage::Complete
    ));
    assert!(!mneme_kernel::admission::non_monotonic_rule_admissible(
        mneme_kernel::completeness::Coverage::Incomplete
    ));
    assert!(!mneme_kernel::admission::non_monotonic_rule_admissible(
        mneme_kernel::completeness::Coverage::Unknown
    ));
}

#[test]
fn capability_attenuation_and_gset_revocation_dominance() {
    use mneme_kernel::capability::{
        Authority, LinkPolicy, RevocationState, ScopeMode, attenuation_valid, authority_attenuates,
        authority_permits, is_revoked, is_revoked_in_merge, merge_revocation_state,
        revocation_state, scope_subset,
    };
    use mneme_kernel::hashing::Digest;

    let vault_a = Digest { hi: 1, lo: 1 };
    let vault_b = Digest { hi: 2, lo: 2 };
    let scope_1 = Digest { hi: 10, lo: 1 };
    let scope_2 = Digest { hi: 10, lo: 2 };
    let scope_3 = Digest { hi: 10, lo: 3 };

    assert!(authority_permits(Authority::SyncPush, Authority::ReadOnly));
    assert!(!authority_permits(Authority::ReadOnly, Authority::SyncPull));
    assert!(authority_attenuates(
        Authority::SyncPush,
        Authority::SyncPull
    ));
    assert!(!authority_attenuates(
        Authority::ReadOnly,
        Authority::SyncPush
    ));

    assert!(scope_subset(
        ScopeMode::Explicit,
        &[scope_1],
        ScopeMode::Wildcard,
        &[]
    ));
    assert!(!scope_subset(
        ScopeMode::Wildcard,
        &[],
        ScopeMode::Explicit,
        &[scope_1]
    ));
    assert!(scope_subset(
        ScopeMode::Explicit,
        &[scope_1],
        ScopeMode::Explicit,
        &[scope_1, scope_2]
    ));
    assert!(!scope_subset(
        ScopeMode::Explicit,
        &[scope_1, scope_3],
        ScopeMode::Explicit,
        &[scope_1, scope_2]
    ));

    let root = LinkPolicy {
        vault_id: vault_a,
        authority: Authority::SyncPush,
        scope_mode: ScopeMode::Wildcard,
        expires_at: 2_000,
        remaining_depth: 4,
    };
    let mid = LinkPolicy {
        vault_id: vault_a,
        authority: Authority::SyncPull,
        scope_mode: ScopeMode::Explicit,
        expires_at: 1_500,
        remaining_depth: 3,
    };
    let leaf = LinkPolicy {
        vault_id: vault_a,
        authority: Authority::ReadOnly,
        scope_mode: ScopeMode::Explicit,
        expires_at: 1_200,
        remaining_depth: 2,
    };
    assert!(attenuation_valid(
        &root,
        &[],
        &mid,
        &[scope_1, scope_2],
        2,
        8
    ));
    assert!(attenuation_valid(
        &mid,
        &[scope_1, scope_2],
        &leaf,
        &[scope_1],
        3,
        8
    ));
    assert!(attenuation_valid(&root, &[], &leaf, &[scope_1], 3, 8));

    let wrong_vault = LinkPolicy {
        vault_id: vault_b,
        ..leaf
    };
    assert!(!attenuation_valid(
        &mid,
        &[scope_1, scope_2],
        &wrong_vault,
        &[scope_1],
        3,
        8
    ));
    assert!(!attenuation_valid(
        &mid,
        &[scope_1, scope_2],
        &leaf,
        &[scope_1],
        9,
        8
    ));

    let chain = [101_u128, 202_u128, 303_u128];
    let left = [999_u128];
    let right = [202_u128];
    assert!(!is_revoked(&chain, &left));
    assert!(is_revoked(&chain, &right));
    assert_eq!(revocation_state(&chain, &left), RevocationState::Active);
    assert_eq!(revocation_state(&chain, &right), RevocationState::Revoked);
    assert_eq!(
        merge_revocation_state(RevocationState::Active, RevocationState::Revoked),
        RevocationState::Revoked
    );
    assert_eq!(
        merge_revocation_state(RevocationState::Revoked, RevocationState::Active),
        RevocationState::Revoked
    );
    assert!(is_revoked_in_merge(&chain, &left, &right));
    assert!(is_revoked_in_merge(&chain, &right, &left));
}
