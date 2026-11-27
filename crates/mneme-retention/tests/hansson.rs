// Integration and property tests for Hansson kernel contraction, well-founded
// cyclic withdrawal, minimal dependent derivations, and Levi-identity revision.
#![allow(unknown_lints, no_unwrap)] // test fixture code panics on unexpected test setup failures
#![allow(clippy::unwrap_used, clippy::expect_used)] // test assertions and fixtures fail fast on panic

const SOURCE_ONE: &[u8] = b"= Launch Plan A\n\nLaunch date is May 5.\n";
const SOURCE_TWO: &[u8] = b"= Launch Plan B\n\nIndependent confirmation of May 5.\n";
const SOURCE_THREE: &[u8] = b"= Launch Plan C\n\nThird independent source.\n";

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "hansson").expect("valid scope")
}

fn make_evidence(
    ev_id: u8,
    ev_rev: u8,
    src_id: u8,
    src_rev: u8,
    assertion_id: u8,
) -> mneme_store::RecordDraft {
    mneme_memory::build_evidence(
        rid(ev_id),
        rev(ev_rev),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(assertion_id),
            source: rid(src_id),
            source_revision: rev(src_rev),
            span: Some(mneme_core::SourceSpan::new(0, 10).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    )
}

struct AssertionSpec<'a> {
    id: u8,
    rev_byte: u8,
    predicate: &'a str,
    value: &'a str,
    origin: mneme_core::Origin,
    evidence_ids: &'a [u8],
}

fn make_assertion(spec: AssertionSpec<'_>) -> mneme_store::RecordDraft {
    let evidence_refs: Vec<mneme_core::Reference> = spec
        .evidence_ids
        .iter()
        .map(|ev| mneme_core::Reference::local(rid(*ev), mneme_core::RecordKind::Evidence))
        .collect();
    mneme_memory::build_proposed_assertion(
        rid(spec.id),
        rev(spec.rev_byte),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: spec.predicate,
            value: mneme_core::Value::string(spec.value),
            stance: mneme_memory::Stance::Affirm,
            origin: spec.origin,
            asserted_by: "tester",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &evidence_refs,
            extraction: None,
            superseded_by: None,
        },
    )
}

fn test_policy() -> mneme_retention::Policy {
    mneme_retention::Policy {
        version: mneme_retention::POLICY_VERSION.to_owned(),
        retain_assertion_after_prune: true,
        block_content_replay: true,
        retain_withdrawn_evidence_metadata: true,
    }
}

struct TestVault {
    _temp: tempfile::TempDir,
    workspace: mneme_store::Workspace,
}

impl TestVault {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig {
                clock: Box::new(mneme_store::FixedClock::new(
                    mneme_core::Timestamp::from_nanos(1_000),
                )),
                faults: Box::new(mneme_store::NoFaults),
            },
        )
        .expect("workspace");
        let mut vault = TestVault {
            _temp: temp,
            workspace,
        };
        vault.seed_entity();
        vault
    }

    fn seed_entity(&mut self) {
        let entity = mneme_store::RecordDraft {
            schema_version: 2,
            kind: mneme_core::RecordKind::Entity,
            record_id: mneme_core::fixtures::entity_id(),
            revision_id: rev(0x02),
            predecessor: None,
            scope: scope(),
            payload: mneme_core::Payload::new([
                (
                    mneme_core::Symbol::from("entity-type"),
                    mneme_core::Value::symbol("project"),
                ),
                (
                    mneme_core::Symbol::from("label"),
                    mneme_core::Value::string("Mneme"),
                ),
                (
                    mneme_core::Symbol::from("properties"),
                    mneme_core::Value::dictionary([]),
                ),
            ]),
        };
        self.commit("seed-entity", vec![entity], Vec::new());
    }

    fn commit(
        &mut self,
        key: &str,
        records: Vec<mneme_store::RecordDraft>,
        blobs: Vec<mneme_store::SourceBlobDraft>,
    ) {
        let base = self.workspace.current_revision().expect("base");
        self.workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "tester".to_owned(),
                scope: scope(),
                idempotency_key: key.to_owned(),
                records,
                source_blobs: blobs,
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit");
    }

    fn add_source(&mut self, key: &str, id_byte: u8, rev_byte: u8, bytes: &[u8]) {
        let (draft, blob) = mneme_memory::build_source(
            rid(id_byte),
            rev(rev_byte),
            &scope(),
            mneme_memory::SourceOptions {
                bytes,
                media_type: "text/asciidoc",
                entity: Some(mneme_core::fixtures::entity_id()),
                path_hint: None,
            },
        )
        .expect("build source");
        self.commit(key, vec![draft], vec![blob]);
    }

    fn accept_assertion(
        &mut self,
        key: &str,
        assertion_id: u8,
        new_rev: u8,
        decision_id: u8,
        decision_rev: u8,
    ) {
        let base = self.workspace.current_revision().expect("base");
        let current = self
            .workspace
            .record_revisions(rid(assertion_id))
            .expect("revisions")
            .into_iter()
            .last()
            .expect("record");
        let decision = mneme_memory::build_decision(
            rid(decision_id),
            rev(decision_rev),
            &scope(),
            mneme_memory::DecisionOptions {
                kind: mneme_memory::DecisionKind::Acceptance,
                target: rid(assertion_id),
                actor: "tester",
                policy: "test-policy/v1",
                input_revision: base,
                outcome: "accepted",
                rationale: "test acceptance",
                evidence: &[],
                related: &[],
            },
        );
        let accepted = mneme_memory::build_assertion_revision(
            &current,
            rev(new_rev),
            mneme_core::Lifecycle::Accepted,
            mneme_core::Reference::local(rid(decision_id), mneme_core::RecordKind::Decision),
            None,
        );
        self.commit(key, vec![decision, accepted], Vec::new());
    }

    fn add_derivation(
        &mut self,
        key: &str,
        deriv_id: u8,
        deriv_rev: u8,
        conclusion_id: u8,
        premise_ids: &[u8],
    ) {
        let eval_rev = self.workspace.current_revision().expect("base");
        let premises: Vec<mneme_core::Reference> = premise_ids
            .iter()
            .map(|id| mneme_core::Reference::local(rid(*id), mneme_core::RecordKind::Assertion))
            .collect();
        let draft = mneme_memory::build_derivation(
            rid(deriv_id),
            rev(deriv_rev),
            &scope(),
            mneme_memory::DerivationOptions {
                conclusion: rid(conclusion_id),
                premises: &premises,
                rule_id: key,
                rule_version: 1,
                evaluation_revision: eval_rev,
                completeness: "complete",
            },
        );
        self.commit(key, vec![draft], Vec::new());
    }

    fn request(
        &self,
        operation: mneme_retention::OperationKind,
        selector: mneme_retention::Selector,
        key: &str,
    ) -> mneme_retention::Request {
        mneme_retention::Request {
            actor: "tester".to_owned(),
            scope: scope(),
            base_revision: self.workspace.current_revision().expect("base"),
            idempotency_key: key.to_owned(),
            operation,
            selector,
            effective: None,
            policy: test_policy(),
        }
    }
}

fn seed_cyclic_pair(vault: &mut TestVault) {
    // Sole root S (0x10) -> E_A (0x20) -> A (0x30) <-> B (0x32) via D_AB (0x40), D_BA (0x42)
    vault.add_source("src-s", 0x10, 0x11, SOURCE_ONE);
    let ev_a = make_evidence(0x20, 0x21, 0x10, 0x11, 0x30);
    let assertion_a = make_assertion(AssertionSpec {
        id: 0x30,
        rev_byte: 0x31,
        predicate: "cycle-a",
        value: "a",
        origin: mneme_core::Origin::AuthoredStatement,
        evidence_ids: &[0x20],
    });
    let assertion_b = make_assertion(AssertionSpec {
        id: 0x32,
        rev_byte: 0x33,
        predicate: "cycle-b",
        value: "b",
        origin: mneme_core::Origin::AuthoredStatement,
        evidence_ids: &[],
    });
    vault.commit("seed-ab", vec![ev_a, assertion_a, assertion_b], Vec::new());
    vault.add_derivation("deriv-ab", 0x40, 0x41, 0x32, &[0x30]);
    vault.add_derivation("deriv-ba", 0x42, 0x43, 0x30, &[0x32]);
}

#[test]
fn cyclic_withdrawal_in_support_retraction_withdraws_entire_cycle() {
    let mut vault = TestVault::new();
    seed_cyclic_pair(&mut vault);

    let req = vault.request(
        mneme_retention::OperationKind::AssertionRetraction,
        mneme_retention::Selector::SourceSupport(rid(0x10)),
        "withdraw-cycle-root",
    );
    let mut retention = mneme_retention::Engine::new(&mut vault.workspace);
    let plan = retention.plan(req).expect("plan");

    assert!(plan.withdrawn_evidence.contains(&rid(0x20)));
    assert!(
        !plan.surviving_assertions.contains(&rid(0x30)),
        "A must not survive via self-supporting cycle B -> A"
    );
    assert!(
        !plan.surviving_assertions.contains(&rid(0x32)),
        "B must not survive via self-supporting cycle A -> B"
    );
    assert!(plan.invalidated_derivations.contains(&rid(0x40)));
    assert!(plan.invalidated_derivations.contains(&rid(0x42)));
}

#[test]
fn cyclic_withdrawal_in_forget_suppresses_entire_cycle() {
    let mut vault = TestVault::new();
    seed_cyclic_pair(&mut vault);

    let req = vault.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x10)),
        "forget-cycle-root",
    );
    let mut retention = mneme_retention::Engine::new(&mut vault.workspace);
    let plan = retention.plan(req).expect("plan");

    let suppressed: std::collections::BTreeSet<mneme_core::RecordId> =
        plan.suppressed.iter().map(|item| item.target).collect();
    assert!(suppressed.contains(&rid(0x10)));
    assert!(suppressed.contains(&rid(0x20)));
    assert!(suppressed.contains(&rid(0x30)));
    assert!(suppressed.contains(&rid(0x32)));
    assert!(suppressed.contains(&rid(0x40)));
    assert!(suppressed.contains(&rid(0x42)));
    assert!(plan.surviving_assertions.is_empty());
}

#[test]
fn cycle_with_independent_surviving_root_genuinely_survives() {
    let mut vault = TestVault::new();
    seed_cyclic_pair(&mut vault);
    // Add an independent surviving root S2 (0x12) backing B (0x32)
    vault.add_source("src-s2", 0x12, 0x13, SOURCE_TWO);
    let ev_b = make_evidence(0x22, 0x23, 0x12, 0x13, 0x32);
    let mut b_rev = make_assertion(AssertionSpec {
        id: 0x32,
        rev_byte: 0x34,
        predicate: "cycle-b",
        value: "b",
        origin: mneme_core::Origin::AuthoredStatement,
        evidence_ids: &[0x22],
    });
    b_rev.predecessor = Some(rev(0x33));
    vault.commit("ground-b", vec![ev_b, b_rev], Vec::new());

    let req = vault.request(
        mneme_retention::OperationKind::AssertionRetraction,
        mneme_retention::Selector::SourceSupport(rid(0x10)),
        "withdraw-only-s1",
    );
    let mut retention = mneme_retention::Engine::new(&mut vault.workspace);
    let plan = retention.plan(req).expect("plan");

    assert!(plan.surviving_assertions.contains(&rid(0x30)));
    assert!(plan.surviving_assertions.contains(&rid(0x32)));
    assert!(plan.invalidated_derivations.is_empty());
}

#[test]
fn dependent_derivations_preserve_downstream_conclusion_with_independent_proof() {
    let mut vault = TestVault::new();
    vault.add_source("s1", 0x10, 0x11, SOURCE_ONE);
    vault.add_source("s2", 0x12, 0x13, SOURCE_TWO);

    let ev1 = make_evidence(0x20, 0x21, 0x10, 0x11, 0x30);
    let ev2 = make_evidence(0x22, 0x23, 0x12, 0x13, 0x32);
    let p1 = make_assertion(AssertionSpec {
        id: 0x30,
        rev_byte: 0x31,
        predicate: "p1",
        value: "v1",
        origin: mneme_core::Origin::AuthoredStatement,
        evidence_ids: &[0x20],
    });
    let p2 = make_assertion(AssertionSpec {
        id: 0x32,
        rev_byte: 0x33,
        predicate: "p2",
        value: "v2",
        origin: mneme_core::Origin::AuthoredStatement,
        evidence_ids: &[0x22],
    });
    let c = make_assertion(AssertionSpec {
        id: 0x34,
        rev_byte: 0x35,
        predicate: "c",
        value: "derived-c",
        origin: mneme_core::Origin::Inference,
        evidence_ids: &[],
    });
    let e = make_assertion(AssertionSpec {
        id: 0x36,
        rev_byte: 0x37,
        predicate: "e",
        value: "downstream-e",
        origin: mneme_core::Origin::Inference,
        evidence_ids: &[],
    });
    vault.commit("seed-diamond", vec![ev1, ev2, p1, p2, c, e], Vec::new());
    // D1: P1 -> C, D2: P2 -> C, D3: C -> E
    vault.add_derivation("d1", 0x40, 0x41, 0x34, &[0x30]);
    vault.add_derivation("d2", 0x42, 0x43, 0x34, &[0x32]);
    vault.add_derivation("d3", 0x44, 0x45, 0x36, &[0x34]);

    let req = vault.request(
        mneme_retention::OperationKind::AssertionRetraction,
        mneme_retention::Selector::Assertion(rid(0x30)),
        "retract-p1-only",
    );
    let mut retention = mneme_retention::Engine::new(&mut vault.workspace);
    let plan = retention.plan(req).expect("plan");

    assert_eq!(plan.invalidated_derivations, vec![rid(0x40)]);
    assert!(
        !plan.invalidated_derivations.contains(&rid(0x44)),
        "D3: C -> E must not be invalidated because C has independent proof D2"
    );
    assert!(plan.surviving_assertions.contains(&rid(0x34)));
    assert!(plan.surviving_assertions.contains(&rid(0x36)));
}

#[test]
fn kernel_contraction_incises_by_entrenchment_order_and_preserves_independent_derivations() {
    let mut vault = TestVault::new();
    vault.add_source("s1", 0x10, 0x11, SOURCE_ONE);
    vault.add_source("s2", 0x12, 0x13, SOURCE_TWO);
    vault.add_source("s3", 0x14, 0x15, SOURCE_THREE);

    // P_authored (0x30): AuthoredStatement backed by 2 distinct roots (S1, S2)
    // P_model (0x32): ModelExtraction backed by 1 root (S3)
    // C (0x34): derived from {P_authored, P_model} via D1 (0x40)
    // E (0x36): derived from {P_authored} via D2 (0x42)
    let ev1 = make_evidence(0x20, 0x21, 0x10, 0x11, 0x30);
    let ev2 = make_evidence(0x22, 0x23, 0x12, 0x13, 0x30);
    let ev3 = make_evidence(0x24, 0x25, 0x14, 0x15, 0x32);
    let p_authored = make_assertion(AssertionSpec {
        id: 0x30,
        rev_byte: 0x31,
        predicate: "base-authored",
        value: "human-verified",
        origin: mneme_core::Origin::AuthoredStatement,
        evidence_ids: &[0x20, 0x22],
    });
    let p_model = make_assertion(AssertionSpec {
        id: 0x32,
        rev_byte: 0x33,
        predicate: "base-model",
        value: "llm-extracted",
        origin: mneme_core::Origin::ModelExtraction,
        evidence_ids: &[0x24],
    });
    let c = make_assertion(AssertionSpec {
        id: 0x34,
        rev_byte: 0x35,
        predicate: "launch-date",
        value: "May 5",
        origin: mneme_core::Origin::Inference,
        evidence_ids: &[],
    });
    let e = make_assertion(AssertionSpec {
        id: 0x36,
        rev_byte: 0x37,
        predicate: "unrelated-conclusion",
        value: "safe",
        origin: mneme_core::Origin::Inference,
        evidence_ids: &[],
    });
    vault.commit(
        "seed-entrenchment",
        vec![ev1, ev2, ev3, p_authored, p_model, c, e],
        Vec::new(),
    );
    vault.add_derivation("d-c", 0x40, 0x41, 0x34, &[0x30, 0x32]);
    vault.add_derivation("d-e", 0x42, 0x43, 0x36, &[0x30]);

    let rev_before = vault.workspace.current_revision().expect("rev");
    let req = vault.request(
        mneme_retention::OperationKind::KernelContract,
        mneme_retention::Selector::Assertion(rid(0x34)),
        "contract-c",
    );
    let mut retention = mneme_retention::Engine::new(&mut vault.workspace);
    let plan = retention.plan(req).expect("plan");

    assert_eq!(vault.workspace.current_revision().expect("rev"), rev_before);
    let report = plan.contraction.as_ref().expect("contraction report");
    assert_eq!(report.kernels, vec![vec![rid(0x30), rid(0x32)]]);
    assert_eq!(
        report.incised_premises,
        vec![rid(0x32)],
        "ModelExtraction single-root premise must be cut before Authored multi-root premise"
    );
    assert_eq!(plan.retracted_assertions, vec![rid(0x32)]);
    assert_eq!(plan.invalidated_derivations, vec![rid(0x40)]);
    assert!(!plan.invalidated_derivations.contains(&rid(0x42)));

    let authored_meta = report
        .entrenchment
        .iter()
        .find(|entry| entry.record_id == rid(0x30))
        .expect("authored entry");
    assert_eq!(
        authored_meta.origin,
        mneme_kernel::contraction::OriginTier::Authored
    );
    assert_eq!(authored_meta.root_count, 2);
    assert!(!authored_meta.incised);
}

#[test]
fn kernel_contraction_fails_closed_when_budget_truncated() {
    let mut vault = TestVault::new();
    vault.add_source("s1", 0x10, 0x11, SOURCE_ONE);
    let ev1 = make_evidence(0x20, 0x21, 0x10, 0x11, 0x30);
    let p1 = make_assertion(AssertionSpec {
        id: 0x30,
        rev_byte: 0x31,
        predicate: "p1",
        value: "v1",
        origin: mneme_core::Origin::ModelExtraction,
        evidence_ids: &[0x20],
    });
    let c = make_assertion(AssertionSpec {
        id: 0x32,
        rev_byte: 0x33,
        predicate: "c",
        value: "derived",
        origin: mneme_core::Origin::Inference,
        evidence_ids: &[],
    });
    vault.commit("seed-p1-c", vec![ev1, p1, c], Vec::new());
    vault.add_derivation("d1", 0x40, 0x41, 0x32, &[0x30]);

    let base = vault.workspace.current_revision().expect("base");
    let mut retention = mneme_retention::Engine::new(&mut vault.workspace);
    let err = retention
        .plan_revision(mneme_retention::contraction::RevisionRequest {
            actor: "tester".to_owned(),
            scope: scope(),
            base_revision: base,
            idempotency_key: "budget-truncated".to_owned(),
            contract_targets: vec![rid(0x32)],
            proposed: None,
            policy: test_policy(),
            max_ancestry_nodes: Some(1),
        })
        .expect_err("budget of 1 node must fail closed as Truncated");
    assert!(matches!(
        err,
        mneme_retention::PolicyError::Engine(mneme_memory::EvidenceError::Truncated)
    ));
}

#[test]
fn levi_identity_revision_plan_discovers_conflicts_and_never_mutates_workspace() {
    let mut vault = TestVault::new();
    vault.add_source("s1", 0x10, 0x11, SOURCE_ONE);
    let ev1 = make_evidence(0x20, 0x21, 0x10, 0x11, 0x30);
    let old_claim = make_assertion(AssertionSpec {
        id: 0x30,
        rev_byte: 0x31,
        predicate: "launch-date",
        value: "May 5",
        origin: mneme_core::Origin::ModelExtraction,
        evidence_ids: &[0x20],
    });
    vault.commit("seed-old", vec![ev1, old_claim], Vec::new());
    vault.accept_assertion("accept-old", 0x30, 0x32, 0x50, 0x51);

    let rev_before = vault.workspace.current_revision().expect("base");
    let mut retention = mneme_retention::Engine::new(&mut vault.workspace);
    let rev_plan = retention
        .plan_revision(mneme_retention::contraction::RevisionRequest {
            actor: "operator".to_owned(),
            scope: scope(),
            base_revision: rev_before,
            idempotency_key: "levi-may-12".to_owned(),
            contract_targets: Vec::new(),
            proposed: Some(mneme_retention::contraction::ProposedAssertionSpec {
                subject: mneme_core::fixtures::entity_id(),
                predicate: "launch-date".to_owned(),
                value: mneme_core::Value::string("May 12"),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
            }),
            policy: test_policy(),
            max_ancestry_nodes: None,
        })
        .expect("revision plan");

    assert_eq!(rev_plan.conflicting_assertions, vec![rid(0x30)]);
    assert_eq!(rev_plan.report.kernels, vec![vec![rid(0x30)]]);
    assert_eq!(rev_plan.report.incised_premises, vec![rid(0x30)]);
    assert!(rev_plan.proposed.is_some());
    assert_eq!(
        vault.workspace.current_revision().expect("after"),
        rev_before,
        "plan_revision must never commit silently"
    );
}

fn origin_from_u8(tag: u8) -> mneme_kernel::contraction::OriginTier {
    match tag % 3 {
        0 => mneme_kernel::contraction::OriginTier::ModelExtraction,
        1 => mneme_kernel::contraction::OriginTier::Imported,
        _ => mneme_kernel::contraction::OriginTier::Authored,
    }
}

proptest::proptest! {
    #[test]
    fn proptest_hansson_postulates_inclusion_success_core_retainment_uniformity(
        base_specs in proptest::collection::vec((0_u8..3_u8, 0_u64..10_u64, 1_u128..64_u128), 1..12),
        kernel_indices in proptest::collection::vec(proptest::collection::vec(0_usize..12_usize, 1..5), 1..6),
    ) {
        let mut keys_by_id = std::collections::BTreeMap::new();
        for (tier_tag, roots, id) in base_specs {
            keys_by_id.entry(id).or_insert(mneme_kernel::contraction::EntrenchmentKey {
                origin: origin_from_u8(tier_tag),
                root_count: roots,
                record_id: id,
            });
        }
        let key_list: Vec<mneme_kernel::contraction::EntrenchmentKey> =
            keys_by_id.values().copied().collect();
        let base_ids: Vec<u128> = key_list.iter().map(|k| k.record_id).collect();
        let mut members_fwd = Vec::with_capacity(kernel_indices.len().saturating_mul(5));
        let mut spans_fwd = Vec::with_capacity(kernel_indices.len());
        let mut kernel_union = std::collections::BTreeSet::new();
        for raw_kernel in &kernel_indices {
            let start = members_fwd.len();
            for raw_idx in raw_kernel {
                let idx = raw_idx.checked_rem(key_list.len()).expect("non-empty keys");
                let key = key_list[idx];
                members_fwd.push(key);
                kernel_union.insert(key.record_id);
            }
            spans_fwd.push(mneme_kernel::contraction::RangeSpan {
                start,
                len: members_fwd.len().saturating_sub(start),
            });
        }

        let mut members_rev = Vec::with_capacity(members_fwd.len());
        let mut spans_rev = Vec::with_capacity(spans_fwd.len());
        for span in spans_fwd.iter().rev() {
            let start = members_rev.len();
            let stop = span.start.saturating_add(span.len);
            for key in members_fwd[span.start..stop].iter().rev() {
                members_rev.push(*key);
            }
            spans_rev.push(mneme_kernel::contraction::RangeSpan {
                start,
                len: members_rev.len().saturating_sub(start),
            });
        }

        proptest::prop_assert!(!mneme_kernel::contraction::any_proof_survives(
            &base_ids,
            &members_fwd,
            &spans_fwd,
        ));

        for candidate in 0_u128..70_u128 {
            let is_surviving_fwd = mneme_kernel::contraction::survives_incision(
                candidate,
                &base_ids,
                &members_fwd,
                &spans_fwd,
            );
            let is_surviving_rev = mneme_kernel::contraction::survives_incision(
                candidate,
                &base_ids,
                &members_rev,
                &spans_rev,
            );
            proptest::prop_assert_eq!(is_surviving_fwd, is_surviving_rev);
            if is_surviving_fwd {
                proptest::prop_assert!(base_ids.contains(&candidate));
            }
            if base_ids.contains(&candidate) && !is_surviving_fwd {
                proptest::prop_assert!(kernel_union.contains(&candidate));
            }
        }
    }

    #[test]
    fn proptest_well_founded_grounding_rejects_arbitrary_unfounded_cycles(
        root_flags in proptest::collection::vec(proptest::bool::ANY, 2..10),
        extra_edges in proptest::collection::vec((0_usize..10_usize, proptest::collection::vec(0_usize..10_usize, 1..4)), 0..16),
    ) {
        let outside_count = root_flags.len();
        let node_a = outside_count;
        let node_b = outside_count.saturating_add(1);
        let total = outside_count.saturating_add(2);

        let mut grounded = Vec::with_capacity(total);
        grounded.extend(root_flags.iter().copied());
        grounded.push(false);
        grounded.push(false);

        let mut premises = Vec::with_capacity(extra_edges.len().saturating_mul(4).saturating_add(2));
        let mut edges = Vec::with_capacity(extra_edges.len().saturating_add(2));

        premises.push(node_a);
        edges.push(mneme_kernel::contraction::SupportEdge {
            target: node_b,
            premises: mneme_kernel::contraction::RangeSpan { start: 0, len: 1 },
        });
        premises.push(node_b);
        edges.push(mneme_kernel::contraction::SupportEdge {
            target: node_a,
            premises: mneme_kernel::contraction::RangeSpan { start: 1, len: 1 },
        });

        for (raw_target, raw_prems) in extra_edges {
            let target = raw_target
                .checked_rem(outside_count)
                .expect("non-empty outside");
            let start = premises.len();
            for p in raw_prems {
                let prem = p.checked_rem(total).expect("non-empty total");
                premises.push(prem);
            }
            edges.push(mneme_kernel::contraction::SupportEdge {
                target,
                premises: mneme_kernel::contraction::RangeSpan {
                    start,
                    len: premises.len().saturating_sub(start),
                },
            });
        }

        for _ in 0..total {
            let next: Vec<bool> = (0..total)
                .map(|node| {
                    mneme_kernel::contraction::node_next_grounded(
                        node,
                        &edges,
                        &premises,
                        &grounded,
                    )
                })
                .collect();
            grounded = next;
        }

        proptest::prop_assert!(!grounded[node_a]);
        proptest::prop_assert!(!grounded[node_b]);
        for (idx, is_root) in root_flags.iter().enumerate() {
            if *is_root {
                proptest::prop_assert!(grounded[idx]);
            }
        }
    }
}
