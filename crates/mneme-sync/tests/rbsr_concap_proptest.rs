//! Property-based (`proptest`) suites for `mneme-sync`:
//! 1. RBSR set reconciliation exact convergence, round bounds, and malformed-frame rejection.
//! 2. Convergent Capabilities (`concap`) G-Set CRDT ACI semilattice laws,
//!    delegation attenuation / non-escalation, and revocation dominance.

#![allow(
    unknown_lints,
    no_unwrap,
    function_length,
    allocation_in_loop,
    too_many_parameters,
    unbounded_collection_growth,
    platform_dependent_cast,
    raw_arithmetic_overflow,
    magic_number,
    explicit_defaults,
    compound_condition,
    non_trait_imports,
    unchecked_narrowing,
    unchecked_division,
    bool_naming
)] // property test harness exercises randomized protocol and CRDT states and asserts via expect
#![allow(clippy::expect_used, clippy::unwrap_used)] // property test harness asserts via expect

use proptest::prelude::*;
use std::collections::BTreeSet;

const TEST_VAULT_ID: &str = "vault-proptest-concap";
const BASE_TIME_SECS: u64 = 1_700_000_000;

fn deterministic_secret_key(seed: u8) -> iroh::SecretKey {
    let mut bytes = [0_u8; 32];
    let mut acc = u64::from(seed)
        .wrapping_add(1)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for slot in &mut bytes {
        acc = acc
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *slot = (acc >> 56) as u8;
    }
    iroh::SecretKey::from_bytes(&bytes)
}

fn make_rbsr_key(kind: mneme_sync::RbsrItemKind, id: u32) -> mneme_sync::RbsrKey {
    let id_bytes = id.to_be_bytes();
    match kind {
        mneme_sync::RbsrItemKind::Blob => {
            let mut raw = [0_u8; 32];
            raw[0..4].copy_from_slice(&id_bytes);
            raw[4..8].copy_from_slice(&id.wrapping_mul(2_654_435_761).to_be_bytes());
            mneme_sync::RbsrKey::from_blob_bytes(raw)
        }
        mneme_sync::RbsrItemKind::Revision => {
            let mut rec = [0_u8; 16];
            let mut rev = [0_u8; 16];
            rec[0..4].copy_from_slice(&id_bytes);
            rev[0..4].copy_from_slice(&id.wrapping_mul(31).to_be_bytes());
            mneme_sync::RbsrKey::from_revision(
                mneme_core::RecordId::from_bytes(rec),
                mneme_core::RevisionId::from_bytes(rev),
            )
        }
    }
}

fn kind_from_bit(bit: u8) -> mneme_sync::RbsrItemKind {
    if bit.is_multiple_of(2) {
        mneme_sync::RbsrItemKind::Blob
    } else {
        mneme_sync::RbsrItemKind::Revision
    }
}

fn scope_from_mask(mask: u8) -> mneme_sync::CapabilityScope {
    let names = ["alpha", "beta", "gamma", "delta"];
    if mask == 0 || mask >= 16 {
        return mneme_sync::CapabilityScope::wildcard();
    }
    let scopes: Vec<mneme_core::ScopeId> = names
        .iter()
        .enumerate()
        .filter(|(idx, _)| (mask & (1_u8 << idx)) != 0)
        .map(|(_, name)| {
            mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, *name).expect("scope")
        })
        .collect();
    mneme_sync::CapabilityScope::from_scopes(scopes).expect("non-empty scope set")
}

fn authority_from_idx(idx: u8) -> mneme_sync::CapabilityAuthority {
    match idx % 3 {
        0 => mneme_sync::CapabilityAuthority::ReadOnly,
        1 => mneme_sync::CapabilityAuthority::SyncPull,
        _ => mneme_sync::CapabilityAuthority::SyncPush,
    }
}

fn tombstone_id_set(set: &mneme_sync::RevocationSet) -> BTreeSet<mneme_sync::TombstoneId> {
    set.tombstones().map(|t| t.tombstone_id).collect()
}

fn merge_sets(
    left: &mneme_sync::RevocationSet,
    right: &mneme_sync::RevocationSet,
) -> mneme_sync::RevocationSet {
    let mut out = left.clone();
    out.merge(right).expect("merge revocation sets");
    out
}

fn arb_rbsr_key_spec() -> impl Strategy<Value = (u8, u32)> {
    (0_u8..2, 0_u32..512)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, failure_persistence: None, .. ProptestConfig::default() })]

    #[test]
    fn proptest_rbsr_exact_symmetric_difference_and_symmetry(
        shared in prop::collection::vec(arb_rbsr_key_spec(), 0..160),
        only_a in prop::collection::vec(arb_rbsr_key_spec(), 0..40),
        only_b in prop::collection::vec(arb_rbsr_key_spec(), 0..40),
    ) {
        let mut set_a_keys = BTreeSet::new();
        let mut set_b_keys = BTreeSet::new();
        for (kind, id) in shared {
            let k = make_rbsr_key(kind_from_bit(kind), id);
            set_a_keys.insert(k);
            set_b_keys.insert(k);
        }
        for (kind, id) in only_a {
            set_a_keys.insert(make_rbsr_key(kind_from_bit(kind), id));
        }
        for (kind, id) in only_b {
            set_b_keys.insert(make_rbsr_key(kind_from_bit(kind), id));
        }

        let rbsr_a = mneme_sync::RbsrSet::from_keys(set_a_keys.iter().copied());
        let rbsr_b = mneme_sync::RbsrSet::from_keys(set_b_keys.iter().copied());

        let expected_local_only: Vec<mneme_sync::RbsrKey> =
            set_a_keys.difference(&set_b_keys).copied().collect();
        let expected_remote_only: Vec<mneme_sync::RbsrKey> =
            set_b_keys.difference(&set_a_keys).copied().collect();

        let ab = mneme_sync::reconcile_in_memory(&rbsr_a, &rbsr_b).expect("reconcile A->B");
        prop_assert_eq!(&ab.local_only, &expected_local_only);
        prop_assert_eq!(&ab.remote_only, &expected_remote_only);
        prop_assert!(ab.rounds >= 1);
        prop_assert!(ab.rounds <= u64::from(mneme_sync::MAX_RBSR_ROUNDS));

        if expected_local_only.is_empty() && expected_remote_only.is_empty() {
            prop_assert_eq!(ab.rounds, 1);
        }

        let ba = mneme_sync::reconcile_in_memory(&rbsr_b, &rbsr_a).expect("reconcile B->A");
        prop_assert_eq!(&ba.local_only, &expected_remote_only);
        prop_assert_eq!(&ba.remote_only, &expected_local_only);
    }

    #[test]
    fn proptest_rbsr_small_delta_logarithmic_rounds(
        base_size in 256_u32..1024_u32,
        delta_count in 1_u32..=8_u32,
        seed in any::<u32>(),
    ) {
        let mut keys_a = BTreeSet::new();
        for i in 0..base_size {
            keys_a.insert(make_rbsr_key(kind_from_bit((i % 2) as u8), i));
        }
        let mut keys_b = keys_a.clone();
        for d in 0..delta_count {
            let new_id = base_size + 10_000 + (seed % 1000) + d;
            keys_b.insert(make_rbsr_key(mneme_sync::RbsrItemKind::Blob, new_id));
        }

        let set_a = mneme_sync::RbsrSet::from_keys(keys_a.iter().copied());
        let set_b = mneme_sync::RbsrSet::from_keys(keys_b.iter().copied());
        let outcome = mneme_sync::reconcile_in_memory(&set_a, &set_b).expect("reconcile");
        prop_assert_eq!(outcome.local_only.len(), 0);
        prop_assert_eq!(outcome.remote_only.len(), delta_count as usize);
        // Binary range partitioning over <=1024 keys with <=8 diffs finishes well within O(log N).
        prop_assert!(
            outcome.rounds <= 16,
            "expected logarithmic rounds <= 16, got {} for N={}, delta={}",
            outcome.rounds,
            base_size,
            delta_count
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, failure_persistence: None, .. ProptestConfig::default() })]

    #[test]
    fn proptest_revocation_set_aci_semilattice_laws(
        specs_a in prop::collection::vec((0_u8..4, 0_u8..16, 0_u64..1000), 0..5),
        specs_b in prop::collection::vec((0_u8..4, 0_u8..16, 0_u64..1000), 0..5),
        specs_c in prop::collection::vec((0_u8..4, 0_u8..16, 0_u64..1000), 0..5),
    ) {
        let keys: Vec<iroh::SecretKey> = (0_u8..4).map(deterministic_secret_key).collect();
        let build_set = |specs: &[(u8, u8, u64)]| -> mneme_sync::RevocationSet {
            let mut set = mneme_sync::RevocationSet::default();
            for &(key_idx, target_byte, offset) in specs {
                let target = mneme_sync::TokenId::from_bytes([target_byte; 16]);
                let tombstone = mneme_sync::RevocationTombstone::issue(
                    &keys[(key_idx % 4) as usize],
                    TEST_VAULT_ID,
                    target,
                    BASE_TIME_SECS + offset,
                    Some("proptest-revoke"),
                )
                .expect("issue tombstone");
                set.insert(tombstone).expect("insert valid tombstone");
            }
            set
        };

        let set_a = build_set(&specs_a);
        let set_b = build_set(&specs_b);
        let set_c = build_set(&specs_c);

        // Idempotence: A ⊔ A == A
        let aa = merge_sets(&set_a, &set_a);
        prop_assert_eq!(tombstone_id_set(&aa), tombstone_id_set(&set_a));
        prop_assert_eq!(aa.len_u64(), set_a.len_u64());

        // Commutativity: A ⊔ B == B ⊔ A
        let ab = merge_sets(&set_a, &set_b);
        let ba = merge_sets(&set_b, &set_a);
        prop_assert_eq!(tombstone_id_set(&ab), tombstone_id_set(&ba));
        prop_assert_eq!(ab.len_u64(), ba.len_u64());

        // Associativity: (A ⊔ B) ⊔ C == A ⊔ (B ⊔ C)
        let ab_c = merge_sets(&ab, &set_c);
        let bc = merge_sets(&set_b, &set_c);
        let a_bc = merge_sets(&set_a, &bc);
        prop_assert_eq!(tombstone_id_set(&ab_c), tombstone_id_set(&a_bc));
        prop_assert_eq!(ab_c.len_u64(), a_bc.len_u64());

        // Monotonicity: A ⊆ (A ⊔ B) and B ⊆ (A ⊔ B)
        let ids_ab = tombstone_id_set(&ab);
        for id in tombstone_id_set(&set_a) {
            prop_assert!(ids_ab.contains(&id));
        }
        for id in tombstone_id_set(&set_b) {
            prop_assert!(ids_ab.contains(&id));
        }
    }

    #[test]
    fn proptest_delegation_attenuation_non_escalation_and_revocation_dominance(
        root_auth_idx in 0_u8..3,
        child_auth_idx in 0_u8..3,
        root_scope_mask in 0_u8..17,
        child_scope_mask in 0_u8..17,
        root_ttl in 600_u64..10_000,
        child_ttl_delta in -500_i64..500,
        revoke_link_selector in 0_u8..2,
    ) {
        let root_key = deterministic_secret_key(10);
        let mid_key = deterministic_secret_key(11);
        let leaf_key = deterministic_secret_key(12);
        let outsider_key = deterministic_secret_key(99);

        let root_auth = authority_from_idx(root_auth_idx);
        let child_auth = authority_from_idx(child_auth_idx);
        let root_scope = scope_from_mask(root_scope_mask);
        let child_scope = scope_from_mask(child_scope_mask);

        let root_expires = BASE_TIME_SECS + root_ttl;
        let child_expires = if child_ttl_delta >= 0 {
            root_expires.saturating_add(child_ttl_delta as u64)
        } else {
            root_expires.saturating_sub(child_ttl_delta.unsigned_abs())
        };

        let root_token = mneme_sync::CapabilityToken::grant(
            &root_key,
            mneme_sync::GrantRequest {
                vault_id: TEST_VAULT_ID.to_owned(),
                subject: mid_key.public(),
                scope: root_scope.clone(),
                authority: root_auth,
                issued_at_secs: BASE_TIME_SECS,
                expires_at_secs: root_expires,
                max_delegation_depth: 3,
            },
        )
        .expect("grant root token");

        let delegate_res = root_token.delegate(
            &mid_key,
            mneme_sync::DelegateRequest {
                subject: leaf_key.public(),
                scope: child_scope.clone(),
                authority: child_auth,
                issued_at_secs: BASE_TIME_SECS + 10,
                expires_at_secs: child_expires,
                remaining_depth: Some(2),
            },
        );

        let expected_valid_attenuation = root_auth.allows_attenuation_to(child_auth)
            && child_scope.is_attenuation_of(&root_scope)
            && child_expires <= root_expires
            && child_expires > BASE_TIME_SECS + 10;

        if !expected_valid_attenuation {
            prop_assert!(
                delegate_res.is_err(),
                "escalation must be rejected: root_auth={root_auth:?} child_auth={child_auth:?} root_scope={root_scope:?} child_scope={child_scope:?} root_exp={root_expires} child_exp={child_expires}"
            );
            return Ok(());
        }

        let delegated = delegate_res.expect("valid attenuation should delegate");
        let mut trusted_roots = BTreeSet::new();
        trusted_roots.insert(root_key.public());
        let empty_revocations = mneme_sync::RevocationSet::default();

        // Pick a scope guaranteed to be inside child_scope.
        let test_scope = match &child_scope {
            mneme_sync::CapabilityScope::Wildcard => {
                mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "alpha").expect("scope")
            }
            mneme_sync::CapabilityScope::Scopes(set) => {
                let first = set.iter().next().expect("non-empty scope set");
                mneme_sync::parse_scope_id(first).expect("parse scope")
            }
        };

        let verified = mneme_sync::verify_capability(&mneme_sync::VerificationRequest {
            token: &delegated,
            presenter: leaf_key.public(),
            vault_id: TEST_VAULT_ID,
            scope: &test_scope,
            required_authority: child_auth,
            now_secs: BASE_TIME_SECS + 20,
            trusted_roots: &trusted_roots,
            revocations: &empty_revocations,
        })
        .expect("valid delegated capability must verify");
        prop_assert_eq!(verified.authority, child_auth);
        prop_assert_eq!(verified.subject, leaf_key.public());

        // Outsider revocation must NOT revoke the chain.
        let link_ids = delegated.link_ids();
        let target_idx = (revoke_link_selector as usize) % link_ids.len();
        let target_id = link_ids[target_idx];
        let outsider_tomb = mneme_sync::RevocationTombstone::issue(
            &outsider_key,
            TEST_VAULT_ID,
            target_id,
            BASE_TIME_SECS + 15,
            Some("unauthorized"),
        )
        .expect("issue outsider tombstone");
        let mut outsider_revocations = mneme_sync::RevocationSet::default();
        outsider_revocations.insert(outsider_tomb).expect("insert outsider");
        prop_assert!(
            mneme_sync::verify_capability(&mneme_sync::VerificationRequest {
                token: &delegated,
                presenter: leaf_key.public(),
                vault_id: TEST_VAULT_ID,
                scope: &test_scope,
                required_authority: child_auth,
                now_secs: BASE_TIME_SECS + 20,
                trusted_roots: &trusted_roots,
                revocations: &outsider_revocations,
            })
            .is_ok(),
            "unrelated third party must not revoke valid chain"
        );

        // Authorized ancestor revocation (root_key is ancestor of both link 0 and link 1)
        // MUST dominate after merging in any order.
        let auth_tomb = mneme_sync::RevocationTombstone::issue(
            &root_key,
            TEST_VAULT_ID,
            target_id,
            BASE_TIME_SECS + 15,
            Some("authorized-revoke"),
        )
        .expect("issue authorized tombstone");
        let mut auth_revocations = mneme_sync::RevocationSet::default();
        auth_revocations.insert(auth_tomb).expect("insert auth");
        let merged_1 = merge_sets(&outsider_revocations, &auth_revocations);
        let merged_2 = merge_sets(&auth_revocations, &outsider_revocations);

        for rev_set in [&merged_1, &merged_2] {
            prop_assert!(
                mneme_sync::verify_capability(&mneme_sync::VerificationRequest {
                    token: &delegated,
                    presenter: leaf_key.public(),
                    vault_id: TEST_VAULT_ID,
                    scope: &test_scope,
                    required_authority: child_auth,
                    now_secs: BASE_TIME_SECS + 20,
                    trusted_roots: &trusted_roots,
                    revocations: rev_set,
                })
                .is_err(),
                "authorized ancestor revocation must dominate regardless of merge order"
            );
        }
    }
}

#[test]
fn rbsr_malformed_frames_and_invalid_keys_fail_closed() {
    let key_a = make_rbsr_key(mneme_sync::RbsrItemKind::Blob, 10);
    let key_b = make_rbsr_key(mneme_sync::RbsrItemKind::Blob, 20);
    let set = mneme_sync::RbsrSet::from_keys([key_a, key_b]);

    // Invalid key tag and invalid key byte length fail closed.
    assert!(mneme_sync::RbsrKey::decode_bytes(&[0_u8; 33]).is_err());
    assert!(mneme_sync::RbsrKey::decode_bytes(&[99_u8; 33]).is_err());
    assert!(mneme_sync::RbsrKey::decode_bytes(&[1_u8; 32]).is_err());

    // Empty request fails closed.
    let empty_req = mneme_sync::RbsrRequest { ranges: Vec::new() };
    assert!(set.evaluate_request(&empty_req).is_err());

    // Inverted bounds (lower >= upper) fail closed.
    let inverted_req = mneme_sync::RbsrRequest {
        ranges: vec![mneme_sync::RbsrQueryRange {
            lower: mneme_sync::RangeBound::Key(key_b),
            upper: mneme_sync::RangeBound::Key(key_a),
            depth: 0,
            probe: mneme_sync::RbsrProbe::Fingerprint(mneme_sync::RbsrFingerprint::empty()),
        }],
    };
    assert!(set.evaluate_request(&inverted_req).is_err());

    // Depth exceeding MAX_RBSR_DEPTH fails closed.
    let over_deep_req = mneme_sync::RbsrRequest {
        ranges: vec![mneme_sync::RbsrQueryRange {
            lower: mneme_sync::RangeBound::NegInfinity,
            upper: mneme_sync::RangeBound::Infinity,
            depth: mneme_sync::MAX_RBSR_DEPTH + 1,
            probe: mneme_sync::RbsrProbe::Fingerprint(mneme_sync::RbsrFingerprint::empty()),
        }],
    };
    assert!(set.evaluate_request(&over_deep_req).is_err());

    // Mismatched response length and unsorted leaf items fail closed in RbsrSession.
    let mut session = mneme_sync::RbsrSession::new(set.clone());
    let (_req, in_flight) = session
        .next_request()
        .expect("next request")
        .expect("initial request");
    let mismatched_resp = mneme_sync::RbsrResponse {
        resolutions: Vec::new(),
    };
    assert!(session.apply_response(&in_flight, mismatched_resp).is_err());

    let unsorted_resp = mneme_sync::RbsrResponse {
        resolutions: vec![mneme_sync::RbsrResolution::Items {
            lower: mneme_sync::RangeBound::NegInfinity,
            upper: mneme_sync::RangeBound::Infinity,
            items: vec![key_b, key_a],
        }],
    };
    assert!(session.apply_response(&in_flight, unsorted_resp).is_err());

    // Duplicate items in leaf response fail closed.
    let dup_resp = mneme_sync::RbsrResponse {
        resolutions: vec![mneme_sync::RbsrResolution::Items {
            lower: mneme_sync::RangeBound::NegInfinity,
            upper: mneme_sync::RangeBound::Infinity,
            items: vec![key_a, key_a],
        }],
    };
    assert!(session.apply_response(&in_flight, dup_resp).is_err());
}

#[test]
fn concap_tampered_tombstone_signature_fails_closed() {
    let key = deterministic_secret_key(55);
    let mut tomb = mneme_sync::RevocationTombstone::issue(
        &key,
        TEST_VAULT_ID,
        mneme_sync::TokenId::from_bytes([7; 16]),
        BASE_TIME_SECS,
        Some("valid-reason"),
    )
    .expect("issue tombstone");
    assert!(tomb.verify_signature().is_ok());

    tomb.reason = Some("tampered-reason".to_owned());
    assert!(tomb.verify_signature().is_err());

    let mut set = mneme_sync::RevocationSet::default();
    assert!(set.insert(tomb).is_err());
}
