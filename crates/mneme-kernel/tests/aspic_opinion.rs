//! Integration tests for `mneme_kernel::argumentation` and `mneme_kernel::opinion`.
#![allow(unknown_lints, no_unwrap)] // test assertions panic on failure
#![allow(clippy::unwrap_used, clippy::expect_used)] // test assertions panic on failure

fn solve_grounded(
    count: usize,
    edges: &[mneme_kernel::argumentation::DefeatEdge],
) -> Vec<mneme_kernel::argumentation::Label> {
    let mut labels = vec![mneme_kernel::argumentation::Label::Undec; count];
    for _ in 0..=count {
        let next: Vec<mneme_kernel::argumentation::Label> = (0..count)
            .map(|node| mneme_kernel::argumentation::next_label(node, edges, &labels))
            .collect();
        if next == labels {
            return labels;
        }
        labels = next;
    }
    labels
}

#[test]
fn grounded_labelling_reinstates_defended_argument() {
    // 0 -> 1 -> 2 -> 3: 0 is In, 1 is Out, 2 is reinstated In, 3 is Out.
    let edges = [
        mneme_kernel::argumentation::DefeatEdge {
            attacker: 0,
            target: 1,
        },
        mneme_kernel::argumentation::DefeatEdge {
            attacker: 1,
            target: 2,
        },
        mneme_kernel::argumentation::DefeatEdge {
            attacker: 2,
            target: 3,
        },
    ];
    let labels = solve_grounded(4, &edges);
    assert_eq!(
        labels,
        vec![
            mneme_kernel::argumentation::Label::In,
            mneme_kernel::argumentation::Label::Out,
            mneme_kernel::argumentation::Label::In,
            mneme_kernel::argumentation::Label::Out,
        ]
    );
    assert!(mneme_kernel::argumentation::is_fixpoint(&edges, &labels));
    assert!(mneme_kernel::argumentation::is_conflict_free(
        &edges, &labels
    ));
    assert!(mneme_kernel::argumentation::is_admissible(&edges, &labels));
}

#[test]
fn grounded_labelling_marks_symmetric_and_odd_cycles_undec() {
    let two_cycle = [
        mneme_kernel::argumentation::DefeatEdge {
            attacker: 0,
            target: 1,
        },
        mneme_kernel::argumentation::DefeatEdge {
            attacker: 1,
            target: 0,
        },
    ];
    let labels_two = solve_grounded(2, &two_cycle);
    assert_eq!(
        labels_two,
        vec![
            mneme_kernel::argumentation::Label::Undec,
            mneme_kernel::argumentation::Label::Undec,
        ]
    );
    assert!(mneme_kernel::argumentation::is_fixpoint(
        &two_cycle,
        &labels_two
    ));

    let three_cycle = [
        mneme_kernel::argumentation::DefeatEdge {
            attacker: 0,
            target: 1,
        },
        mneme_kernel::argumentation::DefeatEdge {
            attacker: 1,
            target: 2,
        },
        mneme_kernel::argumentation::DefeatEdge {
            attacker: 2,
            target: 0,
        },
    ];
    let labels_three = solve_grounded(3, &three_cycle);
    assert_eq!(
        labels_three,
        vec![mneme_kernel::argumentation::Label::Undec; 3]
    );
    assert!(mneme_kernel::argumentation::is_admissible(
        &three_cycle,
        &labels_three
    ));
}

#[test]
fn preference_ordering_matches_authority_hierarchy() {
    let proposed = mneme_kernel::argumentation::Authority::Proposed;
    let accepted = mneme_kernel::argumentation::Authority::Accepted;
    let resolved = mneme_kernel::argumentation::Authority::ConflictResolution;

    assert!(mneme_kernel::argumentation::preference_defeats(
        resolved, accepted
    ));
    assert!(!mneme_kernel::argumentation::preference_defeats(
        accepted, resolved
    ));
    assert!(mneme_kernel::argumentation::preference_defeats(
        accepted, proposed
    ));
    assert!(!mneme_kernel::argumentation::preference_defeats(
        proposed, accepted
    ));
    assert!(mneme_kernel::argumentation::preference_defeats(
        accepted, accepted
    ));
}

#[test]
fn subjective_logic_vacuous_echo_chamber_and_independent_fusion() {
    let vac = mneme_kernel::opinion::vacuous(mneme_kernel::opinion::DEFAULT_BASE_RATE);
    let vac_proj = mneme_kernel::opinion::project(&vac).expect("vacuous projection");
    assert_eq!(vac_proj.b_num, 0);
    assert_eq!(vac_proj.d_num, 0);
    assert_eq!(vac_proj.u_num, vac_proj.denom);
    assert_eq!(vac_proj.conflict_num, 0);

    // Echo-chamber invariance: 1 vs 50 supporting copies from one root keep u = 2/3.
    let one_copy =
        mneme_kernel::opinion::averaging_cluster(1, 0, mneme_kernel::opinion::DEFAULT_BASE_RATE);
    let fifty_copies =
        mneme_kernel::opinion::averaging_cluster(50, 0, mneme_kernel::opinion::DEFAULT_BASE_RATE);
    let proj_one = mneme_kernel::opinion::project(&one_copy).expect("one copy");
    let proj_fifty = mneme_kernel::opinion::project(&fifty_copies).expect("fifty copies");
    assert_eq!(
        proj_one.u_num.saturating_mul(3),
        proj_one.denom.saturating_mul(2)
    );
    assert_eq!(
        proj_fifty.u_num.saturating_mul(3),
        proj_fifty.denom.saturating_mul(2)
    );
    assert_eq!(
        proj_one.b_num.saturating_mul(proj_fifty.denom),
        proj_fifty.b_num.saturating_mul(proj_one.denom)
    );

    // Independent cumulative fusion of 4 roots: u = 2 / (4 + 2) = 1/3, b = 4/6 = 2/3.
    let mut fused = vac;
    for _ in 0..4 {
        fused = mneme_kernel::opinion::cumulative_fuse(&fused, &one_copy).expect("fuse");
    }
    let fused_proj = mneme_kernel::opinion::project(&fused).expect("fused proj");
    assert_eq!(fused_proj.u_num.saturating_mul(3), fused_proj.denom);
    assert_eq!(
        fused_proj.b_num.saturating_mul(3),
        fused_proj.denom.saturating_mul(2)
    );
    assert_eq!(fused_proj.conflict_num, 0);
}

#[test]
fn subjective_logic_averaging_idempotent_and_trust_discount_non_inflating() {
    let ev = mneme_kernel::opinion::Evidence {
        r: 3,
        s: 1,
        w: mneme_kernel::opinion::PRIOR_WEIGHT,
        base_rate: mneme_kernel::opinion::DEFAULT_BASE_RATE,
    };
    let avg = mneme_kernel::opinion::averaging_fuse(&ev, &ev).expect("avg");
    let p_ev = mneme_kernel::opinion::project(&ev).expect("p_ev");
    let p_avg = mneme_kernel::opinion::project(&avg).expect("p_avg");
    assert_eq!(
        p_ev.b_num.saturating_mul(p_avg.denom),
        p_avg.b_num.saturating_mul(p_ev.denom)
    );
    assert_eq!(
        p_ev.u_num.saturating_mul(p_avg.denom),
        p_avg.u_num.saturating_mul(p_ev.denom)
    );

    let partial_trust = mneme_kernel::opinion::Evidence {
        r: 2,
        s: 0,
        w: mneme_kernel::opinion::PRIOR_WEIGHT,
        base_rate: mneme_kernel::opinion::DEFAULT_BASE_RATE,
    };
    let discounted = mneme_kernel::opinion::trust_discount(&partial_trust, &ev).expect("discount");
    let p_disc = mneme_kernel::opinion::project(&discounted).expect("p_disc");
    assert!(p_disc.b_num.saturating_mul(p_ev.denom) <= p_ev.b_num.saturating_mul(p_disc.denom));
    assert!(p_disc.u_num.saturating_mul(p_ev.denom) >= p_ev.u_num.saturating_mul(p_disc.denom));
}
