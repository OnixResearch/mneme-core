//! Bounded, content-addressed justification hypergraph (ATMS minimal environments).
//!
//! Replaces flat truncated `FactData.supports` lists with a shared justification
//! DAG mapping content-addressed [`NodeId`]s to rule applications and
//! premise hyperedges. Supports exact $O(\Delta)$ reverse-dependency invalidation,
//! ATMS minimal environment extraction, and projection back to [`crate::Derivation`]
//! for API/CLI backward compatibility.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Default bound on justification nodes stored per build or session.
pub const DEFAULT_MAX_JUSTIFICATION_NODES: u64 = 65_536;

/// Ground fact reference `(predicate, terms)` used as a hypergraph vertex.
pub type FactRef = (String, Vec<mneme_core::Value>);

/// Content-addressed identifier for one justification hyperedge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Raw 32-byte digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hexadecimal representation.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            let hi = byte >> 4;
            let lo = byte & 0x0f;
            out.push(hex_nibble(hi));
            out.push(hex_nibble(lo));
        }
        out
    }
}

fn hex_nibble(nibble: u8) -> char {
    const DIGITS: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    DIGITS[usize::from(nibble & 0x0f)]
}

/// One premise hyperedge link inside a [`Node`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PremiseEdge {
    pub predicate: String,
    pub terms: Vec<mneme_core::Value>,
    /// Content-addressed justification IDs of the supporting premise fact at intern time.
    pub premise_node_ids: Vec<NodeId>,
    pub canonical: Option<mneme_core::RecordId>,
    pub canonical_roots: std::collections::BTreeSet<mneme_core::RecordId>,
    pub sources: std::collections::BTreeSet<crate::SourceKey>,
    pub source_availability: Option<String>,
    pub vault: Option<String>,
    pub vaults: std::collections::BTreeSet<String>,
    pub absent: bool,
    pub coverage: Option<String>,
    pub epistemic: crate::EpistemicStatus,
}

impl PremiseEdge {
    /// Convert back to the public [`crate::Premise`] representation.
    pub fn to_premise(&self) -> crate::Premise {
        crate::Premise {
            predicate: self.predicate.clone(),
            terms: self.terms.clone(),
            canonical: self.canonical,
            canonical_roots: self.canonical_roots.clone(),
            sources: self.sources.clone(),
            source_availability: self.source_availability.clone(),
            vault: self.vault.clone(),
            vaults: self.vaults.clone(),
            absent: self.absent,
            coverage: self.coverage.clone(),
            epistemic: self.epistemic,
        }
    }
}

/// One content-addressed justification hyperedge deriving [`Node::head`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub id: NodeId,
    pub head: FactRef,
    pub rule_id: String,
    pub rule_version: String,
    pub premises: Vec<PremiseEdge>,
    pub sources: std::collections::BTreeSet<crate::SourceKey>,
    pub canonical_roots: std::collections::BTreeSet<mneme_core::RecordId>,
    pub vaults: std::collections::BTreeSet<String>,
    pub temporal_parameters: Vec<String>,
    pub epistemic: crate::EpistemicStatus,
    pub truncated: bool,
}

impl Node {
    /// Project this hypergraph node back to a [`crate::Derivation`].
    pub fn to_derivation(
        &self,
        revision: mneme_core::WorkspaceRevisionId,
        scope: &mneme_core::ScopeId,
    ) -> crate::Derivation {
        crate::Derivation {
            rule_id: self.rule_id.clone(),
            rule_version: self.rule_version.clone(),
            premises: self.premises.iter().map(PremiseEdge::to_premise).collect(),
            sources: self.sources.clone(),
            vaults: self.vaults.clone(),
            temporal_parameters: self.temporal_parameters.clone(),
            revision,
            scope: scope.clone(),
            truncated: self.truncated,
            epistemic: self.epistemic,
        }
    }

    fn merge(
        &mut self,
        derivation: &crate::Derivation,
        incoming_premises: &[PremiseEdge],
        incoming_roots: &std::collections::BTreeSet<mneme_core::RecordId>,
    ) {
        self.sources.extend(derivation.sources.iter().copied());
        self.canonical_roots.extend(incoming_roots.iter().copied());
        self.vaults.extend(derivation.vaults.iter().cloned());
        self.truncated = self.truncated || derivation.truncated;
        for (left, right) in self.premises.iter_mut().zip(incoming_premises) {
            left.sources.extend(right.sources.iter().copied());
            left.canonical_roots
                .extend(right.canonical_roots.iter().copied());
            left.vaults.extend(right.vaults.iter().cloned());
            left.epistemic = left.epistemic.union(right.epistemic);
            for node_id in &right.premise_node_ids {
                if !left.premise_node_ids.contains(node_id) {
                    left.premise_node_ids.push(*node_id);
                }
            }
        }
        self.epistemic = self
            .premises
            .iter()
            .fold(crate::EpistemicStatus::ONE, |acc, edge| {
                acc.join(edge.epistemic)
            });
    }
}

/// Bounded, content-addressed justification hypergraph shared across derivations.
#[derive(Clone, Debug)]
pub struct Hypergraph {
    nodes: std::collections::BTreeMap<NodeId, Node>,
    by_fact: std::collections::BTreeMap<FactRef, std::collections::BTreeSet<NodeId>>,
    dependents: std::collections::BTreeMap<FactRef, std::collections::BTreeSet<NodeId>>,
    max_nodes: u64,
    truncated: bool,
}

impl Default for Hypergraph {
    fn default() -> Self {
        Self::with_capacity_bound(DEFAULT_MAX_JUSTIFICATION_NODES)
    }
}

impl Hypergraph {
    /// Create an empty justification DAG bounded to `max_nodes` distinct hyperedges.
    pub const fn with_capacity_bound(max_nodes: u64) -> Self {
        Self {
            nodes: std::collections::BTreeMap::new(),
            by_fact: std::collections::BTreeMap::new(),
            dependents: std::collections::BTreeMap::new(),
            max_nodes,
            truncated: false,
        }
    }

    /// Number of interned justification nodes.
    pub fn node_count(&self) -> u64 {
        let mut count = 0_u64;
        for _ in self.nodes.keys() {
            count = count.saturating_add(1);
        }
        count
    }

    /// Whether the justification graph contains no stored nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Whether the node bound was hit during interning.
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Look up one justification node by content-addressed id.
    pub fn get(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(&id)
    }

    /// All justification node ids currently supporting `fact`.
    pub fn node_ids_for(&self, fact: &FactRef) -> Vec<NodeId> {
        self.by_fact
            .get(fact)
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default()
    }

    /// All justification nodes currently supporting `fact`.
    pub fn nodes_for(&self, fact: &FactRef) -> Vec<&Node> {
        self.by_fact
            .get(fact)
            .map(|ids| ids.iter().filter_map(|id| self.nodes.get(id)).collect())
            .unwrap_or_default()
    }

    /// Intern one derivation for `head` into the content-addressed DAG.
    ///
    /// Returns `None` only when the graph's node capacity bound is reached.
    pub fn intern_derivation(
        &mut self,
        head: FactRef,
        derivation: &crate::Derivation,
    ) -> Option<NodeId> {
        let premises: Vec<PremiseEdge> = derivation
            .premises
            .iter()
            .map(|premise| {
                let premise_ref = (premise.predicate.clone(), premise.terms.clone());
                let premise_node_ids = if premise.absent {
                    Vec::new()
                } else {
                    self.node_ids_for(&premise_ref)
                };
                PremiseEdge {
                    predicate: premise.predicate.clone(),
                    terms: premise.terms.clone(),
                    premise_node_ids,
                    canonical: premise.canonical,
                    canonical_roots: premise.canonical_roots.clone(),
                    sources: premise.sources.clone(),
                    source_availability: premise.source_availability.clone(),
                    vault: premise.vault.clone(),
                    vaults: premise.vaults.clone(),
                    absent: premise.absent,
                    coverage: premise.coverage.clone(),
                    epistemic: premise.epistemic,
                }
            })
            .collect();
        let canonical_roots = premises
            .iter()
            .flat_map(|edge| edge.canonical_roots.iter().copied())
            .collect::<std::collections::BTreeSet<_>>();
        let id = compute_node_id(&head, &derivation.rule_id, &premises, &derivation.vaults);
        if let Some(existing) = self.nodes.get_mut(&id) {
            existing.merge(derivation, &premises, &canonical_roots);
            return Some(id);
        }
        if self.node_count() >= self.max_nodes {
            self.truncated = true;
            return None;
        }
        let node = Node {
            id,
            head: head.clone(),
            rule_id: derivation.rule_id.clone(),
            rule_version: derivation.rule_version.clone(),
            premises,
            sources: derivation.sources.clone(),
            canonical_roots,
            vaults: derivation.vaults.clone(),
            temporal_parameters: derivation.temporal_parameters.clone(),
            epistemic: derivation.epistemic,
            truncated: derivation.truncated,
        };
        for edge in &node.premises {
            let dep_key = (edge.predicate.clone(), edge.terms.clone());
            self.dependents.entry(dep_key).or_default().insert(id);
        }
        self.by_fact.entry(head).or_default().insert(id);
        self.nodes.insert(id, node);
        Some(id)
    }

    /// Remove all justifications for `fact` and return the reverse-dependent facts
    /// invalidated transitively in $O(\Delta)$ without scanning unrelated relations.
    pub fn invalidate_facts(
        &mut self,
        seed_facts: &[FactRef],
    ) -> std::collections::BTreeSet<FactRef> {
        let mut invalidated_facts = std::collections::BTreeSet::new();
        let mut queue = std::collections::VecDeque::with_capacity(seed_facts.len());
        for fact in seed_facts {
            if invalidated_facts.insert(fact.clone()) {
                queue.push_back(fact.clone());
            }
        }
        while let Some(current_fact) = queue.pop_front() {
            let dependent_ids: Vec<NodeId> = self
                .dependents
                .remove(&current_fact)
                .map(|set| set.into_iter().collect())
                .unwrap_or_default();
            for node_id in dependent_ids {
                if let Some(removed) = self.remove_node(node_id)
                    && invalidated_facts.insert(removed.head.clone())
                {
                    queue.push_back(removed.head);
                }
            }
        }
        invalidated_facts
    }

    /// Remove all justification nodes directly supporting `fact`.
    pub fn clear_fact(&mut self, fact: &FactRef) {
        let ids = self.node_ids_for(fact);
        for id in ids {
            let _ = self.remove_node(id);
        }
    }

    /// Project up to `max_supports` derivations for `fact` back into [`crate::Derivation`].
    pub fn project_derivations(
        &self,
        fact: &FactRef,
        revision: mneme_core::WorkspaceRevisionId,
        scope: &mneme_core::ScopeId,
        max_supports: u64,
    ) -> (Vec<crate::Derivation>, bool) {
        let Some(ids) = self.by_fact.get(fact) else {
            return (Vec::new(), false);
        };
        let mut out = Vec::with_capacity(ids.len());
        let mut emitted = 0_u64;
        let mut is_truncated = false;
        for id in ids {
            let Some(node) = self.nodes.get(id) else {
                continue;
            };
            if emitted >= max_supports {
                is_truncated = true;
                break;
            }
            if node.truncated {
                is_truncated = true;
            }
            out.push(node.to_derivation(revision, scope));
            emitted = emitted.saturating_add(1);
        }
        (out, is_truncated)
    }

    pub(crate) fn project_derivations_bounded(
        &self,
        fact: &FactRef,
        revision: mneme_core::WorkspaceRevisionId,
        scope: &mneme_core::ScopeId,
        max_supports: usize,
    ) -> (Vec<crate::Derivation>, bool) {
        let Some(ids) = self.by_fact.get(fact) else {
            return (Vec::new(), false);
        };
        let mut out = Vec::with_capacity(ids.len().min(max_supports));
        let mut is_truncated = false;
        for id in ids {
            let Some(node) = self.nodes.get(id) else {
                continue;
            };
            if out.len() >= max_supports {
                is_truncated = true;
                break;
            }
            if node.truncated {
                is_truncated = true;
            }
            out.push(node.to_derivation(revision, scope));
        }
        (out, is_truncated)
    }

    /// Extract ATMS subsumption-minimal canonical record environments supporting `fact`.
    pub fn minimal_environments(
        &self,
        fact: &FactRef,
        max_envs: u64,
    ) -> Vec<std::collections::BTreeSet<mneme_core::RecordId>> {
        let mut candidates: Vec<std::collections::BTreeSet<mneme_core::RecordId>> = self
            .nodes_for(fact)
            .into_iter()
            .filter(|node| node.epistemic.is_active())
            .map(|node| node.canonical_roots.clone())
            .collect();
        candidates
            .sort_by(|left, right| left.len().cmp(&right.len()).then_with(|| left.cmp(right)));
        let mut minimal: Vec<std::collections::BTreeSet<mneme_core::RecordId>> =
            Vec::with_capacity(candidates.len());
        let mut emitted = 0_u64;
        for env in candidates {
            if emitted >= max_envs {
                break;
            }
            if minimal.iter().any(|existing| existing.is_subset(&env)) {
                continue;
            }
            minimal.push(env);
            emitted = emitted.saturating_add(1);
        }
        minimal
    }

    fn remove_node(&mut self, id: NodeId) -> Option<Node> {
        let node = self.nodes.remove(&id)?;
        if let Some(set) = self.by_fact.get_mut(&node.head) {
            set.remove(&id);
            if set.is_empty() {
                self.by_fact.remove(&node.head);
            }
        }
        for edge in &node.premises {
            let dep_key = (edge.predicate.clone(), edge.terms.clone());
            if let Some(dep_set) = self.dependents.get_mut(&dep_key) {
                dep_set.remove(&id);
                if dep_set.is_empty() {
                    self.dependents.remove(&dep_key);
                }
            }
        }
        Some(node)
    }
}

fn compute_node_id(
    head: &FactRef,
    rule_id: &str,
    premises: &[PremiseEdge],
    vaults: &std::collections::BTreeSet<String>,
) -> NodeId {
    let premise_values = premises
        .iter()
        .map(|edge| {
            mneme_core::Value::record_named(
                "justification-premise",
                vec![
                    mneme_core::Value::string(edge.predicate.clone()),
                    mneme_core::Value::sequence(edge.terms.clone()),
                    edge.canonical.map_or_else(
                        || mneme_core::Value::symbol("derived"),
                        mneme_core::RecordId::to_value,
                    ),
                    edge.vault.as_ref().map_or_else(
                        || mneme_core::Value::symbol("multi"),
                        |v| mneme_core::Value::string(v.clone()),
                    ),
                    mneme_core::Value::Boolean(edge.absent),
                ],
            )
        })
        .collect();
    let payload = mneme_core::Value::record_named(
        "justification-node-v1",
        vec![
            mneme_core::Value::string(head.0.clone()),
            mneme_core::Value::sequence(head.1.clone()),
            mneme_core::Value::string(rule_id.to_owned()),
            mneme_core::Value::sequence(premise_values),
            mneme_core::Value::set(vaults.iter().cloned().map(mneme_core::Value::string)),
        ],
    );
    let digest = mneme_core::ContentDigest::of_payload(&payload);
    NodeId(*digest.as_bytes())
}

#[cfg(test)]
mod tests {
    #[test]
    fn content_addressed_dedup_invalidation_and_minimal_environments() {
        let mut graph = super::Hypergraph::default();
        let scope =
            mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "dag").expect("scope");
        let rev = mneme_core::WorkspaceRevisionId::from_bytes([0x11; 16]);
        let r1 = mneme_core::RecordId::from_bytes([0x01; 16]);
        let r2 = mneme_core::RecordId::from_bytes([0x02; 16]);

        let base_a: super::FactRef = ("edge".to_owned(), vec![mneme_core::Value::integer(1)]);
        let base_b: super::FactRef = ("edge".to_owned(), vec![mneme_core::Value::integer(2)]);
        let derived: super::FactRef = ("reach".to_owned(), vec![mneme_core::Value::integer(1)]);

        let d_base_a = crate::Derivation {
            rule_id: "canonical".to_owned(),
            rule_version: "1".to_owned(),
            premises: vec![crate::Premise {
                predicate: "relation".to_owned(),
                terms: Vec::new(),
                canonical: Some(r1),
                canonical_roots: std::collections::BTreeSet::from([r1]),
                sources: std::collections::BTreeSet::new(),
                source_availability: None,
                vault: Some("primary".to_owned()),
                vaults: std::collections::BTreeSet::from(["primary".to_owned()]),
                absent: false,
                coverage: None,
                epistemic: crate::EpistemicStatus::Accepted,
            }],
            sources: std::collections::BTreeSet::new(),
            vaults: std::collections::BTreeSet::from(["primary".to_owned()]),
            temporal_parameters: Vec::new(),
            revision: rev,
            scope: scope.clone(),
            truncated: false,
            epistemic: crate::EpistemicStatus::Accepted,
        };
        let id_a = graph
            .intern_derivation(base_a.clone(), &d_base_a)
            .expect("intern a");
        let id_a_dup = graph
            .intern_derivation(base_a.clone(), &d_base_a)
            .expect("dedup a");
        assert_eq!(id_a, id_a_dup);
        assert_eq!(graph.node_count(), 1);

        // Two derivations for `derived`: minimal `{r1}` and subsumed `{r1, r2}`.
        let d_min = crate::Derivation {
            rule_id: "r_direct".to_owned(),
            rule_version: "1".to_owned(),
            premises: vec![crate::Premise {
                predicate: "edge".to_owned(),
                terms: vec![mneme_core::Value::integer(1)],
                canonical: Some(r1),
                canonical_roots: std::collections::BTreeSet::from([r1]),
                sources: std::collections::BTreeSet::new(),
                source_availability: None,
                vault: Some("primary".to_owned()),
                vaults: std::collections::BTreeSet::from(["primary".to_owned()]),
                absent: false,
                coverage: None,
                epistemic: crate::EpistemicStatus::Accepted,
            }],
            sources: std::collections::BTreeSet::new(),
            vaults: std::collections::BTreeSet::from(["primary".to_owned()]),
            temporal_parameters: Vec::new(),
            revision: rev,
            scope: scope.clone(),
            truncated: false,
            epistemic: crate::EpistemicStatus::Accepted,
        };
        let d_subsumed = crate::Derivation {
            rule_id: "r_two_hop".to_owned(),
            rule_version: "1".to_owned(),
            premises: vec![
                d_min.premises[0].clone(),
                crate::Premise {
                    predicate: "edge".to_owned(),
                    terms: vec![mneme_core::Value::integer(2)],
                    canonical: Some(r2),
                    canonical_roots: std::collections::BTreeSet::from([r2]),
                    sources: std::collections::BTreeSet::new(),
                    source_availability: None,
                    vault: Some("primary".to_owned()),
                    vaults: std::collections::BTreeSet::from(["primary".to_owned()]),
                    absent: false,
                    coverage: None,
                    epistemic: crate::EpistemicStatus::Accepted,
                },
            ],
            sources: std::collections::BTreeSet::new(),
            vaults: std::collections::BTreeSet::from(["primary".to_owned()]),
            temporal_parameters: Vec::new(),
            revision: rev,
            scope: scope.clone(),
            truncated: false,
            epistemic: crate::EpistemicStatus::Accepted,
        };
        let _ = graph.intern_derivation(derived.clone(), &d_min);
        let _ = graph.intern_derivation(derived.clone(), &d_subsumed);

        let envs = graph.minimal_environments(&derived, 8);
        assert_eq!(envs, vec![std::collections::BTreeSet::from([r1])]);

        let (projected, truncated) = graph.project_derivations(&derived, rev, &scope, 8);
        assert_eq!(projected.len(), 2);
        assert!(!truncated);

        // Retracting base_b invalidates only `r_two_hop` (derived still keeps `r_direct`).
        let invalidated = graph.invalidate_facts(&[base_b]);
        assert!(invalidated.contains(&derived));
        assert_eq!(graph.nodes_for(&derived).len(), 1);
        assert_eq!(graph.nodes_for(&derived)[0].rule_id, "r_direct");

        // Retracting base_a invalidates `r_direct` too.
        let invalidated2 = graph.invalidate_facts(&[base_a]);
        assert!(invalidated2.contains(&derived));
        assert!(graph.nodes_for(&derived).is_empty());
    }
}
