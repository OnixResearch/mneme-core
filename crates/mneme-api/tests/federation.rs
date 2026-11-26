//! Deterministic offline tests for read-only, revision-pinned `irpc` vault
//! federation across in-memory, Quinn (`noq`), and Iroh transports.

fn cedar() -> Result<mneme_core::ScopeId, Box<dyn std::error::Error>> {
    Ok(mneme_core::ScopeId::new(
        mneme_core::ScopeClass::Project,
        "cedar",
    )?)
}

fn birch() -> Result<mneme_core::ScopeId, Box<dyn std::error::Error>> {
    Ok(mneme_core::ScopeId::new(
        mneme_core::ScopeClass::Project,
        "birch",
    )?)
}

fn deterministic_key(seed: u8) -> iroh::SecretKey {
    iroh::SecretKey::from_bytes(&[seed; 32])
}

struct SeedEntity<'a> {
    root: &'a std::path::Path,
    scope: &'a mneme_core::ScopeId,
    key: &'a str,
    id_byte: u8,
    kind: &'a str,
    label: &'a str,
}

fn commit_entity(
    seed: SeedEntity<'_>,
) -> Result<mneme_core::WorkspaceRevisionId, Box<dyn std::error::Error>> {
    let mut ws = if seed.root.join("ledger.sqlite3").exists() {
        mneme_store::Workspace::open(
            seed.root,
            mneme_store::WorkspaceConfig::new(
                Box::new(mneme_store::SystemClock),
                Box::new(mneme_store::NoFaults),
            ),
        )?
    } else {
        mneme_store::Workspace::create(
            seed.root,
            mneme_store::WorkspaceConfig::new(
                Box::new(mneme_store::SystemClock),
                Box::new(mneme_store::NoFaults),
            ),
        )?
    };
    let base = ws.current_revision()?;
    let payload = mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol(seed.kind),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(seed.label),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ]);
    let outcome = ws.commit(mneme_store::CommitCommand {
        base,
        actor: "federation-test".to_owned(),
        scope: seed.scope.clone(),
        idempotency_key: seed.key.to_owned(),
        records: vec![mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: mneme_core::RecordId::from_bytes([seed.id_byte; 16]),
            revision_id: mneme_core::RevisionId::from_bytes([seed.id_byte.wrapping_add(1); 16]),
            predecessor: None,
            scope: seed.scope.clone(),
            payload,
        }],
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })?;
    assert_ne!(outcome.revision, base);
    let head = ws.current_revision()?;
    assert_eq!(head, outcome.revision);
    Ok(head)
}

fn entity_bundle(bundle_id: &str) -> mneme_datalog::RuleBundle {
    mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: bundle_id.to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([("entity".to_owned(), 3)]),
        complete_predicates: std::collections::BTreeSet::from(["entity".to_owned()]),
        rules: vec![mneme_datalog::Rule::new(
            "entity-labels",
            mneme_datalog::Atom::new(
                "entity_label",
                vec![
                    mneme_datalog::Term::var("Id"),
                    mneme_datalog::Term::var("Label"),
                ],
            ),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "entity",
                vec![
                    mneme_datalog::Term::var("Id"),
                    mneme_datalog::Term::var("Kind"),
                    mneme_datalog::Term::var("Label"),
                ],
            ))],
        )],
    })
}

fn cross_vault_bundle(remote_alias: &str) -> mneme_datalog::RuleBundle {
    mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "remote-bridge".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([("vault_entity".to_owned(), 4)]),
        complete_predicates: std::collections::BTreeSet::from(["vault_entity".to_owned()]),
        rules: vec![mneme_datalog::Rule::new(
            "bridge-rule",
            mneme_datalog::Atom::new(
                "bridge",
                vec![
                    mneme_datalog::Term::var("RemoteId"),
                    mneme_datalog::Term::var("PrimaryId"),
                    mneme_datalog::Term::var("Label"),
                ],
            ),
            vec![
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "vault_entity",
                    vec![
                        mneme_datalog::Term::constant(mneme_core::Value::string(remote_alias)),
                        mneme_datalog::Term::var("RemoteId"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("paper")),
                        mneme_datalog::Term::var("Label"),
                    ],
                )),
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "vault_entity",
                    vec![
                        mneme_datalog::Term::constant(mneme_core::Value::string(
                            mneme_datalog::PRIMARY_VAULT_ALIAS,
                        )),
                        mneme_datalog::Term::var("PrimaryId"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("principle")),
                        mneme_datalog::Term::var("Label"),
                    ],
                )),
                mneme_datalog::Literal::Negative(mneme_datalog::Atom::new(
                    "vault_entity",
                    vec![
                        mneme_datalog::Term::constant(mneme_core::Value::string(
                            mneme_datalog::PRIMARY_VAULT_ALIAS,
                        )),
                        mneme_datalog::Term::constant(
                            mneme_core::RecordId::from_bytes([0x13; 16]).to_value(),
                        ),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("suppressed")),
                        mneme_datalog::Term::var("Label"),
                    ],
                )),
            ],
        )],
    })
}

async fn run_protocol_checks(
    client: &mneme_api::federation::VaultFederationClient,
    scope: &mneme_core::ScopeId,
    pinned_rev: mneme_core::WorkspaceRevisionId,
    head_rev: mneme_core::WorkspaceRevisionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let head = client.query_head(scope).await?;
    assert_eq!(head.head_revision, *head_rev.as_bytes());

    let meta_rev1 = client.query_metadata(scope, Some(pinned_rev)).await?;
    assert_eq!(meta_rev1.served_revision, *pinned_rev.as_bytes());
    assert_eq!(meta_rev1.scoped_record_count, 1);

    let meta_head = client.query_metadata(scope, None).await?;
    assert_eq!(meta_head.served_revision, *head_rev.as_bytes());
    assert_eq!(meta_head.scoped_record_count, 2);

    let eval_rev1 = client
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope: scope.clone(),
            revision: Some(pinned_rev),
            read_hlc: None,
            calm_seal: None,
            bundle: entity_bundle("remote-eval"),
            predicate: "entity_label".to_owned(),
            constants: Vec::new(),
            limit: 16,
            at: None,
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
        })
        .await?;
    assert_eq!(eval_rev1.status, "complete");
    assert_eq!(eval_rev1.served_revision, *pinned_rev.as_bytes());
    assert_eq!(eval_rev1.rows.len(), 1);
    assert_eq!(eval_rev1.rows[0].epistemic, "accepted");
    assert!(eval_rev1.exhaustive);

    let eval_head = client
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope: scope.clone(),
            revision: None,
            read_hlc: None,
            calm_seal: None,
            bundle: entity_bundle("remote-eval"),
            predicate: "entity_label".to_owned(),
            constants: Vec::new(),
            limit: 16,
            at: None,
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
        })
        .await?;
    assert_eq!(eval_head.served_revision, *head_rev.as_bytes());
    assert_eq!(eval_head.rows.len(), 2);
    Ok(())
}

#[tokio::test]
async fn in_memory_transport_serves_read_only_head_metadata_snapshot_and_datalog()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let scope = cedar()?;
    let other_scope = birch()?;
    let rev1 = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &scope,
        key: "k1",
        id_byte: 0x21,
        kind: "paper",
        label: "first-topic",
    })?;
    let _rev2 = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &scope,
        key: "k2",
        id_byte: 0x22,
        kind: "paper",
        label: "second-topic",
    })?;
    let rev3 = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &other_scope,
        key: "k3",
        id_byte: 0x51,
        kind: "secret",
        label: "birch-only",
    })?;

    let allowed_peer = deterministic_key(7).public();
    let denied_peer = deterministic_key(8).public();
    let mut allowlist = mneme_api::federation::PeerAllowlist::empty();
    allowlist.allow(allowed_peer);
    let server = mneme_api::federation::VaultFederationServer::spawn(
        mneme_api::federation::ServerConfig::new(temp.path(), allowlist),
    )?;

    let client = server.local_client_for(allowed_peer);
    run_protocol_checks(&client, &scope, rev1, rev3).await?;

    // Unallowlisted peer is denied even over in-memory transport.
    let denied_client = server.local_client_for(denied_peer);
    let denied = denied_client.query_head(&scope).await;
    assert!(matches!(
        denied,
        Err(mneme_api::federation::FederationError::Unauthorized(_))
    ));

    // Remote vault remains unmutated at rev3.
    let ws = mneme_store::Workspace::open_read_only(
        temp.path(),
        mneme_store::WorkspaceConfig::new(
            Box::new(mneme_store::SystemClock),
            Box::new(mneme_store::NoFaults),
        ),
    )?;
    assert_eq!(ws.current_revision()?, rev3);
    Ok(())
}

#[tokio::test]
async fn quinn_transport_enforces_ed25519_allowlist_and_serves_pinned_datalog()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let scope = cedar()?;
    let rev1 = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &scope,
        key: "q1",
        id_byte: 0x21,
        kind: "paper",
        label: "quinn-rev1",
    })?;
    let rev2 = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &scope,
        key: "q2",
        id_byte: 0x22,
        kind: "paper",
        label: "quinn-rev2",
    })?;

    let server_key = deterministic_key(11);
    let client_key = deterministic_key(12);
    let rogue_key = deterministic_key(13);
    let mut allowlist = mneme_api::federation::PeerAllowlist::empty();
    allowlist.allow(client_key.public());

    let server = mneme_api::federation::VaultFederationServer::spawn(
        mneme_api::federation::ServerConfig::new(temp.path(), allowlist),
    )?;
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    let server_ep = mneme_api::federation::make_authenticated_server_endpoint(
        bind,
        &server_key,
        server.allowlist().clone(),
    )?;
    let server_addr = server_ep.local_addr()?;
    let server_task = server.serve_noq(server_ep);

    let client_ep = mneme_api::federation::make_authenticated_client_endpoint(
        bind,
        &client_key,
        server_key.public(),
    )?;
    let client = mneme_api::federation::VaultFederationClient::connect_noq(client_ep, server_addr);
    run_protocol_checks(&client, &scope, rev1, rev2).await?;

    // Unallowlisted Ed25519 client certificate is rejected by Quinn mTLS.
    let rogue_ep = mneme_api::federation::make_authenticated_client_endpoint(
        bind,
        &rogue_key,
        server_key.public(),
    )?;
    let rogue_client =
        mneme_api::federation::VaultFederationClient::connect_noq(rogue_ep, server_addr);
    let rogue_res = rogue_client.query_head(&scope).await;
    assert!(rogue_res.is_err());
    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn iroh_loopback_transport_federates_cross_vault_datalog_with_pinned_revision_and_provenance()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let primary_root = temp.path().join("primary");
    let remote_root = temp.path().join("remote");
    let scope = cedar()?;

    let _ = commit_entity(SeedEntity {
        root: &primary_root,
        scope: &scope,
        key: "p1",
        id_byte: 0x11,
        kind: "principle",
        label: "stratified-negation",
    })?;
    let _ = commit_entity(SeedEntity {
        root: &primary_root,
        scope: &scope,
        key: "p2",
        id_byte: 0x12,
        kind: "principle",
        label: "bounded-search",
    })?;
    let _ = commit_entity(SeedEntity {
        root: &primary_root,
        scope: &scope,
        key: "p3",
        id_byte: 0x13,
        kind: "suppressed",
        label: "bounded-search",
    })?;

    let remote_rev1 = commit_entity(SeedEntity {
        root: &remote_root,
        scope: &scope,
        key: "r1",
        id_byte: 0x21,
        kind: "paper",
        label: "stratified-negation",
    })?;
    let remote_rev2 = commit_entity(SeedEntity {
        root: &remote_root,
        scope: &scope,
        key: "r2",
        id_byte: 0x22,
        kind: "paper",
        label: "bounded-search",
    })?;

    let server_ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(deterministic_key(21))
        .bind()
        .await?;
    let allowed_ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(deterministic_key(22))
        .bind()
        .await?;
    let denied_ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(deterministic_key(23))
        .bind()
        .await?;

    let mut allowlist = mneme_api::federation::PeerAllowlist::empty();
    allowlist.allow(allowed_ep.id());
    let server = mneme_api::federation::VaultFederationServer::spawn(
        mneme_api::federation::ServerConfig::new(&remote_root, allowlist),
    )?;
    let router = server.serve_iroh(server_ep.clone());
    let server_addr = server_ep.addr();

    // Denied Iroh peer is refused before any RPC executes.
    let denied_client = mneme_api::federation::VaultFederationClient::connect_iroh(
        denied_ep.clone(),
        server_addr.clone(),
    );
    assert!(denied_client.query_head(&scope).await.is_err());

    let client =
        mneme_api::federation::VaultFederationClient::connect_iroh(allowed_ep.clone(), server_addr);
    run_protocol_checks(&client, &scope, remote_rev1, remote_rev2).await?;

    // Fetch pinned @remote_rev1 view over Iroh and join locally with primary vault.
    let locator = format!("iroh://{}", server_ep.id());
    let access = mneme_memory::Access::scopes([scope.clone()]);
    let external = client
        .fetch_external_vault_view(mneme_api::federation::RemoteViewFetchOptions {
            alias: "bookmarks",
            locator: &locator,
            scope: &scope,
            revision: Some(remote_rev1),
            read_hlc: None,
            limits: mneme_api::federation::FederationLimits::standard(),
            access: &access,
        })
        .await?;

    let mut primary_ws = mneme_store::Workspace::open(
        &primary_root,
        mneme_store::WorkspaceConfig::new(
            Box::new(mneme_store::SystemClock),
            Box::new(mneme_store::NoFaults),
        ),
    )?;
    let primary_rev = primary_ws.current_revision()?;
    let mut service = mneme_datalog::Service::new(&mut primary_ws);
    let build = service.build_federated_sources(
        mneme_datalog::BuildRequest {
            actor: "federation-test".to_owned(),
            scope: scope.clone(),
            revision: primary_rev,
            bundle: cross_vault_bundle("bookmarks"),
            limits: mneme_datalog::Limits {
                max_work: 100_000,
                max_time_ms: 2_000,
                max_result_rows: 1_000,
                max_supports_per_fact: 8,
                max_recursion_depth: 32,
            },
            publish: false,
            incomplete_extents: std::collections::BTreeSet::new(),
            cancellation: None,
            access,
            at: None,
        },
        vec![mneme_datalog::FederatedVaultSource::External(Box::new(
            external,
        ))],
    )?;
    let mut query = mneme_datalog::Query::all("bridge", 32);
    query.allow_stale = true;
    let result = service.query_build(&build, query)?;
    assert_eq!(result.status, mneme_datalog::ExecutionStatus::Complete);
    assert!(result.exhaustive);
    assert_eq!(result.vaults.len(), 2);
    assert_eq!(result.vaults[1].alias, "bookmarks");
    assert_eq!(
        result.vaults[1].peer(),
        Some(server_ep.id().to_string().as_str())
    );
    assert_eq!(result.vaults[1].served_revision, remote_rev1);
    assert_eq!(result.rows.len(), 1);
    assert_eq!(
        result.rows[0].values[2],
        mneme_core::Value::string("stratified-negation")
    );
    let expected_vaults = std::collections::BTreeSet::from([
        "bookmarks".to_owned(),
        mneme_datalog::PRIMARY_VAULT_ALIAS.to_owned(),
    ]);
    assert_eq!(result.rows[0].supports[0].vaults, expected_vaults);

    allowed_ep.close().await;
    denied_ep.close().await;
    let shutdown_res = router.shutdown().await;
    assert!(shutdown_res.is_ok());
    Ok(())
}

#[tokio::test]
async fn scope_isolation_and_budget_enforcement_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let cedar_scope = cedar()?;
    let birch_scope = birch()?;
    let _ = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &cedar_scope,
        key: "c1",
        id_byte: 0x21,
        kind: "paper",
        label: "cedar-1",
    })?;
    let _ = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &cedar_scope,
        key: "c2",
        id_byte: 0x22,
        kind: "paper",
        label: "cedar-2",
    })?;
    let _ = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &birch_scope,
        key: "b1",
        id_byte: 0x31,
        kind: "paper",
        label: "birch-secret",
    })?;

    let caller = deterministic_key(31).public();
    let server_ceiling = mneme_api::federation::FederationLimits {
        max_work: 500,
        max_rows: 100,
        max_time_ms: 2_000,
        max_bytes: 256 * 1024,
        max_supports_per_fact: 8,
        max_recursion_depth: 16,
    };
    let mut cfg = mneme_api::federation::ServerConfig::new(
        temp.path(),
        mneme_api::federation::PeerAllowlist::from_peers([caller]),
    );
    cfg.max_limits = server_ceiling;
    let server = mneme_api::federation::VaultFederationServer::spawn(cfg)?;
    let client = server.local_client_for(caller);

    // Scope isolation: querying cedar never returns birch records.
    let access = mneme_memory::Access::scopes([cedar_scope.clone()]);
    let external = client
        .fetch_external_vault_view(mneme_api::federation::RemoteViewFetchOptions {
            alias: "remote",
            locator: &format!("iroh://{caller}"),
            scope: &cedar_scope,
            revision: None,
            read_hlc: None,
            limits: server_ceiling,
            access: &access,
        })
        .await?;
    assert_eq!(external.view.snapshot().records.len(), 2);

    // Budget enforcement 1: exceeding server ceiling fails closed.
    let oversized = mneme_api::federation::FederationLimits {
        max_work: 1_000,
        ..server_ceiling
    };
    let err = client
        .fetch_pinned_snapshot(&cedar_scope, None, oversized)
        .await;
    assert!(matches!(
        err,
        Err(mneme_api::federation::FederationError::BudgetExceeded(_))
    ));

    // Budget enforcement 2: tight max_rows on snapshot fails closed.
    let tight_rows = mneme_api::federation::FederationLimits {
        max_rows: 1,
        ..server_ceiling
    };
    let err_rows = client
        .fetch_pinned_snapshot(&cedar_scope, None, tight_rows)
        .await;
    assert!(matches!(
        err_rows,
        Err(mneme_api::federation::FederationError::BudgetExceeded(_))
    ));

    // Budget enforcement 3: tight max_bytes on snapshot fails closed.
    let tight_bytes = mneme_api::federation::FederationLimits {
        max_bytes: 32,
        ..server_ceiling
    };
    let err_bytes = client
        .fetch_pinned_snapshot(&cedar_scope, None, tight_bytes)
        .await;
    assert!(matches!(
        err_bytes,
        Err(mneme_api::federation::FederationError::BudgetExceeded(_))
    ));

    // Budget enforcement 4: EvaluateDatalog row/work limits bound output deterministically.
    let limited_eval = client
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope: cedar_scope.clone(),
            revision: None,
            read_hlc: None,
            calm_seal: None,
            bundle: entity_bundle("budgeted"),
            predicate: "entity_label".to_owned(),
            constants: Vec::new(),
            limit: 1,
            at: None,
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: server_ceiling,
        })
        .await?;
    assert_eq!(limited_eval.rows.len(), 1);
    assert!(limited_eval.truncated);
    assert!(!limited_eval.exhaustive);

    // Budget enforcement 5: Tight max_work stops evaluation before completion.
    let tight_work_eval = client
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope: cedar_scope,
            revision: None,
            read_hlc: None,
            calm_seal: None,
            bundle: entity_bundle("budgeted-work"),
            predicate: "entity_label".to_owned(),
            constants: Vec::new(),
            limit: 10,
            at: None,
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits {
                max_work: 1,
                ..server_ceiling
            },
        })
        .await?;
    assert_ne!(tight_work_eval.status, "complete");
    assert!(!tight_work_eval.exhaustive);

    // Empty allowlist denies every peer.
    let deny_all = mneme_api::federation::VaultFederationServer::spawn(
        mneme_api::federation::ServerConfig::new(
            temp.path(),
            mneme_api::federation::PeerAllowlist::empty(),
        ),
    )?;
    let denied_res = deny_all
        .local_client_for(caller)
        .query_head(&birch_scope)
        .await;
    assert!(matches!(
        denied_res,
        Err(mneme_api::federation::FederationError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn attachment_spec_parses_iroh_uris_and_rejects_malformed_specs()
-> Result<(), Box<dyn std::error::Error>> {
    let key = deterministic_key(41).public();
    let rev = mneme_core::WorkspaceRevisionId::from_bytes([0xab; 16]);
    let spec_head = format!("peer_a=iroh://{key}");
    let parsed_head = mneme_api::federation::parse_attachment_spec(&spec_head)?;
    assert_eq!(parsed_head.alias, "peer_a");
    assert_eq!(
        parsed_head.target,
        mneme_api::federation::AttachmentTarget::Iroh {
            node_id: key,
            canonical_uri: format!("iroh://{key}"),
        }
    );
    assert_eq!(parsed_head.revision, None);

    let spec_pinned = format!("peer_b=iroh://{key}@{}", rev.to_hex());
    let parsed_pinned = mneme_api::federation::parse_attachment_spec(&spec_pinned)?;
    assert_eq!(parsed_pinned.alias, "peer_b");
    assert_eq!(parsed_pinned.revision, Some(rev));

    assert!(mneme_api::federation::parse_attachment_spec("primary=iroh://invalid").is_err());
    assert!(
        mneme_api::federation::parse_attachment_spec("peer=iroh://not-a-valid-node-id").is_err()
    );
    assert!(mneme_api::federation::parse_attachment_spec("peer=iroh://").is_err());
    Ok(())
}

#[tokio::test]
async fn iroh_loopback_transport_federates_prolog_reason_query()
-> Result<(), Box<dyn std::error::Error>> {
    #[allow(unknown_lints, ambient_env)] // Scryer engine path comes from the Nix test shell
    let engine_path = std::env::var("MNEME_SCRYER_PROLOG").unwrap_or_default();
    if engine_path.trim().is_empty() {
        return Err("MNEME_SCRYER_PROLOG must be set in nix develop".into());
    }
    let temp = tempfile::tempdir()?;
    let primary_root = temp.path().join("primary");
    let remote_root = temp.path().join("remote");
    let scope = cedar()?;

    let _ = commit_entity(SeedEntity {
        root: &primary_root,
        scope: &scope,
        key: "p1",
        id_byte: 0x11,
        kind: "principle",
        label: "cross-topic",
    })?;
    let remote_rev = commit_entity(SeedEntity {
        root: &remote_root,
        scope: &scope,
        key: "r1",
        id_byte: 0x41,
        kind: "paper",
        label: "cross-topic",
    })?;

    let server_ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(deterministic_key(51))
        .bind()
        .await?;
    let client_ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(deterministic_key(52))
        .bind()
        .await?;
    let server = mneme_api::federation::VaultFederationServer::spawn(
        mneme_api::federation::ServerConfig::new(
            &remote_root,
            mneme_api::federation::PeerAllowlist::from_peers([client_ep.id()]),
        ),
    )?;
    let router = server.serve_iroh(server_ep.clone());
    let client = mneme_api::federation::VaultFederationClient::connect_iroh(
        client_ep.clone(),
        server_ep.addr(),
    );

    let access = mneme_memory::Access::scopes([scope.clone()]);
    let external = client
        .fetch_external_vault_view(mneme_api::federation::RemoteViewFetchOptions {
            alias: "bookmarks",
            locator: &format!("iroh://{}", server_ep.id()),
            scope: &scope,
            revision: Some(remote_rev),
            read_hlc: None,
            limits: mneme_api::federation::FederationLimits::standard(),
            access: &access,
        })
        .await?;

    let metadata = mneme_prolog::CapabilityMetadata {
        adapter_version: "1".to_owned(),
        profile: "positive-minimal/v1".to_owned(),
        engine: Some(mneme_prolog::EngineIdentity {
            name: "scryer-prolog".to_owned(),
            version: "0.10.0".to_owned(),
            source_revision: "nixpkgs-pinned".to_owned(),
        }),
        state: mneme_prolog::CapabilityState::Enabled,
        features: std::collections::BTreeSet::from([mneme_prolog::Feature::PositiveQuery]),
        allowed_predicates: std::collections::BTreeSet::from([
            "assertion".to_owned(),
            "relation".to_owned(),
            "vault_entity".to_owned(),
            "bridge".to_owned(),
        ]),
        limits: mneme_prolog::ProfileLimits {
            max_time_ms: 5_000,
            max_solutions: 16,
            max_output_bytes: 65_536,
            max_term_depth: 8,
            max_rule_count: 4,
        },
        terms: mneme_prolog::TermProfile {
            max_depth: 8,
            max_collection: 32,
            references_allowed: false,
        },
    };
    let session =
        mneme_api::LocalSession::for_scope("federated-prolog", &primary_root, scope.clone())?;
    let api = mneme_api::ApiService::new(session).with_prolog(engine_path, metadata)?;
    let rule = mneme_prolog::Rule {
        id: "r1".to_owned(),
        version: "1".to_owned(),
        head: mneme_prolog::Atom {
            predicate: "bridge".to_owned(),
            terms: vec![
                mneme_prolog::Term::Variable("Paper".to_owned()),
                mneme_prolog::Term::Variable("Principle".to_owned()),
                mneme_prolog::Term::Variable("Label".to_owned()),
            ],
        },
        body: vec![
            mneme_prolog::Literal::Positive(mneme_prolog::Atom {
                predicate: "vault_entity".to_owned(),
                terms: vec![
                    mneme_prolog::Term::String("bookmarks".to_owned()),
                    mneme_prolog::Term::Variable("Paper".to_owned()),
                    mneme_prolog::Term::String("paper".to_owned()),
                    mneme_prolog::Term::Variable("Label".to_owned()),
                ],
            }),
            mneme_prolog::Literal::Positive(mneme_prolog::Atom {
                predicate: "vault_entity".to_owned(),
                terms: vec![
                    mneme_prolog::Term::String(mneme_datalog::PRIMARY_VAULT_ALIAS.to_owned()),
                    mneme_prolog::Term::Variable("Principle".to_owned()),
                    mneme_prolog::Term::String("principle".to_owned()),
                    mneme_prolog::Term::Variable("Label".to_owned()),
                ],
            }),
        ],
    };
    let response =
        api.execute_federated_reason_with_sources(&mneme_api::FederatedReasonWithSourcesRequest {
            request_id: "iroh-prolog-1".to_owned(),
            scope,
            primary_revision: None,
            sources: vec![mneme_api::FederatedReasonSource::External(Box::new(
                external,
            ))],
            query: mneme_api::ReasonQuery {
                mode: mneme_prolog::QueryMode::Enumerate,
                goal: mneme_prolog::Atom {
                    predicate: "bridge".to_owned(),
                    terms: vec![
                        mneme_prolog::Term::Variable("Paper".to_owned()),
                        mneme_prolog::Term::Variable("Principle".to_owned()),
                        mneme_prolog::Term::Variable("Label".to_owned()),
                    ],
                },
                variables: vec![
                    mneme_prolog::QueryVariable {
                        name: "Paper".to_owned(),
                        role: mneme_prolog::VariableRole::Output,
                    },
                    mneme_prolog::QueryVariable {
                        name: "Principle".to_owned(),
                        role: mneme_prolog::VariableRole::Output,
                    },
                    mneme_prolog::QueryVariable {
                        name: "Label".to_owned(),
                        role: mneme_prolog::VariableRole::Output,
                    },
                ],
                rules: vec![rule],
                assumptions: Vec::new(),
                features: std::collections::BTreeSet::from([mneme_prolog::Feature::PositiveQuery]),
                limits: mneme_prolog::RequestLimits {
                    max_time_ms: 2_000,
                    max_solutions: 8,
                    max_output_bytes: 16_384,
                },
            },
        });
    assert!(response.ok, "{:?}", response.value);
    let data = response
        .value
        .as_dictionary()
        .and_then(|map| map.get(&mneme_core::Value::symbol("data")))
        .and_then(mneme_core::Value::as_dictionary)
        .ok_or("missing data")?;
    let vaults = data
        .get(&mneme_core::Value::symbol("vaults"))
        .and_then(mneme_core::Value::as_sequence)
        .ok_or("missing vaults")?;
    assert_eq!(vaults.len(), 2);
    let remote_vault = vaults[1]
        .as_dictionary()
        .ok_or("missing remote vault dict")?;
    assert_eq!(
        remote_vault
            .get(&mneme_core::Value::symbol("alias"))
            .and_then(mneme_core::Value::as_string),
        Some("bookmarks")
    );
    assert_eq!(
        remote_vault
            .get(&mneme_core::Value::symbol("peer"))
            .and_then(mneme_core::Value::as_string),
        Some(server_ep.id().to_string().as_str())
    );

    client_ep.close().await;
    let shutdown_res = router.shutdown().await;
    assert!(shutdown_res.is_ok());
    Ok(())
}

#[tokio::test]
async fn live_reloadable_per_scope_allowlist_and_concap_revocation_enforced()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let scope_a = cedar()?;
    let scope_b = birch()?;
    let _rev_a = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &scope_a,
        key: "seed-a",
        id_byte: 71,
        kind: "paper",
        label: "Scope A Paper",
    })?;
    let _rev_b = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &scope_b,
        key: "seed-b",
        id_byte: 72,
        kind: "paper",
        label: "Scope B Secret",
    })?;

    let root_key = deterministic_key(81);
    let peer_allow = deterministic_key(82).public();
    let peer_cap = deterministic_key(83).public();
    let now_secs: u64 = 1_700_000_000;
    let clock: std::sync::Arc<dyn mneme_store::Clock> =
        std::sync::Arc::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos((now_secs as i64) * 1_000_000_000),
        ));

    let mut allowlist = mneme_api::federation::PeerAllowlist::empty();
    allowlist.allow_scopes(peer_allow, [scope_a.clone()]);
    let authorizer = mneme_api::federation::SharedFederationAuthorizer::from_allowlist(allowlist);
    authorizer.set_vault_id("vault-fed-1")?;
    authorizer.add_trusted_root(root_key.public())?;

    let server = mneme_api::federation::VaultFederationServer::spawn_with_authorizer_and_clock(
        mneme_api::federation::ServerConfig::new(
            temp.path(),
            mneme_api::federation::PeerAllowlist::empty(),
        ),
        authorizer.clone(),
        clock,
    )?;

    // 1. Per-scope allowlist permits scope_a, refuses scope_b, and live-revokes mid-session.
    let allow_client = server.local_client_for(peer_allow);
    let head = allow_client.query_head(&scope_a).await?;
    assert_eq!(head.head_sequence, 2);

    let denied_b = allow_client.query_head(&scope_b).await;
    assert!(matches!(
        denied_b,
        Err(mneme_api::federation::FederationError::Unauthorized(_))
    ));

    // Live-revoke peer_allow without restarting the server.
    authorizer.revoke_peer(&peer_allow)?;
    let after_revoke = allow_client.query_head(&scope_a).await;
    assert!(matches!(
        after_revoke,
        Err(mneme_api::federation::FederationError::Unauthorized(_))
    ));

    // 2. Non-allowlisted peer using concap token bound to (vault-fed-1, scope_a).
    let token_id = mneme_api::federation::TokenId::from_bytes([7_u8; 16]);
    let token = mneme_api::federation::CapabilityToken::grant(
        &root_key,
        mneme_api::federation::GrantParams {
            token_id,
            vault_id: "vault-fed-1".to_owned(),
            subject: peer_cap,
            scope: mneme_api::federation::CapabilityScope::from_scopes([scope_a.clone()])?,
            authority: mneme_api::federation::CapabilityAuthority::ReadOnly,
            issued_at_secs: now_secs,
            expires_at_secs: now_secs + 600,
            max_delegation_depth: 2,
        },
    )?;
    let cap_json = token.to_json()?;
    let cap_client = server
        .local_client_for(peer_cap)
        .with_capability(cap_json.clone());

    let cap_head = cap_client.query_head(&scope_a).await?;
    assert_eq!(cap_head.head_sequence, 2);

    // Cross-scope with scope_a concap token fails closed!
    let cap_scope_b = cap_client.query_head(&scope_b).await;
    assert!(matches!(
        cap_scope_b,
        Err(mneme_api::federation::FederationError::Unauthorized(_))
    ));

    // Wrong presenter using peer_cap's token fails closed!
    let wrong_presenter = server
        .local_client_for(peer_allow)
        .with_capability(cap_json);
    assert!(matches!(
        wrong_presenter.query_head(&scope_a).await,
        Err(mneme_api::federation::FederationError::Unauthorized(_))
    ));

    // Live revocation tombstone immediately revokes peer_cap's token!
    let tombstone = mneme_api::federation::RevocationTombstone::issue(
        &root_key,
        &mneme_api::federation::RevocationParams {
            tombstone_id: mneme_api::federation::TombstoneId::from_bytes([9_u8; 16]),
            vault_id: "vault-fed-1",
            target_token_id: token_id,
            revoked_at_secs: now_secs + 1,
            reason: Some("live revoke"),
        },
    )?;
    authorizer.insert_revocation(tombstone)?;
    let after_tombstone = cap_client.query_head(&scope_a).await;
    assert!(matches!(
        after_tombstone,
        Err(mneme_api::federation::FederationError::Unauthorized(_))
    ));

    // 3. Streaming max_bytes check refuses oversized pinned snapshot cleanly.
    authorizer.allow_peer_scopes(peer_allow, [scope_a.clone()])?;
    let mut tiny_limits = mneme_api::federation::FederationLimits::standard();
    tiny_limits.max_bytes = 32;
    let budget_err = allow_client
        .fetch_pinned_snapshot(&scope_a, None, tiny_limits)
        .await;
    assert!(matches!(
        budget_err,
        Err(mneme_api::federation::FederationError::BudgetExceeded(_))
    ));
    Ok(())
}

#[tokio::test]
async fn client_rejects_cross_scope_records_and_tampered_manifest_digest()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let scope_a = cedar()?;
    let scope_b = birch()?;
    let rev = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &scope_a,
        key: "seed-a",
        id_byte: 81,
        kind: "paper",
        label: "Legit Scope A",
    })?;
    let rev_b = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &scope_b,
        key: "seed-b",
        id_byte: 82,
        kind: "paper",
        label: "Foreign Scope B",
    })?;
    let _ = rev;

    let caller = deterministic_key(91).public();
    let server = mneme_api::federation::VaultFederationServer::spawn(
        mneme_api::federation::ServerConfig::new(
            temp.path(),
            mneme_api::federation::PeerAllowlist::from_peers([caller]),
        ),
    )?;
    let honest_client = server.local_client_for(caller);
    let legit_a = honest_client
        .fetch_pinned_snapshot(
            &scope_a,
            Some(rev_b),
            mneme_api::federation::FederationLimits::standard(),
        )
        .await?;
    let legit_b = honest_client
        .fetch_pinned_snapshot(
            &scope_b,
            Some(rev_b),
            mneme_api::federation::FederationLimits::standard(),
        )
        .await?;

    // Helper: spawn a rogue local irpc server returning a crafted PinnedSnapshotPayload.
    async fn run_rogue_fetch(
        payload: mneme_api::federation::PinnedSnapshotPayload,
        scope: &mneme_core::ScopeId,
    ) -> Result<mneme_datalog::ExternalVaultView, mneme_api::federation::FederationError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        tokio::task::spawn(async move {
            if let Some(mneme_api::federation::VaultFederationMessage::FetchPinnedSnapshot(msg)) =
                rx.recv().await
            {
                let _sent = msg.tx.send(Ok(payload)).await.is_ok();
            }
        });
        let client =
            mneme_api::federation::VaultFederationClient::from_irpc(irpc::Client::local(tx));
        // Use Access::Operator to prove client enforces envelope.scope == *scope strictly!
        let operator = mneme_memory::Access::Operator;
        let options = mneme_api::federation::RemoteViewFetchOptions {
            alias: "rogue",
            locator: "iroh://rogue",
            scope,
            revision: None,
            read_hlc: None,
            limits: mneme_api::federation::FederationLimits::standard(),
            access: &operator,
        };
        assert_eq!(options.alias, "rogue");
        assert!(!scope.to_string().is_empty());
        client.fetch_external_vault_view(options).await
    }

    // 1. Rogue server returns scope_b's payload when client asked for scope_a -> MUST FAIL!
    let cross_scope_err = run_rogue_fetch(legit_b.clone(), &scope_a).await;
    assert!(matches!(
        cross_scope_err,
        Err(mneme_api::federation::FederationError::ProtocolError(_))
    ));

    // 2. Rogue server smugges a scope_b record inside history_documents -> MUST FAIL!
    let mut bad_history = legit_a.clone();
    bad_history
        .history_documents
        .extend(legit_b.record_documents.clone());
    let history_err = run_rogue_fetch(bad_history, &scope_a).await;
    assert!(matches!(
        history_err,
        Err(mneme_api::federation::FederationError::ProtocolError(_))
    ));

    // 3. Rogue server tampers with manifest_digest_document -> MUST FAIL!
    let mut bad_digest = legit_a.clone();
    let bogus_digest = mneme_core::ContentDigest::of_source_bytes(b"tampered-manifest");
    bad_digest.manifest_digest_document =
        mneme_core::encode_document_string(&bogus_digest.to_value());
    let tamper_err = run_rogue_fetch(bad_digest, &scope_a).await;
    assert!(matches!(
        tamper_err,
        Err(mneme_api::federation::FederationError::ProtocolError(_))
    ));

    // 4. Honest payload verifies cleanly!
    let honest_ok = run_rogue_fetch(legit_a, &scope_a).await;
    assert!(honest_ok.is_ok());
    Ok(())
}

#[test]
fn federation_auth_kernel_attenuation_and_revocation_dominance()
-> Result<(), Box<dyn std::error::Error>> {
    let root_key = iroh::SecretKey::from_bytes(&[0x41; 32]);
    let peer_key = iroh::SecretKey::from_bytes(&[0x42; 32]);
    let scope_a = mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "fed-a")?;
    let scope_b = mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "fed-b")?;
    let now_secs = 1_700_000_000_u64;

    let parent_scope = mneme_api::federation::CapabilityScope::from_scopes([scope_a.clone()])?;
    let child_wildcard = mneme_api::federation::CapabilityScope::Wildcard;
    assert!(!child_wildcard.is_attenuation_of(&parent_scope));
    assert!(parent_scope.is_attenuation_of(&mneme_api::federation::CapabilityScope::Wildcard));
    assert!(
        mneme_api::federation::CapabilityAuthority::SyncPush
            .allows_attenuation_to(mneme_api::federation::CapabilityAuthority::ReadOnly)
    );
    assert!(
        !mneme_api::federation::CapabilityAuthority::ReadOnly
            .allows_attenuation_to(mneme_api::federation::CapabilityAuthority::SyncPull)
    );

    let token_id = mneme_api::federation::TokenId::from_bytes([0x55; 16]);
    let token = mneme_api::federation::CapabilityToken::grant(
        &root_key,
        mneme_api::federation::GrantParams {
            token_id,
            vault_id: "fed-vault".to_owned(),
            subject: peer_key.public(),
            scope: parent_scope,
            authority: mneme_api::federation::CapabilityAuthority::ReadOnly,
            issued_at_secs: now_secs,
            expires_at_secs: now_secs + 600,
            max_delegation_depth: 2,
        },
    )?;
    let doc = token.to_json()?;

    let auth = mneme_api::federation::SharedFederationAuthorizer::from_allowlist(
        mneme_api::federation::PeerAllowlist::empty(),
    );
    auth.set_vault_id("fed-vault")?;
    auth.add_trusted_root(root_key.public())?;

    assert!(
        auth.authorize_scope(peer_key.public(), &scope_a, Some(&doc), now_secs + 10)
            .is_ok()
    );
    assert!(
        auth.authorize_scope(peer_key.public(), &scope_b, Some(&doc), now_secs + 10)
            .is_err()
    );

    let tomb = mneme_api::federation::RevocationTombstone::issue(
        &root_key,
        &mneme_api::federation::RevocationParams {
            tombstone_id: mneme_api::federation::TombstoneId::from_bytes([0x66; 16]),
            vault_id: "fed-vault",
            target_token_id: token_id,
            revoked_at_secs: now_secs + 20,
            reason: Some("revoked-by-root"),
        },
    )?;
    auth.insert_revocation(tomb)?;
    assert!(
        auth.authorize_scope(peer_key.public(), &scope_a, Some(&doc), now_secs + 30)
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn remote_datalog_preserves_proposed_epistemic_and_explain_missing_rpc()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let scope = cedar()?;
    let mut workspace = mneme_store::Workspace::create(
        temp.path(),
        mneme_store::WorkspaceConfig::new(
            Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_700_000_000_000_000_000),
            )),
            Box::new(mneme_store::NoFaults),
        ),
    )?;
    let base = workspace.current_revision()?;

    let accepted_entity = mneme_core::RecordId::from_bytes([0x61; 16]);
    let proposed_entity = mneme_core::RecordId::from_bytes([0x62; 16]);
    let relation_id = mneme_core::RecordId::from_bytes([0x63; 16]);

    let accepted_draft = mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Entity,
        record_id: accepted_entity,
        revision_id: mneme_core::RevisionId::from_bytes([0x71; 16]),
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol("topic"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string("verified-node"),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary([]),
            ),
        ]),
    };
    let proposed_draft = mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Entity,
        record_id: proposed_entity,
        revision_id: mneme_core::RevisionId::from_bytes([0x72; 16]),
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol("topic"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string("candidate-node"),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::symbol_dictionary([(
                    mneme_core::Symbol::from("status"),
                    mneme_core::Value::symbol("proposed"),
                )]),
            ),
        ]),
    };
    let relation_draft = mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Relation,
        record_id: relation_id,
        revision_id: mneme_core::RevisionId::from_bytes([0x73; 16]),
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("relation-type"),
                mneme_core::Value::symbol("links"),
            ),
            (
                mneme_core::Symbol::from("from"),
                mneme_core::Reference::local(accepted_entity, mneme_core::RecordKind::Entity)
                    .to_value(),
            ),
            (
                mneme_core::Symbol::from("to"),
                mneme_core::Reference::local(proposed_entity, mneme_core::RecordKind::Entity)
                    .to_value(),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::symbol_dictionary([(
                    mneme_core::Symbol::from("status"),
                    mneme_core::Value::symbol("proposed"),
                )]),
            ),
        ]),
    };
    workspace.commit(mneme_store::CommitCommand {
        base,
        actor: "epistemic-test".to_owned(),
        scope: scope.clone(),
        idempotency_key: "epistemic-seed".to_owned(),
        records: vec![accepted_draft, proposed_draft, relation_draft],
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })?;

    let mut base_predicates = std::collections::BTreeMap::new();
    base_predicates.insert("entity".to_owned(), 3);
    base_predicates.insert("relation".to_owned(), 3);
    let mut complete_predicates = std::collections::BTreeSet::new();
    complete_predicates.insert("entity".to_owned());
    complete_predicates.insert("relation".to_owned());
    let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "epistemic-federation".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates,
        complete_predicates,
        rules: vec![mneme_datalog::Rule::new(
            "linked-label",
            mneme_datalog::Atom::new(
                "linked_label",
                vec![
                    mneme_datalog::Term::var("FromLabel"),
                    mneme_datalog::Term::var("ToLabel"),
                ],
            ),
            vec![
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "entity",
                    vec![
                        mneme_datalog::Term::var("From"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("topic")),
                        mneme_datalog::Term::var("FromLabel"),
                    ],
                )),
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "relation",
                    vec![
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("links")),
                        mneme_datalog::Term::var("From"),
                        mneme_datalog::Term::var("To"),
                    ],
                )),
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "entity",
                    vec![
                        mneme_datalog::Term::var("To"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("topic")),
                        mneme_datalog::Term::var("ToLabel"),
                    ],
                )),
            ],
        )],
    });

    let caller = iroh::SecretKey::from_bytes(&[0x64; 32]).public();
    let mut allowlist = mneme_api::federation::PeerAllowlist::empty();
    allowlist.allow_scopes(caller, [scope.clone()]);
    let server = mneme_api::federation::VaultFederationServer::spawn(
        mneme_api::federation::ServerConfig::new(temp.path(), allowlist),
    )?;
    let client = server.local_client_for(caller);

    // 1. EvaluateDatalog preserves Proposed epistemic status on row, derivation, and premises.
    let eval = client
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope: scope.clone(),
            revision: None,
            read_hlc: None,
            calm_seal: None,
            bundle: bundle.clone(),
            predicate: "linked_label".to_owned(),
            constants: Vec::new(),
            limit: 16,
            at: Some(mneme_core::Timestamp::from_nanos(1_700_000_000_000_000_000)),
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
        })
        .await?;
    assert_eq!(eval.status, "complete");
    assert_eq!(eval.at, Some(1_700_000_000_000_000_000));
    assert_eq!(eval.rows.len(), 1);
    assert_eq!(eval.rows[0].epistemic, "proposed");
    assert_eq!(eval.rows[0].supports.len(), 1);
    assert_eq!(eval.rows[0].supports[0].epistemic, "proposed");
    assert!(
        eval.rows[0].supports[0]
            .premises
            .iter()
            .any(|p| p.epistemic == "proposed")
    );
    assert!(
        eval.rows[0].supports[0]
            .premises
            .iter()
            .any(|p| p.epistemic == "accepted")
    );
    assert!(
        eval.rows[0].supports[0]
            .premises
            .iter()
            .all(|p| !p.canonical_roots.is_empty())
    );

    // 2. Incomplete extents propagate into coverage on EvaluateDatalog.
    let incomplete_eval = client
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope: scope.clone(),
            revision: None,
            read_hlc: None,
            calm_seal: None,
            bundle: bundle.clone(),
            predicate: "linked_label".to_owned(),
            constants: Vec::new(),
            limit: 16,
            at: None,
            incomplete_extents: std::collections::BTreeSet::from(["relation".to_owned()]),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
        })
        .await?;
    assert_eq!(
        incomplete_eval.incomplete_extents,
        vec!["relation".to_owned()]
    );
    assert!(
        incomplete_eval
            .coverage
            .iter()
            .any(|c| c.predicate == "relation" && c.status == "incomplete")
    );

    // 3. ExplainMissing RPC reports `present` + `proposed` epistemic for derived tuple.
    let present_explain = client
        .explain_missing(mneme_api::federation::client::RemoteExplainMissingRequest {
            scope: scope.clone(),
            revision: None,
            read_hlc: None,
            bundle: bundle.clone(),
            predicate: "linked_label".to_owned(),
            terms: vec![
                mneme_core::Value::string("verified-node"),
                mneme_core::Value::string("candidate-node"),
            ],
            at: None,
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
            explain_limits: mneme_api::federation::protocol::RemoteExplainLimits::standard(),
        })
        .await?;
    assert_eq!(present_explain.status, "present");
    assert_eq!(
        present_explain.present_epistemic.as_deref(),
        Some("proposed")
    );
    assert_eq!(present_explain.present_supports.len(), 1);
    assert_eq!(present_explain.present_supports[0].epistemic, "proposed");

    // 4. ExplainMissing RPC reports structured `missing` reasons for an absent tuple.
    let missing_explain = client
        .explain_missing(mneme_api::federation::client::RemoteExplainMissingRequest {
            scope,
            revision: None,
            read_hlc: None,
            bundle,
            predicate: "linked_label".to_owned(),
            terms: vec![
                mneme_core::Value::string("verified-node"),
                mneme_core::Value::string("nonexistent-node"),
            ],
            at: None,
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
            explain_limits: mneme_api::federation::protocol::RemoteExplainLimits::standard(),
        })
        .await?;
    assert_eq!(missing_explain.status, "missing");
    assert!(!missing_explain.reasons.is_empty());
    assert!(missing_explain.exhaustive);
    Ok(())
}

#[tokio::test]
async fn unsealed_federated_negation_refuses_absence_established_while_valid_calm_seal_admits()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let scope = cedar()?;
    let head_rev = commit_entity(SeedEntity {
        root: temp.path(),
        scope: &scope,
        key: "seed-neg-1",
        id_byte: 0x91,
        kind: "paper",
        label: "only-paper",
    })?;

    // Negated rule: `unlinked_paper(L) :- entity(E, :paper, L), not relation(:cites, E, _)`?
    // Even simpler: negate `entity(E, :paper, L)` for the same E so `ghost_paper(L)` has 0 rows
    // with complete extent -> local `absence_established == true`.
    let mut base_predicates = std::collections::BTreeMap::new();
    base_predicates.insert("entity".to_owned(), 3);
    let mut complete_predicates = std::collections::BTreeSet::new();
    complete_predicates.insert("entity".to_owned());
    let negated_bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "federated-negation".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates,
        complete_predicates,
        rules: vec![mneme_datalog::Rule::new(
            "ghost-paper",
            mneme_datalog::Atom::new("ghost_paper", vec![mneme_datalog::Term::var("Label")]),
            vec![
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "entity",
                    vec![
                        mneme_datalog::Term::var("E"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("paper")),
                        mneme_datalog::Term::var("Label"),
                    ],
                )),
                mneme_datalog::Literal::Negative(mneme_datalog::Atom::new(
                    "entity",
                    vec![
                        mneme_datalog::Term::var("E"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("paper")),
                        mneme_datalog::Term::var("Label"),
                    ],
                )),
            ],
        )],
    });

    let caller_key = deterministic_key(95);
    let rogue_key = deterministic_key(96);
    let caller = caller_key.public();
    let server = mneme_api::federation::VaultFederationServer::spawn(
        mneme_api::federation::ServerConfig::new(
            temp.path(),
            mneme_api::federation::PeerAllowlist::from_peers([caller]),
        ),
    )?;
    let client = server.local_client_for(caller);

    // 1. Unsealed federated Stratum B negation MUST refuse `absence_established = true`.
    let unsealed = client
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope: scope.clone(),
            revision: Some(head_rev),
            read_hlc: None,
            calm_seal: None,
            bundle: negated_bundle.clone(),
            predicate: "ghost_paper".to_owned(),
            constants: Vec::new(),
            limit: 16,
            at: None,
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
        })
        .await?;
    assert_eq!(unsealed.status, "complete");
    assert!(unsealed.rows.is_empty());
    assert!(unsealed.exhaustive);
    assert!(!unsealed.absence_established);
    assert!(unsealed.reason.is_some());

    // 2. Valid signed CalmSeal covering (scope, epoch_generation, head_rev) admits `absence_established = true`.
    let head_state = client.query_head(&scope).await?;
    let mut valid_seal = mneme_api::federation::CalmSeal {
        scope: scope.to_string(),
        epoch_generation: head_state.eligibility_generation,
        frontier_heads: vec![("primary".to_owned(), *head_rev.as_bytes())],
        sigs: Vec::new(),
    };
    valid_seal.sign(&caller_key);

    let sealed = client
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope: scope.clone(),
            revision: Some(head_rev),
            read_hlc: None,
            calm_seal: Some(valid_seal.clone()),
            bundle: negated_bundle.clone(),
            predicate: "ghost_paper".to_owned(),
            constants: Vec::new(),
            limit: 16,
            at: None,
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
        })
        .await?;
    assert_eq!(sealed.status, "complete");
    assert!(sealed.rows.is_empty());
    assert!(sealed.absence_established);

    // 3. Tampered signature, wrong epoch, wrong head, or unauthorized signer all refuse `absence_established`.
    let mut tampered = valid_seal.clone();
    tampered.sigs[0].signature[0] ^= 0xff;
    let tampered_eval = client
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope: scope.clone(),
            revision: Some(head_rev),
            read_hlc: None,
            calm_seal: Some(tampered),
            bundle: negated_bundle.clone(),
            predicate: "ghost_paper".to_owned(),
            constants: Vec::new(),
            limit: 16,
            at: None,
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
        })
        .await?;
    assert!(!tampered_eval.absence_established);

    let mut wrong_epoch = mneme_api::federation::CalmSeal {
        scope: scope.to_string(),
        epoch_generation: head_state.eligibility_generation + 1,
        frontier_heads: vec![("primary".to_owned(), *head_rev.as_bytes())],
        sigs: Vec::new(),
    };
    wrong_epoch.sign(&caller_key);
    let wrong_epoch_eval = client
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope: scope.clone(),
            revision: Some(head_rev),
            read_hlc: None,
            calm_seal: Some(wrong_epoch),
            bundle: negated_bundle.clone(),
            predicate: "ghost_paper".to_owned(),
            constants: Vec::new(),
            limit: 16,
            at: None,
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
        })
        .await?;
    assert!(!wrong_epoch_eval.absence_established);

    let mut unauthorized_seal = mneme_api::federation::CalmSeal {
        scope: scope.to_string(),
        epoch_generation: head_state.eligibility_generation,
        frontier_heads: vec![("primary".to_owned(), *head_rev.as_bytes())],
        sigs: Vec::new(),
    };
    unauthorized_seal.sign(&rogue_key);
    let unauthorized_eval = client
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope,
            revision: Some(head_rev),
            read_hlc: None,
            calm_seal: Some(unauthorized_seal),
            bundle: negated_bundle,
            predicate: "ghost_paper".to_owned(),
            constants: Vec::new(),
            limit: 16,
            at: None,
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
        })
        .await?;
    assert!(!unauthorized_eval.absence_established);

    Ok(())
}

struct SharedAtomicClock(std::sync::Arc<std::sync::atomic::AtomicI64>);

impl mneme_store::Clock for SharedAtomicClock {
    fn now(&self) -> mneme_core::Timestamp {
        mneme_core::Timestamp::from_nanos(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

fn next_skew_ns(rng_state: &mut u64) -> i64 {
    // Deterministic xorshift64 mapped into [-500_000_000, +500_000_000] ns (±500 ms).
    *rng_state ^= *rng_state << 13;
    *rng_state ^= *rng_state >> 7;
    *rng_state ^= *rng_state << 17;
    let span: u64 = 1_000_000_001;
    let offset = (*rng_state % span) as i64;
    offset - 500_000_000
}

fn trial_entity_draft(
    scope: &mneme_core::ScopeId,
    tag: u8,
    trial: u32,
    label: &str,
) -> mneme_store::RecordDraft {
    let mut rec_bytes = [0_u8; 16];
    let mut rev_bytes = [0_u8; 16];
    rec_bytes[0] = tag;
    rec_bytes[1..5].copy_from_slice(&trial.to_be_bytes());
    rev_bytes[0] = tag.wrapping_add(0x40);
    rev_bytes[1..5].copy_from_slice(&trial.to_be_bytes());
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Entity,
        record_id: mneme_core::RecordId::from_bytes(rec_bytes),
        revision_id: mneme_core::RevisionId::from_bytes(rev_bytes),
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol("paper"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string(label),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary([]),
            ),
        ]),
    }
}

#[tokio::test]
async fn three_vault_hlc_causal_cut_zero_torn_cuts_across_1000_trials_and_byzantine_skew_guard()
-> Result<(), Box<dyn std::error::Error>> {
    const TRIALS: u32 = 1_000;
    const BASE_TIME_NS: i64 = 1_700_000_000_000_000_000;
    const STEP_NS: i64 = 2_000_000; // 2 ms true-time advance per trial

    let temp = tempfile::tempdir()?;
    let root_a = temp.path().join("vault-a");
    let root_b = temp.path().join("vault-b");
    let root_c = temp.path().join("vault-c");
    let scope = cedar()?;

    let clock_a_ns = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(BASE_TIME_NS));
    let clock_b_ns = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(BASE_TIME_NS));
    let clock_c_ns = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(BASE_TIME_NS));

    let mut ws_a = mneme_store::Workspace::create(
        &root_a,
        mneme_store::WorkspaceConfig::new(
            Box::new(SharedAtomicClock(std::sync::Arc::clone(&clock_a_ns))),
            Box::new(mneme_store::NoFaults),
        ),
    )?;
    let mut ws_b = mneme_store::Workspace::create(
        &root_b,
        mneme_store::WorkspaceConfig::new(
            Box::new(SharedAtomicClock(std::sync::Arc::clone(&clock_b_ns))),
            Box::new(mneme_store::NoFaults),
        ),
    )?;
    let ws_c = mneme_store::Workspace::create(
        &root_c,
        mneme_store::WorkspaceConfig::new(
            Box::new(SharedAtomicClock(std::sync::Arc::clone(&clock_c_ns))),
            Box::new(mneme_store::NoFaults),
        ),
    )?;

    let caller = deterministic_key(101).public();
    let allow_a = mneme_api::federation::SharedFederationAuthorizer::from_allowlist(
        mneme_api::federation::PeerAllowlist::from_peers([caller]),
    );
    let allow_b = mneme_api::federation::SharedFederationAuthorizer::from_allowlist(
        mneme_api::federation::PeerAllowlist::from_peers([caller]),
    );
    let server_a = mneme_api::federation::VaultFederationServer::spawn_with_authorizer_and_clock(
        mneme_api::federation::ServerConfig::new(
            &root_a,
            mneme_api::federation::PeerAllowlist::empty(),
        ),
        allow_a,
        std::sync::Arc::new(SharedAtomicClock(std::sync::Arc::clone(&clock_a_ns))),
    )?;
    let server_b = mneme_api::federation::VaultFederationServer::spawn_with_authorizer_and_clock(
        mneme_api::federation::ServerConfig::new(
            &root_b,
            mneme_api::federation::PeerAllowlist::empty(),
        ),
        allow_b,
        std::sync::Arc::new(SharedAtomicClock(std::sync::Arc::clone(&clock_b_ns))),
    )?;
    let client_a = server_a
        .local_client_for(caller)
        .with_clock(std::sync::Arc::new(SharedAtomicClock(
            std::sync::Arc::clone(&clock_c_ns),
        )));
    let client_b = server_b
        .local_client_for(caller)
        .with_clock(std::sync::Arc::new(SharedAtomicClock(
            std::sync::Arc::clone(&clock_c_ns),
        )));

    let mut rng_state: u64 = 0x5eed_cafe_1234_5678;
    let mut torn_cuts: u32 = 0;

    // 1. 1,000-trial ±500 ms skew 3-vault causal-cut verification.
    let mut history_a: Vec<(
        mneme_kernel::hlc::HybridTimestamp,
        mneme_core::WorkspaceRevisionId,
    )> = Vec::with_capacity(TRIALS as usize);
    let mut history_b: Vec<(
        mneme_kernel::hlc::HybridTimestamp,
        mneme_core::WorkspaceRevisionId,
    )> = Vec::with_capacity(TRIALS as usize);

    for trial in 0..TRIALS {
        let true_now = BASE_TIME_NS + i64::from(trial) * STEP_NS;
        let skew_a = next_skew_ns(&mut rng_state);
        let skew_b = next_skew_ns(&mut rng_state);
        let skew_c = next_skew_ns(&mut rng_state);
        clock_a_ns.store(true_now + skew_a, std::sync::atomic::Ordering::SeqCst);
        clock_b_ns.store(true_now + skew_b, std::sync::atomic::Ordering::SeqCst);
        clock_c_ns.store(true_now + skew_c, std::sync::atomic::Ordering::SeqCst);

        // Vault A writes cause S_k; Vault B observes HLC(S_k) and writes derived claim A1_k.
        // We exercise real on-disk Workspace commits on 50 spaced trials (including 0..25 and every 40th)
        // and pure kernel HLC transitions on all 1,000 trials to verify 0% torn cuts across 1,000 trials.
        let use_disk_commit = trial < 25 || trial % 40 == 0;
        let (hlc_s, hlc_a1) = if use_disk_commit {
            let base_a = ws_a.current_revision()?;
            let rev_a = ws_a
                .commit(mneme_store::CommitCommand {
                    base: base_a,
                    actor: "vault-a".to_owned(),
                    scope: scope.clone(),
                    idempotency_key: format!("cause-{trial}"),
                    records: vec![trial_entity_draft(
                        &scope,
                        0x0a,
                        trial,
                        &format!("S-{trial}"),
                    )],
                    source_blobs: Vec::new(),
                    publications: Vec::new(),
                    import_candidates: Vec::new(),
                    retention: None,
                })?
                .revision;
            let hlc_s = ws_a
                .revision_hlc(rev_a)?
                .ok_or("missing HLC on Vault A commit")?;

            // Causal message from A -> B advances B's HLC strictly past hlc_s even when B lags by up to 1s.
            ws_b.observe_remote_hlc(hlc_s)?;
            let base_b = ws_b.current_revision()?;
            let rev_b = ws_b
                .commit(mneme_store::CommitCommand {
                    base: base_b,
                    actor: "vault-b".to_owned(),
                    scope: scope.clone(),
                    idempotency_key: format!("effect-{trial}"),
                    records: vec![trial_entity_draft(
                        &scope,
                        0x0b,
                        trial,
                        &format!("A1-{trial}"),
                    )],
                    source_blobs: Vec::new(),
                    publications: Vec::new(),
                    import_candidates: Vec::new(),
                    retention: None,
                })?
                .revision;
            let hlc_a1 = ws_b
                .revision_hlc(rev_b)?
                .ok_or("missing HLC on Vault B commit")?;
            history_a.push((hlc_s, rev_a));
            history_b.push((hlc_a1, rev_b));

            // Vault C mints read_hlc across all boundary regions and resolves both vaults via live federation RPCs.
            let c_tick = ws_c.tick_hlc()?;
            let cut_candidates = [hlc_s, hlc_a1, c_tick];
            for cut in cut_candidates {
                let snap_a = client_a
                    .fetch_pinned_snapshot_at_hlc(
                        &scope,
                        None,
                        Some(cut),
                        mneme_api::federation::FederationLimits::standard(),
                    )
                    .await?;
                let snap_b = client_b
                    .fetch_pinned_snapshot_at_hlc(
                        &scope,
                        None,
                        Some(cut),
                        mneme_api::federation::FederationLimits::standard(),
                    )
                    .await?;
                let saw_s = snap_a.sequence >= (history_a.len() as u64);
                let saw_a1 = snap_b.sequence >= (history_b.len() as u64);
                if saw_a1 && !saw_s {
                    torn_cuts += 1;
                }
            }
            (hlc_s, hlc_a1)
        } else {
            let hlc_s = ws_a.tick_hlc()?;
            ws_b.observe_remote_hlc(hlc_s)?;
            let hlc_a1 = ws_b.tick_hlc()?;
            (hlc_s, hlc_a1)
        };

        assert!(mneme_kernel::hlc::is_before(hlc_s, hlc_a1));

        // Probe random read_hlc from Vault C's skewed clock as well as boundary points.
        let read_hlc_c = ws_c.tick_hlc()?;
        for probe in [hlc_s, hlc_a1, read_hlc_c] {
            let saw_s = mneme_kernel::hlc::is_at_or_before(hlc_s, probe);
            let saw_a1 = mneme_kernel::hlc::is_at_or_before(hlc_a1, probe);
            if saw_a1 && !saw_s {
                torn_cuts += 1;
            }
        }
    }
    assert_eq!(
        torn_cuts, 0,
        "expected 0% torn causal cuts across 1,000 trials"
    );

    // 2. Live EvaluateDatalog with read_hlc returns historical causal cut cleanly.
    let (first_hlc_s, first_rev_a) = history_a[0];
    let eval_at_first = client_a
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope: scope.clone(),
            revision: None,
            read_hlc: Some(first_hlc_s),
            calm_seal: None,
            bundle: entity_bundle("hlc-cut-eval"),
            predicate: "entity_label".to_owned(),
            constants: Vec::new(),
            limit: 128,
            at: None,
            incomplete_extents: std::collections::BTreeSet::new(),
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
        })
        .await?;
    assert_eq!(eval_at_first.served_revision, *first_rev_a.as_bytes());
    assert_eq!(eval_at_first.rows.len(), 1);

    // 3. Byzantine future-clock injection (+60s > 5s default max_skew_ns) fails closed with ClockSkewExceeded.
    let current_a_ns = clock_a_ns.load(std::sync::atomic::Ordering::SeqCst);
    let byzantine_clock = std::sync::Arc::new(mneme_store::FixedClock::new(
        mneme_core::Timestamp::from_nanos(current_a_ns + 60_000_000_000),
    ));
    let byzantine_client = server_a
        .local_client_for(caller)
        .with_clock(byzantine_clock);
    let skew_head_err = byzantine_client.query_head(&scope).await;
    assert!(matches!(
        skew_head_err,
        Err(mneme_api::federation::FederationError::ClockSkewExceeded(_))
    ));
    let skew_snap_err = byzantine_client
        .fetch_pinned_snapshot_at_hlc(
            &scope,
            None,
            Some(mneme_kernel::hlc::HybridTimestamp {
                physical_ns: current_a_ns + 60_000_000_000,
                logical: 0,
            }),
            mneme_api::federation::FederationLimits::standard(),
        )
        .await;
    assert!(matches!(
        skew_snap_err,
        Err(mneme_api::federation::FederationError::ClockSkewExceeded(_))
    ));

    // 4. Crossing an eligibility_generation barrier with an older read_hlc fails closed with Conflict.
    let head_a = ws_a.current_revision()?;
    let next_gen = ws_a.eligibility_generation()? + 1;
    let first_target = mneme_core::RecordId::from_bytes({
        let mut bytes = [0_u8; 16];
        bytes[0] = 0x0a;
        bytes
    });
    ws_a.commit(mneme_store::CommitCommand {
        base: head_a,
        actor: "vault-a".to_owned(),
        scope: scope.clone(),
        idempotency_key: "forget-first-cause".to_owned(),
        records: Vec::new(),
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: Some(mneme_store::RetentionCommit {
            operation_id: "op-forget-cause-0".to_owned(),
            operation_kind: "forget".to_owned(),
            policy_version: "1".to_owned(),
            selectors: Vec::new(),
            suppressions: vec![mneme_store::RetentionSuppression {
                operation_id: "op-forget-cause-0".to_owned(),
                target: first_target,
                revision: None,
                target_kind: "entity".to_owned(),
                mode: mneme_store::SuppressionMode::Forgotten,
                content_digest: None,
                generation: next_gen,
            }],
            locations: Vec::new(),
            retained_metadata: Vec::new(),
        }),
    })?;
    let barrier_err = client_a
        .fetch_pinned_snapshot_at_hlc(
            &scope,
            None,
            Some(first_hlc_s),
            mneme_api::federation::FederationLimits::standard(),
        )
        .await;
    assert!(matches!(
        barrier_err,
        Err(mneme_api::federation::FederationError::Conflict(_))
    ));

    Ok(())
}
