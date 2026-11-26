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
            bundle: entity_bundle("remote-eval"),
            predicate: "entity_label".to_owned(),
            constants: Vec::new(),
            limit: 16,
            stale_policy: mneme_api::federation::StalePolicy::Refuse,
            limits: mneme_api::federation::FederationLimits::standard(),
        })
        .await?;
    assert_eq!(eval_rev1.status, "complete");
    assert_eq!(eval_rev1.served_revision, *pinned_rev.as_bytes());
    assert_eq!(eval_rev1.rows.len(), 1);
    assert!(eval_rev1.exhaustive);

    let eval_head = client
        .evaluate_datalog(mneme_api::federation::RemoteDatalogRequest {
            scope: scope.clone(),
            revision: None,
            bundle: entity_bundle("remote-eval"),
            predicate: "entity_label".to_owned(),
            constants: Vec::new(),
            limit: 16,
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
            bundle: entity_bundle("budgeted"),
            predicate: "entity_label".to_owned(),
            constants: Vec::new(),
            limit: 1,
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
            bundle: entity_bundle("budgeted-work"),
            predicate: "entity_label".to_owned(),
            constants: Vec::new(),
            limit: 10,
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
