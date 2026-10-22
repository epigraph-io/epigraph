//! Where `ingest_workflow` stores the embedding of a GROUP-PRIVATE claim it
//! created, on the application role.
//!
//! A declared-tenancy ingest (`tenancy: {"visibility": "group", ...}`) creates
//! claims owned by group G, authored by the workflow-ingest system agent. The
//! embedder's own store path (`McpEmbedder::store_vector`) resolves a claim's
//! author by reading the claim as PUBLIC, so it cannot even find the author of
//! a G-private claim and stores nothing. `store_ingest_embedding` therefore
//! takes the author the ingest already knows and stores on a transaction
//! stamped from it.
//!
//! `McpEmbedder` has no mock provider, so the vector itself is a fixed literal
//! here: what is pinned is the STORE half, which is where the two paths differ.
//! Calibrated both ways: the embedder's path stores nothing on the G-private
//! claim and does store on a public one, so the difference is the claim's
//! tenancy and not a broken fixture.
//!
//! The database is unarmed and carries no extra permissive policy; every pool
//! the server holds is `epigraph_app`.

mod viewer_fixture;

use epigraph_db::{GroupRepository, ScopedPool, SessionGucMode};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn mcp_server(pool: &PgPool, seed: u8) -> epigraph_mcp::server::EpiGraphMcpFull {
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    epigraph_mcp::server::EpiGraphMcpFull::new(plain, signer, embedder, false)
        .with_scoped_pool(scoped)
}

fn extraction(name: &str) -> serde_json::Value {
    json!({
        "source": {"canonical_name": name, "goal": format!("workflow-plan goal for {name}"),
                   "generation": 0, "metadata": {}},
        "thesis_derivation": "TopDown",
        "phases": [{"title": "Body", "summary": format!("{name} phase"),
                    "steps": [{"compound": format!("{name} step"), "rationale": "r",
                               "operations": [], "generality": [], "confidence": 0.8}]}],
        "relationships": []
    })
}

/// Ingest over stdio and return the created step claim's id.
async fn ingest_step(
    pool: &PgPool,
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    name: &str,
    group: Option<Uuid>,
) -> Uuid {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("the stdio viewer");
    let mut params = json!({ "extraction": extraction(name) });
    if let Some(g) = group {
        params["tenancy"] = json!({"visibility": "group", "owner_group_id": g});
    }
    let params: epigraph_mcp::types::IngestWorkflowParams =
        serde_json::from_value(params).expect("params");
    let out = epigraph_mcp::tools::workflow_ingest::ingest_workflow(server, &viewer, params, None)
        .await
        .expect("the ingest");
    assert_ne!(out.is_error, Some(true), "{out:?}");
    let (id, visibility): (Uuid, String) =
        sqlx::query_as("SELECT id, visibility::text FROM claims WHERE content = $1")
            .bind(format!("{name} step"))
            .fetch_one(pool)
            .await
            .expect("the step claim");
    assert_eq!(
        visibility,
        if group.is_some() { "group" } else { "public" },
        "the fixture's tenancy"
    );
    id
}

async fn embedded(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("embedding state")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_group_private_ingest_claim_is_embedded_through_its_known_author(pool: PgPool) {
    let server = mcp_server(&pool, 0x4E).await;
    let caller = {
        epigraph_mcp::tools::viewer::request_viewer(&server, None)
            .await
            .expect("the stdio viewer");
        let key = epigraph_crypto::AgentSigner::from_bytes(&[0x4E; 32])
            .expect("signer")
            .public_key();
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM agents WHERE public_key = $1")
            .bind(key.as_slice())
            .fetch_one(&pool)
            .await
            .expect("the stdio agent")
    };
    // A public ingest first: it resolves (and provisions) the system agent.
    let public_claim = ingest_step(&pool, &server, "acme-embed-public", None).await;
    let system = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    let (admin, _) = viewer_fixture::seed_agent_with_group(&pool, "workflow-plan-admin").await;
    let g = Uuid::new_v4();
    GroupRepository::create_with_admin(
        &pool,
        g,
        Some("workflow-plan team group"),
        &format!("did:epigraph:test:workflow-plan:{g}"),
        blake3::hash(g.as_bytes()).as_bytes(),
        None,
        admin,
    )
    .await
    .expect("the team group");
    for agent in [system, caller] {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(g)
        .bind(agent)
        .execute(&pool)
        .await
        .expect("writer row");
    }
    let private_claim = ingest_step(&pool, &server, "acme-embed-private", Some(g)).await;
    // No embedding provider is configured, so the ingest stored no vector.
    assert!(!embedded(&pool, private_claim).await);
    assert!(!embedded(&pool, public_claim).await);

    let pgvec = epigraph_mcp::embed::format_pgvector(&vec![0.01_f32; 1536]);

    // The embedder's own path (`author: None`) cannot store on the
    // group-private claim...
    assert!(
        !epigraph_mcp::tools::workflow_ingest::store_ingest_embedding(
            &server,
            None,
            private_claim,
            &pgvec
        )
        .await,
        "the public-reader path must not store on a group-private claim"
    );
    assert!(!embedded(&pool, private_claim).await);
    // ...and does store on a public one (calibration).
    assert!(
        epigraph_mcp::tools::workflow_ingest::store_ingest_embedding(
            &server,
            None,
            public_claim,
            &pgvec
        )
        .await
    );
    assert!(embedded(&pool, public_claim).await);

    // Through the known author, the group-private claim is embedded.
    assert!(
        epigraph_mcp::tools::workflow_ingest::store_ingest_embedding(
            &server,
            Some(system),
            private_claim,
            &pgvec
        )
        .await,
        "the author-stamped store must succeed"
    );
    assert!(embedded(&pool, private_claim).await);
}
