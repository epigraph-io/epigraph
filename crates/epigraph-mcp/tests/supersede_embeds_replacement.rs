//! A supersession's replacement claim is embedded (backlog 7628ab2c).
//!
//! `supersede_claim` and `evolve_step` each INSERT a current claim with new
//! text. The act copies no vector on purpose (the content differs), and
//! neither tool used to embed afterwards, so the claim that replaced a
//! recallable one had `embedding IS NULL` and was invisible to `recall` until
//! a backfill ran. Both now embed post-commit, best-effort, like every other
//! write path in CLAUDE.md's "Embedding policy".
//!
//! Each test builds its server with a deterministic generator
//! (`McpEmbedder::with_generator`): a keyless test embedder refuses every
//! `generate`, which would make "embedded" and "skipped for want of a key"
//! indistinguishable.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::evolve_step::{evolve_step, EvolveStepParams};
use epigraph_mcp::tools::supersede::supersede_claim;
use epigraph_mcp::types::SupersedeClaimParams;
use sqlx::PgPool;
use uuid::Uuid;

fn body(r: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = &r
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text;
    serde_json::from_str(text).expect("json body")
}

async fn has_embedding(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("the claim row")
}

fn generator() -> epigraph_mcp::embed::EmbeddingGenerator {
    std::sync::Arc::new(|_text: &str| Ok(vec![0.01_f32; 1536]))
}

/// `supersede_claim` on the APPLICATION role (row security enforced), by the
/// claim's own writer: the replacement comes back `embedded: true` and carries
/// a vector. The store goes through the replacement's author, which is why the
/// fixture is the app role and not the BYPASSRLS superuser `#[sqlx::test]`
/// connects as, where any store path would succeed.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_embeds_the_replacement(pool: PgPool) {
    use epigraph_db::{ScopedPool, SessionGucMode};
    let url = fixture::database_url_for(&pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool")
            .with_maintenance_pool(fixture::downgraded_pool(&pool, "epigraph_maintenance").await);
    let plain = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(generator());
    let server = epigraph_mcp::EpiGraphMcpFull::new(
        plain,
        epigraph_crypto::AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer"),
        embedder,
        false,
    )
    .with_scoped_pool(scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("viewer");
    let group = *viewer.writable_groups().first().expect("a writable group");
    let auth = epigraph_auth::AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: epigraph_auth::ClientType::Service,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    };

    let old = Uuid::new_v4();
    let hash: Vec<u8> = old.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, visibility, owner_group_id, embedding) \
         VALUES ($1, 'the claim as first stated', $2, 0.5, $3, true, 'public', $4, $5::vector)",
    )
    .bind(old)
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .bind(format!("[{}]", vec!["0.02"; 1536].join(",")))
    .execute(&pool)
    .await
    .expect("an embedded claim the server agent wrote");

    let result = supersede_claim(
        &server,
        &viewer,
        SupersedeClaimParams {
            claim_id: old.to_string(),
            content: "the claim, restated".into(),
            truth_value: 0.6,
            reason: "wording".into(),
        },
        Some(&auth),
    )
    .await
    .expect("the writer supersedes its own claim");
    let b = body(&result);
    let new: Uuid = b["new_claim_id"]
        .as_str()
        .expect("new_claim_id")
        .parse()
        .expect("uuid");

    assert!(
        !has_embedding(&pool, old).await,
        "the retired claim keeps no vector"
    );
    assert!(
        has_embedding(&pool, new).await,
        "the replacement {new} is current and must be embedded post-commit; NULL \
         here is the live_missing row backlog 7628ab2c describes ({b})"
    );
    assert_eq!(
        b["embedded"],
        serde_json::json!(true),
        "the response must report the embed it performed: {b}"
    );
}

/// `evolve_step`, both edge types: the new step is embedded. `revises` leaves
/// the parent current (and embedded or not, as it was); `supersedes` retires
/// it. Either way the NEW claim is current and must carry a vector.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_embeds_the_new_step(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let scoped = epigraph_db::ScopedPool::connect_lazy_for_tests(
        (*pool.connect_options()).clone(),
        epigraph_db::SessionGucMode::Session,
    );
    let embedder = epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(generator());
    let server = epigraph_mcp::EpiGraphMcpFull::new(
        pool.clone(),
        epigraph_crypto::AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer"),
        embedder,
        false,
    )
    .with_scoped_pool(scoped);

    // The parent step lives in a group the CALLER writes, as it must in
    // production (the step INSERT inherits the parent's tenancy and
    // `claims_tenancy` refuses a group the caller cannot write). The embedding
    // store splices the author's writable set, so a parent in an unrelated
    // group would store nothing here for a reason no deployment has.
    let agent = server.server_agent_id().await.expect("server agent");
    let group = *epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("the server agent's viewer")
        .writable_groups()
        .first()
        .expect("a writable group");

    for edge_type in ["revises", "supersedes"] {
        let lineage = Uuid::new_v4();
        let parent = Uuid::new_v4();
        let hash: Vec<u8> = parent.as_bytes().iter().copied().cycle().take(32).collect();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, \
                                 step_lineage_id, visibility, owner_group_id) \
             VALUES ($1, $2, $3, $4, 0.5, \
                     jsonb_build_object('level', 2, 'step_lineage_id', $5::text), $5, \
                     'public', $6)",
        )
        .bind(parent)
        .bind(format!("step v1 ({edge_type})"))
        .bind(&hash)
        .bind(agent)
        .bind(lineage)
        .bind(group)
        .execute(&pool)
        .await
        .expect("parent step");

        let result = evolve_step(
            &server,
            &viewer,
            EvolveStepParams {
                canonical_name: None,
                step_index: None,
                step_lineage_id: lineage.to_string(),
                parent_id: parent.to_string(),
                content: format!("step v2 ({edge_type})"),
                edge_type: edge_type.to_string(),
                rationale: Some("clarified wording".to_string()),
                level: Some(2),
            },
            None,
        )
        .await
        .expect("evolve_step");
        let b = body(&result);
        let new: Uuid = b["claim_id"]
            .as_str()
            .expect("claim_id")
            .parse()
            .expect("uuid");
        assert!(
            has_embedding(&pool, new).await,
            "the `{edge_type}` step {new} is a current claim and must be embedded \
             post-commit (backlog 7628ab2c): {b}"
        );
    }
}
