//! Ruling R-22 (backlog fef24216), the member half, on the APPLICATION ROLE:
//! a group member's own framed `get_belief` of a public claim still folds the
//! BBA derived from its group's private source, while a reader outside the
//! group does not.
//!
//! # What was wrong, measured before this file
//!
//! The derivation scope decides which BBAs a reader may see a fold of by
//! whether the reader can READ each BBA's sources. `get_belief` computed on
//! `server.pool`, an UNSTAMPED application session in production, where row
//! security hides every group-private row whatever the viewer says: the
//! member's group edge and source claim were invisible, so the member's framed
//! read dropped the BBA exactly as a stranger's did. The superuser test pools
//! bypass row security and could not show it; this file runs both server
//! pools as `epigraph_app` (as `evolve_step_refusals_app_role.rs` does).
//!
//! The graph is seeded on the harness (superuser) pool; only the reads run on
//! the application role.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_engine::edge_factor::{
    auto_wire_ds_for_edge, ensure_binary_frame, recompute_claim_cached_belief, EdgeFactorOutcome,
};
use epigraph_mcp::types::GetBeliefParams;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::ContentBlock;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x6au8; 32]).expect("signer");
    let embedder = McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(plain, signer, embedder, false).with_scoped_pool(scoped)
}

async fn with_interval(pool: &PgPool, claim: Uuid, bel: f64, pl: f64) {
    sqlx::query("UPDATE claims SET belief = $2, plausibility = $3 WHERE id = $1")
        .bind(claim)
        .bind(bel)
        .bind(pl)
        .execute(pool)
        .await
        .expect("set the source interval");
}

async fn wire(pool: &PgPool, viewer: &Viewer, signer: Uuid, edge: Uuid, from: Uuid, to: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = auto_wire_ds_for_edge(&mut conn, viewer, edge, signer, from, to, "supports")
        .await
        .expect("wire the edge factor");
    assert_eq!(out, EdgeFactorOutcome::Wired, "PREMISE: the edge wires");
}

async fn framed_betp(server: &EpiGraphMcpFull, viewer: &Viewer, claim: Uuid, frame: Uuid) -> f64 {
    let out = tools::ds::get_belief(
        server,
        viewer,
        GetBeliefParams {
            claim_id: claim.to_string(),
            frame_id: Some(frame.to_string()),
            perspective_id: None,
        },
    )
    .await
    .expect("get_belief");
    let text = match out.content.first().cloned().expect("content") {
        ContentBlock::Text(t) => t.text,
        other => panic!("expected text, got {other:?}"),
    };
    let json: serde_json::Value = serde_json::from_str(&text).expect("json");
    json["pignistic_prob"].as_f64().expect("pignistic_prob")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_members_framed_read_folds_its_groups_source_on_the_app_role(pool: PgPool) {
    let public = fixture::public_viewer(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "r22-app-member").await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "r22-app-author").await;
    let member_viewer = Viewer::resolve(&pool, member).await.expect("member viewer");
    let frame = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary_truth");

    let target = fixture::seed_public_claim(&pool, author, "r22 app target").await;
    let public_source = fixture::seed_public_claim(&pool, author, "r22 app public source").await;
    let private_source =
        fixture::seed_group_claim(&pool, member, group, "r22 app private source").await;
    with_interval(&pool, public_source, 0.6, 0.8).await;
    with_interval(&pool, private_source, 0.9, 0.95).await;
    let public_edge = fixture::seed_edge(&pool, public_source, target).await;
    wire(&pool, &public, author, public_edge, public_source, target).await;
    let private_edge = fixture::seed_edge(&pool, private_source, target).await;
    wire(
        &pool,
        &member_viewer,
        member,
        private_edge,
        private_source,
        target,
    )
    .await;
    let mut conn = pool.acquire().await.expect("acquire");
    recompute_claim_cached_belief(&mut conn, &member_viewer, target)
        .await
        .expect("recompute");
    drop(conn);

    let server = app_role_server(&pool).await;
    let stranger = framed_betp(&server, &public, target, frame).await;
    let mine = framed_betp(&server, &member_viewer, target, frame).await;
    let cached: f64 = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(target)
        .fetch_one(&pool)
        .await
        .expect("cache");
    assert!(
        (stranger - cached).abs() < 1e-9,
        "a reader outside the group must see only the admissible fold ({cached}), got {stranger}"
    );
    assert!(
        mine > stranger + 1e-3,
        "the group member's own framed read on the application role must still fold its \
         group's source: member {mine} vs stranger {stranger}"
    );
}
