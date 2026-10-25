//! `submit_ds_evidence` naming `hypothesis_assessment` for a PROMOTED
//! hypothesis files the BBA on `research_validity` (operator ruling R-8:
//! evidence submitted against a hypothesis after its promotion goes to the
//! frame its readers read, on every transport that writes hypothesis evidence).
//! The REST twin is `epigraph-api/tests/promoted_hypothesis_evidence_frame.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x7bu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

async fn ensure_frame(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['supported','unsupported']::text[]) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {name} frame: {e}"))
}

async fn hypothesis(pool: &PgPool, status: &str) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let content = format!("r8 mcp {status} hypothesis {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, labels, \
                             properties)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, ARRAY['hypothesis'], $3) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(serde_json::json!({ "hypothesis_status": status }))
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn frames_with_bbas(pool: &PgPool, claim: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT frame_id FROM mass_functions WHERE claim_id = $1 ORDER BY created_at, id",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read BBAs")
}

async fn submit(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim: Uuid,
    frame: Uuid,
) -> serde_json::Value {
    first_text(
        &tools::ds::submit_ds_evidence(
            server,
            viewer,
            serde_json::from_value(serde_json::json!({
                "claim_id": claim.to_string(),
                "frame_id": frame.to_string(),
                "hypothesis_index": 0,
                "masses": {"1": 0.7, "0,1": 0.3},
            }))
            .unwrap(),
            None,
        )
        .await
        .expect("accepted"),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn evidence_named_on_hypothesis_assessment_for_a_promoted_hypothesis_lands_on_research_validity(
    pool: PgPool,
) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let hyp_frame = ensure_frame(&pool, "hypothesis_assessment").await;
    let rv_frame = ensure_frame(&pool, "research_validity").await;
    let promoted = hypothesis(&pool, "promoted").await;
    let active = hypothesis(&pool, "active").await;

    // CALIBRATION: an unpromoted hypothesis's evidence goes where it was named.
    submit(&server, &viewer, active, hyp_frame).await;
    assert_eq!(frames_with_bbas(&pool, active).await, vec![hyp_frame]);

    let out = submit(&server, &viewer, promoted, hyp_frame).await;
    assert_eq!(
        frames_with_bbas(&pool, promoted).await,
        vec![rv_frame],
        "a promoted hypothesis's evidence is filed on research_validity, where its readers \
         look: {out}"
    );
    let warned = out["warnings"].as_array().is_some_and(|w| {
        w.iter().any(|s| {
            s.as_str()
                .is_some_and(|s| s.contains("research_validity") && s.contains("promoted"))
        })
    });
    assert!(warned, "the response says where the evidence went: {out}");
}
