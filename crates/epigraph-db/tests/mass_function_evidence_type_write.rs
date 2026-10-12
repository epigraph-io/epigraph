//! `mass_functions.evidence_type` on the repo-layer write paths (backlog
//! bc06ec6f).
//!
//! * `MassFunctionRepository::store` had no `evidence_type` parameter and
//!   always wrote NULL, so no `store()` caller could record a type it knew.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{MassFunctionRepository, MassFunctionRow};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, is_current) \
         VALUES ($1, sha256($1::bytea), $2, 0.5, true) RETURNING id",
    )
    .bind(format!("bc06ec6f repo typing {}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn seed_frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, '{\"TRUE\",\"FALSE\"}') RETURNING id",
    )
    .bind(format!("bc06ec6f-frame-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

async fn rows(pool: &PgPool, claim: Uuid, frame: Uuid) -> Vec<MassFunctionRow> {
    let viewer = fixture::public_viewer(pool).await;
    MassFunctionRepository::get_for_claim_frame(pool, &viewer, claim, frame)
        .await
        .expect("get_for_claim_frame")
}

#[sqlx::test(migrations = "../../migrations")]
async fn store_persists_the_evidence_type_it_is_given(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let claim = seed_claim(&pool, agent).await;
    let frame = seed_frame(&pool).await;

    MassFunctionRepository::store(
        &pool,
        claim,
        frame,
        Some(agent),
        &json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("interview_extraction"),
        Some("testimonial"),
        "unknown",
        None,
    )
    .await
    .expect("store");

    let stored = rows(&pool, claim, frame).await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].evidence_type.as_deref(), Some("testimonial"));
}
