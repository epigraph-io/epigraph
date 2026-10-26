//! `mass_functions.evidence_type` on the repo-layer write paths (backlog
//! bc06ec6f).
//!
//! * `MassFunctionRepository::store` had no `evidence_type` parameter and
//!   always wrote NULL, so no `store()` caller could record a type it knew.
//! * Hypothesis promotion copied a BBA into `research_validity` with a raw
//!   INSERT that dropped `evidence_type`, `source_strength`, `locality_tag` and
//!   `evidence_id`; `copy_to_frame` carries them.

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

#[sqlx::test(migrations = "../../migrations")]
async fn copy_to_frame_carries_every_provenance_column(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let claim = seed_claim(&pool, agent).await;
    let (from, to) = (seed_frame(&pool).await, seed_frame(&pool).await);
    let evidence: Uuid = sqlx::query_scalar(
        "INSERT INTO evidence (content_hash, evidence_type, claim_id) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'reference', $1) RETURNING id",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("seed evidence");

    MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        from,
        Some(agent),
        None,
        &json!({"0": 0.7, "0,1": 0.3}),
        Some(0.1),
        Some("auto_wire"),
        Some(0.85),
        Some("logical"),
        "intra_self_cite",
        Some(evidence),
    )
    .await
    .expect("store source BBA");
    let source = rows(&pool, claim, from).await.pop().expect("source BBA");

    MassFunctionRepository::copy_to_frame(&pool, &source, to)
        .await
        .expect("copy_to_frame");

    let copied = rows(&pool, claim, to).await;
    assert_eq!(copied.len(), 1, "one copied BBA");
    let c = &copied[0];
    assert_eq!(c.frame_id, to);
    assert_eq!(c.source_agent_id, Some(agent));
    assert_eq!(c.masses, source.masses);
    assert_eq!(c.conflict_k, Some(0.1));
    assert_eq!(c.combination_method.as_deref(), Some("auto_wire"));
    assert_eq!(c.evidence_type.as_deref(), Some("logical"));
    assert_eq!(c.source_strength, Some(0.85));
    assert_eq!(c.locality_tag, "intra_self_cite");
    assert_eq!(c.evidence_id, Some(evidence));

    // Re-promoting re-states the same row (ON CONFLICT), it does not add one.
    MassFunctionRepository::copy_to_frame(&pool, &source, to)
        .await
        .expect("copy_to_frame again");
    assert_eq!(rows(&pool, claim, to).await.len(), 1);
}
