//! `EdgeRepository::upsert_asserts_edge` — the write path that makes it
//! impossible for an ingestion call site to assert a claim without naming the
//! bytes it came from (backlog 7c909c49).

mod helpers;

use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, PaperRepository, PgPool};
use helpers::{make_agent, make_claim};
use uuid::Uuid;

const DIGEST_A: [u8; 32] = [0xa1; 32];
const DIGEST_B: [u8; 32] = [0xb2; 32];

async fn seed(pool: &PgPool, doi: &str, content: &str) -> (Uuid, Uuid) {
    let paper = PaperRepository::get_or_create(pool, doi, Some("T"), None)
        .await
        .unwrap();
    let agent = make_agent(Some("upsert-asserts"));
    let agent_id: Uuid = AgentRepository::create(pool, &agent)
        .await
        .unwrap()
        .id
        .into();
    let claim = make_claim(epigraph_core::AgentId::from_uuid(agent_id), content, 0.5);
    let claim_id: Uuid = ClaimRepository::create(pool, &claim)
        .await
        .unwrap()
        .id
        .into();
    (paper, claim_id)
}

async fn digest_on(pool: &PgPool, edge_id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT properties ->> 'essence_digest' FROM edges WHERE id = $1")
        .bind(edge_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The digest lands on a fresh edge, alongside — not instead of — the planner's
/// own properties, and the call is idempotent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_fresh_asserts_edge_carries_the_digest_and_the_planner_properties(pool: PgPool) {
    let (paper, claim) = seed(&pool, "10.9999/upsert-fresh", "a paragraph").await;

    let (edge, created) = EdgeRepository::upsert_asserts_edge(
        &pool,
        paper,
        claim,
        &DIGEST_A,
        Some(serde_json::json!({ "level": 2, "section": "Intro" })),
    )
    .await
    .unwrap();
    assert!(created);
    assert_eq!(edge.properties["essence_digest"], hex::encode(DIGEST_A));
    assert_eq!(edge.properties["level"], 2);
    assert_eq!(edge.properties["section"], "Intro");

    let (again, created_again) =
        EdgeRepository::upsert_asserts_edge(&pool, paper, claim, &DIGEST_A, None)
            .await
            .unwrap();
    assert!(!created_again, "second call must not insert a second edge");
    assert_eq!(again.id, edge.id);
}

/// The reason this is an upsert and not a create-if-not-exists: on a re-ingest
/// the edge already exists, and a plain create would leave the FIRST-written
/// edge unbound forever.
#[sqlx::test(migrations = "../../migrations")]
async fn an_existing_unbound_edge_is_patched_rather_than_left_unbound(pool: PgPool) {
    let (paper, claim) = seed(&pool, "10.9999/upsert-patch", "a paragraph").await;

    // Stage a pre-essence row the way the corpus already holds them.
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *conn)
        .await
        .unwrap();
    let legacy: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, 'paper', $2, 'claim', 'asserts', '{\"level\": 2}'::jsonb) RETURNING id",
    )
    .bind(paper)
    .bind(claim)
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    sqlx::query("SET session_replication_role = origin")
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(digest_on(&pool, legacy).await, None);

    let (edge, created) = EdgeRepository::upsert_asserts_edge(&pool, paper, claim, &DIGEST_A, None)
        .await
        .unwrap();
    assert!(!created, "the row already existed");
    assert_eq!(edge.id, legacy);
    assert_eq!(
        digest_on(&pool, legacy).await.as_deref(),
        Some(hex::encode(DIGEST_A).as_str()),
        "the legacy row must be bound, not skipped"
    );
    // The merge is additive: the planner's properties survive.
    assert_eq!(edge.properties["level"], 2);
}

/// A later rendition does NOT rewrite an existing binding. The edge names the
/// bytes the claim was FIRST extracted from; a newer rendition of the same
/// document is a different rendition, not a correction. (The verifier reports
/// that state as `stale_binding` — a warning, not a fault.)
#[sqlx::test(migrations = "../../migrations")]
async fn an_existing_digest_is_never_overwritten_by_a_later_rendition(pool: PgPool) {
    let (paper, claim) = seed(&pool, "10.9999/upsert-keep", "a paragraph").await;

    let (first, _) = EdgeRepository::upsert_asserts_edge(&pool, paper, claim, &DIGEST_A, None)
        .await
        .unwrap();
    let (second, created) =
        EdgeRepository::upsert_asserts_edge(&pool, paper, claim, &DIGEST_B, None)
            .await
            .unwrap();

    assert!(!created);
    assert_eq!(second.id, first.id);
    assert_eq!(
        digest_on(&pool, first.id).await.as_deref(),
        Some(hex::encode(DIGEST_A).as_str()),
        "the first binding must survive a re-ingest over different bytes"
    );
}

/// Non-object properties have nowhere to put the digest and must be a clean
/// validation error, not a constraint violation from the trigger.
#[sqlx::test(migrations = "../../migrations")]
async fn non_object_properties_are_rejected_before_the_write(pool: PgPool) {
    let (paper, claim) = seed(&pool, "10.9999/upsert-scalar", "a paragraph").await;

    let err = EdgeRepository::upsert_asserts_edge(
        &pool,
        paper,
        claim,
        &DIGEST_A,
        Some(serde_json::json!("not an object")),
    )
    .await
    .expect_err("scalar properties must be refused");
    assert!(
        matches!(err, epigraph_db::DbError::InvalidData { .. }),
        "expected InvalidData, got {err:?}"
    );

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges WHERE source_id = $1")
        .bind(paper)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "a rejected call must leave no edge behind");
}
