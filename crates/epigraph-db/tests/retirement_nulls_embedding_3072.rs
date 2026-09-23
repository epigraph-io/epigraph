//! Every path that retires a claim (`is_current = false`) nulls BOTH vector
//! columns, `embedding` (1536-d) and `embedding_3072`, in the same statement.
//!
//! # Why the second column needs its own lock
//!
//! Migration 052 constrained `embedding` only (`chk_deprecated_no_embedding`)
//! and excused `embedding_3072` as "always NULL in practice". That stopped
//! being true once `epigraph-cli reembed` became the documented way to fill the
//! column: it wrote 3072-d vectors onto retired claims, and none of the five
//! retirement UPDATEs in `ClaimRepository` nulled that column. Recall and theme
//! k-means at `centroid_dim = 3072` read `embedding_3072 IS NOT NULL` as
//! "live", so superseded, duplicate, deprecated and consolidated claims came
//! back. The 2026-05-18 embedding-pipeline plan had asked for a daily sweeper
//! as the safety net; this file and migration 101's CHECK are what replaced it
//! (deferred-commitment screen key `stale-embedding-sweeper`).
//!
//! Each retirement test seeds a claim carrying BOTH vectors plus an untouched
//! current control that also carries both, so a path that nulled every vector
//! in the table cannot pass.

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::{ClaimRepository, ConsolidateMode};
use sqlx::PgPool;
use uuid::Uuid;

fn vector_literal(dim: usize) -> String {
    let mut v = vec!["0"; dim];
    v[0] = "0.1";
    format!("[{}]", v.join(","))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'retire-3072-test', 'system', \
                 ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A CURRENT claim carrying a vector in both columns.
async fn seed_embedded_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             embedding, embedding_3072) \
         VALUES ($1, sha256($1::bytea), 0.7, $2, true, $3::vector, $4::vector) \
         RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(vector_literal(1536))
    .bind(vector_literal(3072))
    .fetch_one(pool)
    .await
    .expect("seed embedded claim")
}

/// `(is_current, embedding IS NOT NULL, embedding_3072 IS NOT NULL)`.
async fn state(pool: &PgPool, id: Uuid) -> (bool, bool, bool) {
    sqlx::query_as(
        "SELECT is_current, embedding IS NOT NULL, embedding_3072 IS NOT NULL \
           FROM claims WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read claim vector state")
}

async fn assert_retired_without_vectors(pool: &PgPool, id: Uuid, path: &str) {
    let (is_current, has_1536, has_3072) = state(pool, id).await;
    assert!(!is_current, "{path}: claim {id} must be retired");
    assert!(
        !has_1536,
        "{path}: retired claim {id} must not keep `embedding`"
    );
    assert!(
        !has_3072,
        "{path}: retired claim {id} must not keep `embedding_3072` — recall and \
         theme k-means at centroid_dim=3072 read a non-NULL vector as live"
    );
}

async fn assert_control_untouched(pool: &PgPool, id: Uuid, path: &str) {
    assert_eq!(
        state(pool, id).await,
        (true, true, true),
        "{path}: the current control claim {id} must keep both vectors"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn supersede_nulls_embedding_3072_on_the_old_claim(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let old = seed_embedded_claim(&pool, agent, "retire-3072 supersede old").await;
    let control = seed_embedded_claim(&pool, agent, "retire-3072 supersede control").await;

    ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(old),
        "retire-3072 supersede new",
        TruthValue::clamped(0.8),
        "retirement must null both vector columns",
    )
    .await
    .expect("supersede");

    assert_retired_without_vectors(&pool, old, "supersede").await;
    assert_control_untouched(&pool, control, "supersede").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_nulls_embedding_3072_on_the_parent(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_embedded_claim(&pool, agent, "retire-3072 evolve parent").await;
    let control = seed_embedded_claim(&pool, agent, "retire-3072 evolve control").await;

    ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(parent),
        "retire-3072 evolve child",
        "supersedes",
        Some("retirement must null both vector columns"),
        2,
        agent,
    )
    .await
    .expect("evolve_step supersedes");

    assert_retired_without_vectors(&pool, parent, "evolve_step(supersedes)").await;
    assert_control_untouched(&pool, control, "evolve_step(supersedes)").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_nulls_embedding_3072_on_the_duplicate(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_embedded_claim(&pool, agent, "retire-3072 canonical").await;
    let dup = seed_embedded_claim(&pool, agent, "retire-3072 duplicate").await;

    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("mark_duplicate");

    assert_retired_without_vectors(&pool, dup, "mark_duplicate").await;
    // The canonical is the natural control here: it is the claim the
    // duplicate forwards to, and it must stay live and embedded.
    assert_control_untouched(&pool, canonical, "mark_duplicate").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn deprecate_claim_nulls_embedding_3072(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let target = seed_embedded_claim(&pool, agent, "retire-3072 deprecate me").await;
    let control = seed_embedded_claim(&pool, agent, "retire-3072 deprecate control").await;

    let affected = ClaimRepository::deprecate_claim(&pool, ClaimId::from_uuid(target))
        .await
        .expect("deprecate_claim");
    assert_eq!(
        affected, 1,
        "deprecate_claim touches exactly the target row"
    );

    assert_retired_without_vectors(&pool, target, "deprecate_claim").await;
    assert_control_untouched(&pool, control, "deprecate_claim").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_nulls_embedding_3072_on_every_source(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s1 = seed_embedded_claim(&pool, agent, "retire-3072 source one").await;
    let s2 = seed_embedded_claim(&pool, agent, "retire-3072 source two").await;
    let control = seed_embedded_claim(&pool, agent, "retire-3072 consolidate control").await;

    let res = ClaimRepository::consolidate(
        &pool,
        &[s1, s2],
        "retire-3072 merged restatement",
        0.8,
        ConsolidateMode::Merge,
        "retirement must null both vector columns",
        agent,
    )
    .await
    .expect("consolidate");
    assert_eq!(res.superseded.len(), 2);

    assert_retired_without_vectors(&pool, s1, "consolidate").await;
    assert_retired_without_vectors(&pool, s2, "consolidate").await;
    assert_control_untouched(&pool, control, "consolidate").await;
}
