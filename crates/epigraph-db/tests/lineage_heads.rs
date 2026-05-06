//! Integration tests for `ClaimRepository::latest_in_lineage`.
//!
//! Verifies the head-walking semantics defined in spec §3.1
//! (`docs/superpowers/specs/2026-05-05-step-level-versioning-design.md`):
//! a claim is a head of its `step_lineage_id` if and only if no other
//! claim has a `supersedes` edge pointing AT it. `revises` edges do
//! not remove head status — they mark concurrent branches.

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_versioned_claim(pool: &PgPool, agent: Uuid, lineage: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, step_lineage_id) \
         VALUES ($1, $2, $3, $4, 0.5, jsonb_build_object('level', 2, 'step_lineage_id', $5::text), $5)",
    )
    .bind(id)
    .bind(format!("c-{id}"))
    .bind(hash)
    .bind(agent)
    .bind(lineage)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn seed_edge(pool: &PgPool, src: Uuid, tgt: Uuid, rel: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3)",
    )
    .bind(src)
    .bind(tgt)
    .bind(rel)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn linear_supersedes_chain_has_one_head(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let lineage = Uuid::new_v4();

    // v1 -> v2 -> v3 (each supersedes the previous)
    let v1 = seed_versioned_claim(&pool, agent, lineage).await;
    let v2 = seed_versioned_claim(&pool, agent, lineage).await;
    let v3 = seed_versioned_claim(&pool, agent, lineage).await;
    seed_edge(&pool, v2, v1, "supersedes").await;
    seed_edge(&pool, v3, v2, "supersedes").await;

    let heads = ClaimRepository::latest_in_lineage(&pool, lineage)
        .await
        .unwrap();
    let head_ids: Vec<Uuid> = heads.iter().map(|h| h.id).collect();
    assert_eq!(heads.len(), 1, "single head expected; got {head_ids:?}");
    assert_eq!(
        head_ids[0], v3,
        "v3 must be the head (v2 superseded v1, v3 superseded v2)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn revises_branches_produce_multiple_heads(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let lineage = Uuid::new_v4();

    // v1 revised by both A_v2 and B_v2 (no supersedes edges)
    let v1 = seed_versioned_claim(&pool, agent, lineage).await;
    let a_v2 = seed_versioned_claim(&pool, agent, lineage).await;
    let b_v2 = seed_versioned_claim(&pool, agent, lineage).await;
    seed_edge(&pool, a_v2, v1, "revises").await;
    seed_edge(&pool, b_v2, v1, "revises").await;

    let heads = ClaimRepository::latest_in_lineage(&pool, lineage)
        .await
        .unwrap();
    let head_ids: std::collections::HashSet<Uuid> = heads.iter().map(|h| h.id).collect();

    // Per spec §3.1, head = not pointed-at by any supersedes edge.
    // v1 has incoming `revises` edges (from a_v2 and b_v2) but NO incoming `supersedes`.
    // a_v2 and b_v2 have no incoming edges of either kind.
    // So all three are heads.
    assert_eq!(
        heads.len(),
        3,
        "v1, a_v2, b_v2 must all be heads (revises does not remove head status); got {head_ids:?}"
    );
    assert!(head_ids.contains(&v1));
    assert!(head_ids.contains(&a_v2));
    assert!(head_ids.contains(&b_v2));
}

#[sqlx::test(migrations = "../../migrations")]
async fn empty_when_lineage_has_no_claims(pool: PgPool) {
    let heads = ClaimRepository::latest_in_lineage(&pool, Uuid::new_v4())
        .await
        .unwrap();
    assert!(heads.is_empty());
}
