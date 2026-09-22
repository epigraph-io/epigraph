//! `ClaimRepository::supersede` must null the superseded claim's embedding so
//! it drops out of semantic search.  Mirrors mark_duplicate_nulls_embedding.rs.
//!
//! Regression for the backlog item router-c1cabe28: the invariant
//! `chk_deprecated_no_embedding` (migration 052) requires that any row with
//! `is_current = false` also has `embedding = NULL`. The supersede path must
//! satisfy this in the same UPDATE statement — splitting the two assignments
//! would violate the per-statement CHECK between statements.
//!
//! This test is the lock: if someone removes `embedding = NULL` from the
//! supersede UPDATE in `ClaimRepository::supersede`, the test will fail with a
//! `chk_deprecated_no_embedding` constraint violation before any assertion is
//! reached, making the regression immediately visible.

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn supersede_nulls_embedding_on_old_claim(pool: PgPool) {
    // Seed one agent row.
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind([0u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();

    // Seed a CURRENT, embedded claim directly via SQL.  The stub vectors are
    // sized to each column's declared dim (1536 and 3072; both columns have
    // fixed-dim constraints).  This is the claim that will be superseded.
    let old_id = Uuid::new_v4();
    let stub_vec = {
        let mut v = vec!["0.0"; 1536];
        v[0] = "0.1";
        format!("[{}]", v.join(","))
    };
    let stub_vec = stub_vec.as_str();
    let stub_vec_3072 = {
        let mut v = vec!["0.0"; 3072];
        v[0] = "0.1";
        format!("[{}]", v.join(","))
    };
    let stub_vec_3072 = stub_vec_3072.as_str();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, embedding, embedding_3072) \
         VALUES ($1, $2, $3, $4, 0.7, true, $5::vector, $6::vector)",
    )
    .bind(old_id)
    .bind("supersede-embedding-test-old")
    .bind(blake3::hash("supersede-embedding-test-old".as_bytes()).as_bytes().as_slice())
    .bind(agent_id)
    .bind(stub_vec)
    .bind(stub_vec_3072)
    .execute(&pool)
    .await
    .unwrap();

    // Confirm the pre-condition: the old claim has non-NULL embeddings.
    let has_embedding_before: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(old_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        has_embedding_before,
        "pre-condition: old claim {old_id} must have an embedding before supersede"
    );
    let has_embedding_3072_before: bool =
        sqlx::query_scalar("SELECT embedding_3072 IS NOT NULL FROM claims WHERE id = $1")
            .bind(old_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        has_embedding_3072_before,
        "pre-condition: old claim {old_id} must have an embedding_3072 before supersede"
    );

    // Supersede the old claim.
    let (new_id, returned_old) = ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(old_id),
        "supersede-embedding-test-new",
        TruthValue::clamped(0.85),
        "regression test for chk_deprecated_no_embedding",
    )
    .await
    .unwrap();

    assert_eq!(
        returned_old, old_id,
        "supersede must return the old claim id"
    );

    // Post-condition 1: old claim's embedding is NULL (the invariant).
    let old_embedding_null: bool =
        sqlx::query_scalar("SELECT embedding IS NULL FROM claims WHERE id = $1")
            .bind(old_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        old_embedding_null,
        "superseded claim {old_id} embedding must be NULL after supersede \
         (chk_deprecated_no_embedding invariant)"
    );
    let old_embedding_3072_null: bool =
        sqlx::query_scalar("SELECT embedding_3072 IS NULL FROM claims WHERE id = $1")
            .bind(old_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        old_embedding_3072_null,
        "superseded claim {old_id} embedding_3072 must be NULL after supersede"
    );

    // Post-condition 2: old claim is not current.
    let old_is_current: bool =
        sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
            .bind(old_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !old_is_current,
        "superseded claim {old_id} must have is_current = false"
    );

    // Post-condition 3: new claim exists and is current (with no embedding yet —
    // callers embed post-commit; the INSERT leaves it NULL intentionally).
    let new_is_current: bool =
        sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
            .bind(new_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        new_is_current,
        "replacement claim {new_id} must be is_current = true"
    );

    // Post-condition 4: new claim's supersedes pointer links back to the old claim.
    let new_supersedes: Option<Uuid> =
        sqlx::query_scalar("SELECT supersedes FROM claims WHERE id = $1")
            .bind(new_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        new_supersedes,
        Some(old_id),
        "replacement claim {new_id} must have supersedes = {old_id}"
    );
}
