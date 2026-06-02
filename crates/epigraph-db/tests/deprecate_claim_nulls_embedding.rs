//! `ClaimRepository::deprecate_claim` is the third `is_current = false`
//! cleanup path (after supersede + mark_duplicate). Per CLAUDE.md
//! "Embedding policy" it MUST null the deprecated claim's embedding so the
//! row leaves semantic recall and does not inflate the `stale_present`
//! audit count. Mirrors mark_duplicate_nulls_embedding.rs.

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn deprecate_claim_nulls_embedding_and_preserves_control(pool: PgPool) {
    // Seed one agent row.
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind([0u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();

    // Seed two CURRENT, embedded claims directly via SQL. Both get a stub
    // vector sized to the column's declared dim (1536). `target` will be
    // deprecated; `control` must be left completely untouched.
    let target_id = Uuid::new_v4();
    let control_id = Uuid::new_v4();
    let stub_vec = {
        let mut v = vec!["0.0"; 1536];
        v[0] = "0.1";
        format!("[{}]", v.join(","))
    };
    let stub_vec = stub_vec.as_str();
    for (id, content) in [(target_id, "deprecate-me"), (control_id, "leave-me")] {
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, embedding) \
             VALUES ($1, $2, $3, $4, 0.9, true, $5::vector)",
        )
        .bind(id)
        .bind(content)
        .bind(blake3::hash(content.as_bytes()).as_bytes().as_slice())
        .bind(agent_id)
        .bind(stub_vec)
        .execute(&pool)
        .await
        .unwrap();
    }

    let affected = ClaimRepository::deprecate_claim(&pool, ClaimId::from_uuid(target_id))
        .await
        .unwrap();
    assert_eq!(affected, 1, "deprecate_claim should touch exactly the target row");

    // Full post-condition on the target: truth 0.05, not current, embedding NULL.
    let (truth, is_current, has_embedding): (f64, bool, bool) = sqlx::query_as(
        "SELECT truth_value, is_current, embedding IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(target_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!((truth - 0.05).abs() < 1e-9, "target truth_value should be 0.05, got {truth}");
    assert!(!is_current, "target is_current should be false");
    assert!(!has_embedding, "target embedding should be NULL after deprecate_claim");

    // Control row must be entirely unaffected: still current, still embedded,
    // truth unchanged. Without this assertion the test would pass even if
    // deprecate_claim nulled every embedding in the table.
    let (c_truth, c_current, c_has_embedding): (f64, bool, bool) = sqlx::query_as(
        "SELECT truth_value, is_current, embedding IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(control_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!((c_truth - 0.9).abs() < 1e-9, "control truth_value must be unchanged");
    assert!(c_current, "control is_current must stay true");
    assert!(c_has_embedding, "control embedding must be preserved");

    // Idempotency: a second call (the post-deploy remediation path for claims
    // the pre-fix binary deprecated) must remain a safe no-op flip.
    let affected2 = ClaimRepository::deprecate_claim(&pool, ClaimId::from_uuid(target_id))
        .await
        .unwrap();
    assert_eq!(affected2, 1, "re-deprecating an already-deprecated claim is a safe no-op flip");
    let still_null: bool =
        sqlx::query_scalar("SELECT embedding IS NULL FROM claims WHERE id = $1")
            .bind(target_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(still_null, "embedding stays NULL after a second deprecate_claim");
}
