//! mark_duplicate must null the duplicate's embedding so superseded claims
//! drop out of semantic search. Mirrors supersede() at claim.rs:1401.

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_nulls_embedding(pool: PgPool) {
    // Seed one agent row.
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind([0u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();

    // Seed two claim rows directly via SQL — bypasses any cross-crate helper
    // churn. Both get a stub embedding sized to the column's declared dim
    // (1536; the column has a fixed-dim constraint).
    let canonical_id = Uuid::new_v4();
    let dup_id = Uuid::new_v4();
    let stub_vec = {
        let mut v = vec!["0.0"; 1536];
        v[0] = "0.1";
        format!("[{}]", v.join(","))
    };
    let stub_vec = stub_vec.as_str();
    for (id, content) in [(canonical_id, "canonical"), (dup_id, "duplicate")] {
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, embedding) \
             VALUES ($1, $2, $3, $4, 0.5, $5::vector)",
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

    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup_id),
        ClaimId::from_uuid(canonical_id),
    )
    .await
    .unwrap();

    let dup_has_embedding: bool = sqlx::query_scalar(
        "SELECT embedding IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(dup_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let canon_has_embedding: bool = sqlx::query_scalar(
        "SELECT embedding IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(canonical_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(!dup_has_embedding, "duplicate {dup_id} embedding should be NULL after mark_duplicate");
    assert!(canon_has_embedding, "canonical {canonical_id} embedding must be preserved");
}
