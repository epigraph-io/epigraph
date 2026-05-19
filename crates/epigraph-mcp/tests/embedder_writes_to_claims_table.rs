//! Regression: `McpEmbedder` must persist embeddings on `claims.embedding`,
//! not `evidence.embedding`. Per the embedding-policy contract in CLAUDE.md
//! the canonical storage site is `claims.embedding`; an earlier path called
//! `EvidenceRepository::store_embedding(claim_id.into(), ...)`, which UPDATE-d
//! a non-existent evidence row (claim_id ≠ evidence.id) and silently no-op'd.

use epigraph_embeddings::EmbeddingService;
use epigraph_mcp::embed::McpEmbedder;
use sqlx::PgPool;

mod common;
use common::seed_claim;

#[sqlx::test(migrations = "../../migrations")]
async fn mcp_embedder_store_writes_to_claims_embedding(pool: PgPool) {
    let claim_id = seed_claim(&pool, "embedder write target", 0.5).await;
    let embedder = McpEmbedder::new(pool.clone(), None);
    let fake_vec = vec![0.1_f32; 1536];

    EmbeddingService::store(&embedder, claim_id, &fake_vec)
        .await
        .expect("store should succeed");

    let (claim_has_emb,): (bool,) =
        sqlx::query_as("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("query claim");
    assert!(
        claim_has_emb,
        "claims.embedding must be populated after McpEmbedder::store(); \
         the storage target is `claims`, not `evidence` (see CLAUDE.md embedding policy)"
    );

    let evidence_row_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM evidence WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .expect("query evidence");
    assert_eq!(
        evidence_row_count, 0,
        "no evidence row should exist at id = claim_id; if this fails the schema \
         contract changed and the test premise is stale"
    );
}
