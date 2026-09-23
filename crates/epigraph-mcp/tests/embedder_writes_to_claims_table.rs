//! Regression: `McpEmbedder` must persist embeddings on `claims.embedding`,
//! not `evidence.embedding`. Per the embedding-policy contract in CLAUDE.md
//! the canonical storage site for claim embeddings is `claims.embedding`; an
//! earlier path called `EvidenceRepository::store_embedding(claim_id.into(), …)`,
//! which UPDATE-d a non-existent evidence row (claim_id ≠ evidence.id) and
//! silently no-op'd.
//!
//! # Why these arms changed shape
//!
//! `McpEmbedder` no longer has an unstamped store. Its `UPDATE claims SET
//! embedding` is governed by migration 077's `claims_tenancy` `WITH CHECK`, which
//! is refused on a session carrying no tenancy GUCs — and refused SILENTLY,
//! because embedding is best-effort, which is why seven tools were landing
//! `embedding = NULL` while reporting success. The capability is now declared
//! (`embed::StorePath`), the default declares nothing, and stores route through
//! the claim AUTHOR's stamped connection.
//!
//! So the original arm — `McpEmbedder::new(pool, None)` then `store` — now
//! measures the refusal rather than the column, and the column assertion needs a
//! `ScopedPool`-declared embedder over a claim whose author has a writable group.
//! Both arms are kept: the first is the one that would have caught the silent
//! no-op, the second is the one that keeps the default from drifting back to a
//! pool write.
//!
//! **What these arms do NOT prove.** `#[sqlx::test]` connects as `epigraph`
//! (superuser, BYPASSRLS, table owner), so the STAMP is not what admits the write
//! here — the bypass is. The tenancy mechanism is measured on the real
//! non-bypassing role by
//! `epigraph-db/tests/embedding_store_requires_a_stamp.rs`. What these arms pin is
//! the crate-level wiring those arms cannot see: which column is written, and that
//! an embedder with no declared store path refuses instead of falling back.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_embeddings::EmbeddingService;
use epigraph_mcp::embed::McpEmbedder;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::seed_claim;

/// A claim in the shape the MCP write path produces —
/// `('public', personal_group_of(author))` — so the author's viewer carries write
/// authority over the row and `store_vector`'s author lookup can see it.
async fn seed_author_owned_public_claim(pool: &PgPool, author: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, visibility, owner_group_id, labels) \
         VALUES ($1, 'embedder write target', $2, 0.5, $3, true, 'public', $4, \
                 ARRAY[]::text[])",
    )
    .bind(id)
    .bind(&hash)
    .bind(author)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed an author-owned public claim");
    id
}

/// The column contract, through the declared author-stamped store path.
#[sqlx::test(migrations = "../../migrations")]
async fn mcp_embedder_store_writes_to_claims_embedding(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "embedder-store").await;
    let claim_id = seed_author_owned_public_claim(&pool, author, group).await;
    let embedder =
        McpEmbedder::new(pool.clone(), None).with_scoped_pool(fixture::scoped_pool(&pool).await);
    let fake_vec = vec![0.1_f32; 1536];

    EmbeddingService::store(&embedder, claim_id, &fake_vec)
        .await
        .expect("store should succeed on a declared author-stamped embedder");

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

/// The default must REFUSE, not fall back.
///
/// This is the arm that fails if `StorePath::Undeclared` is ever made to mean
/// "write on `self.pool`". It is deliberately asserted on the BYPASSRLS harness
/// connection, where a pool write WOULD succeed: that makes the arm sensitive to
/// the code path rather than to the policies, so it stays meaningful on a
/// developer's superuser database as well as on the least-privilege role.
#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_embedder_refuses_to_store_rather_than_using_its_pool(pool: PgPool) {
    let claim_id = seed_claim(&pool, "undeclared store target", 0.5).await;
    let embedder = McpEmbedder::new(pool.clone(), None);
    let fake_vec = vec![0.2_f32; 1536];

    let err = EmbeddingService::store(&embedder, claim_id, &fake_vec)
        .await
        .expect_err(
            "an embedder that declared no StorePath must refuse. If this now succeeds it is \
             writing on the plain pool, where a cleanly-migrated schema refuses the UPDATE and \
             swallows the refusal — the silent `live_missing` shape this type was changed to \
             make impossible.",
        );
    let msg = err.to_string();
    assert!(
        msg.contains("StorePath"),
        "the refusal must name the missing declaration so an operator can act on it: {msg}"
    );

    let (claim_has_emb,): (bool,) =
        sqlx::query_as("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("query claim");
    assert!(
        !claim_has_emb,
        "nothing may be written on the refused path — and this database BYPASSES RLS, so a \
         fallback pool write would have landed here"
    );
}
