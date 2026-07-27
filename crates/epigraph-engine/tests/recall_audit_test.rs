//! The library-level `recall` audits too (backlog 8cbffa0e / design F5).
//!
//! This is the THIRD retrieval surface — episcience synthesis calls it
//! directly, not over MCP. It has no auth context, so its rows carry
//! agent_id = NULL, which is what migration 058's nullable column is for.
//! Without this the audit log would silently omit every episcience retrieval.

use epigraph_embeddings::{config::EmbeddingConfig, providers::MockProvider};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn engine_recall_writes_an_audit_row_with_null_agent(pool: PgPool) {
    let agent = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-engine-audit', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(&pool).await.expect("seed agent");

    sqlx::query(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ('grendlewick synthesis seed', sha256('grendlewick synthesis seed'::bytea), 0.8, $1, true)",
    )
    .bind(agent).execute(&pool).await.expect("seed claim");

    let provider = MockProvider::new(EmbeddingConfig::local(64));
    let results = epigraph_engine::recall::recall(&pool, &provider, "grendlewick", 10, 0.0)
        .await
        .expect("engine recall ok");

    let row = sqlx::query!(
        "SELECT tool, agent_id, query_text, returned_claim_ids FROM recall_events
         ORDER BY created_at DESC LIMIT 1"
    )
    .fetch_optional(&pool)
    .await
    .unwrap()
    .expect("the library path must write an audit row, not silently skip auditing");

    assert_eq!(
        row.tool, "engine::recall",
        "attributed to the library surface"
    );
    assert!(
        row.agent_id.is_none(),
        "no auth context on this path => NULL agent_id"
    );
    assert_eq!(row.query_text, "grendlewick");
    assert_eq!(
        row.returned_claim_ids.len(),
        results.len(),
        "the row records exactly what the caller received"
    );
}
