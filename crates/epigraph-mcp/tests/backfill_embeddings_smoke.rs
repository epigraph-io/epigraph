//! Smoke tests for the `backfill_embeddings` MCP tool — the server-side,
//! MCP-executable embed stage of the decomposition-cycle pipeline.
//!
//! The build harness constructs the server with a MOCK embedder
//! (`McpEmbedder::new(pool, None)`), so the real OpenAI generate+store happy
//! path cannot run in CI (same scaffold boundary as the `decompose_claims`
//! LLM call). These tests pin the two behaviors that DO run without a network
//! round-trip: candidate selection (`dry_run`) and the fail-loud guard when
//! the server has no API key. The generate→store mechanics themselves are
//! covered by `ClaimRepository::store_embedding` /
//! `find_claims_needing_embeddings` unit tests in epigraph-db.

use epigraph_crypto::AgentSigner;
use epigraph_mcp::tools;
use epigraph_mcp::tools::embeddings::BackfillEmbeddingsParams;
use epigraph_mcp::{embed::McpEmbedder, EpiGraphMcpFull};
use rmcp::model::{CallToolResult, RawContent};
use sqlx::PgPool;
use uuid::Uuid;

async fn build_server(pool: PgPool, read_only: bool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x2au8; 32]).expect("signer");
    // None => mock embedder: `generate` errors, exercising the fail-loud guard.
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, read_only)
}

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

/// A current claim with `embedding IS NULL` — exactly what backfill targets.
async fn insert_unembedded_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("backfill candidate {id} with enough length to pass filters");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, embedding)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, true, NULL)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

fn result_text(out: CallToolResult) -> String {
    let first = out.content.first().cloned().expect("first content");
    match first.raw {
        RawContent::Text(t) => t.text,
        other => panic!("expected text content, got {other:?}"),
    }
}

fn parse(out: CallToolResult) -> serde_json::Value {
    serde_json::from_str(&result_text(out)).expect("valid json body")
}

#[sqlx::test(migrations = "../../migrations")]
async fn dry_run_counts_candidates_without_writing(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    for _ in 0..3 {
        insert_unembedded_claim(&pool, agent).await;
    }

    let out = tools::embeddings::backfill_embeddings(
        &server,
        BackfillEmbeddingsParams {
            limit: Some(100),
            dry_run: Some(true),
        },
    )
    .await
    .expect("dry_run succeeds even with a mock embedder");

    let body = parse(out);
    assert_eq!(
        body["candidates"], 3,
        "all three NULL-embedding claims counted"
    );
    assert_eq!(body["embedded"], 0, "dry_run writes nothing");
    assert_eq!(body["dry_run"], true);

    // And nothing was actually written.
    let still_null: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE embedding IS NULL AND agent_id = $1")
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(still_null, 3, "dry_run must not have stored any embeddings");
}

#[sqlx::test(migrations = "../../migrations")]
async fn limit_is_respected_and_clamped(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    for _ in 0..5 {
        insert_unembedded_claim(&pool, agent).await;
    }

    let out = tools::embeddings::backfill_embeddings(
        &server,
        BackfillEmbeddingsParams {
            limit: Some(2),
            dry_run: Some(true),
        },
    )
    .await
    .expect("dry_run");
    assert_eq!(
        parse(out)["candidates"],
        2,
        "limit caps the candidate window"
    );

    // limit below 1 clamps up to 1 rather than returning everything/nothing.
    let out = tools::embeddings::backfill_embeddings(
        &server,
        BackfillEmbeddingsParams {
            limit: Some(0),
            dry_run: Some(true),
        },
    )
    .await
    .expect("dry_run");
    assert_eq!(parse(out)["candidates"], 1, "limit 0 clamps to 1");
}

#[sqlx::test(migrations = "../../migrations")]
async fn non_dry_run_with_mock_embedder_fails_loudly(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    insert_unembedded_claim(&pool, agent).await;

    let err = tools::embeddings::backfill_embeddings(
        &server,
        BackfillEmbeddingsParams {
            limit: Some(100),
            dry_run: Some(false),
        },
    )
    .await
    .expect_err("must refuse to churn through a batch with no API key");

    let msg = format!("{err:?}");
    assert!(
        msg.contains("OPENAI_API_KEY") || msg.contains("embeddings disabled"),
        "error must explain the missing-key cause: {msg}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn zero_candidates_succeeds_even_without_a_key(pool: PgPool) {
    // No unembedded claims at all => candidates==0 short-circuits BEFORE the
    // mock-embedder guard, so a scheduled run on a drained backlog is a clean
    // no-op rather than a config error.
    let server = build_server(pool.clone(), false).await;

    let out = tools::embeddings::backfill_embeddings(
        &server,
        BackfillEmbeddingsParams {
            limit: Some(100),
            dry_run: Some(false),
        },
    )
    .await
    .expect("empty backlog is a no-op, not an error");

    let body = parse(out);
    assert_eq!(body["candidates"], 0);
    assert_eq!(body["embedded"], 0);
    assert_eq!(body["failed"], 0);
}
