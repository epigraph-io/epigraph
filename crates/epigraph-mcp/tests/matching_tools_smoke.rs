//! T19: smoke tests for the cross-source matching MCP tools.

#[macro_use]
mod common;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::tools;
use epigraph_mcp::types::{
    DecideMatchCandidateParams, FindCrossSourceMatchesParams, ListMatchCandidatesParams,
};
use epigraph_mcp::{embed::McpEmbedder, EpiGraphMcpFull};
use rmcp::model::RawContent;
use sqlx::types::Json;
use sqlx::PgPool;
use uuid::Uuid;

async fn build_server(pool: PgPool, read_only: bool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x19u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, read_only)
}

async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("t19 {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, true)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

/// Insert a claim with `is_current = false` — a retired endpoint (superseded
/// or marked-duplicate) that the `are_all_current` guard must refuse to
/// promote an edge onto.
async fn insert_retired_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("t19 retired {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, false)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("retired claim");
    id
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

async fn insert_candidate(pool: &PgPool, a: Uuid, b: Uuid, score: f32, status: &str) -> Uuid {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .bind(score)
    .bind(Json(serde_json::json!({"embed_cosine": 0.99})))
    .bind(status)
    .fetch_one(pool)
    .await
    .expect("insert candidate");
    id
}

fn result_text(out: rmcp::model::CallToolResult) -> String {
    let first = out.content.first().cloned().expect("first content");
    match first.raw {
        RawContent::Text(t) => t.text,
        other => panic!("expected text content, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_match_candidates_returns_only_status_filter(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let c = insert_claim(&pool, agent).await;

    let pending_id = insert_candidate(&pool, a, b, 0.9, "pending").await;
    let _rejected = insert_candidate(&pool, a, c, 0.4, "rejected").await;

    let out = tools::matching::list_match_candidates(
        &server,
        ListMatchCandidatesParams {
            status: Some("pending".into()),
            limit: Some(10),
        },
    )
    .await
    .expect("list");
    let text = result_text(out);

    assert!(
        text.contains(&pending_id.to_string()),
        "missing pending row"
    );
    assert!(
        !text.contains("\"rejected\""),
        "rejected row leaked into pending filter: {text}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_match_candidates_rejects_invalid_status(pool: PgPool) {
    let server = build_server(pool, false).await;
    let err = tools::matching::list_match_candidates(
        &server,
        ListMatchCandidatesParams {
            status: Some("garbage".into()),
            limit: None,
        },
    )
    .await
    .expect_err("should reject");
    assert!(
        format!("{err:?}").contains("pending|promoted|rejected|stale"),
        "error should explain valid options: {err:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_cross_source_matches_returns_candidates_and_edges(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;

    let cand = insert_candidate(&pool, a, b, 0.92, "promoted").await;

    // Pre-existing CORROBORATES edge (simulating a prior apply).
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
         VALUES ($1, 'claim', $2, 'claim', 'CORROBORATES', $3)",
    )
    .bind(a)
    .bind(b)
    .bind(Json(serde_json::json!({"score": 0.92, "source": "cross_source_matcher"})))
    .execute(&pool)
    .await
    .expect("edge insert");

    let out = tools::matching::find_cross_source_matches(
        &server,
        FindCrossSourceMatchesParams {
            claim_id: a.to_string(),
        },
    )
    .await
    .expect("find");
    let text = result_text(out);
    assert!(text.contains(&cand.to_string()));
    assert!(text.contains(&b.to_string()));
    assert!(text.contains("CORROBORATES") || text.contains("corroborates"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_promote_writes_edge_and_updates_status(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.95, "pending").await;

    tools::matching::decide_match_candidate(
        &server,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect("decide");

    let (status,): (String,) = sqlx::query_as("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "promoted");

    let edge_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE relationship = 'CORROBORATES'
           AND ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(edge_count.0, 1, "promote must write exactly one edge");

    // Second decide is idempotent at the edge layer.
    tools::matching::decide_match_candidate(
        &server,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect("decide again");
    let edge_count2: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE relationship = 'CORROBORATES'
           AND ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        edge_count2.0, 1,
        "duplicate promote must NOT duplicate edges"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_reject_marks_status_and_skips_edge(pool: PgPool) {
    let server = build_server(pool.clone(), false).await;
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.6, "pending").await;

    tools::matching::decide_match_candidate(
        &server,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "reject".into(),
        },
    )
    .await
    .expect("decide");

    let (status,): (String,) = sqlx::query_as("SELECT status FROM match_candidates WHERE id = $1")
        .bind(cand)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "rejected");
    let edge_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges WHERE relationship = 'CORROBORATES'
         AND ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1))",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(edge_count.0, 0, "reject must NOT write an edge");
}

#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_rejected_in_read_only_mode(pool: PgPool) {
    let server = build_server(pool.clone(), true).await; // read_only=true
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cand = insert_candidate(&pool, a, b, 0.95, "pending").await;

    let err = tools::matching::decide_match_candidate(
        &server,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect_err("read-only must refuse writes");
    assert!(
        format!("{err:?}").to_lowercase().contains("read-only"),
        "expected read-only refusal: {err:?}"
    );
}

/// Guard survives the refactor: `are_all_current` lives at the MCP call site,
/// NOT inside `EdgeRepository::create_symmetric_if_absent`. When one endpoint
/// is `is_current = false`, promote must refuse and write NO edge. If a future
/// edit folded the guard into the repo method (or dropped it), this catches it
/// because the repo method has no notion of current-ness — backlog bug
/// 5c7fc645 would re-open.
#[sqlx::test(migrations = "../../migrations")]
async fn decide_match_candidate_promote_blocked_when_endpoint_not_current(pool: PgPool) {
    let server = build_server(pool.clone(), false).await; // write-enabled
    let agent = insert_agent(&pool).await;
    let live = insert_claim(&pool, agent).await;
    let retired = insert_retired_claim(&pool, agent).await; // is_current = false
    let cand = insert_candidate(&pool, live, retired, 0.97, "pending").await;

    let err = tools::matching::decide_match_candidate(
        &server,
        DecideMatchCandidateParams {
            candidate_id: cand.to_string(),
            verdict: "promote".into(),
        },
    )
    .await
    .expect_err("promote must be refused when an endpoint is not current");
    assert!(
        format!("{err:?}").to_lowercase().contains("current"),
        "refusal must cite the current-ness guard: {err:?}"
    );

    // The guard must short-circuit BEFORE any edge write.
    let edge_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges WHERE relationship = 'CORROBORATES'
         AND ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1))",
    )
    .bind(live)
    .bind(retired)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        edge_count.0, 0,
        "no CORROBORATES edge may be written onto a retired claim"
    );
}
