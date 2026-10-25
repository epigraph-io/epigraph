//! MCP `query_claims_by_label` keyset paging (backlog 6f072833, ruling R-9),
//! the twin of `crates/epigraph-api/tests/claims_by_labels_cursor.rs`.
//!
//! With `after` present the tool answers `{claims, next_cursor}` and resumes
//! strictly after the previous page's last row in `(created_at DESC, id DESC)`
//! order; without it the legacy bare array is unchanged.

#[path = "viewer_fixture.rs"]
mod fixture;

use chrono::{DateTime, Duration, TimeZone, Utc};
use epigraph_mcp::tools::paper_queries::query_claims_by_label;
use epigraph_mcp::types::QueryClaimsByLabelParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

/// Bound on pages a walk may take; a cursor that does not advance would
/// otherwise loop forever.
const MAX_PAGES: usize = 20;

fn params(label: &str, limit: i64, after: Option<String>) -> QueryClaimsByLabelParams {
    QueryClaimsByLabelParams {
        labels: vec![label.to_string()],
        exclude_labels: vec![],
        current_only: false,
        min_truth: None,
        limit: Some(limit),
        offset: None,
        after,
        include_source_urls: false,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn cursor_walk_visits_each_row_once_across_created_at_ties(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let t = Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap();
    let mut seeded: Vec<(DateTime<Utc>, Uuid)> = Vec::new();
    for at in [t + Duration::seconds(1), t, t, t, t - Duration::seconds(1)] {
        seeded.push((at, seed_claim_at(&pool, agent, "mcp-keyset", at).await));
    }
    seeded.sort_by(|a, b| b.cmp(a));
    let expected: Vec<String> = seeded.iter().map(|(_, id)| id.to_string()).collect();
    let server = build_test_server(pool.clone());

    let mut walked: Vec<String> = Vec::new();
    // "" starts a keyset walk.
    let mut after = String::new();
    let mut pages = 0;
    loop {
        pages += 1;
        assert!(pages <= MAX_PAGES, "cursor walk did not terminate");
        let result = query_claims_by_label(
            &server,
            &viewer,
            params("mcp-keyset", 2, Some(after.clone())),
        )
        .await
        .expect("query_claims_by_label with after");
        let body = parse(&result);
        let claims = body["claims"].as_array().unwrap_or_else(|| {
            panic!("with `after`, the response is {{claims, next_cursor}}: {body}")
        });
        walked.extend(claims.iter().map(|c| c["id"].as_str().unwrap().to_string()));
        match &body["next_cursor"] {
            Value::String(next) => after = next.clone(),
            Value::Null => break,
            other => panic!("next_cursor must be a string or null, got {other}"),
        }
        if walked.len() > expected.len() {
            break;
        }
    }
    assert_eq!(
        walked, expected,
        "following next_cursor must visit every labelled row once, newest first, ties by id DESC"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn without_after_the_response_stays_a_bare_array(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let t = Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap();
    for i in 0..3 {
        seed_claim_at(&pool, agent, "mcp-legacy", t + Duration::seconds(i)).await;
    }
    let server = build_test_server(pool.clone());
    let result = query_claims_by_label(&server, &viewer, params("mcp-legacy", 2, None))
        .await
        .expect("legacy call");
    let body = parse(&result);
    assert_eq!(
        body.as_array().map(Vec::len),
        Some(2),
        "no `after` keeps the legacy bare-array response: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_malformed_cursor_and_a_cursor_with_offset_are_invalid_params(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let t = Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap();
    for i in 0..3 {
        seed_claim_at(&pool, agent, "mcp-refuse", t + Duration::seconds(i)).await;
    }
    let server = build_test_server(pool.clone());

    let err = query_claims_by_label(
        &server,
        &viewer,
        params("mcp-refuse", 2, Some("garbage".into())),
    )
    .await
    .expect_err("a malformed cursor must be refused");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");

    let first = parse(
        &query_claims_by_label(
            &server,
            &viewer,
            params("mcp-refuse", 2, Some(String::new())),
        )
        .await
        .expect("first page"),
    );
    let cursor = first["next_cursor"]
        .as_str()
        .expect("a full page carries next_cursor")
        .to_string();
    let mut both = params("mcp-refuse", 2, Some(cursor.clone()));
    both.offset = Some(2);
    let err = query_claims_by_label(&server, &viewer, both)
        .await
        .expect_err("`after` with a non-zero offset must be refused");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");

    let last = parse(
        &query_claims_by_label(&server, &viewer, params("mcp-refuse", 2, Some(cursor)))
            .await
            .expect("second page"),
    );
    assert_eq!(last["claims"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        last["next_cursor"],
        Value::Null,
        "the short page ends the walk"
    );
}

#[test]
fn after_is_accepted_from_json_arguments() {
    let p: QueryClaimsByLabelParams =
        serde_json::from_value(serde_json::json!({"labels": ["x"], "after": "k1.0.0"}))
            .expect("`after` deserializes");
    assert_eq!(p.after.as_deref(), Some("k1.0.0"));
    let p: QueryClaimsByLabelParams =
        serde_json::from_value(serde_json::json!({"labels": ["x"]})).expect("legacy args");
    assert_eq!(p.after, None);
}

fn parse(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    serde_json::from_str(&text).expect("response is JSON")
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("cc".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim_at(pool: &PgPool, agent_id: Uuid, label: &str, at: DateTime<Utc>) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat(0).take(16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             labels, is_current, created_at, updated_at) \
         VALUES ($1, $2, $3, 0.5, $4, $5, true, $6, $6)",
    )
    .bind(id)
    .bind(format!("mcp cursor claim {id}"))
    .bind(hash)
    .bind(agent_id)
    .bind(vec![label.to_string()])
    .bind(at)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}
