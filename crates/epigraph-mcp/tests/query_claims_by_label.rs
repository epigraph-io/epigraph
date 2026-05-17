//! Integration test for [`query_claims_by_label`] after Task 3 of the
//! backlog-retirement plan: surfaces `labels`/`is_current`/`supersedes` on
//! `ClaimResponse` and accepts `exclude_labels` + `current_only` filters.
//!
//! Seeds three backlog claims directly via SQL (one current open, one current
//! resolved, one superseded pointing at the open one), then exercises the
//! filter cross-product through the MCP tool entry point.

use epigraph_core::ClaimId;
use epigraph_mcp::tools::paper_queries::query_claims_by_label;
use epigraph_mcp::types::QueryClaimsByLabelParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

#[sqlx::test(migrations = "../../migrations")]
async fn query_by_label_returns_labels_and_filters(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let backlog_open = seed_claim(&pool, agent, &["backlog"], true, None).await;
    let backlog_resolved = seed_claim(&pool, agent, &["backlog", "resolved"], true, None).await;
    let backlog_superseded =
        seed_claim(&pool, agent, &["backlog"], false, Some(backlog_open)).await;

    let server = build_test_server(pool.clone());

    // Default call (no filters): all 3 claims, with labels populated and
    // is_current/supersedes carried through.
    let result = query_claims_by_label(
        &server,
        QueryClaimsByLabelParams {
            labels: vec!["backlog".into()],
            exclude_labels: vec![],
            current_only: false,
            min_truth: None,
            limit: Some(10),
        },
    )
    .await
    .expect("query_claims_by_label default");
    let claims = parse_claims(&result);
    assert_eq!(claims.len(), 3, "expected all 3 backlog claims");

    let open = find_claim(&claims, backlog_open);
    assert_eq!(open["labels"], serde_json::json!(["backlog"]));
    assert_eq!(open["is_current"], Value::Bool(true));
    assert!(
        open.get("supersedes").map(|v| v.is_null()).unwrap_or(true),
        "open claim should not supersede anything: {open:?}"
    );

    let resolved = find_claim(&claims, backlog_resolved);
    let resolved_labels: Vec<String> = resolved["labels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(resolved_labels.contains(&"backlog".to_string()));
    assert!(resolved_labels.contains(&"resolved".to_string()));
    assert_eq!(resolved["is_current"], Value::Bool(true));

    let superseded = find_claim(&claims, backlog_superseded);
    assert_eq!(superseded["is_current"], Value::Bool(false));
    assert_eq!(
        superseded["supersedes"].as_str().unwrap(),
        backlog_open.as_uuid().to_string(),
        "superseded.supersedes should point at backlog_open"
    );

    // exclude_labels=["resolved"]: drops the resolved one.
    let result = query_claims_by_label(
        &server,
        QueryClaimsByLabelParams {
            labels: vec!["backlog".into()],
            exclude_labels: vec!["resolved".into()],
            current_only: false,
            min_truth: None,
            limit: Some(10),
        },
    )
    .await
    .expect("query_claims_by_label exclude_labels");
    let claims = parse_claims(&result);
    assert_eq!(claims.len(), 2);
    let resolved_str = backlog_resolved.as_uuid().to_string();
    assert!(
        claims
            .iter()
            .all(|c| c["id"].as_str().unwrap() != resolved_str),
        "exclude_labels=[resolved] should drop backlog_resolved"
    );

    // current_only=true: drops the superseded one.
    let result = query_claims_by_label(
        &server,
        QueryClaimsByLabelParams {
            labels: vec!["backlog".into()],
            exclude_labels: vec![],
            current_only: true,
            min_truth: None,
            limit: Some(10),
        },
    )
    .await
    .expect("query_claims_by_label current_only");
    let claims = parse_claims(&result);
    assert_eq!(claims.len(), 2);
    let superseded_str = backlog_superseded.as_uuid().to_string();
    assert!(
        claims
            .iter()
            .all(|c| c["id"].as_str().unwrap() != superseded_str),
        "current_only=true should drop backlog_superseded"
    );

    // Both filters combined: only the live open backlog claim survives.
    let result = query_claims_by_label(
        &server,
        QueryClaimsByLabelParams {
            labels: vec!["backlog".into()],
            exclude_labels: vec!["resolved".into()],
            current_only: true,
            min_truth: None,
            limit: Some(10),
        },
    )
    .await
    .expect("query_claims_by_label both filters");
    let claims = parse_claims(&result);
    assert_eq!(claims.len(), 1);
    assert_eq!(
        claims[0]["id"].as_str().unwrap(),
        backlog_open.as_uuid().to_string()
    );
}

fn parse_claims(result: &CallToolResult) -> Vec<Value> {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    let parsed: Value = serde_json::from_str(&text).expect("response is JSON");
    parsed.as_array().expect("response is JSON array").clone()
}

fn find_claim(claims: &[Value], id: ClaimId) -> &Value {
    let id_str = id.as_uuid().to_string();
    claims
        .iter()
        .find(|c| c["id"].as_str() == Some(id_str.as_str()))
        .unwrap_or_else(|| panic!("claim {id_str} not in response: {claims:?}"))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("bb".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(
    pool: &PgPool,
    agent_id: Uuid,
    labels: &[&str],
    is_current: bool,
    supersedes: Option<ClaimId>,
) -> ClaimId {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             labels, is_current, supersedes) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(format!("test claim {}", id))
    .bind(hash)
    .bind(agent_id)
    .bind(labels.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .bind(is_current)
    .bind(supersedes.map(|s| s.as_uuid()))
    .execute(pool)
    .await
    .expect("seed claim");
    ClaimId::from_uuid(id)
}
