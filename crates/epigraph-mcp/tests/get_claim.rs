//! Integration test for [`get_claim`] after Task 4 of the
//! backlog-retirement plan: surfaces `labels`/`is_current`/`supersedes` on
//! `ClaimResponse` for single-claim lookup (previously stubbed defaults).
//!
//! Seeds two claims directly via SQL (one open backlog claim, one superseded
//! pointing at the open one), then verifies the MCP `get_claim` handler
//! returns the new fields with real database state.

use epigraph_core::ClaimId;
use epigraph_mcp::tools::claims::get_claim;
use epigraph_mcp::types::GetClaimParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_returns_labels_and_retirement_state(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    // Claim 1: an open backlog claim (is_current=true, supersedes=None).
    let open_id = seed_claim(&pool, agent, &["backlog"], true, None).await;

    let server = build_test_server(pool.clone());

    let result = get_claim(
        &server,
        GetClaimParams {
            claim_id: open_id.as_uuid().to_string(),
        },
    )
    .await
    .expect("get_claim open");
    let body = parse_claim(&result);

    assert_eq!(
        body["id"].as_str().unwrap(),
        open_id.as_uuid().to_string(),
        "id round-trips"
    );
    assert_eq!(body["labels"], serde_json::json!(["backlog"]));
    assert_eq!(body["is_current"], Value::Bool(true));
    assert!(
        body.get("supersedes").map(|v| v.is_null()).unwrap_or(true),
        "open claim should not include supersedes (None skips serialization): {body:?}"
    );

    // Claim 2: superseded, points at the open claim.
    let superseded_id = seed_claim(&pool, agent, &["backlog"], false, Some(open_id)).await;

    let result = get_claim(
        &server,
        GetClaimParams {
            claim_id: superseded_id.as_uuid().to_string(),
        },
    )
    .await
    .expect("get_claim superseded");
    let body = parse_claim(&result);

    assert_eq!(body["is_current"], Value::Bool(false));
    assert_eq!(
        body["supersedes"].as_str().unwrap(),
        open_id.as_uuid().to_string(),
        "superseded.supersedes should point at open_id"
    );
}

fn parse_claim(result: &CallToolResult) -> Value {
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
