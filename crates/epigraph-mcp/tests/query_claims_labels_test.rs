//! Regression test for backlog `babd5904`: the `query_claims` MCP tool always
//! returned `labels: []` because its handler hardcoded `labels: Vec::new()` in
//! the `ClaimResponse` map, while `get_claim` on the same id populated labels
//! correctly via `ClaimRepository::get_labels`.
//!
//! Seeds TWO labelled claims — one current, one superseded — because the fix's
//! batch label fetch must NOT filter on `is_current` (`query_claims` /
//! `list_by_truth_range` return superseded claims, and `get_claim`'s label
//! source has no `is_current` clause). A naive helper that copies the
//! `COALESCE(is_current, true)` filter from `contents_by_ids` would silently
//! re-drop labels for the superseded claim — the same bug class, narrowed. This
//! test locks in the no-filter decision by asserting BOTH claims surface their
//! labels through the `query_claims` tool entry point.

use epigraph_mcp::tools::claims::query_claims;
use epigraph_mcp::types::QueryClaimsParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

#[sqlx::test(migrations = "../../migrations")]
async fn query_claims_populates_labels_for_current_and_superseded(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    // Two claims with distinct truth values so both land in the [min,max]
    // window, each carrying known labels. `current` is live; `superseded` has
    // is_current=false — the discriminating case for the is_current filter.
    let current = seed_claim(&pool, agent, &["backlog", "task-3-1"], 0.7, true, None).await;
    let superseded = seed_claim(&pool, agent, &["archived"], 0.3, false, Some(current)).await;

    let server = build_test_server(pool.clone());

    let result = query_claims(
        &server,
        QueryClaimsParams {
            min_truth: Some(0.0),
            max_truth: Some(1.0),
            limit: Some(50),
        },
        None,
    )
    .await
    .expect("query_claims");
    let claims = parse_claims(&result);

    let current_claim = find_claim(&claims, current);
    let current_labels = labels_of(current_claim);
    assert!(
        current_labels.contains(&"backlog".to_string())
            && current_labels.contains(&"task-3-1".to_string()),
        "current claim must surface its labels through query_claims, got {current_labels:?}"
    );

    let superseded_claim = find_claim(&claims, superseded);
    let superseded_labels = labels_of(superseded_claim);
    assert!(
        superseded_labels.contains(&"archived".to_string()),
        "SUPERSEDED claim must ALSO surface its labels — the batch helper must \
         NOT filter on is_current, matching get_claim's label source. got {superseded_labels:?}"
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

fn find_claim(claims: &[Value], id: Uuid) -> &Value {
    let id_str = id.to_string();
    claims
        .iter()
        .find(|c| c["id"].as_str() == Some(id_str.as_str()))
        .unwrap_or_else(|| panic!("claim {id_str} not in response: {claims:?}"))
}

fn labels_of(claim: &Value) -> Vec<String> {
    claim["labels"]
        .as_array()
        .expect("labels is an array")
        .iter()
        .map(|v| v.as_str().expect("label is a string").to_string())
        .collect()
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

async fn seed_claim(
    pool: &PgPool,
    agent_id: Uuid,
    labels: &[&str],
    truth: f64,
    is_current: bool,
    supersedes: Option<Uuid>,
) -> Uuid {
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
                             labels, is_current, supersedes) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(format!("query_claims labels regression {id}"))
    .bind(hash)
    .bind(truth)
    .bind(agent_id)
    .bind(labels.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .bind(is_current)
    .bind(supersedes)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}
