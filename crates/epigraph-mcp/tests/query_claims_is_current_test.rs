//! Regression test for backlog bug `a85ee585`: the `query_claims` MCP tool had
//! no retirement-state filter and hardcoded `is_current: true` /
//! `supersedes: None` on every `ClaimResponse`.
//!
//! Two independent defects, both pinned here:
//!
//! 1. **Superseded rows resurfaced.** `query_claims(max_truth=0.4)` is used as
//!    an assessment-queue proxy, and `ClaimRepository::list_by_truth_range`
//!    neither filtered nor projected `is_current`, so already-refuted claims
//!    came back as "pending low-truth" candidates every cycle.
//! 2. **The response lied about currency.** Because the hardcode was a literal,
//!    a superseded row was serialised as `is_current: true` with no
//!    `supersedes` pointer — a caller could not tell the two populations apart
//!    even after fetching them.
//!
//! The seeded superseded claim is given the *lower* truth value so it sits
//! inside the low-truth window the queue actually queries: a test that only
//! looked at a wide `[0,1]` range would not exercise the queue's real call.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::claims::query_claims;
use epigraph_mcp::types::QueryClaimsParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

#[sqlx::test(migrations = "../../migrations")]
async fn query_claims_excludes_superseded_by_default(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    // Both claims are low-truth, i.e. both inside the assessment queue's
    // `max_truth = 0.4` window. Only the live one is a real candidate.
    let live = seed_claim(&pool, agent, 0.30, true, None).await;
    let refuted = seed_claim(&pool, agent, 0.10, false, Some(live)).await;

    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    // ---- Default (is_current omitted) == the assessment-queue call ----
    let claims = run(&server, &viewer, 0.0, 0.4, None).await;
    let ids = ids_of(&claims);
    assert!(
        ids.contains(&live.to_string()),
        "the live low-truth claim is a real candidate and must be returned: {ids:?}"
    );
    assert!(
        !ids.contains(&refuted.to_string()),
        "a superseded claim must NOT resurface in the default query_claims \
         result — its presence is backlog a85ee585, the re-assessment loop"
    );

    // ---- Explicit is_current = false: superseded rows ONLY ----
    let claims = run(&server, &viewer, 0.0, 0.4, Some(false)).await;
    let ids = ids_of(&claims);
    assert_eq!(
        ids,
        vec![refuted.to_string()],
        "is_current=false must select exactly the superseded row"
    );

    // ---- The row must report its real retirement state, not a literal ----
    let row = &claims[0];
    assert_eq!(
        row["is_current"],
        Value::Bool(false),
        "the superseded row must serialise is_current: false — `true` here is \
         the a85ee585 hardcode"
    );
    assert_eq!(
        row["supersedes"].as_str(),
        Some(live.to_string().as_str()),
        "the superseded row must carry the id of the claim that replaced it, \
         not the hardcoded None"
    );

    // ---- And the live row still reports true / no supersedes ----
    let claims = run(&server, &viewer, 0.0, 0.4, Some(true)).await;
    assert_eq!(ids_of(&claims), vec![live.to_string()]);
    assert_eq!(claims[0]["is_current"], Value::Bool(true));
    assert_eq!(claims[0]["supersedes"], Value::Null);
}

async fn run(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    min_truth: f64,
    max_truth: f64,
    is_current: Option<bool>,
) -> Vec<Value> {
    let result = query_claims(
        server,
        viewer,
        QueryClaimsParams {
            min_truth: Some(min_truth),
            max_truth: Some(max_truth),
            limit: Some(50),
            is_current,
        },
    )
    .await
    .expect("query_claims");
    parse_claims(&result)
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

fn ids_of(claims: &[Value]) -> Vec<String> {
    claims
        .iter()
        .map(|c| c["id"].as_str().expect("id is a string").to_string())
        .collect()
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("bd".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(
    pool: &PgPool,
    agent_id: Uuid,
    truth: f64,
    is_current: bool,
    supersedes: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        // `repeat(..).take(..)`, not `repeat_n`: this crate's clippy MSRV is
        // 1.75 and `iter::repeat_n` is 1.82+.
        .chain(std::iter::repeat(0).take(16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, supersedes) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(format!("query_claims is_current regression {id}"))
    .bind(hash)
    .bind(truth)
    .bind(agent_id)
    .bind(is_current)
    .bind(supersedes)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}
