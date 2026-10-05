//! Regression tests for the residual of backlog `1e6efd2d` (Foreman feature
//! `router-1e6efd2d9c524b59`'s planned `fix-sibling-handlers`): four MCP list
//! handlers built every `ClaimResponse` with a hardcoded `labels: Vec::new()`,
//! and three of them also with `is_current: true` / `supersedes: None` —
//! the same defect `query_claims` had under backlog `babd5904` / `a85ee585`
//! and that `get_claim` had before #327.
//!
//! * `paper_queries.rs::query_claims_by_evidence` and
//!   `::query_claims_by_methodology` iterate `ClaimRepository::list`, which
//!   returns superseded rows AND projects their real `is_current` /
//!   `supersedes` — the handlers threw both away.
//! * `paper_queries.rs::query_paper` reads `PaperRepository::list_asserted_claims`,
//!   which has no `is_current` filter, so a superseded asserted claim was
//!   reported as current.
//! * `claims.rs::query_undecomposed_claims` reads `list_undecomposed`, which IS
//!   current-only (so `is_current: true` is correct there), but a current claim
//!   that superseded another still carries a non-null `supersedes`.
//!
//! Each test seeds a CURRENT claim and a SUPERSEDED claim with distinct labels,
//! so one run discriminates all three fabricated fields. The superseded row is
//! found with a panicking `find_claim`, so these tests also pin that no handler
//! silently gains an `is_current` filter (which would change its paging set).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::claims::query_undecomposed_claims;
use epigraph_mcp::tools::paper_queries::{
    query_claims_by_evidence, query_claims_by_methodology, query_paper,
};
use epigraph_mcp::types::{
    QueryClaimsByEvidenceParams, QueryClaimsByMethodologyParams, QueryPaperParams,
    QueryUndecomposedClaimsParams,
};
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

#[sqlx::test(migrations = "../../migrations")]
async fn query_claims_by_evidence_returns_real_labels_and_retirement_state(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    let superseded = seed_claim(&pool, agent, &["ev-archived"], 0.6, false, None).await;
    let current = seed_claim(&pool, agent, &["ev-current"], 0.7, true, Some(superseded)).await;
    // `EvidenceRepository::get_by_claim` decodes the type from `properties`
    // and falls back to `EvidenceType::Document` when that does not parse —
    // which the column default does not — so both rows match "document".
    seed_evidence(&pool, current).await;
    seed_evidence(&pool, superseded).await;

    let server = build_test_server(pool.clone());
    let result = query_claims_by_evidence(
        &server,
        &viewer,
        QueryClaimsByEvidenceParams {
            evidence_type: "document".into(),
            min_strength: None,
            min_truth: Some(0.0),
            limit: Some(50),
        },
    )
    .await
    .expect("query_claims_by_evidence");
    let claims = parse_array(&result);

    assert_retirement_pair(
        &claims,
        current,
        &["ev-current"],
        superseded,
        &["ev-archived"],
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn query_claims_by_methodology_returns_real_labels_and_retirement_state(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    let superseded = seed_claim(&pool, agent, &["meth-archived"], 0.6, false, None).await;
    let current = seed_claim(&pool, agent, &["meth-current"], 0.7, true, Some(superseded)).await;
    // `reasoning_type = 'deductive'` decodes to `Methodology::Deductive`, whose
    // description ("Deductive reasoning from premises") contains "deductive".
    seed_trace(&pool, current).await;
    seed_trace(&pool, superseded).await;

    let server = build_test_server(pool.clone());
    let result = query_claims_by_methodology(
        &server,
        &viewer,
        QueryClaimsByMethodologyParams {
            methodology: "deductive".into(),
            min_truth: Some(0.0),
            limit: Some(50),
        },
    )
    .await
    .expect("query_claims_by_methodology");
    let claims = parse_array(&result);

    assert_retirement_pair(
        &claims,
        current,
        &["meth-current"],
        superseded,
        &["meth-archived"],
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn query_paper_returns_real_labels_and_retirement_state(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let doi = "10.48550/arXiv.9999.00808";

    let paper = seed_paper(&pool, doi).await;
    let superseded = seed_claim(&pool, agent, &["paper-archived"], 0.6, false, None).await;
    let current = seed_claim(
        &pool,
        agent,
        &["paper-current"],
        0.7,
        true,
        Some(superseded),
    )
    .await;
    seed_asserts_edge(&pool, paper, superseded).await;
    seed_asserts_edge(&pool, paper, current).await;

    let server = build_test_server(pool.clone());
    let result = query_paper(
        &server,
        &viewer,
        QueryPaperParams {
            doi: doi.to_string(),
            limit: Some(50),
            offset: None,
        },
    )
    .await
    .expect("query_paper");
    let body = parse_value(&result);
    let claims = body["claims"]
        .as_array()
        .unwrap_or_else(|| panic!("query_paper body has a claims array: {body}"))
        .clone();

    assert_eq!(
        claims.len(),
        2,
        "both asserted claims are on the page — query_paper has no is_current \
         filter and must not gain one (its has_more paging depends on the set): {body}"
    );
    assert_retirement_pair(
        &claims,
        current,
        &["paper-current"],
        superseded,
        &["paper-archived"],
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn query_undecomposed_claims_returns_real_labels(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // `list_undecomposed` is current-only, so the superseded row is NOT in the
    // response; what it buys is a non-null `supersedes` on the current one.
    let superseded = seed_claim(&pool, agent, &["undecomp-old"], 0.6, false, None).await;
    let current = seed_claim(&pool, agent, &["undecomp-x"], 0.7, true, Some(superseded)).await;

    let server = build_test_server(pool.clone());
    let result = query_undecomposed_claims(
        &server,
        &viewer,
        QueryUndecomposedClaimsParams {
            // Ordered created_at ASC: a large page so any migration-seeded rows
            // cannot push the fixture off it.
            limit: Some(1000),
            offset: None,
        },
    )
    .await
    .expect("query_undecomposed_claims");
    let claims = parse_array(&result);

    let c = find_claim(&claims, current);
    assert_eq!(
        labels_of(c),
        vec!["undecomp-x".to_string()],
        "query_undecomposed_claims must surface the claim's stored labels, not []: {c}"
    );
    assert_eq!(
        c["is_current"],
        Value::Bool(true),
        "list_undecomposed is current-only, so is_current is true by its predicate: {c}"
    );
    assert_eq!(
        c["supersedes"].as_str(),
        Some(superseded.to_string().as_str()),
        "a current claim that superseded another must report that lineage, not null: {c}"
    );
    assert!(
        claims
            .iter()
            .all(|x| x["id"].as_str() != Some(superseded.to_string().as_str())),
        "the superseded claim must not be offered for decomposition: {claims:?}"
    );
}

// ---------------------------------------------------------------------------
// shared assertion
// ---------------------------------------------------------------------------

/// `current` supersedes `superseded`; both are in `claims`. Asserts every field
/// the handlers used to fabricate, on both rows.
fn assert_retirement_pair(
    claims: &[Value],
    current: Uuid,
    current_labels: &[&str],
    superseded: Uuid,
    superseded_labels: &[&str],
) {
    let cur = find_claim(claims, current);
    assert_eq!(
        labels_of(cur),
        current_labels
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>(),
        "the current claim's stored labels must be served, not []: {cur}"
    );
    assert_eq!(cur["is_current"], Value::Bool(true), "{cur}");
    assert_eq!(
        cur["supersedes"].as_str(),
        Some(superseded.to_string().as_str()),
        "the current claim's real supersedes link must be served, not null: {cur}"
    );

    let old = find_claim(claims, superseded);
    assert_eq!(
        labels_of(old),
        superseded_labels
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>(),
        "the SUPERSEDED claim's stored labels must be served too — the batch label \
         read is not is_current-filtered: {old}"
    );
    assert_eq!(
        old["is_current"],
        Value::Bool(false),
        "a superseded claim must not be reported as current: {old}"
    );
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn raw_text(result: &CallToolResult) -> String {
    result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block")
}

fn parse_value(result: &CallToolResult) -> Value {
    serde_json::from_str(&raw_text(result)).expect("response is JSON")
}

fn parse_array(result: &CallToolResult) -> Vec<Value> {
    parse_value(result)
        .as_array()
        .expect("response is a JSON array")
        .clone()
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
        .bind("cd".repeat(32))
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
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             labels, is_current, supersedes) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(format!("sibling handler labels regression {id}"))
    .bind(hash)
    .bind(truth)
    .bind(agent_id)
    .bind(labels.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
    .bind(is_current)
    .bind(supersedes)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn seed_evidence(pool: &PgPool, claim_id: Uuid) {
    let evidence_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence (id, content_hash, evidence_type, claim_id) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(evidence_id)
    .bind(evidence_id.as_bytes().repeat(2))
    .bind("document")
    .bind(claim_id)
    .execute(pool)
    .await
    .expect("seed evidence row");
}

async fn seed_trace(pool: &PgPool, claim_id: Uuid) {
    let trace = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO reasoning_traces (id, claim_id, reasoning_type, confidence, explanation) \
         VALUES ($1, $2, 'deductive', 0.5, 'sibling handler labels regression')",
    )
    .bind(trace)
    .bind(claim_id)
    .execute(pool)
    .await
    .expect("seed reasoning trace");
    sqlx::query("UPDATE claims SET trace_id = $2 WHERE id = $1")
        .bind(claim_id)
        .bind(trace)
        .execute(pool)
        .await
        .expect("link trace to claim");
}

async fn seed_paper(pool: &PgPool, doi: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(doi)
        .bind("A paper with a superseded asserted claim")
        .execute(pool)
        .await
        .expect("seed paper");
    id
}

async fn seed_asserts_edge(pool: &PgPool, paper: Uuid, claim: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper)
    .bind(claim)
    .execute(pool)
    .await
    .expect("seed asserts edge");
}
