//! Integration test for the owner-or-admin check in
//! [`resolve_backlog_item`] (deferred-review item #2 of the
//! backlog-retirement work).
//!
//! Background: previously `resolve_backlog_item` called
//! `ClaimRepository::update_labels` directly on the repo layer, bypassing
//! the HTTP `PATCH /api/v1/claims/:id/labels` route's
//! `require_owner_or_admin` middleware. A token with `claims:write`
//! could retire ANY agent's claim. The fix mirrors the HTTP check inside
//! the MCP handler.
//!
//! Caveat: rmcp's `tool_router` macro does NOT forward `AuthContext` into
//! per-tool handlers (only `Parameters<T>`), so the MCP handler cannot
//! read the caller's scopes (`claims:admin` override) or owner UUID. The
//! check therefore degrades to agent-equality against the server's own
//! signer agent. This test exercises that check:
//!
//! - **Foreign-agent claim → FORBIDDEN.** Seeds a claim authored by a
//!   freshly-inserted foreign agent UUID. `resolve_backlog_item` must
//!   refuse with INVALID_PARAMS (the agent-equality fallback maps onto
//!   that rmcp ErrorCode; see the `claims.rs` impl).
//! - **Own-signer claim → OK.** Submits a claim through the same MCP
//!   server (auto-registers the signer agent), then retires it. Must
//!   succeed.
//!
//! The admin-scope override path is intentionally NOT tested here — it
//! is unreachable without plumbing AuthContext into the tool layer
//! (tracked as the follow-up in the handler's authz comment).

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use epigraph_mcp::tools::claims::resolve_backlog_item;
use epigraph_mcp::types::{ResolveBacklogItemParams, SubmitClaimParams};
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

#[sqlx::test(migrations = "../../migrations")]
async fn resolve_backlog_item_refuses_foreign_agent_claim(pool: PgPool) {
    let server = build_test_server(pool.clone());

    // Bootstrap the server's signer agent so `resolve_backlog_item`'s
    // internal `agent_id().await` resolves to a real registered UUID.
    let _server_agent = bootstrap_server_agent(&server, &pool).await;

    // Seed a backlog claim authored by a DIFFERENT, foreign agent. The
    // MCP handler should refuse to retire it.
    let foreign_agent = seed_random_agent(&pool).await;
    let foreign_claim = seed_claim_with_agent(&pool, foreign_agent, &["backlog"]).await;

    let err = resolve_backlog_item(
        &server,
        ResolveBacklogItemParams {
            original_id: foreign_claim.as_uuid().to_string(),
            resolution_content: "should be rejected".to_string(),
            methodology: None,
        },
    )
    .await
    .expect_err("resolve_backlog_item must refuse a foreign-agent claim");

    // The error should explicitly cite ownership / lack of permission.
    let msg = err.message.to_string();
    assert!(
        msg.contains("owned by") && msg.contains("cannot retire"),
        "error must explain the ownership refusal, got: {msg:?}"
    );

    // The foreign claim must NOT have been label-patched as a side effect.
    let labels = ClaimRepository::get_labels(&pool, foreign_claim)
        .await
        .expect("get_labels foreign");
    assert!(
        !labels.contains(&"resolved".to_string()),
        "foreign claim must NOT have been labeled 'resolved' \
         (side-effect leak past the authz check): {labels:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn resolve_backlog_item_permits_own_signer_claim(pool: PgPool) {
    let server = build_test_server(pool.clone());

    // Submit a backlog claim THROUGH the server (so its agent_id is the
    // server's own signer). Then retire it: must succeed.
    let result = epigraph_mcp::tools::claims::submit_claim(
        &server,
        SubmitClaimParams {
            content: "open backlog item authored by server signer".into(),
            methodology: "deductive_logic".into(),
            evidence_data: "ev".into(),
            evidence_type: "logical".into(),
            confidence: 0.5,
            source_url: None,
            reasoning: None,
            labels: vec!["backlog".into()],
        },
    )
    .await
    .expect("submit_claim");
    let body = parse_json(&result);
    let claim_id: Uuid = body["claim_id"]
        .as_str()
        .expect("claim_id is string")
        .parse()
        .expect("valid UUID");

    let result = resolve_backlog_item(
        &server,
        ResolveBacklogItemParams {
            original_id: claim_id.to_string(),
            resolution_content: "retired by own signer".to_string(),
            methodology: None,
        },
    )
    .await
    .expect("resolve_backlog_item must permit retirement of own claim");

    let body = parse_json(&result);
    let labels: Vec<String> = body["original_labels"]
        .as_array()
        .expect("original_labels is array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        labels.contains(&"resolved".to_string()),
        "own claim's label patch must succeed: {labels:?}"
    );
}

fn parse_json(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    serde_json::from_str(&text).expect("response is JSON")
}

/// Submit a throwaway claim through the server to force registration of
/// the server's signer agent. The agent UUID returned is unused by
/// callers that just want the side-effect (registration); the foreign-
/// agent test path discards it.
async fn bootstrap_server_agent(server: &epigraph_mcp::EpiGraphMcpFull, pool: &PgPool) -> Uuid {
    let result = epigraph_mcp::tools::claims::submit_claim(
        server,
        SubmitClaimParams {
            content: "bootstrap claim for ownership test".into(),
            methodology: "deductive_logic".into(),
            evidence_data: "ev".into(),
            evidence_type: "logical".into(),
            confidence: 0.5,
            source_url: None,
            reasoning: None,
            labels: vec![],
        },
    )
    .await
    .expect("bootstrap submit_claim");
    let body = parse_json(&result);
    let claim_id: Uuid = body["claim_id"]
        .as_str()
        .expect("claim_id is string")
        .parse()
        .expect("valid UUID");
    let (agent_id,): (Uuid,) = sqlx::query_as("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("fetch agent_id");
    agent_id
}

async fn seed_random_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    // Use a unique-per-id public key so we don't collide with the
    // server-signer's deterministic public_key.
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key) VALUES ($1, $2) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed foreign agent");
    id
}

async fn seed_claim_with_agent(pool: &PgPool, agent_id: Uuid, labels: &[&str]) -> ClaimId {
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
         VALUES ($1, $2, $3, 0.5, $4, $5, true, NULL)",
    )
    .bind(id)
    .bind(format!("foreign claim {id}"))
    .bind(hash)
    .bind(agent_id)
    .bind(labels.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .execute(pool)
    .await
    .expect("seed foreign claim");
    ClaimId::from_uuid(id)
}
