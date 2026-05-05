//! Integration tests for #61: event log was empty despite claim/agent
//! persistence. These tests round-trip publish → read for the three event
//! types named in the issue (`claim.created`, `agent.registered`,
//! `tool.invoked`) via the canonical user-facing surface — the MCP
//! `list_events` tool.
//!
//! Pattern matches `tool_resubmit_tests.rs`: build a real `EpiGraphMcpFull`
//! against a live test DB, exercise the persistence path, then assert the
//! event log has the expected entry.

#[macro_use]
mod common;

use common::*;

use epigraph_core::{Agent, AgentId, Claim, TruthValue};
use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_db::{AgentRepository, ClaimRepository};
use epigraph_mcp::types::{ListEventsParams, SubmitClaimParams};
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

async fn build_test_server(pool: PgPool, signer_seed: [u8; 32]) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&signer_seed).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // mock — no API key
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

/// Extract the JSON body from a `list_events` `CallToolResult`. The MCP
/// surface returns text content with a JSON string payload — this helper
/// just decodes that envelope so tests can assert on the event array.
fn parse_list_events(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("list_events result has at least one text content block");
    serde_json::from_str(&text).expect("list_events payload is valid JSON")
}

/// Count events of a given type in a `list_events` JSON envelope.
fn count_events_of_type(body: &serde_json::Value, event_type: &str) -> usize {
    body["events"]
        .as_array()
        .expect("events is array")
        .iter()
        .filter(|e| e["event_type"].as_str() == Some(event_type))
        .count()
}

// ────────────────────────────────────────────────────────────────────────────
// claim.created round-trip
// ────────────────────────────────────────────────────────────────────────────

/// Submitting a claim must produce a `claim.created` event visible via
/// MCP `list_events(event_type="claim.created")`. Pre-fix, this assertion
/// failed because no persistence path called `EventRepository::insert`.
#[tokio::test]
async fn submit_claim_emits_claim_created_event() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    // Use a fresh signer seed so the server agent (and any side-effect
    // events from its registration) don't collide with other tests sharing
    // the same DB.
    let signer_seed = [0xC1u8; 32];
    let server = build_test_server(pool.clone(), signer_seed).await;

    // Use a unique content string so we can be sure the event we read back
    // is the one we just emitted (filtered by created_at after our marker).
    let unique_marker = format!("event-log-fix-{}", Uuid::new_v4());
    let params = SubmitClaimParams {
        content: unique_marker.clone(),
        evidence_data: "evidence body".to_string(),
        evidence_type: "empirical".to_string(),
        methodology: "bayesian".to_string(),
        confidence: 0.7,
        source_url: None,
        reasoning: None,
    };

    let before = chrono::Utc::now();

    tools::claims::submit_claim(&server, params)
        .await
        .expect("submit_claim succeeds");

    // Read back via the canonical surface — `list_events` MCP tool.
    let result = tools::events::list_events(
        &server,
        ListEventsParams {
            event_type: Some("claim.created".to_string()),
            actor_id: None,
            limit: Some(50),
        },
    )
    .await
    .expect("list_events succeeds");

    let body = parse_list_events(&result);
    let count = count_events_of_type(&body, "claim.created");
    assert!(
        count >= 1,
        "expected at least one claim.created event after submit_claim, body = {body}"
    );

    // Stronger assertion: at least one of the events was emitted by the
    // call we just made (created_at >= our marker). Without this guard, a
    // stale row from a previous test run could mask a regression.
    let recent: Vec<&serde_json::Value> = body["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["event_type"].as_str() == Some("claim.created")
                && e["created_at"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|t| t.with_timezone(&chrono::Utc) >= before)
                    .unwrap_or(false)
        })
        .collect();

    assert!(
        !recent.is_empty(),
        "expected at least one claim.created event with created_at >= {before}; got {body}"
    );
}

/// Resubmitting the same `(content, agent_id)` MUST NOT emit a duplicate
/// `claim.created` event — the helper is gated on `was_created=true` so
/// idempotent re-runs don't pollute the audit log. This guard prevents a
/// regression where well-meaning code drops the gate and floods the log.
///
/// Operates on whichever fixture state the DB is in (pre-107 or post-107):
/// the dedup happens inside `ClaimRepository::create_or_get` regardless.
#[tokio::test]
async fn resubmit_does_not_emit_duplicate_claim_created() {
    let pool = test_pool_or_skip!();

    let signer_seed = [0xC2u8; 32];
    let server = build_test_server(pool.clone(), signer_seed).await;

    let content = format!("event-log-dedup-{}", Uuid::new_v4());
    let make_params = |evidence: &str| SubmitClaimParams {
        content: content.clone(),
        evidence_data: evidence.to_string(),
        evidence_type: "empirical".to_string(),
        methodology: "bayesian".to_string(),
        confidence: 0.7,
        source_url: None,
        reasoning: None,
    };

    // First submit — should create the claim and emit one event.
    tools::claims::submit_claim(&server, make_params("evidence-resubmit-1"))
        .await
        .expect("first submit_claim");

    // Snapshot the events table for the agent before the second submit so
    // we can detect a duplicate emission specific to the resubmit.
    let server_agent_uuid: Uuid = sqlx::query_scalar(
        "SELECT id FROM agents WHERE public_key = $1",
    )
    .bind({
        let s = AgentSigner::from_bytes(&signer_seed).unwrap();
        s.public_key().to_vec()
    })
    .fetch_one(&pool)
    .await
    .expect("server agent must exist");

    let before_second: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM events \
         WHERE event_type = 'claim.created' AND actor_id = $1",
    )
    .bind(server_agent_uuid)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Second submit — claim content_hash matches, agent matches →
    // was_created=false. (Vary evidence text so the per-submission Evidence
    // row's own content_hash dedup doesn't collide; each submission emits
    // its own Evidence + Trace per the architecture doc, but the claim
    // itself is the dedup target this test cares about.)
    tools::claims::submit_claim(&server, make_params("evidence-resubmit-2"))
        .await
        .expect("second submit_claim");

    let after_second: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM events \
         WHERE event_type = 'claim.created' AND actor_id = $1",
    )
    .bind(server_agent_uuid)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        before_second, after_second,
        "resubmit must not emit a second claim.created event \
         (was_created=false → no event); before={before_second}, after={after_second}"
    );
}

/// Spec-review I1 regression guard: `ClaimRepository::create` is the
/// boundary that `tools/ingestion.rs::ingest_paper` (line 204) and the
/// API `routes/conventions.rs` paths call. Pre-fix the emit lived in
/// `claim_helper.rs::create_claim_idempotent`, which `ingest_paper` and
/// `ingest_paper_url` bypass entirely — so those paths never emitted
/// `claim.created`. This test calls `ClaimRepository::create` directly
/// (the smallest reproduction of the bug) and asserts the event surfaces.
#[tokio::test]
async fn claim_repo_create_emits_claim_created_event() {
    let pool = test_pool_or_skip!();
    let server = build_test_server(pool.clone(), [0xC5u8; 32]).await;

    // Insert a fresh agent so the FK is satisfied.
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    // Build a Claim with a unique content marker so we can pinpoint our
    // event among any existing rows in the shared test DB.
    let unique_marker = format!("ingest-path-emit-{}", Uuid::new_v4());
    let mut claim = Claim::new(
        unique_marker.clone(),
        AgentId::from_uuid(agent_id),
        [0u8; 32],
        TruthValue::new(0.5).unwrap(),
    );
    claim.content_hash = ContentHasher::hash(unique_marker.as_bytes());

    let before = chrono::Utc::now();

    let persisted = ClaimRepository::create(&pool, &claim)
        .await
        .expect("ClaimRepository::create succeeds");
    let persisted_id = persisted.id.as_uuid();

    let result = tools::events::list_events(
        &server,
        ListEventsParams {
            event_type: Some("claim.created".to_string()),
            actor_id: Some(agent_id.to_string()),
            limit: Some(50),
        },
    )
    .await
    .expect("list_events succeeds");

    let body = parse_list_events(&result);
    let recent: Vec<&serde_json::Value> = body["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["event_type"].as_str() == Some("claim.created")
                && e["payload"]["claim_id"].as_str() == Some(persisted_id.to_string().as_str())
                && e["created_at"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|t| t.with_timezone(&chrono::Utc) >= before)
                    .unwrap_or(false)
        })
        .collect();

    assert_eq!(
        recent.len(),
        1,
        "expected exactly one claim.created event for the claim we just \
         created via ClaimRepository::create (the boundary used by \
         tools/ingestion.rs::ingest_paper); got {body}"
    );
}

/// Spec-review I1 regression guard, second flavor: `tools/workflow_ingest.rs`
/// uses `ClaimRepository::create_with_id_if_absent`. Verify that path also
/// emits exactly once, and that re-running with the same id does NOT
/// double-emit (idempotent re-runs must not pollute the audit log).
#[tokio::test]
async fn claim_repo_create_with_id_if_absent_emits_once() {
    let pool = test_pool_or_skip!();
    let server = build_test_server(pool.clone(), [0xC6u8; 32]).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let unique_marker = format!("workflow-ingest-emit-{}", Uuid::new_v4());
    let claim_id = Uuid::new_v4();
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&ContentHasher::hash(unique_marker.as_bytes()));

    let before = chrono::Utc::now();

    let was_new1 = ClaimRepository::create_with_id_if_absent(
        &pool,
        claim_id,
        &unique_marker,
        &content_hash,
        agent_id,
        TruthValue::new(0.5).unwrap(),
        &["workflow_claim".to_string()],
    )
    .await
    .expect("first create_with_id_if_absent");
    assert!(was_new1, "first call must report was_inserted=true");

    // Second call with the same id should NOT emit a second event.
    let was_new2 = ClaimRepository::create_with_id_if_absent(
        &pool,
        claim_id,
        &unique_marker,
        &content_hash,
        agent_id,
        TruthValue::new(0.5).unwrap(),
        &["workflow_claim".to_string()],
    )
    .await
    .expect("second create_with_id_if_absent");
    assert!(!was_new2, "second call must report was_inserted=false");

    let result = tools::events::list_events(
        &server,
        ListEventsParams {
            event_type: Some("claim.created".to_string()),
            actor_id: Some(agent_id.to_string()),
            limit: Some(50),
        },
    )
    .await
    .expect("list_events succeeds");

    let body = parse_list_events(&result);
    let recent: Vec<&serde_json::Value> = body["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["event_type"].as_str() == Some("claim.created")
                && e["payload"]["claim_id"].as_str() == Some(claim_id.to_string().as_str())
                && e["created_at"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|t| t.with_timezone(&chrono::Utc) >= before)
                    .unwrap_or(false)
        })
        .collect();

    assert_eq!(
        recent.len(),
        1,
        "expected exactly one claim.created event for the workflow ingest \
         path (was_inserted gate must suppress the second call's emit); \
         got {body}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// agent.registered round-trip
// ────────────────────────────────────────────────────────────────────────────

/// Creating an agent via `AgentRepository::create` must emit an
/// `agent.registered` event visible via MCP `list_events`.
#[tokio::test]
async fn create_agent_emits_agent_registered_event() {
    let pool = test_pool_or_skip!();

    // Build a server only so we can call `list_events`. The agent we're
    // testing is freshly minted below.
    let server = build_test_server(pool.clone(), [0xC3u8; 32]).await;

    let pubkey = {
        let mut k = [0u8; 32];
        let id = Uuid::new_v4();
        k[..16].copy_from_slice(id.as_bytes());
        // mark second half so we don't collide with another fresh agent
        k[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        k
    };
    let agent = Agent::new(pubkey, Some("event-log-test-agent".to_string()));

    let before = chrono::Utc::now();

    let created = AgentRepository::create(&pool, &agent)
        .await
        .expect("create agent");

    let result = tools::events::list_events(
        &server,
        ListEventsParams {
            event_type: Some("agent.registered".to_string()),
            actor_id: Some(created.id.as_uuid().to_string()),
            limit: Some(10),
        },
    )
    .await
    .expect("list_events succeeds");

    let body = parse_list_events(&result);
    let recent: Vec<&serde_json::Value> = body["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["event_type"].as_str() == Some("agent.registered")
                && e["created_at"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|t| t.with_timezone(&chrono::Utc) >= before)
                    .unwrap_or(false)
        })
        .collect();

    assert_eq!(
        recent.len(),
        1,
        "expected exactly one fresh agent.registered event for the agent \
         we just created; got {body}"
    );
    assert_eq!(
        recent[0]["payload"]["agent_id"].as_str(),
        Some(created.id.as_uuid().to_string().as_str()),
    );
}

// ────────────────────────────────────────────────────────────────────────────
// tool.invoked round-trip
// ────────────────────────────────────────────────────────────────────────────

/// Invoking the MCP dispatch chokepoint (`emit_tool_invoked`, which
/// `ServerHandler::call_tool` calls for every dispatch) must produce a
/// `tool.invoked` event visible via `list_events`.
///
/// **Coverage gap (spec-review I2):** this test calls `emit_tool_invoked`
/// directly rather than going through `ServerHandler::call_tool`. A
/// future refactor that drops the `self.emit_tool_invoked(&request.name)`
/// line at server.rs would pass this test silently. Synthesizing a full
/// `rmcp::service::RequestContext` to drive `call_tool` end-to-end
/// requires plumbing rmcp internals (mock service handle, peer info,
/// cancellation token, etc.) that no other test in this crate constructs;
/// the cost-benefit didn't justify the scaffolding for this PR.
///
/// Compensating safeguard: server.rs:`call_tool` carries a comment
/// pointing at this test and noting the coupling, so a refactor that
/// removes the line is at least visibly tied to its observability
/// guarantee.
#[tokio::test]
async fn tool_dispatch_emits_tool_invoked_event() {
    let pool = test_pool_or_skip!();
    let server = build_test_server(pool.clone(), [0xC4u8; 32]).await;

    let before = chrono::Utc::now();

    // This is exactly what `ServerHandler::call_tool` does before
    // forwarding to the tool_router.
    server.emit_tool_invoked("system_stats").await;

    let result = tools::events::list_events(
        &server,
        ListEventsParams {
            event_type: Some("tool.invoked".to_string()),
            actor_id: None,
            limit: Some(50),
        },
    )
    .await
    .expect("list_events succeeds");

    let body = parse_list_events(&result);
    let recent: Vec<&serde_json::Value> = body["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["event_type"].as_str() == Some("tool.invoked")
                && e["payload"]["tool"].as_str() == Some("system_stats")
                && e["created_at"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|t| t.with_timezone(&chrono::Utc) >= before)
                    .unwrap_or(false)
        })
        .collect();

    assert!(
        !recent.is_empty(),
        "expected at least one fresh tool.invoked event with payload.tool=system_stats; \
         got {body}"
    );
}
