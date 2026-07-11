//! Integration test for [`resolve_backlog_item`] (Task 6 of the
//! backlog-retirement plan): one-call retirement that submits a resolution
//! claim via the canonical `submit_claim` pipeline AND patches the original
//! claim's labels with `add=["resolved"]`.
//!
//! Seeds one open backlog claim, calls the new tool, and verifies:
//!   - the returned resolution claim is a real UUID;
//!   - the resolution claim's content is prefixed with `Resolves <id>: `;
//!   - the resolution claim is labeled `resolved`;
//!   - the original claim now carries BOTH `backlog` and `resolved` labels;
//!   - the original claim is NOT superseded (is_current stays true, supersedes
//!     stays None) — resolution is label-side, not lineage-side.

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use epigraph_mcp::tools::claims::resolve_backlog_item;
use epigraph_mcp::types::ResolveBacklogItemParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

#[sqlx::test(migrations = "../../migrations")]
async fn resolve_backlog_item_creates_resolution_and_patches_original(pool: PgPool) {
    let server = build_test_server(pool.clone());

    // Author the backlog claim through the MCP server's own signer so the
    // owner-or-admin check inside resolve_backlog_item succeeds. (The
    // server's signer agent is registered as a side-effect of submit_claim;
    // we then look up its UUID via the just-created claim.)
    let server_agent = bootstrap_server_agent(&server, &pool).await;
    let original = seed_claim(&pool, server_agent, &["backlog"], true, None).await;

    let result = resolve_backlog_item(
        &server,
        ResolveBacklogItemParams {
            original_id: original.as_uuid().to_string(),
            resolution_content: "Fixed by replacing the index with a GIN BTREE.".to_string(),
            methodology: None,
        },
        None,
    )
    .await
    .expect("resolve_backlog_item");

    let body = parse_json(&result);

    // resolution_claim_id round-trips as a UUID.
    let resolution_id_str = body["resolution_claim_id"]
        .as_str()
        .expect("resolution_claim_id is string");
    let resolution_id: Uuid = resolution_id_str.parse().expect("valid UUID");

    // original_labels surfaces both backlog (kept) and resolved (added).
    let labels: Vec<String> = body["original_labels"]
        .as_array()
        .expect("original_labels is array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        labels.contains(&"backlog".to_string()),
        "original_labels must still contain 'backlog': {labels:?}"
    );
    assert!(
        labels.contains(&"resolved".to_string()),
        "original_labels must now contain 'resolved': {labels:?}"
    );

    // Fetch the resolution claim and assert content prefix + labels.
    let resolution = ClaimRepository::get_by_id(&pool, ClaimId::from_uuid(resolution_id))
        .await
        .expect("get_by_id resolution")
        .expect("resolution claim exists");
    let expected_prefix = format!("Resolves {}: ", original.as_uuid());
    assert!(
        resolution.content.starts_with(&expected_prefix),
        "resolution content must start with {expected_prefix:?}, got {:?}",
        resolution.content
    );

    let resolution_labels = ClaimRepository::get_labels(&pool, ClaimId::from_uuid(resolution_id))
        .await
        .expect("get_labels resolution");
    assert!(
        resolution_labels.contains(&"resolved".to_string()),
        "resolution claim must be labeled 'resolved': {resolution_labels:?}"
    );

    // Re-fetch the original and confirm label PATCH stuck without touching
    // is_current / supersedes (label-side retirement, not lineage-side).
    let original_after = ClaimRepository::get_by_id(&pool, original)
        .await
        .expect("get_by_id original")
        .expect("original claim still exists");
    let original_labels = ClaimRepository::get_labels(&pool, original)
        .await
        .expect("get_labels original");
    assert!(
        original_labels.contains(&"backlog".to_string()),
        "original must retain 'backlog': {original_labels:?}"
    );
    assert!(
        original_labels.contains(&"resolved".to_string()),
        "original must now carry 'resolved': {original_labels:?}"
    );
    assert!(
        original_after.is_current,
        "original is_current must stay true (label-side retirement)"
    );
    assert!(
        original_after.supersedes.is_none(),
        "original supersedes must stay None (label-side retirement)"
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

/// Submit a throwaway claim through the server so its signer agent is
/// registered, then return that agent's UUID. We need the server-signer
/// agent (not a freshly-seeded random agent) because
/// `resolve_backlog_item` now enforces caller-owns-claim.
async fn bootstrap_server_agent(server: &epigraph_mcp::EpiGraphMcpFull, pool: &PgPool) -> Uuid {
    let result = epigraph_mcp::tools::claims::submit_claim(
        server,
        epigraph_mcp::types::SubmitClaimParams {
            content: "bootstrap claim for resolve_backlog_item test".into(),
            methodology: "deductive_logic".into(),
            evidence_data: "ev".into(),
            evidence_type: "logical".into(),
            confidence: 0.5,
            source_url: None,
            reasoning: None,
            labels: vec![],
            novelty_threshold: None,
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
