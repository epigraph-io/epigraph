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
            frame_id: None,
            perspective_id: None,
        },
        None,
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
            frame_id: None,
            perspective_id: None,
        },
        None,
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

/// Discriminating redaction regression (A3 §7.5, Task 11): a `private`-partition
/// claim must return its full content to the OWNER and exactly `"[REDACTED]"` to
/// a stranger. The stranger assertion is what fails if the redaction branch in
/// `get_claim` is deleted or inverted — making this test discriminating where
/// the `None`-requester tests above are not (those have no ownership row, so
/// `check_content_access` returns `Full` and the redaction branch is never run).
#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_redacts_private_content_for_strangers(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let claim_id = seed_claim(&pool, owner, &[], true, None).await;
    let expected_content = format!("test claim {}", claim_id.as_uuid());

    // Mark the claim private, owned by `owner`.
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2)",
    )
    .bind(claim_id.as_uuid())
    .bind(owner)
    .execute(&pool)
    .await
    .expect("seed private ownership");

    let server = build_test_server(pool.clone());

    // Owner requester → full content AND the real content_hash.
    let owner_body = parse_claim(
        &get_claim(
            &server,
            GetClaimParams {
                claim_id: claim_id.as_uuid().to_string(),
            },
            Some(owner),
        )
        .await
        .expect("get_claim as owner"),
    );
    assert_eq!(
        owner_body["content"].as_str().unwrap(),
        expected_content,
        "owner must see the full private content"
    );
    assert!(
        !owner_body["content_hash"].as_str().unwrap().is_empty(),
        "owner must see the real content_hash (proves blanking is conditional, \
         not always-blank): {owner_body:?}"
    );

    // Stranger requester (a different, non-owner agent id) → content AND
    // content_hash both redacted. The hash assertion guards the
    // confirmation-oracle leak: content_hash = BLAKE3(content), so leaking it
    // for a redacted claim re-exposes the redacted field.
    let stranger = Uuid::new_v4();
    let stranger_body = parse_claim(
        &get_claim(
            &server,
            GetClaimParams {
                claim_id: claim_id.as_uuid().to_string(),
            },
            Some(stranger),
        )
        .await
        .expect("get_claim as stranger"),
    );
    assert_eq!(
        stranger_body["content"].as_str().unwrap(),
        "[REDACTED]",
        "stranger must NOT see private content — this fails if the redaction \
         branch is deleted or inverted"
    );
    assert_eq!(
        stranger_body["content_hash"].as_str().unwrap(),
        "",
        "stranger must NOT see the content_hash — BLAKE3(content) is a \
         confirmation oracle for the redacted content"
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
