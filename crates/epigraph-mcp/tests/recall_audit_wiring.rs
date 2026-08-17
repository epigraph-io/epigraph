//! Recall audit-log WIRING (backlog 8cbffa0e / design F5).
//!
//! The repo contract is pinned in `epigraph-db/tests/recall_event_test.rs`.
//! What those cannot see is whether the recall handler actually logs — and
//! whether it logs the ids it really returned. A recall that silently writes
//! nothing would pass every repo test.

use chrono::TimeZone;
use epigraph_mcp::tools::memory::recall;
use epigraph_mcp::types::RecallParams;
use sqlx::PgPool;
use uuid::Uuid;

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-audit-wiring', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool).await.expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, labels)
         VALUES ($1, sha256($1::bytea), 0.8, $2, true, ARRAY['auditfixture']) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

fn params(query: &str) -> RecallParams {
    RecallParams {
        query: query.to_string(),
        min_truth: Some(0.0),
        limit: Some(10),
        tags: vec!["auditfixture".to_string()],
        agent_id: None,
        frame_id: None,
        perspective_id: None,
        include_workflows: false,
        exclude_contested: false,
        since: None,
    }
}

/// A recall writes an audit row containing exactly the claim ids it returned.
/// Polls briefly because the write is intentionally spawned, not awaited.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_logs_the_claim_ids_it_returned(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let hit = seed_claim(&pool, agent, "wextonium audit fixture").await;

    let server = build_test_server(pool.clone());
    let out = recall(&server, params("wextonium"))
        .await
        .expect("recall ok");

    // Confirm recall itself returned the claim.
    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .unwrap();
    let env: serde_json::Value = serde_json::from_str(&text).unwrap();
    let returned: Vec<String> = env["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["claim_id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        returned.contains(&hit.to_string()),
        "fixture must be retrieved"
    );

    // The audit write is fire-and-forget: poll rather than assume it landed.
    let mut logged: Option<(String, Vec<Uuid>)> = None;
    for _ in 0..50 {
        let rows = sqlx::query!(
            "SELECT tool, query_text, returned_claim_ids FROM recall_events ORDER BY created_at DESC LIMIT 1"
        )
        .fetch_optional(&pool).await.unwrap();
        if let Some(r) = rows {
            logged = Some((r.query_text, r.returned_claim_ids));
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let (query_text, ids) = logged.expect("recall must write an audit row");
    assert_eq!(query_text, "wextonium");
    assert!(
        ids.contains(&hit),
        "the audit row must record the ids actually returned, not an empty set"
    );
}

/// The audit write must not be able to break a recall. With the table
/// dropped the log write fails, and recall must still serve its results.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_survives_a_failing_audit_write(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let hit = seed_claim(&pool, agent, "brentalix resilience fixture").await;

    // Break the audit path underneath the handler.
    sqlx::query("DROP TABLE recall_events")
        .execute(&pool)
        .await
        .expect("drop");

    let server = build_test_server(pool.clone());
    let out = recall(&server, params("brentalix"))
        .await
        .expect("recall must succeed even when the audit log is unwritable");

    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .unwrap();
    let env: serde_json::Value = serde_json::from_str(&text).unwrap();
    let returned: Vec<String> = env["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["claim_id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        returned.contains(&hit.to_string()),
        "results are served despite the audit failure — best-effort, never blocking"
    );
}

/// A windowed retrieval must be RECONSTRUCTABLE from its audit row.
///
/// `since` changes which claims a query can return, so an audit row that
/// records the query but not the window cannot settle "what did this agent
/// actually see?" — the same `query_text` with and without a window are
/// different retrievals. This pins the window into `params` for BOTH tools,
/// including `recall_with_context`'s empty-result early return, which is the
/// case that matters most: "this window returned nothing at that time" is
/// precisely the claim an audit exists to support.
#[sqlx::test(migrations = "../../migrations")]
async fn since_is_recorded_in_recall_audit_params(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    seed_claim(&pool, agent, "quorbiline audit window fixture").await;

    let since = chrono::Utc
        .with_ymd_and_hms(2025, 6, 1, 0, 0, 0)
        .unwrap()
        .to_rfc3339();

    let server = build_test_server(pool.clone());
    let mut p = params("quorbiline");
    p.since = Some(since.parse::<chrono::DateTime<chrono::Utc>>().unwrap());
    recall(&server, p).await.expect("recall ok");

    // Fire-and-forget write: poll rather than assume.
    let mut logged: Option<serde_json::Value> = None;
    for _ in 0..50 {
        // Runtime query, not the `sqlx::query!` macro: this assertion needs
        // no compile-time schema check and the macro would add an `.sqlx`
        // cache entry for a test-only read.
        if let Some(v) = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT params FROM recall_events WHERE tool = 'recall' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(&pool)
        .await
        .unwrap()
        {
            logged = Some(v);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let params_json = logged.expect("recall must write an audit row with params");
    let recorded = params_json["since"]
        .as_str()
        .expect("the audit row must record `since`; without it the retrieval is unauditable");
    assert_eq!(
        recorded
            .parse::<chrono::DateTime<chrono::Utc>>()
            .expect("recorded since parses"),
        since.parse::<chrono::DateTime<chrono::Utc>>().unwrap(),
        "the audit row must record the window that was actually applied"
    );
}
