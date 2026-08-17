//! Recall audit-log WIRING (backlog 8cbffa0e / design F5).
//!
//! The repo contract is pinned in `epigraph-db/tests/recall_event_test.rs`.
//! What those cannot see is whether the recall handler actually logs — and
//! whether it logs the ids it really returned. A recall that silently writes
//! nothing would pass every repo test.

use chrono::TimeZone;
use epigraph_mcp::tools::memory::recall;
use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;
use epigraph_mcp::tools::recall::RecallWithContextParams;
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
/// different retrievals.
///
/// Scope: this pins the `recall` tool only — its `WHERE tool = 'recall'`
/// filter cannot see `recall_with_context` rows. The other half of G8.2 is
/// pinned by `since_is_recorded_in_recall_with_context_audit_params` and
/// `since_is_recorded_on_the_empty_recall_with_context_audit_row` below.
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

// ── G8.2, the `recall_with_context` half ──────────────────────────────────
//
// The test above filters `WHERE tool = 'recall'`, so it says nothing about
// `recall_with_context`'s two `"since": params.since` audit literals. Deleting
// BOTH of them left the entire suite green. The two tests below cover the two
// literals separately: the main path and the empty-result early return.

/// Poll for the most recent audit row written by `tool`, returning its
/// `params` JSON. The write is spawned, not awaited, so polling is the
/// contract, not a workaround.
async fn poll_audit_params(pool: &PgPool, tool: &str) -> serde_json::Value {
    for _ in 0..50 {
        if let Some(v) = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT params FROM recall_events WHERE tool = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tool)
        .fetch_optional(pool)
        .await
        .unwrap()
        {
            return v;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("{tool} must write an audit row with params");
}

fn since_fixture() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap()
}

/// 1536-d vector concentrated in the first eighth — the shape
/// `recall_with_context`'s level=2 ANN leg matches against.
fn pgvec_bucket0() -> String {
    let mut v = vec!["0.0"; 1536];
    for slot in v.iter_mut().take(192) {
        *slot = "1.0";
    }
    format!("[{}]", v.join(","))
}

async fn seed_paragraph(pool: &PgPool, agent: Uuid, content: &str, pgvec: &str) -> Uuid {
    let paper: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (id, doi, title) \
         VALUES (gen_random_uuid(), '10.audit/' || gen_random_uuid()::text, 'audit fixture') \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed paper");
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             properties, embedding) \
         VALUES ($1, sha256($1::bytea), 0.8, $2, true, \
                 jsonb_build_object('level', 2::int), $3::vector) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(pgvec)
    .fetch_one(pool)
    .await
    .expect("seed paragraph");
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper)
    .bind(id)
    .execute(pool)
    .await
    .expect("seed paper edge");
    id
}

fn context_params(since: chrono::DateTime<chrono::Utc>) -> RecallWithContextParams {
    serde_json::from_value(serde_json::json!({
        "query": "quorbiline",
        "min_truth": 0.0,
        "limit": 10,
        "centroid_dim": 1536,
        "since": since.to_rfc3339(),
    }))
    .expect("RecallWithContextParams")
}

/// The `recall_with_context` main-path audit literal records the window.
#[sqlx::test(migrations = "../../migrations")]
async fn since_is_recorded_in_recall_with_context_audit_params(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let pgvec = pgvec_bucket0();
    // Created now, so it is comfortably inside the 2025-06-01 window and the
    // call takes the PAGE path rather than the empty early return.
    seed_paragraph(&pool, agent, "quorbiline context window fixture", &pgvec).await;

    let server = build_test_server(pool.clone());
    let out =
        recall_with_context_with_pgvec(&server, context_params(since_fixture()), 1536, &pgvec)
            .await
            .expect("recall_with_context ok");
    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .unwrap();
    let env: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(
        !env["results"].as_array().unwrap().is_empty(),
        "fixture precondition: this must be the non-empty PAGE path, or the \
         assertion below would be testing the early-return literal instead"
    );

    let recorded = poll_audit_params(&pool, "recall_with_context").await;
    assert_eq!(
        recorded["since"]
            .as_str()
            .expect("recall_with_context must record `since` in its audit params")
            .parse::<chrono::DateTime<chrono::Utc>>()
            .expect("recorded since parses"),
        since_fixture(),
        "the audit row must record the window that was actually applied"
    );
}

/// The empty-result early return is the path whose auditability matters most:
/// "this window returned nothing at that time" is unsettleable without the
/// window that produced it. It has its OWN `json!` literal in
/// `recall_with_context_post_embed`, so the main-path test above does not
/// cover it.
#[sqlx::test(migrations = "../../migrations")]
async fn since_is_recorded_on_the_empty_recall_with_context_audit_row(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let pgvec = pgvec_bucket0();
    // Seeded, but OUTSIDE the window — so the window itself is what empties
    // the page, which is exactly the situation the audit row has to explain.
    let id = seed_paragraph(&pool, agent, "quorbiline archival paragraph", &pgvec).await;
    sqlx::query("UPDATE claims SET created_at = $2 WHERE id = $1")
        .bind(id)
        .bind(chrono::Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap())
        .execute(&pool)
        .await
        .expect("backdate");

    let server = build_test_server(pool.clone());
    let out =
        recall_with_context_with_pgvec(&server, context_params(since_fixture()), 1536, &pgvec)
            .await
            .expect("recall_with_context ok");
    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .unwrap();
    let env: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(
        env["results"].as_array().unwrap().is_empty(),
        "fixture precondition: the window must empty the page so the \
         early-return audit literal is the one under test; got {env}"
    );

    let recorded = poll_audit_params(&pool, "recall_with_context").await;
    assert_eq!(
        recorded["empty"],
        serde_json::json!(true),
        "precondition: this must be the early-return audit row"
    );
    assert_eq!(
        recorded["since"]
            .as_str()
            .expect(
                "the empty-result audit row must still record `since` — an empty \
                 page with no window recorded is indistinguishable from \"the \
                 corpus had nothing\""
            )
            .parse::<chrono::DateTime<chrono::Utc>>()
            .expect("recorded since parses"),
        since_fixture(),
        "the audit row must record the window that produced the empty result"
    );
}
