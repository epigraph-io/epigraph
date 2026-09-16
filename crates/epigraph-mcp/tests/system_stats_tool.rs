//! MCP `system_stats` after its SQL moved into
//! `epigraph_db::StatsRepository` (shared with `GET /api/v1/stats`).
//!
//! Nothing pinned this tool's output before, so the move had no regression
//! guard. These tests are that guard: the exact key set in each mode, and the
//! counts tracking seeded rows.

use epigraph_mcp::tools::batch::system_stats;
use epigraph_mcp::types::SystemStatsParams;
use rmcp::model::{CallToolResult, RawContent};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::{build_test_server, seed_agent};

fn parse(result: &CallToolResult) -> Value {
    let content = result.content.first().expect("one content block");
    match &content.raw {
        RawContent::Text(text) => {
            serde_json::from_str(&text.text).expect("system_stats emits JSON text")
        }
        other => panic!("expected text content, got {other:?}"),
    }
}

fn count(body: &Value, key: &str) -> i64 {
    body[key]
        .as_i64()
        .unwrap_or_else(|| panic!("{key} missing or not an integer in {body}"))
}

fn keys(body: &Value) -> Vec<String> {
    let mut k: Vec<String> = body.as_object().expect("object").keys().cloned().collect();
    k.sort();
    k
}

async fn seed_claim(pool: &PgPool, agent: Uuid, labels: &[&str]) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    let labels: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, 'system-stats fixture', $2, 0.5, $3, true, $4)",
    )
    .bind(id)
    .bind(&hash)
    .bind(agent)
    .bind(&labels)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn default_mode_reports_exactly_the_five_corpus_counts(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let before = parse(
        &system_stats(&server, SystemStatsParams { detailed: None })
            .await
            .expect("system_stats"),
    );
    assert_eq!(
        keys(&before),
        vec!["agents", "claims", "edges", "evidence", "frames"],
        "the un-detailed key set is part of this tool's contract"
    );

    let agent = seed_agent(&pool).await;
    seed_claim(&pool, agent, &[]).await;

    let after = parse(
        &system_stats(
            &server,
            SystemStatsParams {
                detailed: Some(false),
            },
        )
        .await
        .expect("system_stats"),
    );
    assert_eq!(keys(&after), keys(&before));
    assert_eq!(count(&after, "claims") - count(&before, "claims"), 1);
    assert_eq!(count(&after, "agents") - count(&before, "agents"), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn detailed_mode_adds_the_six_extra_counts(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let before = parse(
        &system_stats(
            &server,
            SystemStatsParams {
                detailed: Some(true),
            },
        )
        .await
        .expect("system_stats detailed"),
    );
    assert_eq!(
        keys(&before),
        vec![
            "agents",
            "challenges",
            "claims",
            "edges",
            "embeddings",
            "entities",
            "entity_mentions",
            "evidence",
            "frames",
            "triples",
            "workflows",
        ],
        "the detailed key set is part of this tool's contract"
    );

    // A `workflow` is a claim carrying the `workflow` label, not a `workflows`
    // row — the definition this tool has always reported.
    let agent = seed_agent(&pool).await;
    seed_claim(&pool, agent, &["method"]).await;
    seed_claim(&pool, agent, &["workflow"]).await;

    let after = parse(
        &system_stats(
            &server,
            SystemStatsParams {
                detailed: Some(true),
            },
        )
        .await
        .expect("system_stats detailed"),
    );
    assert_eq!(count(&after, "claims") - count(&before, "claims"), 2);
    assert_eq!(count(&after, "workflows") - count(&before, "workflows"), 1);
    assert_eq!(count(&after, "embeddings"), count(&before, "embeddings"));
}
