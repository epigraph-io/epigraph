//! Behavioral test for the `get_workflow_executions` MCP tool — the read-only
//! window into a workflow's recent behavioral executions that the workflow-
//! evolution (GEPA) proposer consumes. Mirrors the server-construction harness
//! in `recompute_beliefs_test.rs`.

use epigraph_crypto::AgentSigner;
use epigraph_db::{BehavioralExecutionRepository, BehavioralExecutionRow};
use epigraph_mcp::types::GetWorkflowExecutionsParams;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::RawContent;
use sqlx::PgPool;
use uuid::Uuid;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x2bu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

fn result_json(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let first = out.content.first().cloned().expect("first content");
    match first.raw {
        RawContent::Text(t) => serde_json::from_str(&t.text).expect("result is JSON"),
        other => panic!("expected text content, got {other:?}"),
    }
}

async fn insert_agent(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system', ARRAY['test'])
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn insert_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_workflow_executions_returns_recent_rows(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "gwe-agent").await;
    let wf = insert_claim(&pool, agent, "gwe-workflow-root").await;

    let base = chrono::Utc::now();
    for (i, (succ, goal)) in [(true, "run-old"), (false, "run-new")].iter().enumerate() {
        let row = BehavioralExecutionRow {
            id: Uuid::new_v4(),
            workflow_id: wf,
            goal_text: (*goal).to_string(),
            success: *succ,
            step_beliefs: serde_json::json!({"deviation_reason": "none"}),
            tool_pattern: vec!["bash".into()],
            quality: Some(0.7),
            deviation_count: 0,
            total_steps: 2,
            created_at: base + chrono::Duration::seconds(i as i64),
            step_claim_id: None,
            run_label: None,
        };
        BehavioralExecutionRepository::create(&pool, row, None)
            .await
            .unwrap();
    }

    let out = tools::workflows::get_workflow_executions(
        &server,
        GetWorkflowExecutionsParams {
            workflow_id: wf.to_string(),
            limit: Some(10),
        },
    )
    .await
    .expect("get_workflow_executions ok");
    let json = result_json(out);

    assert_eq!(json["returned"], 2, "both executions returned");
    let execs = json["executions"].as_array().expect("executions array");
    assert_eq!(execs.len(), 2);
    // Newest first: the second-inserted ("run-new") leads.
    assert_eq!(execs[0]["goal_text"], "run-new");
    assert_eq!(execs[0]["success"], false);
    assert!(
        execs[0]["step_beliefs"].is_object(),
        "step_beliefs surfaced for reflection"
    );

    // A non-UUID workflow_id must be rejected, NOT silently return an empty set
    // (that would be a confusing false negative for the proposer).
    let bad = tools::workflows::get_workflow_executions(
        &server,
        GetWorkflowExecutionsParams {
            workflow_id: "not-a-uuid".into(),
            limit: None,
        },
    )
    .await;
    assert!(
        bad.is_err(),
        "invalid workflow_id must error, not return empty"
    );
}
