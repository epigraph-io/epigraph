//! Behavioral test for the `get_workflow_executions` MCP tool — the read-only
//! window into a workflow's recent behavioral executions that the workflow-
//! evolution (GEPA) proposer consumes. Mirrors the server-construction harness
//! in `recompute_beliefs_test.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_db::{BehavioralExecutionRepository, BehavioralExecutionRow};
use epigraph_mcp::types::GetWorkflowExecutionsParams;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::ContentBlock;
use sqlx::PgPool;
use uuid::Uuid;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x2bu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    {
        // Every deployed server carries a ScopedPool; content reads refuse
        // without one (`EpiGraphMcpFull::read_as`). Lazy, on this fixture's
        // own connect options.
        let scoped = epigraph_db::ScopedPool::connect_lazy_for_tests(
            (*pool.connect_options()).clone(),
            epigraph_db::SessionGucMode::Session,
        );
        EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
    }
}

fn result_json(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let first = out.content.first().cloned().expect("first content");
    match first {
        ContentBlock::Text(t) => serde_json::from_str(&t.text).expect("result is JSON"),
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
    let viewer = fixture::public_viewer(&pool).await;
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
        &viewer,
        GetWorkflowExecutionsParams {
            include_deviation_summary: None,
            window_days: None,
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
        &viewer,
        GetWorkflowExecutionsParams {
            include_deviation_summary: None,
            window_days: None,
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

/// A step claim with an explicit `step_lineage_id`.
async fn insert_step(pool: &PgPool, agent: Uuid, content: &str, lineage: Uuid) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             step_lineage_id, properties)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, $3, '{\"level\": 2}'::jsonb) \
         RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(lineage)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// One hierarchical step row, `age_days` old.
async fn step_row(
    pool: &PgPool,
    wf: Uuid,
    step: Option<Uuid>,
    deviated: bool,
    reason: Option<&str>,
    age_days: i64,
) {
    BehavioralExecutionRepository::create(
        pool,
        BehavioralExecutionRow {
            id: Uuid::new_v4(),
            workflow_id: wf,
            goal_text: "deviation summary run".into(),
            success: !deviated,
            step_beliefs: serde_json::json!({"deviated": deviated, "deviation_reason": reason}),
            tool_pattern: vec!["step".into()],
            quality: Some(0.5),
            deviation_count: i32::from(deviated),
            total_steps: 1,
            created_at: chrono::Utc::now() - chrono::Duration::days(age_days),
            step_claim_id: step,
            run_label: None,
        },
        None,
    )
    .await
    .unwrap();
}

async fn summary(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    wf: Uuid,
    window_days: Option<i32>,
) -> serde_json::Value {
    result_json(
        tools::workflows::get_workflow_executions(
            server,
            viewer,
            GetWorkflowExecutionsParams {
                workflow_id: wf.to_string(),
                limit: Some(5),
                include_deviation_summary: Some(true),
                window_days,
            },
        )
        .await
        .expect("get_workflow_executions ok"),
    )
}

/// Backlog 0a2ed32d: `include_deviation_summary` rolls the per-step
/// `deviation_reason`s up by STEP LINEAGE over the window: two step claims of
/// one lineage (an evolved step) count together and name the newest claim;
/// the same reason on another lineage is its own entry; rows that did not
/// deviate, gave no reason, fall outside the window, or carry no step claim
/// (a flat report's shape) are not counted. On the old code the tool had no
/// such field.
#[sqlx::test(migrations = "../../migrations")]
async fn the_deviation_summary_groups_recurring_reasons_by_step_lineage(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "gwe-dev-agent").await;
    let wf = Uuid::new_v4();
    epigraph_db::WorkflowRepository::insert_root(
        &pool,
        wf,
        &format!("gwe-dev-{wf}"),
        0,
        "deviation summary workflow",
        None,
        serde_json::json!({}),
        epigraph_core::TenancyDecl::inherited(),
    )
    .await
    .unwrap();
    let (la, lb) = (Uuid::new_v4(), Uuid::new_v4());
    let a1 = insert_step(&pool, agent, &format!("step a v1 {wf}"), la).await;
    let a2 = insert_step(&pool, agent, &format!("step a v2 {wf}"), la).await;
    let b = insert_step(&pool, agent, &format!("step b {wf}"), lb).await;

    step_row(&pool, wf, Some(a1), true, Some("flaky network"), 5).await;
    step_row(&pool, wf, Some(a2), true, Some("  flaky network "), 2).await;
    step_row(&pool, wf, Some(b), true, Some("flaky network"), 3).await;
    step_row(&pool, wf, Some(b), true, Some("missing creds"), 1).await;
    // Not counted: no deviation, a blank reason, outside 30 days, no step.
    step_row(&pool, wf, Some(a1), false, Some("flaky network"), 1).await;
    step_row(&pool, wf, Some(a1), true, Some("   "), 1).await;
    step_row(&pool, wf, Some(a1), true, Some("flaky network"), 40).await;
    step_row(&pool, wf, None, true, Some("flaky network"), 1).await;

    let json = summary(&server, &viewer, wf, None).await;
    assert_eq!(json["deviation_summary"]["window_days"], 30, "{json}");
    let reasons = json["deviation_summary"]["reasons"]
        .as_array()
        .expect("reasons array")
        .iter()
        .map(|r| {
            (
                r["step_lineage_id"].as_str().unwrap().to_string(),
                r["deviation_reason"].as_str().unwrap().to_string(),
                r["occurrences"].as_i64().unwrap(),
                r["latest_step_claim_id"].as_str().unwrap().to_string(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        reasons,
        vec![
            (la.to_string(), "flaky network".into(), 2, a2.to_string()),
            (lb.to_string(), "missing creds".into(), 1, b.to_string()),
            (lb.to_string(), "flaky network".into(), 1, b.to_string()),
        ],
        "{json}"
    );

    // A wider window takes in the 40-day-old run.
    let wide = summary(&server, &viewer, wf, Some(60)).await;
    assert_eq!(
        wide["deviation_summary"]["reasons"][0]["occurrences"], 3,
        "{wide}"
    );

    // Without the flag the response is unchanged.
    let plain = result_json(
        tools::workflows::get_workflow_executions(
            &server,
            &viewer,
            GetWorkflowExecutionsParams {
                workflow_id: wf.to_string(),
                limit: Some(5),
                include_deviation_summary: None,
                window_days: None,
            },
        )
        .await
        .unwrap(),
    );
    assert!(plain.get("deviation_summary").is_none(), "{plain}");
}
