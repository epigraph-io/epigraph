#![cfg(feature = "db")]
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
mod common;

// ── negative / error-path tests ──────────────────────────────────────────────

/// No Authorization header → 401.
#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let fake_id = Uuid::new_v4();
    let body = serde_json::json!({
        "parent_id": fake_id,
        "content": "updated step",
        "edge_type": "supersedes",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/workflows/steps/{fake_id}/evolve"
        ))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 without token; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// Token with only `graph:read` (no `claims:write`) → 403.
#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_with_read_only_token_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["graph:read"]);
    let fake_id = Uuid::new_v4();
    let body = serde_json::json!({
        "parent_id": fake_id,
        "content": "updated step",
        "edge_type": "supersedes",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/workflows/steps/{fake_id}/evolve"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 for graph:read-only token; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// `parent_id` in JSON body differs from `{id}` in path → 400.
#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_mismatched_parent_id_returns_400() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let path_id = Uuid::new_v4();
    let body_id = Uuid::new_v4(); // deliberately different
    let body = serde_json::json!({
        "parent_id": body_id,
        "content": "updated step",
        "edge_type": "supersedes",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/workflows/steps/{path_id}/evolve"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        400,
        "expected 400 for path/body parent_id mismatch; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// Valid `claims:write` token but parent claim does not exist → 404.
#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_nonexistent_parent_returns_404() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let nonexistent = Uuid::new_v4();
    let body = serde_json::json!({
        "parent_id": nonexistent,
        "content": "updated step",
        "edge_type": "supersedes",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/workflows/steps/{nonexistent}/evolve"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        404,
        "expected 404 for non-existent parent; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_supersedes_creates_new_claim_and_edge() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // Seed an agent so the new claim's agent_id FK is satisfied.
    let agent_id = common::seed_system_agent(&pool).await;

    let parent = common::seed_claim(&pool, "parent step").await;
    sqlx::query("UPDATE claims SET labels = ARRAY['workflow_step']::text[] WHERE id = $1")
        .bind(parent)
        .execute(&pool)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;

    // A token in the shape `/oauth/token` mints: `sub` is the OAuth CLIENT
    // row's id (an `oauth_clients.id`, never an agent), `owner_id` is absent
    // for a service client, and the principal is `agent_id`. The handler must
    // author as that principal: authoring as `owner_id` / `sub` (the pre-fix
    // `auth.owner_id.unwrap_or(auth.client_id)`) wrote a claim whose author is
    // no agent, which the agents foreign key refuses (and, once migration 122
    // is armed, OPL01). A token whose `sub` IS an agent id hid that.
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let client_row_id = Uuid::new_v4();
    let (token, _) = cfg
        .issue_access_token(
            client_row_id,
            vec!["claims:write".into()],
            "service",
            None,
            Some(agent_id),
            chrono::Duration::minutes(60),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("test JWT");

    let body = serde_json::json!({
        "parent_id": parent,
        "content": "improved step",
        "edge_type": "supersedes",
        "reason": "tightened wording",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/workflows/steps/{parent}/evolve"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, 200, "body={text}");

    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let new_id: Uuid = json["claim_id"].as_str().unwrap().parse().unwrap();

    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(new_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        author, agent_id,
        "the evolved step is authored by the token's principal"
    );

    let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!parent_current);

    let edge_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = 'supersedes'"
    ).bind(new_id).bind(parent).fetch_one(&pool).await.unwrap();
    assert_eq!(edge_count, 1);

    // Backlog 8d3b4527, the branch prod takes: a request unit holds no
    // maintenance session (it refuses a maintenance DSN), so the Supersede
    // cascade is DEFERRED with the act, attributed to the token's principal,
    // naming the (retired step, head) pair the replay will migrate.
    assert_eq!(json["cascade"]["status"], "deferred", "body={text}");
    let event: Uuid = json["cascade"]["audit_event_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("the deferral names its audit row: {text}"));
    let (et, who, cause, subject, object): (String, Option<Uuid>, String, String, String) =
        sqlx::query_as(
            "SELECT event_type::text, agent_id, details->>'cause', \
                    details#>>'{trigger,subject_id}', details#>>'{trigger,object_id}' \
               FROM security_events WHERE id = $1",
        )
        .bind(event)
        .fetch_one(&pool)
        .await
        .expect("the cascade.deferred row");
    assert_eq!(
        (et.as_str(), cause.as_str()),
        ("cascade.deferred", "supersede")
    );
    assert_eq!(
        who,
        Some(agent_id),
        "the deferral is attributed to the token's principal"
    );
    assert_eq!(
        (subject, object),
        (parent.to_string(), new_id.to_string()),
        "the deferral names the (retired step, head) pair"
    );
}

/// Backlog 8d3b4527: `supersedes` runs the Supersede admin cascade, as
/// `POST /api/v1/claims/:id/supersede` does. With the cascade configured it is
/// APPLIED in the request: the decomposition parent's edge reaches the new
/// head, and the workflow's `executes` stays on the frozen step (heads are
/// resolved through the lineage).
#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_supersedes_runs_the_supersede_cascade() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let agent_id = common::seed_system_agent(&pool).await;
    let step = common::seed_claim(&pool, "a step with structure").await;
    let decomposer = common::seed_claim(&pool, "the step's decomposition parent").await;
    // The workflow records the token's principal as its submitter: an HTTP
    // evolve of a step a workflow executes needs workflow authority over it,
    // and a workflow with no recorded submitter admits only the audited admin
    // path.
    let workflow = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, metadata) \
         VALUES ($1, $2, 'evolve cascade http', jsonb_build_object('epigraph_submitted_by', $3::text))",
    )
    .bind(workflow)
    .bind(format!("evolve-cascade-http-{workflow}"))
    .bind(agent_id.to_string())
    .execute(&pool)
    .await
    .unwrap();
    let decomposes =
        common::insert_edge(&pool, decomposer, step, "claim", "claim", "decomposes_to").await;
    let executes =
        common::insert_edge(&pool, workflow, step, "workflow", "claim", "executes").await;

    let (addr, _shutdown) = common::spawn_app_with_admin_cascade(&url).await;
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:write".into()],
            "service",
            None,
            Some(agent_id),
            chrono::Duration::minutes(60),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("test JWT");

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/workflows/steps/{step}/evolve"
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "parent_id": step,
            "content": "the step, restated",
            "edge_type": "supersedes",
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, 200, "body={text}");
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["cascade"]["status"], "applied", "body={text}");
    let head: Uuid = json["claim_id"].as_str().unwrap().parse().unwrap();

    let ends = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (Uuid, Uuid)>(
                "SELECT source_id, target_id FROM edges WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert_eq!(
        ends(decomposes).await,
        (decomposer, head),
        "the decomposition parent reaches the new head"
    );
    assert_eq!(
        ends(executes).await,
        (workflow, step),
        "executes stays on the frozen step"
    );
}

/// `revises` supersedes nothing (both heads stay current), so even on a server
/// that could apply the Supersede cascade in the request it runs none and the
/// response carries no `cascade`.
#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_revises_runs_no_cascade() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let agent_id = common::seed_system_agent(&pool).await;
    let step = common::seed_claim(&pool, "a step to branch").await;
    let decomposer = common::seed_claim(&pool, "the branched step's parent").await;
    let decomposes =
        common::insert_edge(&pool, decomposer, step, "claim", "claim", "decomposes_to").await;

    let (addr, _shutdown) = common::spawn_app_with_admin_cascade(&url).await;
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:write".into()],
            "service",
            None,
            Some(agent_id),
            chrono::Duration::minutes(60),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("test JWT");

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/workflows/steps/{step}/evolve"
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "parent_id": step,
            "content": "a concurrent branch of the step",
            "edge_type": "revises",
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, 200, "body={text}");
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["edge_type"], "revises", "body={text}");
    assert!(
        json.get("cascade").is_none() && json.get("belief_cascade").is_none(),
        "a revises branch runs no cascade: body={text}"
    );
    let branch: Uuid = json["claim_id"].as_str().unwrap().parse().unwrap();
    assert_ne!(branch, step);
    let ends: (Uuid, Uuid) = sqlx::query_as("SELECT source_id, target_id FROM edges WHERE id = $1")
        .bind(decomposes)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        ends,
        (decomposer, step),
        "the branched-from step keeps its edges"
    );
}
