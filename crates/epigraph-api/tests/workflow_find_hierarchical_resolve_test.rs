#![cfg(feature = "db")]
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn find_workflow_hierarchical_resolve_to_latest_includes_resolved_steps() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // Seed a workflow row in the workflows table; the search filters on goal/canonical_name ILIKE.
    // The workflows table has columns: id, canonical_name, goal, generation, parent_id, metadata, created_at.
    let workflow_id = Uuid::new_v4();
    let unique_goal = format!("resolve_test_goal_{workflow_id}");
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, generation, metadata) \
         VALUES ($1, $2, $3, 0, '{}'::jsonb)",
    )
    .bind(workflow_id)
    .bind(format!("test_workflow_{workflow_id}"))
    .bind(&unique_goal)
    .execute(&pool)
    .await
    .expect("seed workflow");

    let (addr, _shutdown) = common::spawn_app(&url).await;
    // PR-03: this route moved to the protected router. The token must carry a
    // non-null `agent_id`; `mint_token_with_agent` is the only tests/common
    // helper that sets one.
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());

    // Default: resolve_to_latest=false → no resolved_steps key.
    let resp_default: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/workflows/hierarchical/search?q={unique_goal}"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp_default["resolve_to_latest"], serde_json::json!(false));
    assert!(resp_default["workflows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|w| w.get("resolved_steps").is_none()));

    // resolve_to_latest=true → each workflow has a resolved_steps array.
    let resp_resolved: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/workflows/hierarchical/search?q={unique_goal}&resolve_to_latest=true"))
        .bearer_auth(&token)
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(resp_resolved["resolve_to_latest"], serde_json::json!(true));
    let workflows = resp_resolved["workflows"].as_array().unwrap();
    assert!(!workflows.is_empty(), "search should find seeded workflow");
    assert!(
        workflows.iter().all(|w| w["resolved_steps"].is_array()),
        "every workflow must have resolved_steps array when resolve_to_latest=true"
    );
}

/// HTTP twin of the MCP `resolve_to_latest_returns_true_lineage_head`
/// (bridge 37d65fe0, backlog ed6a953e / 21574bd2): the route filtered on each
/// row's own goal text before ordering, so a lineage head whose goal diverged
/// from the query was never returned and `resolve_to_latest=true` reported a
/// lower generation than `improve_workflow_hierarchy` builds on.
#[tokio::test(flavor = "multi_thread")]
async fn find_workflow_hierarchical_resolve_to_latest_returns_true_lineage_head() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // This file shares one database: every name and phrase is unique.
    let tag = Uuid::new_v4().simple().to_string();
    let canonical = format!("lineage-head-http-{}", &tag[..12]);
    let old_phrase = format!("qqold{tag}");
    let mut head = Uuid::nil();
    for generation in 0..4 {
        let id = Uuid::new_v4();
        let goal = if generation < 3 {
            format!("consider {old_phrase} tools")
        } else {
            format!("rewritten qqnew{tag} plan")
        };
        sqlx::query(
            "INSERT INTO workflows (id, canonical_name, goal, generation, metadata) \
             VALUES ($1, $2, $3, $4, '{}'::jsonb)",
        )
        .bind(id)
        .bind(&canonical)
        .bind(&goal)
        .bind(generation)
        .execute(&pool)
        .await
        .expect("seed generation");
        head = id;
    }

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/workflows/hierarchical/search?q={old_phrase}&resolve_to_latest=true&min_truth=0"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let workflows = body["workflows"].as_array().expect("workflows array");
    let head_entry = workflows
        .iter()
        .find(|w| w["workflow_id"].as_str() == Some(&head.to_string()))
        .unwrap_or_else(|| panic!("the true lineage head (gen 3) must be returned; got {body}"));
    assert_eq!(head_entry["generation"], serde_json::json!(3));
    assert_eq!(head_entry["is_lineage_head"], serde_json::json!(true));
    assert!(head_entry["resolved_steps"].is_array());
    assert_eq!(
        workflows.len(),
        4,
        "three matched generations plus the head"
    );
    for w in workflows {
        assert_eq!(w["lineage_head_generation"], serde_json::json!(3), "{w}");
        assert_eq!(
            w["lineage_head_deprecated"],
            serde_json::json!(false),
            "{w}"
        );
    }

    // Default mode is unchanged: matched rows only, no annotations.
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/workflows/hierarchical/search?q={old_phrase}&min_truth=0"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let workflows = body["workflows"].as_array().unwrap();
    assert_eq!(workflows.len(), 3);
    assert!(workflows.iter().all(|w| w.get("is_lineage_head").is_none()));
}

/// HTTP twin of the MCP `retired_step_head_is_flagged_and_evolve_step_names_the_retirement`
/// (bridge 00132b1d): a step lineage head is defined by "no incoming
/// supersedes edge", while `evolve_step`'s guard reads `claims.is_current`. A
/// head retired without a supersedes edge was presented here as an ordinary
/// head, so a caller could not tell that superseding it would be refused. It
/// stays listed (a sole lineage member must not vanish) and is flagged.
#[tokio::test(flavor = "multi_thread")]
async fn find_workflow_hierarchical_flags_a_retired_step_head() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let tag = Uuid::new_v4().simple().to_string();
    let agent = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at) \
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(agent)
    .execute(&pool)
    .await
    .expect("seed agent");

    let workflow_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, generation, metadata) \
         VALUES ($1, $2, $3, 0, '{}'::jsonb)",
    )
    .bind(workflow_id)
    .bind(format!("retired-head-http-{tag}"))
    .bind(format!("retired head probe qq{tag}"))
    .execute(&pool)
    .await
    .expect("seed workflow");

    let mut steps = Vec::new();
    for (i, current) in [true, false].into_iter().enumerate() {
        let id = Uuid::new_v4();
        let mut hash: Vec<u8> = id.as_bytes().to_vec();
        hash.resize(32, 0);
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, step_lineage_id) \
             VALUES ($1, $2, $3, $4, 0.5, jsonb_build_object('level', 2), gen_random_uuid())",
        )
        .bind(id)
        .bind(format!("step {i} {tag}"))
        .bind(hash)
        .bind(agent)
        .execute(&pool)
        .await
        .expect("seed step");
        if !current {
            sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .expect("retire step");
        }
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
             VALUES (gen_random_uuid(), $1, 'workflow', $2, 'claim', 'executes', jsonb_build_object('plan_index', $3::int))",
        )
        .bind(workflow_id)
        .bind(id)
        .bind(i as i32)
        .execute(&pool)
        .await
        .expect("seed executes edge");
        steps.push(id);
    }

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/workflows/hierarchical/search?q=qq{tag}&resolve_to_latest=true"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let wf = body["workflows"]
        .as_array()
        .expect("workflows array")
        .iter()
        .find(|w| w["workflow_id"].as_str() == Some(&workflow_id.to_string()))
        .unwrap_or_else(|| panic!("seeded workflow returned; got {body}"));
    let resolved = wf["resolved_steps"].as_array().expect("resolved_steps");
    assert_eq!(resolved.len(), 2, "{wf}");
    assert_eq!(
        resolved[0]["heads"][0]["id"].as_str(),
        Some(steps[0].to_string().as_str())
    );
    assert_eq!(
        resolved[0]["heads"][0]["is_current"],
        serde_json::json!(true),
        "a healthy head reports true: {wf}"
    );
    assert_eq!(
        resolved[1]["heads"][0]["id"].as_str(),
        Some(steps[1].to_string().as_str()),
        "the retired sole member is still listed: {wf}"
    );
    assert_eq!(
        resolved[1]["heads"][0]["is_current"],
        serde_json::json!(false),
        "the retired head is flagged: {wf}"
    );
}

/// HTTP twin of the MCP `resolve_to_latest_discloses_a_deprecated_head`. The
/// route computes `lineage_head_deprecated` itself (head truth below
/// `min_truth`), so the flag's true branch needs its own HTTP case: a head
/// deprecated to truth 0.05 under the default `min_truth` (0.3) is returned,
/// marked the head, and every entry of its lineage says it is deprecated.
#[tokio::test(flavor = "multi_thread")]
async fn find_workflow_hierarchical_resolve_to_latest_flags_a_deprecated_head() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let tag = Uuid::new_v4().simple().to_string();
    let canonical = format!("deprecated-head-http-{}", &tag[..12]);
    let phrase = format!("qqdep{tag}");
    let live = Uuid::new_v4();
    let dead = Uuid::new_v4();
    for (id, generation, truth) in [(live, 0_i32, 1.0_f64), (dead, 1, 0.05)] {
        sqlx::query(
            "INSERT INTO workflows (id, canonical_name, goal, generation, metadata, truth_value) \
             VALUES ($1, $2, $3, $4, '{}'::jsonb, $5)",
        )
        .bind(id)
        .bind(&canonical)
        .bind(format!("send the {phrase} digest v{generation}"))
        .bind(generation)
        .bind(truth)
        .execute(&pool)
        .await
        .expect("seed generation");
    }

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/workflows/hierarchical/search?q={phrase}&resolve_to_latest=true"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let workflows = body["workflows"].as_array().expect("workflows array");
    let entry = |id: Uuid| {
        workflows
            .iter()
            .find(|w| w["workflow_id"].as_str() == Some(&id.to_string()))
            .unwrap_or_else(|| panic!("workflow {id} must be returned; got {body}"))
    };
    let dead_entry = entry(dead);
    assert_eq!(dead_entry["is_lineage_head"], serde_json::json!(true));
    assert_eq!(dead_entry["generation"], serde_json::json!(1));
    assert_eq!(entry(live)["is_lineage_head"], serde_json::json!(false));
    assert_eq!(workflows.len(), 2, "{body}");
    for w in workflows {
        assert_eq!(w["lineage_head_generation"], serde_json::json!(1), "{w}");
        assert_eq!(
            w["lineage_head_deprecated"],
            serde_json::json!(true),
            "the head's truth (0.05) is below the default min_truth: {w}"
        );
    }
}
