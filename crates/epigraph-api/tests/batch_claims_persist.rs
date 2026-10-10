#![cfg(feature = "db")]
//! `POST /api/v1/claims/batch` persists each item through the single-claim
//! create path (issue #477): rows exist, the caller is the default author,
//! `if_not_exists` makes a re-run idempotent, and a failing item is reported
//! in its own slot without affecting the others.

use axum::extract::State;
use axum::Json;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

mod common;

struct Fixture {
    pool: PgPool,
    url: String,
    token: String,
    agent: Uuid,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn fixture(scopes: &[&str]) -> Fixture {
    let db = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&db)
        .await
        .unwrap();
    let agent = common::seed_system_agent(&pool).await;
    let (addr, shutdown) = common::spawn_app(&db).await;
    let (token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, scopes, agent).await;
    Fixture {
        pool,
        url: format!("http://{addr}/api/v1/claims/batch"),
        token,
        agent,
        _shutdown: shutdown,
    }
}

async fn post(f: &Fixture, body: serde_json::Value) -> (u16, serde_json::Value) {
    let r = reqwest::Client::new()
        .post(&f.url)
        .bearer_auth(&f.token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or(serde_json::Value::Null))
}

fn uniq(tag: &str) -> String {
    format!("batch477 {tag} {}", Uuid::new_v4())
}

fn id_at(body: &serde_json::Value, i: usize) -> Option<String> {
    body["results"][i]["claim_id"].as_str().map(str::to_string)
}

async fn count_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The seeded agent's public key, as `common::seed_system_agent` derives it.
fn seeded_key(agent: Uuid) -> Vec<u8> {
    agent.as_bytes().iter().copied().cycle().take(32).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn persists_each_valid_item_attributed_to_the_caller() {
    let f = fixture(&["claims:write"]).await;
    let (a, b) = (uniq("a"), uniq("b"));
    let (status, body) = post(
        &f,
        serde_json::json!({"claims": [
            {"content": a, "truth_value": 0.6},
            {"content": "", "truth_value": 0.5},
            {"content": b, "truth_value": 0.8}
        ]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["created"], 2, "{body}");
    assert_eq!(body["failed"], 1, "{body}");
    assert_eq!(body["results"][1]["status"], 400, "{body}");
    assert!(body["results"][1]["claim_id"].is_null(), "{body}");

    for (i, truth) in [(0usize, 0.6f64), (2, 0.8)] {
        let id: Uuid = id_at(&body, i).expect("id").parse().unwrap();
        // `public_key` lives on `agents`, not on `claims`; joined here rather
        // than queried from `claims` directly, which has no such column.
        let (agent_id, key, tv): (Uuid, Vec<u8>, f64) = sqlx::query_as(
            "SELECT c.agent_id, a.public_key, c.truth_value \
             FROM claims c JOIN agents a ON a.id = c.agent_id WHERE c.id = $1",
        )
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .unwrap_or_else(|e| panic!("item {i} must be a real claims row: {e}"));
        assert_eq!(
            agent_id, f.agent,
            "item {i}: the caller is the default author"
        );
        assert_eq!(
            key,
            seeded_key(f.agent),
            "item {i}: the key is the caller's, never zero"
        );
        assert!((tv - truth).abs() < 1e-9, "item {i}: truth_value carried");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn carries_properties_labels_and_an_explicit_author() {
    let f = fixture(&["claims:write"]).await;
    let c = uniq("props");
    let (status, body) = post(
        &f,
        serde_json::json!({"claims": [{
            "content": c, "agent_id": f.agent, "initial_truth": 0.7,
            "properties": {"source_uri": "doi:10.1/x", "page": 3}, "labels": ["batch477"]
        }]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let id: Uuid = id_at(&body, 0).expect("id").parse().unwrap();
    let (props, labels): (Option<serde_json::Value>, Vec<String>) =
        sqlx::query_as("SELECT properties, labels FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(
        props,
        Some(serde_json::json!({"source_uri": "doi:10.1/x", "page": 3}))
    );
    assert_eq!(labels, vec!["batch477".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn rerun_with_if_not_exists_returns_the_same_ids() {
    let f = fixture(&["claims:write"]).await;
    let (a, b) = (uniq("idem-a"), uniq("idem-b"));
    let batch = serde_json::json!({"claims": [
        {"content": a, "if_not_exists": true}, {"content": b, "if_not_exists": true}
    ]});
    let (_, first) = post(&f, batch.clone()).await;
    let (status, second) = post(&f, batch).await;
    assert_eq!(status, 200, "{second}");
    assert_eq!(second["created"], 0, "{second}");
    assert_eq!(second["existing"], 2, "{second}");
    assert_eq!(second["failed"], 0, "{second}");
    for i in 0..2 {
        assert_eq!(
            id_at(&first, i),
            id_at(&second, i),
            "slot {i} returns the existing id"
        );
        assert_eq!(second["results"][i]["was_created"], false);
    }
    assert_eq!(count_content(&f.pool, &a).await, 1);
    assert_eq!(count_content(&f.pool, &b).await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn rerun_without_if_not_exists_is_a_per_item_409() {
    let f = fixture(&["claims:write"]).await;
    let a = uniq("dup");
    let batch = serde_json::json!({"claims": [{"content": a}]});
    let (_, first) = post(&f, batch.clone()).await;
    assert_eq!(first["created"], 1, "{first}");
    let (status, second) = post(&f, batch).await;
    assert_eq!(status, 200, "{second}");
    assert_eq!(second["failed"], 1, "{second}");
    assert_eq!(second["results"][0]["status"], 409, "{second}");
    assert_eq!(
        count_content(&f.pool, &a).await,
        1,
        "no duplicate row landed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_items_in_one_batch_share_an_id() {
    let f = fixture(&["claims:write"]).await;
    let a = uniq("twice");
    let (status, body) = post(
        &f,
        serde_json::json!({"claims": [
            {"content": a, "if_not_exists": true}, {"content": a, "if_not_exists": true}
        ]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(id_at(&body, 0), id_at(&body, 1), "{body}");
    assert_eq!(body["results"][0]["was_created"], true);
    assert_eq!(body["results"][1]["was_created"], false);
    assert_eq!(count_content(&f.pool, &a).await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_and_oversized_items_fail_alone() {
    let f = fixture(&["claims:write"]).await;
    let ok = uniq("survivor");
    let (status, body) = post(
        &f,
        serde_json::json!({"claims": [
            "not an object",
            {"content": "x", "truth_value": 0.5, "initial_truth": 0.5},
            {"content": "y".repeat(65_537)},
            {"content": ok}
        ]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    for i in 0..3 {
        assert_eq!(body["results"][i]["status"], 400, "slot {i}: {body}");
    }
    assert_eq!(body["created"], 1, "{body}");
    assert_eq!(count_content(&f.pool, &ok).await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_scope_is_403_and_writes_nothing() {
    let f = fixture(&["claims:read"]).await;
    let a = uniq("noscope");
    let (status, body) = post(&f, serde_json::json!({"claims": [{"content": a}]})).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(count_content(&f.pool, &a).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn agentless_token_is_401_and_writes_nothing() {
    let f = fixture(&["claims:write"]).await;
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (agentless, _) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:write".to_string()],
            "service",
            None,
            None,
            chrono::Duration::minutes(10),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("mint");
    let a = uniq("agentless");
    let r = reqwest::Client::new()
        .post(&f.url)
        .bearer_auth(&agentless)
        .json(&serde_json::json!({"claims": [{"content": a}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    assert_eq!(count_content(&f.pool, &a).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_private_item_persists_without_an_embedding_while_a_public_one_is_embedded() {
    // A live (mock) embedder, so "no embedding" on the private item is a
    // decision and not an absent embedder: the public item is the control.
    let db = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&db)
        .await
        .unwrap();
    let agent = common::seed_system_agent(&pool).await;
    let (addr, _shutdown) = common::spawn_app_with_mock_embedding(&db).await;
    let (token, _) = common::test_bearer_token_with_seeded_client_for_agent(
        &pool,
        &["claims:write", "groups:write"],
        agent,
    )
    .await;
    let client = reqwest::Client::new();
    let group: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/groups"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": uniq("grp"),
            "group_public_key": hex::encode(blake3::hash(b"batch477").as_bytes())
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let group_id = group["group_id"]
        .as_str()
        .expect("group created (epoch 0 active)")
        .to_string();

    let public_content = uniq("public");
    let body: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/claims/batch"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"claims": [
            {"content": public_content},
            {"content": uniq("private"), "privacy_tier": "fully_private", "group_id": group_id,
             "encrypted_content": "Y2lwaGVydGV4dA==", "encryption_epoch": 0}
        ]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["created"], 2, "{body}");
    for (i, want_embedded) in [(0usize, true), (1, false)] {
        let id: Uuid = id_at(&body, i).expect("id").parse().unwrap();
        let (has_embedding, has_3072): (bool, bool) = sqlx::query_as(
            "SELECT embedding IS NOT NULL, embedding_3072 IS NOT NULL FROM claims WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(has_embedding, want_embedded, "slot {i}: {body}");
        assert!(
            !has_3072,
            "slot {i}: create_claim never writes embedding_3072"
        );
    }
}

/// Review finding (fix round 1): `agentless_token_is_401_and_writes_nothing`
/// above goes through HTTP, where `ViewerExtractor::extract_viewer`
/// (`middleware/bearer.rs`) already answers 401 before the handler body
/// runs — it is tautological with respect to `batch_create_claims`'s own
/// `let Some(caller_agent_id) = auth.agent_id else { .. }` guard: that
/// mutation check (fix round 1 report) proved `create_claim_core` carries an
/// identical per-item "token carries no agent_id" check, so even with the
/// handler's own guard deleted, an agentless caller still gets refused —
/// just as a per-item 401 inside a 200, not as the single `Err(Unauthorized)`
/// this test pins. This calls the handler directly, bypassing the extractor,
/// with an `AuthContext` whose `agent_id` is `None` but whose scopes already
/// satisfy `claims:write`, so the ONLY thing that can make the WHOLE request
/// answer `Err(Unauthorized)` (never reaching the per-item loop at all) is
/// the handler's own guard.
#[tokio::test(flavor = "multi_thread")]
async fn batch_create_claims_401s_without_an_agent_id_and_writes_nothing() {
    let db = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&db)
        .await
        .unwrap();
    let agent = common::seed_system_agent(&pool).await;
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("viewer");
    let state = epigraph_api::AppState::with_db(pool.clone(), epigraph_api::ApiConfig::default());
    let auth = epigraph_api::middleware::bearer::AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: None,
        owner_id: None,
        client_type: epigraph_api::middleware::ClientType::Agent,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
    };
    let a = uniq("handler-no-agent");
    let req: epigraph_api::routes::batch::BatchClaimRequest =
        serde_json::from_value(serde_json::json!({"claims": [{"content": a}]})).expect("request");

    let err = epigraph_api::routes::batch::batch_create_claims(
        epigraph_api::middleware::bearer::ViewerExtractor(viewer),
        State(state),
        Some(axum::Extension(auth)),
        Json(req),
    )
    .await
    .expect_err("a token with no agent_id must be refused by the handler itself");
    assert!(
        matches!(err, epigraph_api::errors::ApiError::Unauthorized { .. }),
        "{err:?}"
    );
    assert_eq!(count_content(&pool, &a).await, 0);
}

/// Review finding (fix round 1): the `auth_ctx: None` arm
/// (`let Some(axum::Extension(auth)) = auth_ctx.as_ref() else { .. }`) is
/// unreachable over HTTP on this route. `ViewerExtractor`'s own
/// `extract_viewer` (`middleware/bearer.rs`) reads `AuthContext` straight out
/// of `parts.extensions` and 401s there, before axum ever resolves this
/// handler's separate `Option<Extension<AuthContext>>` parameter — so a
/// request with no `AuthContext` extension never reaches the handler body in
/// the first place, over HTTP. Calling the handler directly with `None` is
/// the only way to prove this guard independently.
#[tokio::test(flavor = "multi_thread")]
async fn batch_create_claims_401s_without_an_auth_ctx_and_writes_nothing() {
    let db = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&db)
        .await
        .unwrap();
    let agent = common::seed_system_agent(&pool).await;
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("viewer");
    let state = epigraph_api::AppState::with_db(pool.clone(), epigraph_api::ApiConfig::default());
    let a = uniq("handler-no-authctx");
    let req: epigraph_api::routes::batch::BatchClaimRequest =
        serde_json::from_value(serde_json::json!({"claims": [{"content": a}]})).expect("request");

    let err = epigraph_api::routes::batch::batch_create_claims(
        epigraph_api::middleware::bearer::ViewerExtractor(viewer),
        State(state),
        None,
        Json(req),
    )
    .await
    .expect_err("no auth_ctx extension must be refused by the handler itself");
    assert!(
        matches!(err, epigraph_api::errors::ApiError::Unauthorized { .. }),
        "{err:?}"
    );
    assert_eq!(count_content(&pool, &a).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn over_max_batch_size_is_400() {
    let f = fixture(&["claims:write"]).await;
    let items: Vec<_> = (0..101)
        .map(|i| serde_json::json!({"content": format!("{} {i}", uniq("big"))}))
        .collect();
    let (status, body) = post(&f, serde_json::json!({"claims": items})).await;
    assert_eq!(status, 400, "{body}");
}
