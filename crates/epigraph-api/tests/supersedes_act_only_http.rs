#![cfg(feature = "db")]
//! K12a (supersede SPEC §11 phase 1; ruling R-132 "supersedes = revision
//! only"; backlog 3ce5e00c's `supersedes` part) on HTTP: the generic
//! `POST /api/v1/edges` route no longer creates a `supersedes` edge, in any
//! spelling; only the supersession act (`POST /api/v1/claims/:id/supersede`)
//! writes it, and it still does.
//!
//! Before K12a `routes/edges.rs::VALID_RELATIONSHIPS` listed `supersedes`
//! (twice) and the upper-case `SUPERSEDES` alias, so any `edges:write` caller
//! could write a lineage edge that retires nothing: a "supersession" the
//! claims' `is_current` / `supersedes` columns never record. The staged
//! promote's twin is in `admin_scope_promotions_test.rs`; the MCP writers' in
//! `epigraph-mcp/tests/supersedes_act_only.rs`.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Extension;
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::AuthContext;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::edges::{create_edge, CreateEdgeRequest};
use epigraph_api::routes::versioning::{supersede_claim, SupersedeRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, downgraded_pool, seed_agent_with_group, seed_group_claim, seed_public_claim,
};

const SPELLINGS: [&str; 3] = ["supersedes", "SUPERSEDES", "Supersedes"];

/// The words of the refusal (`routes::edges::SUPERSEDES_ACT_ONLY`), spelled
/// out so a generic "invalid relationship 'supersedes'" does not satisfy it.
const ACT_ONLY: &str = "written only by the supersession act";

async fn app_role_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

fn auth(agent: Uuid, scopes: &[&str]) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: agent,
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Service,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

fn body(source: Uuid, target: Uuid, relationship: &str) -> Json<CreateEdgeRequest> {
    Json(CreateEdgeRequest {
        source_id: source,
        target_id: target,
        source_type: "claim".to_string(),
        target_type: "claim".to_string(),
        relationship: relationship.to_string(),
        properties: None,
        labels: None,
        valid_from: None,
        valid_to: None,
        if_not_exists: false,
    })
}

async fn edges_between(pool: &PgPool, source: Uuid, target: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2")
        .bind(source)
        .bind(target)
        .fetch_one(pool)
        .await
        .expect("count edges")
}

async fn rendered(e: ApiError) -> (u16, serde_json::Value) {
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// `POST /api/v1/edges` refuses `supersedes` in every spelling with a 400 on
/// `relationship` that names the act, and writes no edge between the pair,
/// for both the default and the `if_not_exists` path. CONTROL: `supports`
/// between the same pair, by the same caller, lands (201), so the refusal is
/// the relationship's.
#[sqlx::test(migrations = "../../migrations")]
async fn post_edges_refuses_supersedes_in_every_spelling(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (w, _) = seed_agent_with_group(&pool, "k12a-http-writer").await;
    let newer = seed_public_claim(&pool, w, "k12a the newer claim").await;
    let older = seed_public_claim(&pool, w, "k12a the older claim").await;

    for rel in SPELLINGS {
        for if_not_exists in [false, true] {
            let mut req = body(newer, older, rel);
            req.0.if_not_exists = if_not_exists;
            let e = create_edge(
                ViewerExtractor(viewer(&pool, w).await),
                State(state.clone()),
                auth(w, &["edges:write"]),
                req,
            )
            .await
            .expect_err("a generic edge write may not create a lineage edge");
            let (status, json) = rendered(e).await;
            assert_eq!(status, 400, "{rel} {if_not_exists}: {json}");
            let text = json.to_string();
            assert!(
                text.contains("relationship") && text.contains(ACT_ONLY),
                "{rel}: the refusal names the field and the act: {text}"
            );
            assert_eq!(
                edges_between(&pool, newer, older).await,
                0,
                "{rel} {if_not_exists}: nothing written"
            );
        }
    }

    let (status, _) = create_edge(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        auth(w, &["edges:write"]),
        body(newer, older, "supports"),
    )
    .await
    .unwrap_or_else(|e| panic!("CONTROL: supports between the same pair lands: {e:?}"));
    assert_eq!(status.as_u16(), 201);
    assert_eq!(edges_between(&pool, newer, older).await, 1);
}

/// The act still writes its lineage edge: the author's `POST
/// /api/v1/claims/:id/supersede` leaves exactly one in-force
/// `new -supersedes-> old`, lower case.
#[sqlx::test(migrations = "../../migrations")]
async fn the_supersede_route_still_writes_its_lineage_edge(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "k12a-http-author").await;
    let old = seed_group_claim(&pool, h, hg, "k12a a claim to restate").await;

    let (_, Json(resp)) = supersede_claim(
        ViewerExtractor(viewer(&pool, h).await),
        State(state.clone()),
        auth(h, &["claims:write"]),
        Path(old),
        Json(SupersedeRequest {
            content: "k12a the restated claim".to_string(),
            truth_value: 0.6,
            reason: "k12a lineage pin".to_string(),
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("the author supersedes its own claim: {e:?}"));
    let lineage: Vec<String> = sqlx::query_scalar(
        "SELECT relationship FROM edges WHERE source_id = $1 AND target_id = $2 \
           AND lower(relationship) = 'supersedes' AND valid_to IS NULL",
    )
    .bind(resp.new_claim_id)
    .bind(old)
    .fetch_all(&pool)
    .await
    .expect("lineage edges");
    assert_eq!(lineage, vec!["supersedes".to_string()]);
}
