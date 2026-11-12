#![cfg(feature = "db")]
//! `POST /api/v1/workflows/ingest` refuses `source.authors[].agent_id`
//! (backlog 94cc12db), the HTTP twin of
//! `epigraph-mcp/tests/ingest_author_resolution.rs`'s workflow case. The field
//! lives on the `AuthorEntry` documents and workflows share; workflow authors
//! are name-derived only, so an id is refused with a 400 naming the entry,
//! before anything is written, rather than silently ignored.
//!
//! The handler runs on the production pool shape (`scoped` and `db_pool` are
//! separate `epigraph_app` pools), as `workflow_ingest_refuses_supersedes_http.rs`
//! does.

mod viewer_fixture;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, downgraded_pool, register_system_agent, seed_agent_with_group,
};

fn claims_writer(
    agent: Uuid,
) -> Option<axum::Extension<epigraph_api::middleware::bearer::AuthContext>> {
    Some(axum::Extension(
        epigraph_api::middleware::bearer::AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: Some(agent),
            owner_id: Some(agent),
            client_type: epigraph_api::middleware::ClientType::Agent,
            scopes: vec!["claims:read".to_string(), "claims:write".to_string()],
            jti: Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
            delegated_by: None,
        },
    ))
}

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

async fn system_agent_registered(pool: &PgPool) {
    let s = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    assert!(register_system_agent(pool, s).await);
}

/// A one-phase, two-step workflow by `authors`.
fn extraction(
    canonical: &str,
    authors: serde_json::Value,
) -> epigraph_ingest::workflow::WorkflowExtraction {
    serde_json::from_value(json!({
        "source": {
            "canonical_name": canonical,
            "goal": format!("author-id rest workflow {canonical}: the goal"),
            "generation": 0,
            "authors": authors,
            "tags": []
        },
        "thesis": format!("author-id rest workflow {canonical}: the thesis"),
        "thesis_derivation": "TopDown",
        "phases": [{
            "title": "Phase One",
            "summary": format!("author-id rest workflow {canonical}: the phase"),
            "steps": [{
                "compound": format!("author-id rest workflow {canonical}: the first step"),
                "rationale": "",
                "operations": [],
                "generality": [],
                "confidence": 0.8
            }, {
                "compound": format!("author-id rest workflow {canonical}: the second step"),
                "rationale": "",
                "operations": [],
                "generality": [],
                "confidence": 0.8
            }]
        }],
        "relationships": []
    }))
    .expect("a well-formed extraction")
}

async fn ingest(
    pool: &PgPool,
    state: &AppState,
    caller: Uuid,
    canonical: &str,
    authors: serde_json::Value,
) -> Result<serde_json::Value, epigraph_api::errors::ApiError> {
    epigraph_api::routes::workflows::ingest_workflow(
        ViewerExtractor(Viewer::resolve(pool, caller).await.expect("viewer")),
        State(state.clone()),
        claims_writer(caller),
        Json(epigraph_api::routes::workflows::IngestWorkflowRequest {
            extraction: extraction(canonical, authors),
            tenancy: None,
            embed: Some(false),
        }),
    )
    .await
    .map(|Json(body)| body)
}

/// The status and the rendered body text.
async fn rendered(e: epigraph_api::errors::ApiError) -> (u16, String) {
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn count(pool: &PgPool, sql: &str, bind: &str) -> i64 {
    sqlx::query_scalar(sql)
        .bind(bind)
        .fetch_one(pool)
        .await
        .expect("count")
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_http_workflow_ingest_author_agent_id_is_refused(pool: PgPool) {
    system_agent_registered(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "author-id-rest-wf-caller").await;
    let state = app_role_state(&pool).await;

    let e = ingest(
        &pool,
        &state,
        caller,
        "author-id-rest-wf-refused",
        json!([{"name": "A Designer"}, {"name": "B Designer", "agent_id": caller.to_string()}]),
    )
    .await
    .expect_err("an author agent_id is refused");
    let (status, text) = rendered(e).await;
    assert_eq!(status, 400, "{text}");
    assert!(text.contains("source.authors[1].agent_id"), "{text}");
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM workflows WHERE canonical_name = $1",
            "author-id-rest-wf-refused"
        )
        .await,
        0,
        "no workflows row"
    );

    ingest(
        &pool,
        &state,
        caller,
        "author-id-rest-wf-control",
        json!([{"name": "A Designer"}]),
    )
    .await
    .expect("CONTROL: a name-only author ingests");
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM workflows WHERE canonical_name = $1",
            "author-id-rest-wf-control"
        )
        .await,
        1,
        "CONTROL"
    );
}
