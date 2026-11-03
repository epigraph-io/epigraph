#![cfg(feature = "db")]
//! K12a (supersede SPEC section 11 phase 1 K12 (a), ruling R-132) on
//! `POST /api/v1/workflows/ingest`, the HTTP twin of
//! `epigraph-mcp/tests/ingest_refuses_supersedes.rs`: an extraction
//! relationship of `supersedes`, in any spelling, refuses the whole ingest
//! with a 400 naming the act, before anything is written. Before this the
//! workflow plan builder copied it verbatim and the executor wrote a lineage
//! edge that retires nothing.
//!
//! The handler runs on the production pool shape (`scoped` and `db_pool` are
//! separate `epigraph_app` pools), as `workflow_rest_tags_persisted.rs` does.

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

/// The shared refusal's words (`epigraph_core::edge::relationships::SUPERSEDES_ACT_ONLY`).
const ACT_ONLY: &str = "written only by the supersession act";

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

/// A one-phase, two-step workflow whose one relationship is `relationship`,
/// from the second step to the first.
fn extraction(
    canonical: &str,
    relationship: &str,
) -> epigraph_ingest::workflow::WorkflowExtraction {
    serde_json::from_value(json!({
        "source": {
            "canonical_name": canonical,
            "goal": format!("k12a rest workflow {canonical}: the goal"),
            "generation": 0,
            "authors": [],
            "tags": []
        },
        "thesis": format!("k12a rest workflow {canonical}: the thesis"),
        "thesis_derivation": "TopDown",
        "phases": [{
            "title": "Phase One",
            "summary": format!("k12a rest workflow {canonical}: the phase"),
            "steps": [{
                "compound": format!("k12a rest workflow {canonical}: the first step"),
                "rationale": "",
                "operations": [],
                "generality": [],
                "confidence": 0.8
            }, {
                "compound": format!("k12a rest workflow {canonical}: the second step"),
                "rationale": "",
                "operations": [],
                "generality": [],
                "confidence": 0.8
            }]
        }],
        "relationships": [{
            "source_path": "phases/0/steps/1",
            "target_path": "phases/0/steps/0",
            "relationship": relationship
        }]
    }))
    .expect("a well-formed extraction")
}

async fn ingest(
    pool: &PgPool,
    state: &AppState,
    caller: Uuid,
    canonical: &str,
    relationship: &str,
) -> Result<serde_json::Value, epigraph_api::errors::ApiError> {
    epigraph_api::routes::workflows::ingest_workflow(
        ViewerExtractor(Viewer::resolve(pool, caller).await.expect("viewer")),
        State(state.clone()),
        claims_writer(caller),
        Json(epigraph_api::routes::workflows::IngestWorkflowRequest {
            extraction: extraction(canonical, relationship),
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
async fn an_http_workflow_ingest_relationship_of_supersedes_is_refused(pool: PgPool) {
    system_agent_registered(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "k12a-rest-wf-caller").await;
    let state = app_role_state(&pool).await;

    for (i, spelling) in ["supersedes", "SUPERSEDES", "Supersedes"]
        .iter()
        .enumerate()
    {
        let canonical = format!("k12a-rest-wf-{i}");
        let e = ingest(&pool, &state, caller, &canonical, spelling)
            .await
            .expect_err("a supersedes relationship is refused");
        let (status, text) = rendered(e).await;
        assert_eq!(status, 400, "{spelling}: {text}");
        assert!(
            text.contains(ACT_ONLY) && text.contains(spelling),
            "{spelling}: the refusal names the act and the spelling: {text}"
        );
        assert_eq!(
            count(
                &pool,
                "SELECT count(*) FROM workflows WHERE canonical_name = $1",
                &canonical
            )
            .await,
            0,
            "{spelling}: no workflows row"
        );
        assert_eq!(
            count(
                &pool,
                "SELECT count(*) FROM claims WHERE content LIKE $1",
                &format!("k12a rest workflow {canonical}:%")
            )
            .await,
            0,
            "{spelling}: no claim"
        );
        assert_eq!(
            count(
                &pool,
                "SELECT count(*) FROM edges WHERE lower(relationship) = $1",
                "supersedes"
            )
            .await,
            0,
            "{spelling}: no lineage edge"
        );
    }

    // CONTROL: the same workflow with `supports` ingests and writes its edge.
    ingest(&pool, &state, caller, "k12a-rest-wf-control", "supports")
        .await
        .unwrap_or_else(|e| panic!("CONTROL: a supports relationship ingests: {e:?}"));
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM workflows WHERE canonical_name = $1",
            "k12a-rest-wf-control"
        )
        .await,
        1,
        "CONTROL: the workflows row"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM edges WHERE lower(relationship) = $1",
            "supports"
        )
        .await,
        1,
        "CONTROL: the relationship edge was written"
    );
}
