#![cfg(feature = "db")]
//! The REST workflow writers' post-commit embeddings, on the APPLICATION ROLE.
//!
//! `POST /api/v1/workflows` (`store_workflow`) and `POST /api/v1/workflows/ingest`
//! (`ingest_workflow`) write their claims on a transaction stamped with the
//! workflow-ingest system agent's viewer, so every row is that agent's and is
//! owned by its personal group. Each claim is then embedded best-effort after
//! the commit, and a failed embed only logs a WARN: the request still answers
//! 200. When that embed ran on the unstamped `state.db_pool`, row security on
//! `claims` refused the `UPDATE` for every claim, so the route returned 200 and
//! left every claim it had just written without a vector. Those claims were
//! then invisible to dense recall, which breaks CLAUDE.md's "Embedding policy"
//! (a current claim carries an embedding).
//!
//! These arms run the handlers on an `AppState` whose `scoped` pool and raw
//! `db_pool` are BOTH separate `epigraph_app` pools, as
//! `system_agent_registry_routes.rs` does. The in-crate `scoped_test_state`
//! can't observe this defect: it connects as the BYPASSRLS harness superuser and
//! makes `db_pool` the scoped pool's own inner pool.
//!
//! No orphan permissive `claims_privacy` policy is installed. With one
//! (`USING (true)`), the unstamped `UPDATE` would succeed and these arms would
//! prove nothing.
//!
//! # Verified to fail
//!
//! 1. At origin/main 934aa332, the embed `UPDATE` ran on `state.db_pool` in both
//!    handlers. Both arms then failed on the claim-embedding assertion: every
//!    claim was left with `embedding IS NULL`.
//! 2. With the store stamped from the CALLER's viewer instead of the system
//!    agent's, both arms fail the same way. The `{WRITABLE:c}` splice renders
//!    the caller's groups, and no system-owned row satisfies it.

mod viewer_fixture;

use axum::extract::State;
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, downgraded_pool, register_system_agent, seed_agent_with_group,
};

/// An application-role `AppState` with a mock embedder: `scoped` and `db_pool`
/// are two separate `epigraph_app` pools, so a write on `db_pool` is an
/// unstamped write that row security governs.
async fn app_role_state_with_embedder(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
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
    let embedder: std::sync::Arc<dyn EmbeddingService> =
        std::sync::Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
    state.with_embedding_service(embedder)
}

/// The system agent, created by the unarmed legacy resolver and registered as
/// the deploy order does (migration 148).
async fn system_agent_registered(pool: &PgPool) -> Uuid {
    let s = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    assert!(register_system_agent(pool, s).await);
    s
}

/// `(content, agent_id, has_embedding)` for every claim whose content is one of
/// `contents`. Read on the harness superuser, so row security hides nothing.
async fn claims_by_content(pool: &PgPool, contents: &[String]) -> Vec<(String, Uuid, bool)> {
    sqlx::query_as(
        "SELECT content, agent_id, embedding IS NOT NULL FROM claims \
          WHERE content = ANY($1) ORDER BY content",
    )
    .bind(contents)
    .fetch_all(pool)
    .await
    .expect("read back the workflow's claims")
}

async fn goal_embedding_present(pool: &PgPool, workflow_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT goal_embedding IS NOT NULL FROM workflows WHERE id = $1")
        .bind(workflow_id)
        .fetch_one(pool)
        .await
        .expect("read back the workflow row")
}

/// `(claims authored by `system`, of those how many have embedding IS NULL)`.
/// Each `sqlx::test` runs in a fresh database and the system agent is created
/// at the start of the arm, so the system agent's claims are exactly the set
/// this request wrote, whatever kinds the executor plans.
async fn system_claim_counts(pool: &PgPool, system: Uuid) -> (i64, i64) {
    sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE embedding IS NULL) FROM claims \
          WHERE agent_id = $1",
    )
    .bind(system)
    .fetch_one(pool)
    .await
    .expect("count the system agent's claims")
}

/// Asserts that every claim the request wrote is the system agent's and carries
/// a vector, and that the workflow row carries a goal embedding. The claim and
/// goal checks have separate messages, so a red run shows which write was lost.
///
/// Two claim checks: the hand-listed `contents` (named, so a red run says which
/// claim lost its vector), and the WHOLE write set (every claim the system agent
/// authored, which must number `claims_ingested`). The whole-set check covers
/// claim kinds the list does not name, such as `store_workflow`'s phase summary.
async fn assert_all_embedded(
    pool: &PgPool,
    system: Uuid,
    workflow_id: Uuid,
    contents: &[String],
    claims_ingested: u64,
    route: &str,
) {
    let rows = claims_by_content(pool, contents).await;
    assert_eq!(
        rows.len(),
        contents.len(),
        "{route}: one claim per expected content, got {rows:?}"
    );
    for (content, agent, _) in &rows {
        assert_eq!(
            *agent, system,
            "{route}: claim {content:?} is authored by the workflow-ingest system agent"
        );
    }
    let missing: Vec<&String> = rows
        .iter()
        .filter(|(_, _, has)| !has)
        .map(|(c, _, _)| c)
        .collect();
    assert!(
        missing.is_empty(),
        "{route}: every claim the request wrote must carry an embedding after a 200; \
         these have embedding IS NULL: {missing:?}"
    );
    let (written, unembedded) = system_claim_counts(pool, system).await;
    assert_eq!(
        u64::try_from(written).expect("non-negative count"),
        claims_ingested,
        "{route}: the system agent's claims are exactly the {claims_ingested} the request wrote"
    );
    assert_eq!(
        unembedded, 0,
        "{route}: {unembedded} of the {written} claims the request wrote have embedding IS NULL \
         (the named contents above all carry one, so the missing vector is on a claim kind \
         the list does not name)"
    );
    assert!(
        goal_embedding_present(pool, workflow_id).await,
        "{route}: workflows.goal_embedding must be set after a 200"
    );
}

/// `POST /api/v1/workflows`: the goal (thesis) and both step claims carry a
/// vector after the call.
#[sqlx::test(migrations = "../../migrations")]
async fn rest_store_workflow_embeds_every_claim_it_writes(pool: PgPool) {
    let system = system_agent_registered(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "caller").await;
    let state = app_role_state_with_embedder(&pool).await;

    let tag = Uuid::new_v4();
    let goal = format!("rest store_workflow embedding goal {tag}");
    let steps = vec![
        format!("rest store_workflow first step {tag}"),
        format!("rest store_workflow second step {tag}"),
    ];
    let req: epigraph_api::routes::workflows::StoreWorkflowRequest =
        serde_json::from_value(serde_json::json!({ "goal": goal, "steps": steps }))
            .expect("request");
    let Json(body) = epigraph_api::routes::workflows::store_workflow(
        ViewerExtractor(Viewer::resolve(&pool, caller).await.expect("viewer")),
        State(state),
        Json(req),
    )
    .await
    .map_err(|e| format!("{e:?}"))
    .expect("store_workflow answers 200");

    assert_eq!(body["already_ingested"].as_bool(), Some(false), "{body}");
    let claims_ingested = body["claims_ingested"].as_u64().unwrap_or(0);
    assert!(
        claims_ingested > 3,
        "the goal, both steps and the phase summary are written: {body}"
    );
    let workflow_id: Uuid = body["workflow_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("workflow_id in {body}"));

    let mut contents = steps.clone();
    contents.push(goal);
    assert_all_embedded(
        &pool,
        system,
        workflow_id,
        &contents,
        claims_ingested,
        "store_workflow",
    )
    .await;
}

/// `POST /api/v1/workflows/ingest`: the thesis, the phase and both step claims
/// carry a vector after the call.
#[sqlx::test(migrations = "../../migrations")]
async fn rest_ingest_workflow_embeds_every_claim_it_writes(pool: PgPool) {
    let system = system_agent_registered(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "caller").await;
    let state = app_role_state_with_embedder(&pool).await;

    let tag = Uuid::new_v4();
    let thesis = format!("rest ingest_workflow thesis {tag}");
    let phase = format!("rest ingest_workflow phase summary {tag}");
    let steps = vec![
        format!("rest ingest_workflow first step {tag}"),
        format!("rest ingest_workflow second step {tag}"),
    ];
    let extraction: epigraph_ingest::workflow::WorkflowExtraction =
        serde_json::from_value(serde_json::json!({
            "source": {
                "canonical_name": format!("rest-ingest-embed-{tag}"),
                "goal": format!("rest ingest_workflow goal {tag}"),
                "generation": 0,
                "authors": []
            },
            "thesis": thesis,
            "thesis_derivation": "TopDown",
            "phases": [{
                "title": "Phase One",
                "summary": phase,
                "steps": steps.iter().map(|s| serde_json::json!({
                    "compound": s,
                    "rationale": "",
                    "operations": [],
                    "generality": [],
                    "confidence": 0.8
                })).collect::<Vec<_>>()
            }],
            "relationships": []
        }))
        .expect("a well-formed extraction");

    let Json(body) = epigraph_api::routes::workflows::ingest_workflow(
        ViewerExtractor(Viewer::resolve(&pool, caller).await.expect("viewer")),
        State(state),
        None,
        Json(epigraph_api::routes::workflows::IngestWorkflowRequest {
            extraction,
            tenancy: None,
            embed: None,
        }),
    )
    .await
    .map_err(|e| format!("{e:?}"))
    .expect("ingest_workflow answers 200");

    assert_eq!(body["already_ingested"].as_bool(), Some(false), "{body}");
    let claims_ingested = body["claims_ingested"].as_u64().unwrap_or(0);
    assert!(
        claims_ingested >= 4,
        "the thesis, the phase and both steps are written: {body}"
    );
    let workflow_id: Uuid = body["workflow_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("workflow_id in {body}"));

    let mut contents = steps.clone();
    contents.push(thesis);
    contents.push(phase);
    assert_all_embedded(
        &pool,
        system,
        workflow_id,
        &contents,
        claims_ingested,
        "ingest_workflow",
    )
    .await;
}
