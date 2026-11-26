#![cfg(feature = "db")]
//! K12d (supersede SPEC §11 phase 1, SF-26): the `claim.superseded` event
//! (payload `superseded_claim_id`, `superseded_by_claim_id`) is emitted by the
//! REST supersession act, `POST /api/v1/claims/:id/supersede`, on the act's
//! own transaction, and by nothing else.
//!
//! Its only emitter was the generic `POST /api/v1/edges` route, on a
//! `supersedes` edge, which K12a removed with that relationship (ruling R-132).
//! So the act a staleness consumer is waiting for emitted nothing: a REST
//! supersession left no `claim.superseded` behind. MCP acts never emitted it
//! and gain no emitter here.
//!
//! The event is read from the persisted `events` table (backlog 8fcc36a0: it
//! used to be pushed to an in-process store that nothing persisted), filtered
//! by this test's own claim ids.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Extension;
use axum::Json;
use epigraph_api::middleware::bearer::AuthContext;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::versioning::{supersede_claim, SupersedeRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group, seed_group_claim};

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

fn auth(agent: Uuid, scopes: &[&str]) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

async fn supersede_as(
    pool: &PgPool,
    state: &AppState,
    caller: Uuid,
    scopes: &[&str],
    old: Uuid,
) -> Result<Uuid, epigraph_api::errors::ApiError> {
    supersede_claim(
        ViewerExtractor(Viewer::resolve(pool, caller).await.expect("resolve")),
        State(state.clone()),
        auth(caller, scopes),
        Path(old),
        Json(SupersedeRequest {
            content: format!("a correction of {old}"),
            truth_value: 0.6,
            reason: "k12d event".to_string(),
        }),
    )
    .await
    .map(|(_, Json(resp))| resp.new_claim_id)
}

/// Every PERSISTED `claim.superseded` event naming `old` as the superseded
/// claim: `(actor_id, payload)`.
async fn superseded_events_for(pool: &PgPool, old: Uuid) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT actor_id, payload FROM events \
          WHERE event_type = 'claim.superseded' \
            AND payload->>'superseded_claim_id' = $1 \
          ORDER BY graph_version",
    )
    .bind(old.to_string())
    .fetch_all(pool)
    .await
    .expect("read persisted claim.superseded events")
}

/// A REST supersession persists exactly one `claim.superseded` naming the
/// retired and the new claim, attributed to the acting agent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rest_supersession_emits_one_claim_superseded(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "k12d-author").await;
    let old = seed_group_claim(&pool, h, hg, "k12d the claim to restate").await;

    let new = supersede_as(&pool, &state, h, &["claims:write"], old)
        .await
        .unwrap_or_else(|e| panic!("the author supersedes its own claim: {e:?}"));

    let events = superseded_events_for(&pool, old).await;
    assert_eq!(events.len(), 1, "exactly one claim.superseded: {events:?}");
    assert_eq!(
        events[0].1,
        serde_json::json!({"superseded_claim_id": old, "superseded_by_claim_id": new}),
        "the payload keys the generic route used"
    );
    assert_eq!(events[0].0, Some(h), "attributed to the acting agent");
}

/// A refused supersession persists none: neither a caller the per-claim rule
/// refuses (a bystander), nor one row security refuses inside the act (a
/// `claims:admin` caller whose stamp does not write the claim's group). The
/// event is written on the act's transaction after the act succeeded, so a
/// refused act rolls back before it, and any later failure before the commit
/// rolls it back with the act.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_supersession_emits_no_claim_superseded(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "k12d-owner").await;
    let (b, _) = seed_agent_with_group(&pool, "k12d-bystander").await;
    // Public and owned by h's group, so both callers can read it.
    let old = Uuid::new_v4();
    let hash: Vec<u8> = old.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, 'k12d the owner''s public claim', $2, 0.5, $3, true, 'public', $4)",
    )
    .bind(old)
    .bind(&hash)
    .bind(h)
    .bind(hg)
    .execute(&pool)
    .await
    .expect("seed claim");

    supersede_as(&pool, &state, b, &["claims:write"], old)
        .await
        .expect_err("a bystander may not supersede");
    supersede_as(&pool, &state, b, &["claims:write", "claims:admin"], old)
        .await
        .expect_err("the admin's stamp cannot write h's group");
    let current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(old)
        .fetch_one(&pool)
        .await
        .expect("is_current");
    assert!(current, "calibration: nothing was superseded");
    assert!(
        superseded_events_for(&pool, old).await.is_empty(),
        "a refused supersession emits nothing"
    );

    // CONTROL: the owner's own supersession of the same claim emits one.
    supersede_as(&pool, &state, h, &["claims:write"], old)
        .await
        .unwrap_or_else(|e| panic!("CONTROL: the owner supersedes: {e:?}"));
    assert_eq!(superseded_events_for(&pool, old).await.len(), 1);
}
