#![cfg(feature = "db")]
//! Backlog 8fcc36a0: the events the REST frame, evidence and community
//! handlers emit are PERSISTED to the `events` table, the log
//! `GET /api/v1/events` and MCP `list_events` read.
//!
//! They used to be pushed to a second, in-process store (`OnceLock` +
//! uncapped `Vec`): lost on every restart, invisible to MCP, and growing for
//! the life of the process. The assertions read the table directly, not
//! `GET /api/v1/events`, whose old merge of that process-global store would
//! have answered the same with or without the fix.
//!
//! The handlers run on the `#[sqlx::test]` superuser pools (where the events
//! land is under test, not row security).

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Json;
use epigraph_api::middleware::bearer::{
    AuthContext, RequireScopeGroupsWrite, RequireScopeWrite, ViewerExtractor,
};
use epigraph_api::routes::belief::{create_frame, submit_evidence};
use epigraph_api::routes::community::create_community;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{scoped_pool, seed_agent_with_group, seed_public_claim};

async fn state(pool: &PgPool) -> AppState {
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped_pool(pool).await);
    state
}

fn auth(principal: Uuid, scope: &str) -> AuthContext {
    AuthContext {
        client_id: principal,
        agent_id: Some(principal),
        owner_id: Some(principal),
        client_type: epigraph_api::middleware::ClientType::Service,
        scopes: vec![scope.to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

/// `(actor_id, payload)` of every persisted `event_type` row whose payload
/// `key` is `id`, oldest first.
async fn persisted(
    pool: &PgPool,
    event_type: &str,
    key: &str,
    id: Uuid,
) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT actor_id, payload FROM events \
          WHERE event_type = $1 AND payload->>$2 = $3 \
          ORDER BY graph_version",
    )
    .bind(event_type)
    .bind(key)
    .bind(id.to_string())
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| panic!("read persisted {event_type} events: {e}"))
}

async fn new_frame(state: &AppState, caller: Uuid, name: &str) -> Uuid {
    let request = serde_json::from_value(serde_json::json!({
        "name": name,
        "hypotheses": ["h0", "h1"],
    }))
    .expect("frame request");
    let (_, Json(frame)) = create_frame(
        RequireScopeWrite(auth(caller, "claims:write")),
        State(state.clone()),
        Json(request),
    )
    .await
    .unwrap_or_else(|e| panic!("create_frame failed: {e:?}"));
    frame.id
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_frame_persists_frame_created(pool: PgPool) {
    let state = state(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "evt-frame-caller").await;
    let frame = new_frame(&state, caller, "evt_persisted_frame").await;
    drop(state);

    let rows = persisted(&pool, "frame.created", "frame_id", frame).await;
    assert_eq!(
        rows,
        vec![(
            None,
            serde_json::json!({
                "frame_id": frame,
                "name": "evt_persisted_frame",
                "hypothesis_count": 2,
            })
        )],
        "exactly one persisted frame.created"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_evidence_persists_evidence_submitted(pool: PgPool) {
    let state = state(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "evt-evidence-caller").await;
    let (author, _) = seed_agent_with_group(&pool, "evt-evidence-author").await;
    let claim = seed_public_claim(&pool, author, "evt persisted: evidence target").await;
    let frame = new_frame(&state, caller, "evt_persisted_evidence_frame").await;

    let request = serde_json::from_value(serde_json::json!({
        "claim_id": claim,
        "agent_id": caller,
        "reliability": 1.0,
        "masses": {"0": 0.6, "0,1": 0.4},
    }))
    .expect("evidence request");
    let viewer = Viewer::resolve(&pool, caller)
        .await
        .expect("resolve caller");
    let (_, Json(resp)) = submit_evidence(
        RequireScopeWrite(auth(caller, "claims:write")),
        ViewerExtractor(viewer),
        State(state.clone()),
        Path(frame),
        Json(request),
    )
    .await
    .unwrap_or_else(|e| panic!("submit_evidence failed: {e:?}"));
    drop(state);

    let rows = persisted(
        &pool,
        "evidence.submitted",
        "mass_function_id",
        resp.mass_function_id,
    )
    .await;
    assert_eq!(rows.len(), 1, "exactly one persisted evidence.submitted");
    let (actor, payload) = &rows[0];
    assert_eq!(*actor, Some(caller), "attributed to the submitting agent");
    assert_eq!(payload["claim_id"], serde_json::json!(claim));
    assert_eq!(payload["frame_id"], serde_json::json!(frame));
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_community_persists_community_formed(pool: PgPool) {
    let state = state(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "evt-community-caller").await;
    let viewer = Viewer::resolve(&pool, caller)
        .await
        .expect("resolve caller");
    let request = serde_json::from_value(serde_json::json!({
        "name": "evt persisted community",
    }))
    .expect("community request");
    let (_, Json(community)) = create_community(
        RequireScopeGroupsWrite(auth(caller, "groups:write")),
        ViewerExtractor(viewer),
        State(state.clone()),
        Json(request),
    )
    .await
    .unwrap_or_else(|e| panic!("create_community failed: {e:?}"));
    drop(state);

    let rows = persisted(&pool, "community.formed", "community_id", community.id).await;
    assert_eq!(rows.len(), 1, "exactly one persisted community.formed");
    assert_eq!(rows[0].1["name"], "evt persisted community");
}
