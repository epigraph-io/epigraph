#![cfg(feature = "db")]
//! SPEC §11 phase 1, K4a, through the HTTP routes: a RETRACTED mass function
//! (migration 184, rulings R-79 / R-103) survives
//! `POST /api/v1/claims/:id/supersede` (cascade inline, and deferred then
//! replayed) and `POST /api/v1/claims/:id/dedup`; each act completes, and the
//! cascade counts what it kept.
//!
//! Handlers are invoked directly with the caller's `ViewerExtractor`, as
//! `own_claim_authority_http.rs` does. The `AppState`'s pools are the
//! application role; the inline cascade and the replay run on a NOSUPERUSER
//! `epigraph_maintenance` login (SPEC §12). Every retracted row is made by
//! migration 184's definer on the application role.

mod viewer_fixture;

#[path = "../../epigraph-db/tests/support/retracted_bba_fixture.rs"]
mod retracted;

use axum::extract::{Path, State};
use axum::Extension;
use axum::Json;
use epigraph_api::middleware::bearer::AuthContext;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::versioning::{
    mark_duplicate, supersede_claim, DedupRequest, SupersedeRequest,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{MassFunctionRepository, ScopedPool, SessionGucMode};
use retracted::{retract_through_definer, row_state};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group};

/// Both pools on the application role; with `inline`, the `ScopedPool`'s
/// maintenance pool is a NOSUPERUSER `epigraph_maintenance` login, so the
/// routes run the cascade in the request.
async fn app_role_state(pool: &PgPool, inline: bool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(!bypassrls, "epigraph_app holds BYPASSRLS: vacuous");
    let url = database_url_for(pool).await;
    let mut scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    if inline {
        scoped = scoped.with_maintenance_pool(downgraded_pool(pool, "epigraph_maintenance").await);
    }
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state.admin_cascade = inline;
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

fn human(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

async fn claim_of(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("{content} {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("seed edge");
    sqlx::query(
        "INSERT INTO perspectives (id, name, perspective_type) VALUES ($1, 'edge_factor', 'edge')",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed the edge's perspective");
    id
}

async fn frame(pool: &PgPool, tag: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("k4a-http-{tag}-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

async fn bba(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, perspective: Uuid) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        Some(perspective),
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("edge_factor"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store a BBA")
}

async fn replay_now(pool: &PgPool) -> epigraph_engine::admin_cascade::ReplayReport {
    let url = database_url_for(pool).await;
    let maintenance = downgraded_pool(pool, "epigraph_maintenance").await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("ScopedPool")
            .with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, admin_viewer) = session.split();
    epigraph_engine::admin_cascade::replay_deferred(
        conn,
        admin_viewer,
        "k4a-http",
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay")
}

async fn belief_counts(pool: &PgPool, subject: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details->'belief' FROM security_events \
          WHERE event_type = 'cascade.belief_rederived' \
            AND details->'trigger'->>'subject_id' = $1::text \
          ORDER BY created_at, id",
    )
    .bind(subject)
    .fetch_all(pool)
    .await
    .expect("belief audit rows")
}

/// The author's claim `old` supports another writer's claim `b`; the
/// edge-keyed BBA on `b` was retracted by a writer of `b`'s group.
async fn supersede_world(pool: &PgPool) -> (Uuid, Uuid, Uuid, Uuid) {
    let (author, ag) = seed_agent_with_group(pool, "k4a-http-author").await;
    let (x, xg) = seed_agent_with_group(pool, "k4a-http-x").await;
    let old = claim_of(pool, author, ag, "k4a http supporter").await;
    let b = claim_of(pool, x, xg, "k4a http downstream").await;
    let e = edge(pool, old, b).await;
    let f = frame(pool, "supersede").await;
    let retracted = bba(pool, b, f, author, e).await;
    retract_through_definer(pool, retracted).await;
    (author, old, b, retracted)
}

fn supersede_body(claim: Uuid) -> Json<SupersedeRequest> {
    Json(SupersedeRequest {
        content: format!("a correction of {claim}"),
        truth_value: 0.6,
        reason: "k4a http".to_string(),
    })
}

/// Sites 1 and 8 over HTTP with the cascade inline.
#[sqlx::test(migrations = "../../migrations")]
async fn http_supersede_inline_keeps_a_retracted_edge_bba_and_counts_it(pool: PgPool) {
    let state = app_role_state(&pool, true).await;
    let (author, old, b, retracted) = supersede_world(&pool).await;
    let (status, Json(resp)) = supersede_claim(
        ViewerExtractor(viewer(&pool, author).await),
        State(state),
        human(author),
        Path(old),
        supersede_body(old),
    )
    .await
    .expect("the author's supersede");
    assert_eq!(status.as_u16(), 201);
    let cascade = serde_json::to_value(&resp.cascade).expect("cascade");
    assert_eq!(cascade["status"], "applied", "{cascade}");
    assert_eq!(
        row_state(&pool, retracted).await,
        Some((b, true)),
        "the retracted edge BBA is kept for audit"
    );
    assert!(
        resp.belief_cascade.errors.is_empty(),
        "the cascade completes with no error: {:?}",
        resp.belief_cascade.errors
    );
    assert_eq!(
        resp.belief_cascade.retracted_key_kept, 1,
        "the caller's copy counts the kept retracted key: {:?}",
        resp.belief_cascade
    );
    let rows = belief_counts(&pool, old).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["retracted_key_kept"], 1, "{rows:?}");
}

/// The same route with no maintenance connection: deferred, then replayed on
/// the maintenance login, which keeps the retracted edge BBA and applies.
#[sqlx::test(migrations = "../../migrations")]
async fn http_supersede_deferred_replay_keeps_a_retracted_edge_bba(pool: PgPool) {
    let state = app_role_state(&pool, false).await;
    let (author, old, b, retracted) = supersede_world(&pool).await;
    let (_, Json(resp)) = supersede_claim(
        ViewerExtractor(viewer(&pool, author).await),
        State(state),
        human(author),
        Path(old),
        supersede_body(old),
    )
    .await
    .expect("the author's supersede");
    let cascade = serde_json::to_value(&resp.cascade).expect("cascade");
    assert_eq!(cascade["status"], "deferred", "{cascade}");

    let report = replay_now(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert_eq!(
        row_state(&pool, retracted).await,
        Some((b, true)),
        "the replay keeps the retracted edge BBA"
    );
    let rows = belief_counts(&pool, old).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["errors"], 0, "{rows:?}");
    assert_eq!(rows[0]["retracted_key_kept"], 1, "{rows:?}");
}

/// Site 2 over HTTP with the cascade inline: the duplicate's live copy whose
/// canonical holder is retracted stays on the duplicate and is counted, and
/// its retracted copy (canonical holder live) is kept; the repair applies.
#[sqlx::test(migrations = "../../migrations")]
async fn http_dedup_inline_keeps_retracted_rows_and_the_live_copy_they_block(pool: PgPool) {
    let state = app_role_state(&pool, true).await;
    let (h, hg) = seed_agent_with_group(&pool, "k4a-http-h").await;
    let (x, xg) = seed_agent_with_group(&pool, "k4a-http-citer").await;
    let dup = claim_of(&pool, h, hg, "k4a http duplicate").await;
    let canonical = claim_of(&pool, h, hg, "k4a http canonical").await;
    let xc = claim_of(&pool, x, xg, "k4a http citer").await;
    let e = edge(&pool, xc, dup).await;
    let (f1, f2) = (frame(&pool, "d1").await, frame(&pool, "d2").await);
    let live_copy = bba(&pool, dup, f1, x, e).await;
    let retracted_holder = bba(&pool, canonical, f1, x, e).await;
    let retracted_copy = bba(&pool, dup, f2, x, e).await;
    bba(&pool, canonical, f2, x, e).await;
    retract_through_definer(&pool, retracted_holder).await;
    retract_through_definer(&pool, retracted_copy).await;

    let Json(resp) = mark_duplicate(
        ViewerExtractor(viewer(&pool, h).await),
        State(state),
        human(h),
        Path(dup),
        Json(DedupRequest {
            canonical_id: canonical,
            reason: None,
        }),
    )
    .await
    .expect("the author's dedup");
    let cascade = serde_json::to_value(&resp.cascade).expect("cascade");
    assert_eq!(
        cascade["status"], "applied",
        "the repair completes: {cascade}"
    );
    assert_eq!(
        row_state(&pool, live_copy).await,
        Some((dup, false)),
        "the live copy a retracted holder blocks stays on the duplicate"
    );
    assert_eq!(
        row_state(&pool, retracted_copy).await,
        Some((dup, true)),
        "the retracted copy is kept where it is"
    );
    assert_eq!(
        row_state(&pool, retracted_holder).await,
        Some((canonical, true))
    );
    assert_eq!(
        cascade["touched"]["bbas_kept_on_duplicate_by_retracted_holder"], 1,
        "the caller's counts report the kept live copy: {cascade}"
    );
}
