#![cfg(feature = "db")]
//! SPEC §11 phase 1, K4a, through the HTTP routes: a RETRACTED mass function
//! (migration 184, rulings R-79 / R-103) survives
//! `POST /api/v1/claims/:id/supersede` (cascade inline, and deferred then
//! replayed), `POST /api/v1/claims/:id/dedup` (its repair and its re-wire of
//! re-sourced edges), `POST /api/v1/claims/:id/undedup` and
//! `DELETE /api/v1/edges/:id` with its maintenance replay; each act
//! completes, and the cascade counts what it kept.
//!
//! Handlers are invoked directly with the caller's `ViewerExtractor`, as
//! `own_claim_authority_http.rs` does. Known limit: the router's wiring and
//! its middleware are not exercised here, only the handlers. The `AppState`'s pools are the
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
use epigraph_api::routes::edges::delete_edge;
use epigraph_api::routes::versioning::{
    mark_duplicate, supersede_claim, unmark_duplicate, DedupRequest, SupersedeRequest,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{MassFunctionRepository, ScopedPool, SessionGucMode};
use retracted::{retract_through_definer, row_state};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{as_role, bypass, database_url_for, downgraded_pool, seed_agent_with_group};

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

fn with_scopes(agent: Uuid, scopes: &[&str]) -> Option<Extension<AuthContext>> {
    let mut ctx = human(agent).expect("an auth context").0;
    ctx.scopes = scopes.iter().map(|s| (*s).to_string()).collect();
    Some(Extension(ctx))
}

#[allow(clippy::too_many_arguments)]
async fn row(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Option<Uuid>,
    perspective: Option<Uuid>,
    masses: serde_json::Value,
    method: Option<&str>,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        agent,
        perspective,
        &masses,
        None,
        method,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store a BBA")
}

async fn is_current(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read is_current")
}

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Stamp `conn` (already `epigraph_app`) for `agent`'s viewer.
async fn stamp(conn: &mut sqlx::PgConnection, v: &Viewer, agent: Uuid) {
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(csv(v.group_bind().expect("scoped")))
    .bind(csv(v.writable_groups()))
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp");
}

/// `agent`'s BBA on `claim`, keyed on `perspective`, written on the
/// application role stamped for `agent` (114 makes it the writer's row).
async fn app_bba(pool: &PgPool, agent: Uuid, claim: Uuid, frame: Uuid, perspective: Uuid) -> Uuid {
    let v = viewer(pool, agent).await;
    as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &v, agent).await;
        let id = MassFunctionRepository::store_with_perspective(
            &mut *conn,
            claim,
            frame,
            Some(agent),
            Some(perspective),
            &serde_json::json!({"0": 0.6, "0,1": 0.4}),
            None,
            Some("test"),
            None,
            None,
            "unknown",
            None,
        )
        .await
        .expect("store the BBA");
        (conn, id)
    })
    .await
}

/// Site 8 on the dedup path over HTTP with the cascade inline (SPEC §11 K4a
/// item 8 skips per KEY): the duplicate's outgoing edge holds a retracted
/// edge BBA of the duplicate's author and another agent's live one; the
/// canonical has a different author. The live row is invalidated, the
/// retracted one is kept and counted, and the edge is re-wired from the
/// canonical under the canonical's author.
#[sqlx::test(migrations = "../../migrations")]
async fn http_dedup_inline_rewires_a_resourced_edge_past_another_keys_retracted_row(pool: PgPool) {
    let state = app_role_state(&pool, true).await;
    let (h, hg) = seed_agent_with_group(&pool, "k4a-http-s8d-h").await;
    let (c, _) = seed_agent_with_group(&pool, "k4a-http-s8d-c").await;
    let (x, xg) = seed_agent_with_group(&pool, "k4a-http-s8d-x").await;
    let dup = claim_of(&pool, h, hg, "k4a http s8d duplicate").await;
    let canonical = claim_of(&pool, c, hg, "k4a http s8d canonical").await;
    let xc = claim_of(&pool, x, xg, "k4a http s8d downstream").await;
    let bf = {
        let (_scoped, v) = bypass(&pool).await;
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_engine::edge_factor::ensure_binary_frame(&mut conn, &v)
            .await
            .expect("binary frame")
    };
    epigraph_db::FrameRepository::assign_claim(&pool, canonical, bf, Some(0))
        .await
        .expect("bind the canonical");
    row(
        &pool,
        canonical,
        bf,
        Some(c),
        None,
        serde_json::json!({"0": 0.9, "0,1": 0.1}),
        None,
    )
    .await;
    let ex = edge(&pool, dup, xc).await;
    let rx = bba(&pool, xc, bf, h, ex).await;
    let lx = bba(&pool, xc, bf, x, ex).await;
    retract_through_definer(&pool, rx).await;

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
    .expect("the caller's dedup");
    let cascade = serde_json::to_value(&resp.cascade).expect("cascade");
    assert_eq!(cascade["status"], "applied", "{cascade}");
    assert_eq!(
        row_state(&pool, rx).await,
        Some((xc, true)),
        "the retracted edge BBA on the re-sourced edge is kept for audit"
    );
    assert!(
        resp.belief_cascade.errors.is_empty(),
        "the cascade completes with no error: {:?}",
        resp.belief_cascade.errors
    );
    assert_eq!(
        row_state(&pool, lx).await,
        None,
        "the live row is invalidated"
    );
    let rewired: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions \
          WHERE claim_id = $1 AND perspective_id = $2 AND source_agent_id = $3 \
            AND retracted_at IS NULL",
    )
    .bind(xc)
    .bind(ex)
    .bind(c)
    .fetch_one(&pool)
    .await
    .expect("count the canonical's re-wired row");
    assert_eq!(
        rewired, 1,
        "the edge is re-wired from the canonical under its author: {:?}",
        resp.belief_cascade
    );
    assert_eq!(
        resp.belief_cascade.retracted_key_kept, 1,
        "{:?}",
        resp.belief_cascade
    );
}

/// Site 3 over HTTP (`POST /claims/:id/undedup`, inline; an un-mark is never
/// deferred): the input the mark pooled onto the canonical finds its slot on
/// the duplicate held by a RETRACTED cached combination. The retracted row is
/// kept, the input does not return, it is reported drifted, and the un-mark
/// itself lands.
#[sqlx::test(migrations = "../../migrations")]
async fn http_undedup_keeps_a_retracted_cached_key_and_reports_drift(pool: PgPool) {
    let state = app_role_state(&pool, true).await;
    let (h, hg) = seed_agent_with_group(&pool, "k4a-http-s3").await;
    let dup = claim_of(&pool, h, hg, "k4a http s3 duplicate").await;
    let canonical = claim_of(&pool, h, hg, "k4a http s3 canonical").await;
    // Not bound to the duplicate: the maintenance role holds no DELETE on
    // `claim_frames` (migration 158), outside what this test measures.
    let f = frame(&pool, "s3").await;
    let input = row(
        &pool,
        dup,
        f,
        None,
        None,
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
    )
    .await;
    let Json(resp) = mark_duplicate(
        ViewerExtractor(viewer(&pool, h).await),
        State(state.clone()),
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
    assert_eq!(cascade["status"], "applied", "{cascade}");
    assert_eq!(
        row_state(&pool, input).await,
        Some((canonical, false)),
        "calibration: the mark pooled the input onto the canonical"
    );
    let cached = row(
        &pool,
        dup,
        f,
        None,
        None,
        serde_json::json!({"0": 0.5, "0,1": 0.5}),
        Some("Dempster"),
    )
    .await;
    retract_through_definer(&pool, cached).await;

    let Json(resp) = unmark_duplicate(
        ViewerExtractor(viewer(&pool, h).await),
        State(state),
        human(h),
        Path(dup),
    )
    .await
    .expect("the author's un-mark");
    assert_eq!(
        row_state(&pool, cached).await,
        Some((dup, true)),
        "the retracted cached row is kept for audit"
    );
    assert_eq!(
        row_state(&pool, input).await,
        Some((canonical, false)),
        "the input whose slot a retracted row holds does not return"
    );
    let cascade = serde_json::to_value(&resp.cascade).expect("cascade");
    let touched = &cascade["touched"];
    assert_eq!(
        (&touched["cached_rows_cleared"], &touched["drifted"]),
        (&serde_json::json!(0), &serde_json::json!(1)),
        "nothing retracted is cleared; the blocked input is reported drifted: {cascade}"
    );
    assert!(
        is_current(&pool, dup).await,
        "calibration: the un-mark landed: {cascade}"
    );
}

/// Sites 4 and 5 over HTTP (`DELETE /edges/:id`) and its replay: the edge's
/// owner retracts it. In the request (the application-session caller arm of
/// `withdraw_edge_bbas_conn`) the owner's live edge BBA goes and its
/// retracted one stays; the maintenance replay removes the other writer's
/// live one and keeps its retracted one. Neither half fails.
#[sqlx::test(migrations = "../../migrations")]
async fn http_delete_edge_and_its_replay_keep_retracted_edge_bbas(pool: PgPool) {
    let state = app_role_state(&pool, false).await;
    let (owner, _) = seed_agent_with_group(&pool, "k4a-http-edge-owner").await;
    let (foreign, _) = seed_agent_with_group(&pool, "k4a-http-edge-foreign").await;
    let author = seed_agent_with_group(&pool, "k4a-http-edge-author").await.0;
    let a = viewer_fixture::seed_public_claim(&pool, author, "k4a http edge source").await;
    let b = viewer_fixture::seed_public_claim(&pool, author, "k4a http edge target").await;
    let (f1, f2) = (frame(&pool, "e1").await, frame(&pool, "e2").await);

    let ov = viewer(&pool, owner).await;
    let e: Uuid = as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &ov, owner).await;
        let e: Uuid = sqlx::query_scalar(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
        )
        .bind(a)
        .bind(b)
        .fetch_one(&mut *conn)
        .await
        .expect("the owner's edge");
        (conn, e)
    })
    .await;
    sqlx::query(
        "INSERT INTO perspectives (id, name, perspective_type) VALUES ($1, 'edge_factor', 'edge')",
    )
    .bind(e)
    .execute(&pool)
    .await
    .expect("seed the edge's perspective");
    let own_live = app_bba(&pool, owner, b, f1, e).await;
    let own_retracted = app_bba(&pool, owner, b, f2, e).await;
    let foreign_live = app_bba(&pool, foreign, b, f1, e).await;
    let foreign_retracted = app_bba(&pool, foreign, b, f2, e).await;
    retract_through_definer(&pool, own_retracted).await;
    retract_through_definer(&pool, foreign_retracted).await;

    let status = delete_edge(
        ViewerExtractor(viewer(&pool, owner).await),
        State(state),
        with_scopes(owner, &["edges:write"]),
        Path(e),
    )
    .await
    .expect("the owner retracts its edge");
    assert!(status.is_success(), "{status}");
    assert_eq!(
        row_state(&pool, own_retracted).await,
        Some((b, true)),
        "the request keeps the owner's retracted edge BBA"
    );
    assert_eq!(
        row_state(&pool, own_live).await,
        None,
        "and deletes its live one"
    );
    assert_eq!(
        row_state(&pool, foreign_live).await,
        Some((b, false)),
        "calibration: another writer's live row waits for the replay"
    );

    let report = replay_now(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert_eq!(
        row_state(&pool, foreign_retracted).await,
        Some((b, true)),
        "the replay keeps another writer's retracted edge BBA"
    );
    assert_eq!(
        row_state(&pool, foreign_live).await,
        None,
        "and removes its live one"
    );
}
