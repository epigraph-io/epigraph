#![cfg(feature = "db")]
//! Ruling R-80 over HTTP: a claim whose EVERY BBA is inadmissible for its
//! cache (ruling R-22 / R-71: some source is narrower than the claim) gets a
//! VACUOUS cache when a REST write recomputes it, and that is what a reader is
//! served afterwards.
//!
//! The REST path is `POST /api/v1/edges`' dependent propagation
//! (`routes/edges.rs::propagate_to_dependents` -> `recompute_claim_belief` ->
//! `edge_factor::recompute_claim_belief_binary`): an epistemic edge into T
//! recomputes every claim whose reasoning trace takes T as an input. That
//! recompute runs on an UNSTAMPED connection from the raw pool, a session
//! state neither MCP twin (a viewer-stamped application session, the
//! maintenance session) has.
//!
//! # The instrument, and what it cannot reach
//!
//! The route is driven with `AppState.scoped` on the application role (the
//! handler's own writes) and `AppState.db_pool` on the harness role, the shape
//! of a deployment whose raw pool is privileged. With the raw pool on the
//! application role as well, the edge wires no factor (measured: no
//! `mass_functions` row for the edge), so the propagation never runs and the
//! route cannot reach the recompute in that configuration. The second test
//! therefore runs the propagation's own call, `recompute_claim_belief_binary`,
//! on an unstamped application-role connection (`downgraded_pool`), which is
//! the row-security state every R-80 read (the claim's combine inputs, their
//! admissibility, the compound test) runs under there. That session decides
//! to vacate, but cannot write the cache at all (a known residual of the
//! unstamped route, pinned there).
//!
//! The read back is `GET /api/v1/claims/:id/belief` (`get_claim_belief`, the
//! claims columns) as a reader outside the evidence's group, on the
//! application role. That response carries no classification; the MCP twin
//! reads it.
//!
//! The MCP twins are `crates/epigraph-mcp/tests/recompute_vacates_inadmissible_only_cache.rs`.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::belief::get_claim_belief;
use epigraph_api::routes::edges::{create_edge, CreateEdgeRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{MassFunctionRepository, PerspectiveRepository, ScopedPool, SessionGucMode};
use epigraph_engine::edge_factor::{
    ensure_binary_frame, preview_claim_belief_on_frame, recompute_claim_belief_binary,
    recompute_claim_cached_belief,
};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, downgraded_pool, public_viewer, seed_agent_with_group, seed_evidence,
    seed_public_claim, seed_reasoning_trace,
};

async fn app_role_scoped(pool: &PgPool) -> ScopedPool {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(!bypassrls, "PREMISE: epigraph_app is held to row security");
    let url = database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// `scoped` on the application role; the raw `db_pool` is `raw`.
async fn state_with_raw(pool: &PgPool, raw: PgPool) -> AppState {
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(app_role_scoped(pool).await);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

/// An unstamped application-role pool, checked.
async fn unstamped_app_pool(pool: &PgPool) -> PgPool {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let raw_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&raw)
        .await
        .expect("current_user on the raw pool");
    assert_eq!(
        raw_user, "epigraph_app",
        "CALIBRATION: the unstamped pool is the application role"
    );
    raw
}

fn auth(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: agent,
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Service,
        scopes: vec!["edges:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

/// The claim's whole cache: (BetP, Bel, Pl, mass_on_empty, mass_on_missing,
/// belief_frame_id, classification).
type Cache = (
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<Uuid>,
    Option<String>,
);

async fn cache(pool: &PgPool, claim: Uuid) -> Cache {
    sqlx::query_as(
        "SELECT pignistic_prob, belief, plausibility, mass_on_empty, mass_on_missing, \
                belief_frame_id, classification \
           FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the cache")
}

fn near(x: Option<f64>, y: f64) -> bool {
    x.is_some_and(|x| (x - y).abs() < 1e-9)
}

/// Full ignorance on the binary `frame`, with `not_enough_info`.
fn is_vacuous(c: &Cache, frame: Uuid) -> bool {
    near(c.0, 0.5)
        && near(c.1, 0.0)
        && near(c.2, 1.0)
        && near(c.3, 0.0)
        && near(c.4, 0.0)
        && c.5 == Some(frame)
        && c.6.as_deref() == Some("not_enough_info")
}

/// What `GET /api/v1/claims/:id/belief` serves `reader` about `claim` must be
/// full ignorance, with no BBA the reader can trace.
async fn assert_served_ignorance(state: &AppState, pool: &PgPool, reader: Uuid, claim: Uuid) {
    let viewer = Viewer::resolve(pool, reader).await.expect("viewer");
    let Json(served) = get_claim_belief(ViewerExtractor(viewer), State(state.clone()), Path(claim))
        .await
        .unwrap_or_else(|e| panic!("get_claim_belief failed: {e:?}"));
    assert!(
        near(served.pignistic_prob, 0.5)
            && near(served.belief, 0.0)
            && near(served.plausibility, 1.0)
            && near(served.ignorance, 1.0)
            && near(served.mass_on_conflict, 0.0)
            && near(served.mass_on_missing, 0.0),
        "GET /api/v1/claims/:id/belief must serve full ignorance after the vacate: {served:?}"
    );
    assert_eq!(
        served.mass_function_count, 0,
        "the reader can trace none of the claim's BBAs"
    );
}

struct World {
    public: Viewer,
    member: Uuid,
    group: Uuid,
    author: Uuid,
    stranger: Uuid,
    binary: Uuid,
}

async fn world(pool: &PgPool, label: &str) -> World {
    let public = public_viewer(pool).await;
    let (member, group) = seed_agent_with_group(pool, &format!("{label}-member")).await;
    let (author, _) = seed_agent_with_group(pool, &format!("{label}-author")).await;
    let (stranger, _) = seed_agent_with_group(pool, &format!("{label}-stranger")).await;
    let binary = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary_truth");
    World {
        public,
        member,
        group,
        author,
        stranger,
        binary,
    }
}

/// D: a public claim whose one BBA cites public evidence, its cache folded
/// from it; then that evidence is narrowed to the member's group, pinned as
/// `epigraph-operator hide-evidence` pins it (migration 110). Every BBA of D
/// is now inadmissible and its cache still holds the old fold.
async fn stale_dependent(pool: &PgPool, w: &World, label: &str) -> (Uuid, Cache) {
    let dependent = seed_public_claim(pool, w.author, label).await;
    let ev = seed_evidence(pool, dependent, "observation").await;
    PerspectiveRepository::ensure_evidence_perspective(pool, ev, Some(w.author))
        .await
        .expect("evidence perspective");
    MassFunctionRepository::store_with_perspective(
        pool,
        dependent,
        w.binary,
        Some(w.author),
        Some(ev),
        &serde_json::json!({"0": 0.8, "0,1": 0.2}),
        None,
        Some("auto_wire"),
        Some(1.0),
        None,
        "unknown",
        Some(ev),
    )
    .await
    .expect("store a BBA");
    recompute_claim_cached_belief(
        &mut pool.acquire().await.expect("acquire"),
        &w.public,
        dependent,
    )
    .await
    .expect("recompute while the evidence is public");
    let stale = cache(pool, dependent).await;
    assert!(
        stale.0.is_some_and(|b| b > 0.55) && stale.6.is_some(),
        "PREMISE: the public evidence's fold is cached ({stale:?})"
    );
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: hidden')",
    )
    .bind(ev)
    .bind(w.member)
    .execute(pool)
    .await
    .expect("pin the hidden evidence");
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(ev)
        .bind(w.group)
        .execute(pool)
        .await
        .expect("narrow the evidence to the group");
    (dependent, stale)
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_edge_write_vacates_a_dependent_whose_every_bba_is_inadmissible(pool: PgPool) {
    let state = state_with_raw(&pool, pool.clone()).await;
    let w = world(&pool, "r80-http").await;
    let (dependent, stale) = stale_dependent(&pool, &w, "r80 http dependent").await;
    let (author, binary) = (w.author, w.binary);

    // T, an input of D's reasoning trace; S, a source with a belief interval,
    // so an S -> T supports edge wires a factor and propagates to D.
    let target = seed_public_claim(&pool, author, "r80 http target").await;
    let source = seed_public_claim(&pool, author, "r80 http source").await;
    sqlx::query(
        "UPDATE claims SET belief = 0.9, plausibility = 0.95, pignistic_prob = 0.9 WHERE id = $1",
    )
    .bind(source)
    .execute(&pool)
    .await
    .expect("source interval");
    let trace = seed_reasoning_trace(&pool, dependent, "deductive").await;
    sqlx::query(
        "UPDATE reasoning_traces \
            SET properties = jsonb_build_object('inputs', \
                    jsonb_build_array(jsonb_build_object('type', 'claim', 'id', $2::text))) \
          WHERE id = $1",
    )
    .bind(trace)
    .bind(target.to_string())
    .execute(&pool)
    .await
    .expect("name T as an input of D's trace");

    let viewer = Viewer::resolve(&pool, author).await.expect("author viewer");
    let (status, Json(created)) = create_edge(
        ViewerExtractor(viewer),
        State(state.clone()),
        auth(author),
        Json(CreateEdgeRequest {
            source_id: source,
            target_id: target,
            source_type: "claim".to_string(),
            target_type: "claim".to_string(),
            relationship: "supports".to_string(),
            properties: None,
            labels: None,
            valid_from: None,
            valid_to: None,
            if_not_exists: true,
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("create_edge failed: {e:?}"));
    assert_eq!(status, StatusCode::CREATED);
    let wired: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mass_functions WHERE perspective_id = $1")
            .bind(created.edge.id)
            .fetch_one(&pool)
            .await
            .expect("count the edge's factor");
    assert_eq!(
        wired, 1,
        "CALIBRATION: the edge wired its factor, so the propagation to D ran"
    );

    let after = cache(&pool, dependent).await;
    assert!(
        is_vacuous(&after, binary),
        "the edge write's dependent recompute must vacate the cache of a claim whose every \
         BBA is inadmissible; it left {after:?} (stale value {stale:?})"
    );

    // What a reader outside the evidence's group is served.
    assert_served_ignorance(&state, &pool, w.stranger, dependent).await;
}

/// The propagation's own recompute (`recompute_claim_belief_binary`, as
/// `routes/edges.rs::recompute_claim_belief` calls it) on an UNSTAMPED
/// application-role connection, where row security hides the narrowed
/// evidence from the session altogether. The R-80 decision reads run under
/// that session state and decide to vacate: the write-free preview, which
/// runs the same decision, is full ignorance.
///
/// KNOWN RESIDUAL, pinned as it stands: that session cannot write the cache
/// at all. `update_claim_belief` is refused by row security there (as it is
/// for an ordinary fold on that session; `routes/edges.rs` is still
/// unstamped), the route logs the failure and continues, and the claim keeps
/// its old cache until a stamped or maintenance recompute vacates it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_unstamped_application_session_decides_to_vacate(pool: PgPool) {
    let raw = unstamped_app_pool(&pool).await;
    let w = world(&pool, "r80-unstamped").await;
    let (dependent, stale) = stale_dependent(&pool, &w, "r80 unstamped dependent").await;
    let visible_evidence: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM evidence WHERE claim_id = $1")
            .bind(dependent)
            .fetch_one(&raw)
            .await
            .expect("count evidence on the unstamped session");
    assert_eq!(
        visible_evidence, 0,
        "CALIBRATION: the unstamped application session cannot see the narrowed evidence"
    );
    let author = Viewer::resolve(&pool, w.author)
        .await
        .expect("author viewer");

    let preview = preview_claim_belief_on_frame(
        &mut raw.acquire().await.expect("acquire unstamped"),
        &author,
        dependent,
        w.binary,
    )
    .await
    .expect("preview on the unstamped application session")
    .unwrap_or_else(|| {
        panic!(
            "on the unstamped session the recompute of a claim whose every BBA is \
             inadmissible decided to leave its cache (stale value {stale:?})"
        )
    });
    assert!(
        near(Some(preview.pignistic_prob), 0.5)
            && near(Some(preview.belief), 0.0)
            && near(Some(preview.plausibility), 1.0)
            && near(Some(preview.conflict_k), 0.0)
            && near(Some(preview.missing_mass), 0.0)
            && preview.classification.as_deref() == Some("not_enough_info"),
        "the unstamped session's decision must be full ignorance: {preview:?}"
    );

    let refused = recompute_claim_belief_binary(
        &mut raw.acquire().await.expect("acquire unstamped"),
        &author,
        dependent,
    )
    .await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| e.contains("update_claim_belief") && e.contains("row-level security")),
        "KNOWN RESIDUAL changed (the unstamped application session cannot write the cache); \
         update this pin with the fix: {refused:?}"
    );
    assert_eq!(
        cache(&pool, dependent).await,
        stale,
        "the refused write left the cache as it was"
    );
}
