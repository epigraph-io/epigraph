#![cfg(feature = "db")]
//! `POST /api/v1/edges` wires belief on the CALLER's stamped transaction, on
//! the PRODUCTION pool shape (backlog 8d720490 (5)).
//!
//! # The defect
//!
//! `create_edge` writes the edge on `AppState::write_as`, but its DS
//! auto-wire (`trigger_edge_ds_recomputation`, and the 1-hop propagation
//! after it) ran after the commit on `state.db_pool`. Production builds that
//! pool as `scoped.inner()` on the `epigraph_app` login, which row security
//! holds to `visibility = 'public'` when no tenancy context is stamped, and an
//! unstamped write sees an empty writable set. So:
//!
//! * between two of the caller's own GROUP-PRIVATE claims, the source-author
//!   read found no row and the wire was skipped without a word;
//! * between two PUBLIC claims the caller's group owns, the author read
//!   succeeded but the wiring's `claim_frames` / `mass_functions` / `claims`
//!   writes were refused, and the route only logged it.
//!
//! Either way the HTTP epistemic edge moved no belief, while its MCP twin
//! `link_epistemic` (which wires on its stamped transaction) did.
//!
//! # The instrument
//!
//! [`production_state`] is `http_public_only_reads.rs`'s: `db_pool` IS
//! `scoped.inner()`, and both run as `epigraph_app`, so a post-commit side
//! effect on the raw pool meets the same row security it meets in production.

mod viewer_fixture;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Extension;
use axum::Json;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::edges::{create_edge, CreateEdgeRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, seed_agent_with_group, seed_group_claim};

/// `AppState` exactly as `bin/server.rs` builds it, on the application role.
async fn production_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("epigraph_app ScopedPool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
    let (user, privileged): (String, bool) = sqlx::query_as(
        "SELECT current_user::text, rolsuper OR rolbypassrls \
           FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&state.db_pool)
    .await
    .expect("role of the production pool");
    assert!(
        user == "epigraph_app" && !privileged,
        "CALIBRATION: db_pool must be the application role under row security, as in \
         production ({user}, privileged {privileged}); otherwise every arm here is vacuous"
    );
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
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

/// A claim owned by `group`, with visibility `vis`, written on the harness
/// superuser as seeding. (`seed_group_claim` then a visibility UPDATE would be
/// refused: a group claim is never declassified in place.)
async fn seed(pool: &PgPool, agent: Uuid, group: Uuid, vis: &str, content: &str) -> Uuid {
    if vis == "group" {
        return seed_group_claim(pool, agent, group, content).await;
    }
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.8, $4, true, $5, $6)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .bind(vis)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// A member, and a SUPPORTS pair in its own group with visibility `vis`. The
/// source has a belief interval (so it is not factorless); the target has no
/// cache. Written on the harness superuser, as seeding.
async fn pair(pool: &PgPool, label: &str, vis: &str) -> (Uuid, Uuid, Uuid) {
    let (member, group) = seed_agent_with_group(pool, label).await;
    let source = seed(pool, member, group, vis, &format!("{label} source")).await;
    let target = seed(pool, member, group, vis, &format!("{label} target")).await;
    sqlx::query(
        "UPDATE claims SET belief = 0.8, plausibility = 0.9, pignistic_prob = 0.85 \
         WHERE id = $1",
    )
    .bind(source)
    .execute(pool)
    .await
    .expect("give the source an interval");
    (member, source, target)
}

/// POST `source SUPPORTS target` as `member` on `state`; insist on 201.
async fn post_supports(
    state: &AppState,
    pool: &PgPool,
    member: Uuid,
    source: Uuid,
    target: Uuid,
) -> Uuid {
    let viewer = Viewer::resolve(pool, member).await.expect("resolve viewer");
    let (status, Json(body)) = create_edge(
        ViewerExtractor(viewer),
        State(state.clone()),
        auth(member),
        Json(CreateEdgeRequest {
            source_id: source,
            target_id: target,
            source_type: "claim".to_string(),
            target_type: "claim".to_string(),
            relationship: "SUPPORTS".to_string(),
            properties: None,
            labels: None,
            valid_from: None,
            valid_to: None,
            if_not_exists: false,
        }),
    )
    .await
    .expect("create_edge");
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the edge itself must be written"
    );
    body.edge.id
}

/// (edge-keyed BBAs, the target's cached BetP, the target's cache frame).
async fn wired(pool: &PgPool, edge: Uuid, target: Uuid) -> (i64, Option<f64>, Option<Uuid>) {
    let bbas: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mass_functions WHERE perspective_id = $1")
            .bind(edge)
            .fetch_one(pool)
            .await
            .expect("count edge BBAs");
    let (betp, frame): (Option<f64>, Option<Uuid>) =
        sqlx::query_as("SELECT pignistic_prob, belief_frame_id FROM claims WHERE id = $1")
            .bind(target)
            .fetch_one(pool)
            .await
            .expect("read the target's cache");
    (bbas, betp, frame)
}

fn assert_wired(what: &str, (bbas, betp, frame): (i64, Option<f64>, Option<Uuid>)) {
    assert_eq!(
        bbas, 1,
        "{what}: the epistemic edge must materialize its BBA on the caller's stamped \
         transaction (target cache {betp:?} on {frame:?})"
    );
    assert!(
        frame.is_some() && betp.is_some_and(|p| p > 0.5),
        "{what}: the wire must recompute the target's cache from the SUPPORTS factor: \
         BetP {betp:?} on {frame:?}"
    );
}

/// The member's own group-private pair: on the raw pool the source-author
/// read could not see the source, so nothing was wired.
#[sqlx::test(migrations = "../../migrations")]
async fn a_supports_edge_between_own_group_private_claims_wires_the_target(pool: PgPool) {
    let state = production_state(&pool).await;
    let (member, source, target) = pair(&pool, "autowire-private", "group").await;
    let edge = post_supports(&state, &pool, member, source, target).await;
    assert_wired("group-private pair", wired(&pool, edge, target).await);
}

/// A public pair the member's group owns: on the raw pool the author read
/// succeeded but the wiring's writes were refused by row security.
#[sqlx::test(migrations = "../../migrations")]
async fn a_supports_edge_between_own_public_claims_wires_the_target(pool: PgPool) {
    let state = production_state(&pool).await;
    let (member, source, target) = pair(&pool, "autowire-public", "public").await;
    let edge = post_supports(&state, &pool, member, source, target).await;
    assert_wired("public pair", wired(&pool, edge, target).await);
}

/// The PROPAGATION half: once the wire lands, `propagate_to_dependents`
/// recomputes each claim whose reasoning trace names the target. Here that is
/// a group-private dependent in the member's group, with a binary_truth BBA
/// and a deliberately stale cache. On the raw pool the trace read could not
/// see the dependent and its cache write would be refused; on the caller's
/// stamped transaction the dependent's cache becomes its BBA fold.
#[sqlx::test(migrations = "../../migrations")]
async fn the_wire_propagates_to_a_group_private_dependent(pool: PgPool) {
    use epigraph_db::MassFunctionRepository;
    use epigraph_engine::edge_factor::{ensure_binary_frame, preview_claim_belief_on_frame};

    let state = production_state(&pool).await;
    let (member, source, target) = pair(&pool, "autowire-propagate", "group").await;
    let group: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(target)
        .fetch_one(&pool)
        .await
        .expect("the pair's group");
    let viewer = Viewer::resolve(&pool, member)
        .await
        .expect("resolve viewer");
    let binary = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &viewer)
        .await
        .expect("binary_truth");

    let dependent = seed_group_claim(&pool, member, group, "autowire-propagate dependent").await;
    MassFunctionRepository::store_with_perspective(
        &pool,
        dependent,
        binary,
        Some(member),
        None,
        &serde_json::json!({"0": 0.8, "0,1": 0.2}),
        None,
        Some("auto_wire"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store the dependent's BBA");
    sqlx::query(
        "UPDATE claims SET belief = 0.1, plausibility = 0.2, pignistic_prob = 0.15, \
                           belief_frame_id = $2 WHERE id = $1",
    )
    .bind(dependent)
    .bind(binary)
    .execute(&pool)
    .await
    .expect("give the dependent a stale cache");
    let trace = viewer_fixture::seed_reasoning_trace(&pool, dependent, "deductive").await;
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
    .expect("name the target as an input of the dependent's trace");
    let fold = preview_claim_belief_on_frame(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
        dependent,
        binary,
    )
    .await
    .expect("preview")
    .expect("the dependent's BBA folds");
    assert!(
        (fold.pignistic_prob - 0.15).abs() > 0.1,
        "PREMISE: the stale cache differs from the fold ({fold:?})"
    );

    let edge = post_supports(&state, &pool, member, source, target).await;
    assert_wired("propagation pair", wired(&pool, edge, target).await);

    let betp: Option<f64> = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(dependent)
        .fetch_one(&pool)
        .await
        .expect("read the dependent's cache");
    assert!(
        betp.is_some_and(|p| (p - fold.pignistic_prob).abs() < 1e-9),
        "the 1-hop propagation must recompute the dependent on the caller's stamped \
         transaction: cached {betp:?}, fold {fold:?}"
    );
}
