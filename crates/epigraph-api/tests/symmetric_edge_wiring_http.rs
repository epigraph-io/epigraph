//! `POST /api/v1/edges` over a symmetric claim/claim relationship wires belief
//! along the STORED orientation on a reverse dedup hit.
//!
//! The HTTP twin of MCP
//! `link_epistemic_smoke.rs::reverse_order_rehit_wires_the_stored_orientation`.
//! The edge-keyed BBA encodes "source's interval restricts target". Once both
//! call orders of `CONTRADICTS` share ONE row, a wake-up that arrives as the
//! REVERSE call must wire the row's direction, or the factor on that edge id
//! describes the opposite of the row it hangs on.
//!
//! Lives here rather than in `routes/edges.rs`'s `db_tests` because it must
//! give two claims a belief interval mid-test, and
//! `viewer_route_table_lint.rs` counts every `UPDATE` statement in
//! `src/routes/` (test modules included) against the route-layer write
//! ratchet.

mod viewer_fixture;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Extension;
use axum::Json;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::edges::{create_edge, CreateEdgeRequest, CreateEdgeResponse};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, seed_agent_with_group, seed_public_claim};

/// The shape `routes/edges.rs`'s in-crate `db_tests::test_state` uses: a
/// session-stamped `ScopedPool` on the harness role, with `db_pool` its inner
/// pool, so the post-commit DS recomputation lands.
async fn state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped = ScopedPool::connect(&url, SessionGucMode::Session)
        .await
        .expect("connect a scoped pool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
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
    }))
}

fn contradicts(source: Uuid, target: Uuid) -> CreateEdgeRequest {
    CreateEdgeRequest {
        source_id: source,
        target_id: target,
        source_type: "claim".to_string(),
        target_type: "claim".to_string(),
        relationship: "CONTRADICTS".to_string(),
        properties: None,
        labels: None,
        valid_from: None,
        valid_to: None,
        if_not_exists: true,
    }
}

async fn post(
    pool: &PgPool,
    state: &AppState,
    agent: Uuid,
    req: CreateEdgeRequest,
) -> (StatusCode, CreateEdgeResponse) {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let (status, Json(body)) = create_edge(
        ViewerExtractor(viewer),
        State(state.clone()),
        auth(agent),
        Json(req),
    )
    .await
    .expect("create_edge");
    (status, body)
}

async fn betp(pool: &PgPool, claim: Uuid) -> f64 {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read pignistic_prob")
        .expect("pignistic_prob set")
}

async fn bbas_on(pool: &PgPool, edge: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM mass_functions WHERE perspective_id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("count edge BBAs")
}

/// Sequenced so the orientation decision matters. The row is written
/// `A CONTRADICTS B` while A is factorless (nothing wired); both claims then
/// gain identical intervals, and the wake-up arrives as `B CONTRADICTS A`. The
/// two candidate orientations have opposite, mutually exclusive outcomes:
///   stored  (A -> B): B is recomputed and drops, A keeps its 0.9
///   request (B -> A): A is recomputed and drops, B keeps its 0.9
#[sqlx::test(migrations = "../../migrations")]
async fn reverse_symmetric_rehit_wires_the_stored_orientation(pool: PgPool) {
    let state = state(&pool).await;
    let (agent, _) = seed_agent_with_group(&pool, "symmetric-wiring").await;
    let a = seed_public_claim(&pool, agent, "stored source, factorless at first").await;
    let b = seed_public_claim(&pool, agent, "stored target").await;

    let (s1, first) = post(&pool, &state, agent, contradicts(a, b)).await;
    assert_eq!(s1, StatusCode::CREATED);
    let id1 = first.edge.id;
    assert_eq!(
        bbas_on(&pool, id1).await,
        0,
        "A is factorless: nothing wired"
    );

    sqlx::query(
        "UPDATE claims SET belief = 0.9, plausibility = 0.9, pignistic_prob = 0.9 \
         WHERE id = ANY($1)",
    )
    .bind(vec![a, b])
    .execute(&pool)
    .await
    .expect("give both claims a belief interval");

    let (s2, second) = post(&pool, &state, agent, contradicts(b, a)).await;

    let a_betp = betp(&pool, a).await;
    assert!(
        (a_betp - 0.9).abs() < 1e-9,
        "A is the STORED source and must keep its seeded 0.9; wiring the \
         request's orientation (B -> A) recomputes A downward. Got {a_betp} \
         (second response {s2}, edge {} {} -> {})",
        second.edge.id,
        second.edge.source_id,
        second.edge.target_id
    );
    let b_betp = betp(&pool, b).await;
    assert!(
        b_betp < 0.5,
        "the stored A -> B contradiction from a high-belief source must push \
         B below 0.5, got {b_betp}"
    );
    assert_eq!(
        bbas_on(&pool, id1).await,
        1,
        "the wake-up BBA is keyed on the one stored edge"
    );
    assert_eq!(second.edge.id, id1, "one row for one disagreement");
    assert_eq!(s2, StatusCode::OK);
}
