//! `POST /api/v1/graph/compose` computes over what its caller can read
//! (backlog 52b96600).
//!
//! The handler took no `Viewer`. It walked both neighborhoods with a recursive
//! CTE over `edges` and read every node's `pignistic_prob` on the raw
//! `state.db_pool`, then returned counts and a boundary inconsistency derived
//! from those rows. On a pool that bypasses row security that is every group's
//! claims and edges; on the production pool (`epigraph_app`, unstamped) it is
//! public rows only, so a member lost their own group's claims.
//!
//! # The graph
//!
//! `p`, `q`, `r` are public; `g` is private to the member's group.
//!
//! ```text
//!   r --(edge private to the group)-- p --(edge forced public)-- g --(edge)-- q
//! ```
//!
//! * `p -> g` is forced `public`, so only the CLAIM predicate on the step's
//!   target can hide `g` (an edge-only filter would walk onto it).
//! * `p -> r` joins two public claims but is private to the group, so only the
//!   EDGE predicate can hide `r`.
//!
//! Composing `p` with `q` at depth 2: the member reaches `{p, g, r, q}` on the
//! left and `{q, g, p}` on the right (4 nodes, boundary 3). An outsider reaches
//! `{p}` and `{q}` (2 nodes, boundary 0).
//!
//! # Two routers, because each one alone proves half
//!
//! * [`superuser_router`]: `build_app_for_tests`, a superuser pool that row
//!   security does not filter. Only the in-query viewer predicate can hide
//!   `g` and `r` from the outsider; the old handler returned 4 nodes here.
//! * [`app_role_router`]: an `epigraph_app` `ScopedPool`, FORCEd row security.
//!   The member must still see `g` and `r`, which needs the connection to be
//!   STAMPED with the member's groups; the old handler's unstamped raw pool
//!   saw public edges only, missed both of the group's edges and returned 3
//!   nodes. The outsider arm runs here too.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;
#[allow(dead_code)]
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{
    seed_agent_with_group, seed_edge, seed_edge_owned_by, seed_group_claim, seed_public_claim,
    world_group,
};

async fn superuser_router(pool: &PgPool) -> axum::Router {
    let url = viewer_fixture::database_url_for(pool).await;
    epigraph_api::build_app_for_tests(&url)
        .await
        .expect("app builds for tests")
}

async fn app_role_router(pool: &PgPool) -> axum::Router {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "CALIBRATION: epigraph_app holds BYPASSRLS, so the app-role arms are vacuous"
    );
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    epigraph_api::routes::create_router(state)
}

/// `(total_nodes, left_boundary, left_interior)` of a compose call. The
/// boundary is the raw shared-node count; `shared_boundary_size` counts only
/// boundary nodes that carry a belief, and these seeded claims carry none.
async fn compose(
    router: &axum::Router,
    agent: Uuid,
    center_a: Uuid,
    center_b: Uuid,
) -> (u64, u64, u64) {
    let token = common::mint_token_with_agent(&["claims:read"], agent);
    let body = json!({ "center_a": center_a, "center_b": center_b, "max_depth": 2 });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/graph/compose")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("router");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let out: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    assert_eq!(status, StatusCode::OK, "compose answered {status}: {out}");
    let n = |k: &str| {
        out[k]
            .as_u64()
            .unwrap_or_else(|| panic!("`{k}` missing: {out}"))
    };
    (
        n("total_nodes"),
        n("left_boundary"),
        n("left_interior"),
    )
}

struct Graph {
    member: Uuid,
    outsider: Uuid,
    p: Uuid,
    q: Uuid,
    g: Uuid,
}

async fn graph(pool: &PgPool) -> Graph {
    let (member, group) = seed_agent_with_group(pool, "compose-member").await;
    let (outsider, _) = seed_agent_with_group(pool, "compose-outsider").await;
    let p = seed_public_claim(pool, member, "compose: public center a").await;
    let q = seed_public_claim(pool, member, "compose: public center b").await;
    let r = seed_public_claim(pool, member, "compose: public, behind a private edge").await;
    let g = seed_group_claim(pool, member, group, "compose: private to the group").await;
    let world = world_group(pool).await;
    seed_edge_owned_by(pool, p, g, "public", world).await;
    seed_edge(pool, g, q).await;
    seed_edge_owned_by(pool, p, r, "group", group).await;
    Graph {
        member,
        outsider,
        p,
        q,
        g,
    }
}

/// On a pool row security does not filter, only the viewer predicate keeps
/// the group's claim and the group's edge out of an outsider's composition.
#[sqlx::test(migrations = "../../migrations")]
async fn an_outsider_composes_without_the_groups_claims_or_edges(pool: PgPool) {
    let w = graph(&pool).await;
    let router = superuser_router(&pool).await;

    // CALIBRATION: the member reaches the private claim and the claim behind
    // the private edge, so the graph is wired as the module doc says.
    assert_eq!(
        compose(&router, w.member, w.p, w.q).await,
        (4, 3, 1),
        "CALIBRATION: the member composes over p, g, r and q"
    );
    assert_eq!(
        compose(&router, w.outsider, w.p, w.q).await,
        (2, 0, 1),
        "the outsider's composition counted a claim or an edge private to a group it is not in"
    );
}

/// A center the caller cannot read answers exactly as an id that names no
/// claim: it is not expanded, so the response is not an existence oracle.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_center_answers_as_a_missing_one(pool: PgPool) {
    let w = graph(&pool).await;
    let router = superuser_router(&pool).await;

    let hidden = compose(&router, w.outsider, w.g, w.q).await;
    let missing = compose(&router, w.outsider, Uuid::new_v4(), w.q).await;
    assert_eq!(
        hidden, missing,
        "composing from a hidden claim differs from composing from no claim"
    );
    assert_eq!(missing, (2, 0, 1), "a missing center is itself plus q");
    // CALIBRATION: from the member, the same center is expanded.
    assert_eq!(compose(&router, w.member, w.g, w.q).await, (4, 3, 1));
}

/// On the application role with FORCEd row security, the member's own
/// group's claim and edge are in their composition (the connection is
/// stamped with their groups) and the outsider's is still public-only.
#[sqlx::test(migrations = "../../migrations")]
async fn on_the_app_role_a_member_composes_over_their_groups_claims(pool: PgPool) {
    let w = graph(&pool).await;
    let router = app_role_router(&pool).await;

    assert_eq!(
        compose(&router, w.member, w.p, w.q).await,
        (4, 3, 1),
        "the member's composition lost their own group's claim or edge: the read was not \
         stamped with their groups"
    );
    assert_eq!(compose(&router, w.outsider, w.p, w.q).await, (2, 0, 1));
}
