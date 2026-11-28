#![cfg(feature = "db")]
//! `DELETE /api/v1/conventions/:id` is a WRITER's act (backlog 5b98b7ce).
//!
//! Forgetting a convention writes refuting evidence against it and drives its
//! truth toward 0. On a PRIVATE convention (owned by a group, not public) only
//! a writer of the owner group may do that: a member who can only READ the
//! group sees the convention, holds `claims:admin` (the route's scope), and is
//! still refused, with nothing written: no evidence row, no `refutes` edge, no
//! truth change, and no principal agent row minted for the refusal.
//!
//! # The discriminating pair
//!
//! One principal, one token, one route, two private conventions, each authored
//! by another agent in that agent's own group. The principal holds `reader` in
//! group A and `writer` in group B; the only variable is the role it holds in
//! the owning group. B's forget lands (200, an evidence row), A's is refused
//! (403) and writes nothing. A negative alone would pass over a route that
//! refuses everything.
//!
//! The check is about PRIVATE conventions; the public path is unchanged.
//!
//! The router runs on an `epigraph_app` `ScopedPool` (row security applies),
//! so the refusal is measured where production measures it.

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

async fn app_scoped(pool: &PgPool) -> ScopedPool {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: the pair is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// A `claims:admin` token for `agent`, `sub` = `client`, no `owner_id`: the
/// handler attributes its evidence to a principal agent keyed on `client`.
fn token(state: &AppState, client: Uuid, agent: Uuid) -> String {
    state
        .jwt_config
        .issue_access_token(
            client,
            vec!["claims:read".to_string(), "claims:admin".to_string()],
            "agent",
            None,
            Some(agent),
            chrono::Duration::minutes(15),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("mint")
        .0
}

async fn forget(router: &axum::Router, token: &str, id: Uuid) -> (StatusCode, String) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/v1/conventions/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A private (`visibility = 'group'`) convention owned by `group`.
async fn private_convention(pool: &PgPool, author: Uuid, group: Uuid, label: &str) -> Uuid {
    let id = fixture::seed_group_claim(pool, author, group, &format!("convention {label}")).await;
    sqlx::query("UPDATE claims SET labels = ARRAY['convention'], truth_value = 0.8 WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("label the convention");
    id
}

/// `(evidence rows, refutes edges, truth)` of one convention.
async fn footprint(pool: &PgPool, claim: Uuid) -> (i64, i64, f64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM evidence WHERE claim_id = $1), \
                (SELECT count(*) FROM edges WHERE target_id = $1 AND relationship = 'refutes'), \
                (SELECT truth_value FROM claims WHERE id = $1)",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("footprint")
}

/// The agents row the handler would get-or-create for a caller whose token
/// names `client` (and no `owner_id`): the 16-byte id repeated to 32 bytes.
async fn principal_agent_rows(pool: &PgPool, client: Uuid) -> i64 {
    let key = client.as_bytes().repeat(2);
    sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(key)
        .fetch_one(pool)
        .await
        .expect("principal agent rows")
}

struct World {
    router: axum::Router,
    pool: PgPool,
    token: String,
    client: Uuid,
    /// Owned by a group the principal holds `reader` in.
    readable: Uuid,
    /// Owned by a group the principal holds `writer` in.
    writable: Uuid,
}

async fn world(pool: &PgPool) -> World {
    let (principal, _) = fixture::seed_agent_with_group(pool, "forget-principal").await;
    let (author, read_group) = fixture::seed_agent_with_group(pool, "forget-author").await;
    let (author_w, write_group) =
        fixture::seed_agent_with_group(pool, "forget-author-writable").await;
    // One shape on both sides: each convention is authored by ANOTHER agent
    // in that agent's own group, and the principal holds a second membership
    // there. The only variable is that membership's role.
    for (group, role) in [(read_group, "reader"), (write_group, "writer")] {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, $3)",
        )
        .bind(group)
        .bind(principal)
        .bind(role)
        .execute(pool)
        .await
        .expect("second membership");
    }

    let readable = private_convention(pool, author, read_group, "read-only").await;
    let writable = private_convention(pool, author_w, write_group, "writable").await;

    let viewer = epigraph_db::Viewer::resolve(pool, principal)
        .await
        .expect("resolve");
    assert!(
        viewer.group_bind().is_some_and(|g| g.contains(&read_group))
            && !viewer.writable_groups().contains(&read_group),
        "PREMISE: the principal reads the read-only group and does not write it"
    );
    assert!(
        viewer.writable_groups().contains(&write_group),
        "PREMISE: the principal writes the other group"
    );

    let state = AppState::with_scoped_pool(app_scoped(pool).await, ApiConfig::default());
    let client = Uuid::new_v4();
    let token = token(&state, client, principal);
    World {
        router: epigraph_api::routes::create_router(state),
        pool: pool.clone(),
        token,
        client,
        readable,
        writable,
    }
}

/// A reader who cannot write the convention's owner group is refused 403, and
/// NOTHING is written: no evidence, no refutation edge, no truth change, no
/// principal agent row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_who_cannot_write_a_private_convention_is_refused_and_nothing_is_written(
    pool: PgPool,
) {
    let w = world(&pool).await;
    let before = footprint(&w.pool, w.readable).await;
    assert_eq!(before.0, 0, "PREMISE: no evidence yet");
    assert_eq!(
        principal_agent_rows(&w.pool, w.client).await,
        0,
        "PREMISE: no principal agent row yet"
    );

    let (status, body) = forget(&w.router, &w.token, w.readable).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a reader's forget of a private convention is refused: {body}"
    );
    assert!(
        body.contains("writer"),
        "the refusal names the writer rule: {body}"
    );
    assert_eq!(
        footprint(&w.pool, w.readable).await,
        before,
        "the refusal wrote no evidence, no refutation and no truth change"
    );
    assert_eq!(
        principal_agent_rows(&w.pool, w.client).await,
        0,
        "the refusal minted no principal agent row"
    );
}

/// POSITIVE CONTROL, the other half of the pair: the SAME principal and token
/// forget a private convention another agent authored in a group the principal
/// writes: 200, one evidence row and one `refutes` edge, and the truth falls.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_forgets_a_private_convention(pool: PgPool) {
    let w = world(&pool).await;
    let (ev0, edges0, truth0) = footprint(&w.pool, w.writable).await;
    let (status, body) = forget(&w.router, &w.token, w.writable).await;
    assert_eq!(status, StatusCode::OK, "a writer's forget lands: {body}");
    let (ev1, edges1, truth1) = footprint(&w.pool, w.writable).await;
    assert_eq!(ev1, ev0 + 1, "one refuting evidence row");
    assert_eq!(edges1, edges0 + 1, "one refutes edge");
    assert!(truth1 < truth0, "the truth falls: {truth0} -> {truth1}");
}
