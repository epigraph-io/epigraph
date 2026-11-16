//! MCP `query_claims` with `created_after` / `created_before` / `offset`
//! (backlog `24caecaa`): a complete, viewer-scoped listing of the claims
//! created in a window.
//!
//! The server's pools are downgraded to `epigraph_app` (the shape of
//! `get_claim_authored_by_app_role.rs`), so the window is asserted through the
//! stamped read and the row security production runs, not on a superuser
//! connection that would see every row whatever the predicate said.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claims::query_claims;
use epigraph_mcp::types::QueryClaimsParams;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

fn at(ts: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .expect("rfc3339")
        .with_timezone(&chrono::Utc)
}

async fn set_created_at(pool: &PgPool, id: Uuid, ts: &str) {
    sqlx::query("UPDATE claims SET created_at = $2::timestamptz WHERE id = $1")
        .bind(id)
        .bind(ts)
        .execute(pool)
        .await
        .expect("set created_at");
}

fn window(after: &str, before: &str, limit: i64, offset: Option<i64>) -> QueryClaimsParams {
    QueryClaimsParams {
        min_truth: Some(0.0),
        max_truth: Some(1.0),
        limit: Some(limit),
        created_after: Some(at(after)),
        created_before: Some(at(before)),
        offset,
        ..Default::default()
    }
}

fn ids(result: &rmcp::model::CallToolResult) -> Vec<Uuid> {
    first_text(result)
        .as_array()
        .expect("a JSON array")
        .iter()
        .map(|c| c["id"].as_str().unwrap().parse().unwrap())
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn query_claims_pages_the_window_completely_and_per_viewer(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "b41qcw").await;

    // Outside the window on each side, then three inside it, one of them
    // group-private.
    let early = fixture::seed_public_claim(&pool, member, "early").await;
    set_created_at(&pool, early, "2026-06-01T08:00:00Z").await;
    let late = fixture::seed_public_claim(&pool, member, "late").await;
    set_created_at(&pool, late, "2026-06-01T20:00:00Z").await;
    let first = fixture::seed_public_claim(&pool, member, "first").await;
    set_created_at(&pool, first, "2026-06-01T10:00:00Z").await;
    let private = fixture::seed_group_claim(&pool, member, group, "private").await;
    set_created_at(&pool, private, "2026-06-01T11:00:00Z").await;
    let third = fixture::seed_public_claim(&pool, member, "third").await;
    set_created_at(&pool, third, "2026-06-01T12:00:00Z").await;

    let (after, before) = ("2026-06-01T10:00:00Z", "2026-06-01T12:00:00Z");

    // A member pages the window one row at a time and gets every in-window
    // row, its own group's private one included, exactly once and in order.
    let member_viewer = Viewer::resolve(&pool, member).await.expect("resolve");
    let mut paged = Vec::new();
    for offset in 0..4 {
        let page = query_claims(
            &server,
            &member_viewer,
            window(after, before, 1, Some(offset)),
        )
        .await
        .expect("query_claims as member");
        paged.extend(ids(&page));
    }
    assert_eq!(
        paged,
        vec![third, private, first],
        "every in-window row once, newest first; never {early} or {late}"
    );

    // A stranger asking the same window sees only the public rows.
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "b41qcw-stranger").await;
    let stranger_viewer = Viewer::resolve(&pool, stranger).await.expect("resolve");
    let page = query_claims(&server, &stranger_viewer, window(after, before, 50, None))
        .await
        .expect("query_claims as stranger");
    assert_eq!(ids(&page), vec![third, first]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn query_claims_refuses_an_inverted_window_and_a_negative_offset(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (caller, _) = fixture::seed_agent_with_group(&pool, "b41qcw-refuse").await;
    let viewer = Viewer::resolve(&pool, caller).await.expect("resolve");

    let err = query_claims(
        &server,
        &viewer,
        window("2026-06-02T00:00:00Z", "2026-06-01T00:00:00Z", 10, None),
    )
    .await
    .expect_err("an inverted window is refused");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(err.message.contains("created_after"), "{}", err.message);

    let err = query_claims(
        &server,
        &viewer,
        window("2026-06-01T00:00:00Z", "2026-06-02T00:00:00Z", 10, Some(-1)),
    )
    .await
    .expect_err("a negative offset is refused");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
}
