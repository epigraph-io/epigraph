#![cfg(feature = "db")]
//! `GET /api/v1/claims` as a timeline (backlog ea26d7aa): `theme_id`, a
//! `(created_at, id)` keyset cursor (`after` / `next_cursor`), and, with
//! `include_edges=true`, the epistemic edges among the page's claims.
//!
//! Every request goes through the full router with a real bearer, on an
//! `AppState` whose pools are both the APPLICATION ROLE, so a row the caller
//! may not read is filtered by the database as well as by the statement, and
//! "a stranger does not see it" can fail.
//!
//! What each test pins:
//!
//! * `theme_id` confines the page AND `total` to the theme;
//! * walking `next_cursor` visits every visible theme claim exactly once, in
//!   `(created_at, id)` order, in both directions, including claims that
//!   share one `created_at` (the id tiebreak); `total` is the same on every
//!   page (the cursor narrows the page, never the count);
//! * `include_edges` lists an edge only when both ends are on the page, it is
//!   in force, it is an epistemic relationship, and the caller may read it;
//! * `after` with a non-zero `offset`, with `sort_by=truth_value`, or as a
//!   malformed token is a 400, never a silently different page.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool};

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
}

async fn get(state: &AppState, caller: Uuid, query: &str) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["claims:read"], caller);
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/claims?{query}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

async fn theme(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ($1, 'claims_query_timeline') \
         RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("insert theme")
}

/// Put `claim` in `theme` at `at`.
async fn place(pool: &PgPool, claim: Uuid, theme: Uuid, at: &str) {
    sqlx::query("UPDATE claims SET theme_id = $2, created_at = $3::timestamptz WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .bind(at)
        .execute(pool)
        .await
        .expect("place claim");
}

fn ids(body: &Value) -> Vec<Uuid> {
    body["claims"]
        .as_array()
        .unwrap_or_else(|| panic!("no claims array: {body}"))
        .iter()
        .map(|c| c["id"].as_str().expect("id").parse().expect("uuid"))
        .collect()
}

/// Walk every page of `query` by `next_cursor`, asserting `total` never moves.
async fn walk(state: &AppState, caller: Uuid, query: &str) -> (Vec<Uuid>, usize, usize) {
    let mut out = Vec::new();
    let mut after: Option<String> = None;
    let mut total: Option<u64> = None;
    let mut pages = 0;
    loop {
        let q = match &after {
            Some(a) => format!("{query}&after={a}"),
            None => query.to_string(),
        };
        let (status, body) = get(state, caller, &q).await;
        assert_eq!(status, StatusCode::OK, "{q}: {body}");
        let t = body["total"].as_u64().expect("total");
        match total {
            None => total = Some(t),
            Some(prev) => assert_eq!(
                prev, t,
                "the cursor narrows the page, never the total: {body}"
            ),
        }
        out.extend(ids(&body));
        pages += 1;
        assert!(pages < 20, "the walk does not end: {body}");
        match body["next_cursor"].as_str() {
            Some(c) => after = Some(c.to_string()),
            None => break,
        }
    }
    (out, usize::try_from(total.unwrap_or(0)).unwrap(), pages)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_themes_claims_walk_by_cursor_in_date_order_each_once(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (author, _) = viewer_fixture::seed_agent_with_group(&pool, "author").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "stranger").await;
    let (owner, owner_group) = viewer_fixture::seed_agent_with_group(&pool, "owner").await;
    let a = theme(&pool, "timeline-a").await;
    let b = theme(&pool, "timeline-b").await;

    // Five visible claims in theme A: three share one timestamp, so only the
    // id tiebreak orders them.
    let mut visible: Vec<(String, Uuid)> = Vec::new();
    for (i, at) in [
        "2026-03-01T00:00:00Z",
        "2026-03-02T00:00:00Z",
        "2026-03-02T00:00:00Z",
        "2026-03-02T00:00:00Z",
        "2026-03-04T00:00:00Z",
    ]
    .iter()
    .enumerate()
    {
        let c =
            viewer_fixture::seed_public_claim(&pool, author, &format!("timeline claim {i}")).await;
        place(&pool, c, a, at).await;
        visible.push((at.to_string(), c));
    }
    // In theme A but private to another group: not the stranger's.
    let hidden = viewer_fixture::seed_group_claim(&pool, owner, owner_group, "hidden").await;
    place(&pool, hidden, a, "2026-03-03T00:00:00Z").await;
    // Visible, but in theme B.
    let other = viewer_fixture::seed_public_claim(&pool, author, "other theme").await;
    place(&pool, other, b, "2026-03-03T00:00:00Z").await;

    visible.sort();
    let asc: Vec<Uuid> = visible.iter().map(|(_, c)| *c).collect();
    let desc: Vec<Uuid> = asc.iter().rev().copied().collect();

    // CALIBRATION: the unfiltered list sees the other theme's claim, so its
    // absence below is the theme filter's doing.
    let (status, all) = get(&state, stranger, "limit=100").await;
    assert_eq!(status, StatusCode::OK, "{all}");
    assert!(ids(&all).contains(&other), "{all}");
    assert!(!ids(&all).contains(&hidden), "{all}");

    let base = format!("theme_id={a}&sort_by=created_at&limit=2");
    let (got, total, pages) = walk(&state, stranger, &format!("{base}&sort_order=asc")).await;
    assert_eq!(got, asc, "every visible theme claim once, oldest first");
    assert_eq!(total, 5, "total is the theme's visible claims");
    assert_eq!(pages, 3);

    let (got, total, _) = walk(&state, stranger, &format!("{base}&sort_order=desc")).await;
    assert_eq!(got, desc, "every visible theme claim once, newest first");
    assert_eq!(total, 5);

    // The owner sees its own private theme claim in its place.
    let (got, total, _) = walk(&state, owner, &format!("{base}&sort_order=asc")).await;
    assert_eq!(total, 6);
    assert_eq!(got.len(), 6);
    assert_eq!(got[4], hidden, "{got:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn include_edges_lists_only_readable_in_force_epistemic_edges_among_the_page(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (author, _) = viewer_fixture::seed_agent_with_group(&pool, "author").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "stranger").await;
    let (_, owner_group) = viewer_fixture::seed_agent_with_group(&pool, "owner").await;
    let t = theme(&pool, "timeline-edges").await;
    let mut c = Vec::new();
    for i in 0..4 {
        let id = viewer_fixture::seed_public_claim(&pool, author, &format!("edge claim {i}")).await;
        place(&pool, id, t, &format!("2026-04-0{}T00:00:00Z", i + 1)).await;
        c.push(id);
    }
    // c[3] is off the first page (limit=3, oldest first).
    let on_page = viewer_fixture::seed_edge(&pool, c[0], c[1]).await;
    let off_page = viewer_fixture::seed_edge(&pool, c[1], c[3]).await;
    let private = viewer_fixture::seed_edge_owned_by(&pool, c[1], c[2], "group", owner_group).await;
    let retracted = viewer_fixture::seed_edge(&pool, c[2], c[0]).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 hour' WHERE id = $1")
        .bind(retracted)
        .execute(&pool)
        .await
        .expect("retract");
    let structural = viewer_fixture::seed_edge(&pool, c[0], c[2]).await;
    sqlx::query("UPDATE edges SET relationship = 'decomposes_to' WHERE id = $1")
        .bind(structural)
        .execute(&pool)
        .await
        .expect("make structural");
    // `cites` is epistemic for a timeline.
    let cites = viewer_fixture::seed_edge(&pool, c[2], c[1]).await;
    sqlx::query("UPDATE edges SET relationship = 'cites' WHERE id = $1")
        .bind(cites)
        .execute(&pool)
        .await
        .expect("make cites");

    let q = format!("theme_id={t}&sort_by=created_at&sort_order=asc&limit=3");
    let (status, plain) = get(&state, stranger, &q).await;
    assert_eq!(status, StatusCode::OK, "{plain}");
    assert!(
        plain.get("edges").is_none_or(Value::is_null),
        "edges only on request: {plain}"
    );

    let (status, body) = get(&state, stranger, &format!("{q}&include_edges=true")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body), c[..3].to_vec(), "{body}");
    let mut listed: Vec<Uuid> = body["edges"]
        .as_array()
        .unwrap_or_else(|| panic!("no edges array: {body}"))
        .iter()
        .map(|e| e["id"].as_str().expect("id").parse().expect("uuid"))
        .collect();
    listed.sort();
    let mut want = vec![on_page, cites];
    want.sort();
    assert_eq!(
        listed, want,
        "on-page, in-force, readable epistemic edges only (off_page {off_page}, private \
         {private}, retracted {retracted}, structural {structural}): {body}"
    );
    let e = body["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == serde_json::json!(on_page))
        .expect("on-page edge");
    assert_eq!(e["source_id"], serde_json::json!(c[0]));
    assert_eq!(e["target_id"], serde_json::json!(c[1]));
    assert_eq!(e["relationship"], serde_json::json!("supports"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_cursor_that_cannot_mean_one_page_is_refused(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (author, _) = viewer_fixture::seed_agent_with_group(&pool, "author").await;
    for i in 0..3 {
        viewer_fixture::seed_public_claim(&pool, author, &format!("refusal claim {i}")).await;
    }
    let (status, body) = get(&state, author, "limit=2").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cursor = body["next_cursor"]
        .as_str()
        .unwrap_or_else(|| panic!("a full page carries a cursor: {body}"))
        .to_string();

    for bad in [
        format!("after={cursor}&offset=1"),
        format!("after={cursor}&sort_by=truth_value"),
        "after=not-a-cursor".to_string(),
    ] {
        let (status, body) = get(&state, author, &bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
    let (status, body) = get(&state, author, &format!("after={cursor}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body).len(), 1, "{body}");
    assert!(body["next_cursor"].is_null(), "a short page ends: {body}");
}
