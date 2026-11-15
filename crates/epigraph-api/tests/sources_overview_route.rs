#![cfg(feature = "db")]
//! `GET /api/v1/sources/overview` (backlog da4a8bc1): the sources of the
//! claims the caller may read (papers, filing agents, web hosts), each with
//! the caller's own claim count, cursor-paged.
//!
//! Every request goes through the full router with a real bearer, on an
//! `AppState` whose pools are both the APPLICATION ROLE: on the superuser pool
//! `epigraph_bypass()` is true, every claim and edge would be readable, and
//! "a stranger's count leaves it out" could not fail.
//!
//! A paper's `asserts` edge is written with the document ingest's own
//! primitive (`epigraph_db::create_ingest_written_edge_if_absent_conn`): the
//! repo counts only ingest-written assertions, as
//! `PaperRepository::count_asserted_claims` does, and
//! [`a_hand_written_asserts_edge_attributes_nothing`] pins that.
//!
//! Entries are looked up by id, never by position in the whole list, so rows
//! a migration seeds cannot move an assertion.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool};

async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
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

/// An agent with its personal group and a display name: `(agent, group)`.
async fn agent(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (id, group) = viewer_fixture::seed_agent_with_group(pool, name).await;
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(id)
        .bind(name)
        .execute(pool)
        .await
        .expect("name the agent");
    (id, group)
}

async fn paper(pool: &PgPool, doi: &str, title: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, $2) RETURNING id")
        .bind(doi)
        .bind(title)
        .fetch_one(pool)
        .await
        .expect("paper")
}

/// `paper -asserts-> claim`, as `by`'s document ingest writes it
/// (ingest-written). Returns the edge id.
async fn asserts(pool: &PgPool, paper: Uuid, claim: Uuid, by: Uuid) -> Uuid {
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn,
        None,
        "ingest_document",
        by,
        paper,
        "paper",
        claim,
        "claim",
        "asserts",
        None,
    )
    .await
    .expect("asserts")
    .0
    .id
}

/// `author`'s authorship of `paper`, as `by`'s document ingest writes it.
async fn authored(pool: &PgPool, author: Uuid, paper: Uuid, by: Uuid, position: i64) {
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn,
        None,
        "ingest_document",
        by,
        author,
        "agent",
        paper,
        "paper",
        "authored",
        Some(json!({"position": position, "role": "author", "affiliations": []})),
    )
    .await
    .expect("authored edge");
}

async fn theme(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO claim_themes (id, label, description) VALUES ($1, $2, 'fixture')")
        .bind(id)
        .bind(label)
        .execute(pool)
        .await
        .expect("theme");
    id
}

async fn set_theme(pool: &PgPool, claim: Uuid, theme: Uuid) {
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .execute(pool)
        .await
        .expect("theme the claim");
}

/// An evidence row on `claim` whose `source_url` is `url`.
async fn linked_evidence(pool: &PgPool, claim: Uuid, url: &str) {
    let ev = viewer_fixture::seed_evidence(pool, claim, "document").await;
    sqlx::query("UPDATE evidence SET source_url = $2 WHERE id = $1")
        .bind(ev)
        .bind(url)
        .execute(pool)
        .await
        .expect("link the evidence");
}

/// `GET /api/v1/sources/overview?<query>` as `caller`.
async fn get(state: &AppState, caller: Uuid, query: &str) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["claims:read"], caller);
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/sources/overview?{query}"))
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

/// The `sources` array of one 200 page.
async fn sources(state: &AppState, caller: Uuid, query: &str) -> Vec<Value> {
    let (status, body) = get(state, caller, query).await;
    assert_eq!(status, StatusCode::OK, "{query}: {body}");
    body["sources"].as_array().cloned().expect("sources array")
}

/// The entry of `kind` whose `field` is `value`, if listed.
fn entry(list: &[Value], kind: &str, field: &str, value: &Value) -> Option<Value> {
    list.iter()
        .find(|s| s["kind"] == json!(kind) && &s[field] == value)
        .cloned()
}

/// That entry's `claim_count`; `None` when the source is not listed.
fn count(list: &[Value], kind: &str, field: &str, value: &Value) -> Option<i64> {
    entry(list, kind, field, value).and_then(|s| s["claim_count"].as_i64())
}

/// A paper is listed with its DOI, title, authors and the number of claims
/// it asserts; an agent with its name and the claims it filed directly (a
/// claim a paper asserts is the paper's, not its filer's); a web host with
/// the claims whose evidence links to it. Papers come first, then agents,
/// then hosts.
#[sqlx::test(migrations = "../../migrations")]
async fn a_paper_an_agent_and_a_host_are_listed_with_their_counts(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (reader, _) = agent(&pool, "reader-fixture").await;
    let (ingester, _) = agent(&pool, "ingester-fixture").await;
    let (filer, _) = agent(&pool, "filer-fixture").await;
    let (author, _) = agent(&pool, "Author Fixture").await;

    let doc = paper(&pool, "10.0000/fixture.sources", "Sources Paper").await;
    let c1 = viewer_fixture::seed_public_claim(&pool, ingester, "paper claim one").await;
    let c2 = viewer_fixture::seed_public_claim(&pool, ingester, "paper claim two").await;
    asserts(&pool, doc, c1, ingester).await;
    asserts(&pool, doc, c2, ingester).await;
    authored(&pool, author, doc, ingester, 0).await;

    let d1 = viewer_fixture::seed_public_claim(&pool, filer, "direct claim one").await;
    // A retired claim is not counted.
    let old = viewer_fixture::seed_public_claim(&pool, filer, "direct claim, retired").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(old)
        .execute(&pool)
        .await
        .expect("retire");

    // Userinfo and port are dropped, the host is lowercased; free text in
    // the column is not a host.
    linked_evidence(&pool, c1, "https://user:secret@Example.ORG:8443/a?b#c").await;
    linked_evidence(&pool, d1, "http://example.org/other").await;
    linked_evidence(&pool, d1, "a witness, not a link").await;

    let list = sources(&state, reader, "limit=200").await;

    let p = entry(&list, "paper", "id", &json!(doc)).expect("the paper is listed");
    assert_eq!(p["doi"], json!("10.0000/fixture.sources"), "{p}");
    assert_eq!(p["title"], json!("Sources Paper"), "{p}");
    assert_eq!(p["claim_count"], json!(2), "{p}");
    assert_eq!(
        p["authors"],
        json!([{"id": author, "display_name": "Author Fixture", "pending_countersign": false}]),
        "{p}"
    );
    assert_eq!(p["authors_truncated"], json!(false), "{p}");

    let a = entry(&list, "agent", "id", &json!(filer)).expect("the filer is listed");
    assert_eq!(a["display_name"], json!("filer-fixture"), "{a}");
    assert_eq!(a["claim_count"], json!(1), "one current direct claim: {a}");
    assert_eq!(
        count(&list, "agent", "id", &json!(ingester)),
        None,
        "the ingester's claims are the paper's: {list:?}"
    );

    let w = entry(&list, "web", "domain", &json!("example.org")).expect("the host is listed");
    assert_eq!(w["claim_count"], json!(2), "{w}");
    assert!(
        !serde_json::to_string(&list)
            .expect("json")
            .contains("secret"),
        "userinfo is never served"
    );

    // Grouped by kind: every paper before every agent before every host.
    let rank = |s: &Value| match s["kind"].as_str() {
        Some("paper") => 0,
        Some("agent") => 1,
        Some("web") => 2,
        other => panic!("unknown kind {other:?}"),
    };
    let ranks: Vec<i32> = list.iter().map(rank).collect();
    let mut sorted = ranks.clone();
    sorted.sort_unstable();
    assert_eq!(ranks, sorted, "{list:?}");
}

/// A claim private to a group is counted for a member and not for a
/// stranger, under its paper, its filer and its evidence's host alike; a
/// source whose every claim is private is absent for the stranger. A public
/// claim whose asserting edge the stranger cannot read is counted under its
/// filer for the stranger and under the paper for the member.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_claim_is_counted_for_a_member_and_not_for_a_stranger(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (stranger, _) = agent(&pool, "stranger-fixture").await;
    let (member, group) = agent(&pool, "member-fixture").await;
    let (ingester, _) = agent(&pool, "ingester-fixture").await;
    let (filer, _) = agent(&pool, "filer-fixture").await;

    let doc = paper(&pool, "10.0000/fixture.mixed", "Mixed Paper").await;
    let c1 = viewer_fixture::seed_public_claim(&pool, ingester, "public paper claim").await;
    let g1 = viewer_fixture::seed_group_claim(&pool, ingester, group, "private paper claim").await;
    asserts(&pool, doc, c1, ingester).await;
    asserts(&pool, doc, g1, ingester).await;
    // A public claim the filer filed, asserted by the paper through an edge
    // private to the member's group (an administrative state).
    let h1 = viewer_fixture::seed_public_claim(&pool, filer, "public claim, hidden edge").await;
    let hidden = asserts(&pool, doc, h1, ingester).await;
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(hidden)
    .bind(group)
    .execute(&pool)
    .await
    .expect("make the asserts edge group-private");

    let closed = paper(&pool, "10.0000/fixture.closed", "Closed Paper").await;
    let q1 = viewer_fixture::seed_group_claim(&pool, ingester, group, "closed paper claim").await;
    asserts(&pool, closed, q1, ingester).await;

    let d1 = viewer_fixture::seed_public_claim(&pool, filer, "public direct claim").await;
    let g2 = viewer_fixture::seed_group_claim(&pool, filer, group, "private direct claim").await;
    linked_evidence(&pool, d1, "https://host.example/public").await;
    linked_evidence(&pool, g2, "https://host.example/private").await;
    linked_evidence(&pool, g2, "https://private-only.example/x").await;

    let theirs = sources(&state, stranger, "limit=200").await;
    assert_eq!(
        count(&theirs, "paper", "id", &json!(doc)),
        Some(1),
        "{theirs:?}"
    );
    assert_eq!(
        count(&theirs, "paper", "id", &json!(closed)),
        None,
        "a paper with no readable claim is absent: {theirs:?}"
    );
    assert_eq!(
        count(&theirs, "agent", "id", &json!(filer)),
        Some(2),
        "d1 and h1 (its paper edge is not readable): {theirs:?}"
    );
    assert_eq!(
        count(&theirs, "web", "domain", &json!("host.example")),
        Some(1),
        "{theirs:?}"
    );
    assert_eq!(
        count(&theirs, "web", "domain", &json!("private-only.example")),
        None,
        "{theirs:?}"
    );

    let mine = sources(&state, member, "limit=200").await;
    assert_eq!(
        count(&mine, "paper", "id", &json!(doc)),
        Some(3),
        "c1, g1 and h1: {mine:?}"
    );
    assert_eq!(
        count(&mine, "paper", "id", &json!(closed)),
        Some(1),
        "{mine:?}"
    );
    assert_eq!(
        count(&mine, "agent", "id", &json!(filer)),
        Some(2),
        "d1 and g2 (h1 is the paper's for a member): {mine:?}"
    );
    assert_eq!(
        count(&mine, "web", "domain", &json!("host.example")),
        Some(2),
        "{mine:?}"
    );
    assert_eq!(
        count(&mine, "web", "domain", &json!("private-only.example")),
        Some(1),
        "{mine:?}"
    );
}

/// An `asserts` edge the document ingest did not write (a plain `edges` row)
/// attributes nothing: the claim stays its filer's and the paper is absent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hand_written_asserts_edge_attributes_nothing(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (reader, _) = agent(&pool, "reader-fixture").await;
    let (filer, _) = agent(&pool, "filer-fixture").await;
    let doc = paper(&pool, "10.0000/fixture.unmarked", "Unmarked Paper").await;
    let claim = viewer_fixture::seed_public_claim(&pool, filer, "claim with a plain edge").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(doc)
    .bind(claim)
    .execute(&pool)
    .await
    .expect("plain asserts edge");

    let list = sources(&state, reader, "limit=200").await;
    assert_eq!(count(&list, "paper", "id", &json!(doc)), None, "{list:?}");
    assert_eq!(
        count(&list, "agent", "id", &json!(filer)),
        Some(1),
        "{list:?}"
    );
}

/// `theme_id` restricts every count to that theme's claims, `kind` to one
/// kind; an empty value is the parameter left out, and a bad one is a 400.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_id_and_kind_filter(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (reader, _) = agent(&pool, "reader-fixture").await;
    let (ingester, _) = agent(&pool, "ingester-fixture").await;
    let (filer, _) = agent(&pool, "filer-fixture").await;
    let (other, _) = agent(&pool, "other-filer-fixture").await;

    let doc = paper(&pool, "10.0000/fixture.themed", "Themed Paper").await;
    let c1 = viewer_fixture::seed_public_claim(&pool, ingester, "themed paper claim").await;
    let c2 = viewer_fixture::seed_public_claim(&pool, ingester, "unthemed paper claim").await;
    asserts(&pool, doc, c1, ingester).await;
    asserts(&pool, doc, c2, ingester).await;
    let d1 = viewer_fixture::seed_public_claim(&pool, filer, "themed direct claim").await;
    let d2 = viewer_fixture::seed_public_claim(&pool, filer, "unthemed direct claim").await;
    viewer_fixture::seed_public_claim(&pool, other, "another filer's unthemed claim").await;
    linked_evidence(&pool, d1, "https://themed.example/a").await;
    linked_evidence(&pool, d2, "https://unthemed.example/a").await;

    let t = theme(&pool, "sources-fixture-theme").await;
    set_theme(&pool, c1, t).await;
    set_theme(&pool, d1, t).await;

    // The whole corpus first, so the theme arm below is a real restriction.
    let all = sources(&state, reader, "theme_id=&kind=&after=&limit=200").await;
    assert_eq!(count(&all, "paper", "id", &json!(doc)), Some(2), "{all:?}");
    assert_eq!(
        count(&all, "agent", "id", &json!(filer)),
        Some(2),
        "{all:?}"
    );
    assert_eq!(
        count(&all, "agent", "id", &json!(other)),
        Some(1),
        "{all:?}"
    );

    // The theme holds exactly the fixture's two claims, so its listing is
    // exactly these three sources.
    let themed = sources(&state, reader, &format!("theme_id={t}&limit=200")).await;
    assert_eq!(
        themed,
        vec![
            json!({"kind": "paper", "id": doc, "doi": "10.0000/fixture.themed",
                   "title": "Themed Paper", "authors": [], "authors_truncated": false,
                   "claim_count": 1}),
            json!({"kind": "agent", "id": filer, "display_name": "filer-fixture",
                   "claim_count": 1}),
            json!({"kind": "web", "domain": "themed.example", "claim_count": 1}),
        ]
    );

    for (kind, field, value) in [
        ("paper", "id", json!(doc)),
        ("agent", "id", json!(filer)),
        ("web", "domain", json!("themed.example")),
    ] {
        let only = sources(&state, reader, &format!("theme_id={t}&kind={kind}")).await;
        assert_eq!(only.len(), 1, "{kind}: {only:?}");
        assert_eq!(only[0]["kind"], json!(kind), "{only:?}");
        assert_eq!(only[0][field], value, "{only:?}");
    }

    // A theme with no claim lists nothing.
    let empty = theme(&pool, "sources-fixture-empty-theme").await;
    let (status, body) = get(&state, reader, &format!("theme_id={empty}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"sources": [], "next_cursor": null}));

    for bad in [
        "theme_id=not-a-uuid",
        "kind=book",
        "after=not-a-cursor",
        "limit=many",
    ] {
        let (status, body) = get(&state, reader, bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
}

/// `limit=1` walks every source exactly once through `next_cursor`, in the
/// order of the unpaged listing, across the three kinds; a cursor of one
/// kind is refused on a page of another.
#[sqlx::test(migrations = "../../migrations")]
async fn paging_by_one_walks_every_source_exactly_once(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (reader, _) = agent(&pool, "reader-fixture").await;
    let (ingester, _) = agent(&pool, "ingester-fixture").await;
    let t = theme(&pool, "sources-fixture-paging").await;

    // Two papers (2 claims and 1), three filers (2, 1 and 1: a tie the key
    // breaks), two hosts.
    let big = paper(&pool, "10.0000/fixture.big", "Big Paper").await;
    let small = paper(&pool, "10.0000/fixture.small", "Small Paper").await;
    for (doc, text) in [(big, "big one"), (big, "big two"), (small, "small one")] {
        let c = viewer_fixture::seed_public_claim(&pool, ingester, text).await;
        asserts(&pool, doc, c, ingester).await;
        set_theme(&pool, c, t).await;
    }
    for (name, n) in [("filer-a", 2), ("filer-b", 1), ("filer-c", 1)] {
        let (filer, _) = agent(&pool, name).await;
        for i in 0..n {
            let c =
                viewer_fixture::seed_public_claim(&pool, filer, &format!("{name} claim {i}")).await;
            set_theme(&pool, c, t).await;
            linked_evidence(&pool, c, &format!("https://{name}.example/{i}")).await;
        }
    }

    let whole = sources(&state, reader, &format!("theme_id={t}&limit=200")).await;
    // 2 papers + 3 agents + 3 hosts.
    assert_eq!(whole.len(), 8, "{whole:?}");
    let counts: Vec<i64> = whole
        .iter()
        .map(|s| s["claim_count"].as_i64().expect("count"))
        .collect();
    assert_eq!(counts, vec![2, 1, 2, 1, 1, 2, 1, 1], "{whole:?}");

    let mut walked: Vec<Value> = Vec::new();
    let mut after: Option<String> = None;
    // Bounded, so a cursor that does not advance fails instead of looping.
    for _ in 0..20 {
        let query = match &after {
            None => format!("theme_id={t}&limit=1"),
            Some(c) => format!("theme_id={t}&limit=1&after={c}"),
        };
        let (status, body) = get(&state, reader, &query).await;
        assert_eq!(status, StatusCode::OK, "{query}: {body}");
        let page = body["sources"].as_array().cloned().expect("sources");
        assert!(page.len() <= 1, "limit=1: {body}");
        walked.extend(page);
        match body["next_cursor"].as_str() {
            Some(c) => after = Some(c.to_string()),
            None => {
                after = None;
                break;
            }
        }
    }
    assert_eq!(after, None, "the walk ended on a null next_cursor");
    assert_eq!(walked, whole, "every source once, in listing order");

    // A page of two straddles the paper/agent boundary without loss.
    let mut by_two: Vec<Value> = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..20 {
        let query = match &after {
            None => format!("theme_id={t}&limit=2"),
            Some(c) => format!("theme_id={t}&limit=2&after={c}"),
        };
        let (status, body) = get(&state, reader, &query).await;
        assert_eq!(status, StatusCode::OK, "{query}: {body}");
        by_two.extend(body["sources"].as_array().cloned().expect("sources"));
        match body["next_cursor"].as_str() {
            Some(c) => after = Some(c.to_string()),
            None => {
                after = None;
                break;
            }
        }
    }
    assert_eq!(after, None);
    assert_eq!(by_two, whole);

    // A cursor from the paper pages is not a position in the agent pages.
    let (_, first) = get(&state, reader, &format!("theme_id={t}&limit=1")).await;
    let cursor = first["next_cursor"].as_str().expect("a first cursor");
    let (status, body) = get(
        &state,
        reader,
        &format!("theme_id={t}&kind=agent&after={cursor}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}
