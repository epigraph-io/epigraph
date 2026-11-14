#![cfg(feature = "db")]
//! `GET /api/v1/sources/overview` (backlog da4a8bc1): who said what across a
//! scope. The caller's current, readable claims (optionally one theme's),
//! grouped by source: a PAPER through its ingest-written assertions, a WEB
//! domain through the claims' evidence `source_url`, and the filing AGENT for
//! a claim no readable paper asserts. Each with a claim count as the caller
//! sees it, paged by an opaque cursor.
//!
//! Every request goes through the full router with a real bearer, on an
//! `AppState` whose pools are both the APPLICATION ROLE.
//!
//! What each test pins:
//!
//! * the theme filter confines every bucket to the theme's claims;
//! * a claim the caller cannot read is counted nowhere, and an assertion the
//!   document ingest did not write credits no paper;
//! * a claim whose paper assertion the caller cannot read moves to its
//!   filer's agent bucket instead (and back for a reader of the assertion);
//! * walking `next_cursor` visits every source once in `(claim_count DESC,
//!   kind, key)` order; `kind` narrows to one kind; an unknown kind or a
//!   malformed cursor is a 400.

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

async fn named_agent(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (id, group) = viewer_fixture::seed_agent_with_group(pool, name).await;
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(id)
        .bind(name)
        .execute(pool)
        .await
        .expect("name the agent");
    (id, group)
}

async fn theme(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ($1, 'sources_overview') \
         RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("insert theme")
}

async fn in_theme(pool: &PgPool, claim: Uuid, theme: Uuid) {
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .execute(pool)
        .await
        .expect("attach theme");
}

async fn evidence_at(pool: &PgPool, claim: Uuid, url: &str) {
    let hash = blake3::hash(format!("{claim}:{url}").as_bytes());
    sqlx::query(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, source_url) \
         VALUES ($1, 'document', $2, $3)",
    )
    .bind(claim)
    .bind(hash.as_bytes().as_slice())
    .bind(url)
    .execute(pool)
    .await
    .expect("seed evidence");
}

/// `author`'s authorship of `paper`, as `by`'s document ingest writes it.
async fn authored(pool: &PgPool, author: Uuid, paper: Uuid, by: Uuid, props: Value) {
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
        Some(props),
    )
    .await
    .expect("authored edge");
}

/// `by`'s document ingest asserts `claim` from `paper`. Returns the edge.
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

fn rows(body: &Value) -> Vec<(String, String, i64)> {
    body["sources"]
        .as_array()
        .unwrap_or_else(|| panic!("no sources array: {body}"))
        .iter()
        .map(|s| {
            (
                s["kind"].as_str().expect("kind").to_string(),
                s["key"].as_str().expect("key").to_string(),
                s["claim_count"].as_i64().expect("count"),
            )
        })
        .collect()
}

async fn walk(state: &AppState, caller: Uuid, query: &str) -> Vec<(String, String, i64)> {
    let mut out = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..20 {
        let q = match &after {
            Some(a) => format!("{query}&after={a}"),
            None => query.to_string(),
        };
        let (status, body) = get(state, caller, &q).await;
        assert_eq!(status, StatusCode::OK, "{q}: {body}");
        out.extend(rows(&body));
        match body["next_cursor"].as_str() {
            Some(c) => after = Some(c.to_string()),
            None => return out,
        }
    }
    panic!("the walk does not end: {out:?}");
}

struct Corpus {
    t: Uuid,
    paper: Uuid,
    filer: Uuid,
    ingester: Uuid,
    stranger: Uuid,
    member: Uuid,
    /// The paper's authors as the ingester's ingest wrote them: `lead` at
    /// position 1, `second` at 2, and `pending` at 0, awaiting
    /// countersignature. `outsider` is the filer's authorship of the paper,
    /// written by an ingest that is not the paper's first.
    lead: Uuid,
    second: Uuid,
    pending: Uuid,
    outsider: Uuid,
}

async fn corpus(pool: &PgPool) -> Corpus {
    let (filer, _) = named_agent(pool, "Direct Filer").await;
    let (ingester, _) = named_agent(pool, "Paper Ingester").await;
    let (stranger, _) = named_agent(pool, "stranger").await;
    let (member, group) = named_agent(pool, "member").await;
    let t = theme(pool, "sources-t").await;
    let u = theme(pool, "sources-u").await;
    let paper: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ('10.5555/sources.p', 'Sources Paper') \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("paper");

    // Two theme claims the paper asserts; one of them also cites a web page.
    let c1 = viewer_fixture::seed_public_claim(pool, ingester, "sources c1").await;
    let c2 = viewer_fixture::seed_public_claim(pool, ingester, "sources c2").await;
    asserts(pool, paper, c1, ingester).await;
    asserts(pool, paper, c2, ingester).await;
    evidence_at(pool, c1, "https://other.net/x").await;
    // Two directly filed theme claims citing one domain (two spellings).
    let c3 = viewer_fixture::seed_public_claim(pool, filer, "sources c3").await;
    let c4 = viewer_fixture::seed_public_claim(pool, filer, "sources c4").await;
    evidence_at(pool, c3, "https://www.Example.org/a").await;
    evidence_at(pool, c4, "http://example.org:8080/b?q=1").await;
    // A hand-written `paper -asserts->` edge onto c3 (no ingest marker): it
    // credits no paper, so c3 stays its filer's.
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper)
    .bind(c3)
    .execute(pool)
    .await
    .expect("hand-written assertion");
    // A claim the stranger cannot read, in every bucket.
    let hidden = viewer_fixture::seed_group_claim(pool, filer, group, "sources hidden").await;
    asserts(pool, paper, hidden, ingester).await;
    evidence_at(pool, hidden, "https://example.org/h").await;
    // A public claim whose paper assertion only the member's group can read.
    let c5 = viewer_fixture::seed_public_claim(pool, ingester, "sources c5").await;
    let e5 = asserts(pool, paper, c5, ingester).await;
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(e5)
    .bind(group)
    .execute(pool)
    .await
    .expect("make the assertion group-private");
    for c in [c1, c2, c3, c4, hidden, c5] {
        in_theme(pool, c, t).await;
    }
    // The paper's authors. `authored` edges run agent -> paper, so they move
    // no claim count. The pending author sorts FIRST by position, which is
    // the case where dropping pending rows after the bound used to hide them.
    let (lead, _) = named_agent(pool, "Lead Author").await;
    let (second, _) = named_agent(pool, "Second Author").await;
    let (pending, _) = named_agent(pool, "Pending Author").await;
    let pos = |p: i64| json!({"position": p, "role": "author", "affiliations": []});
    authored(pool, second, paper, ingester, pos(2)).await;
    authored(pool, lead, paper, ingester, pos(1)).await;
    authored(
        pool,
        pending,
        paper,
        ingester,
        json!({"position": 0, "pending_countersign": true, "ingested_by": ingester.to_string()}),
    )
    .await;
    // Another ingest's author list is never mixed into the first one's.
    let (outsider, _) = named_agent(pool, "Outsider Author").await;
    authored(pool, outsider, paper, filer, pos(0)).await;
    // Outside the theme: the paper asserts one more claim.
    let other = viewer_fixture::seed_public_claim(pool, ingester, "sources other").await;
    asserts(pool, paper, other, ingester).await;
    in_theme(pool, other, u).await;

    Corpus {
        t,
        paper,
        filer,
        ingester,
        stranger,
        member,
        lead,
        second,
        pending,
        outsider,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_themes_sources_group_by_kind_with_the_callers_counts(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let k = corpus(&pool).await;

    let got = walk(&state, k.stranger, &format!("theme_id={}&limit=2", k.t)).await;
    assert_eq!(
        got,
        vec![
            ("agent".to_string(), k.filer.to_string(), 2),
            ("paper".to_string(), k.paper.to_string(), 2),
            ("web".to_string(), "example.org".to_string(), 2),
            ("agent".to_string(), k.ingester.to_string(), 1),
            ("web".to_string(), "other.net".to_string(), 1),
        ],
        "each source once, by count then kind then key; the hidden claim nowhere; c5's \
         unreadable assertion puts it under its filer"
    );

    // The member reads the hidden claim and c5's assertion.
    let theirs = walk(&state, k.member, &format!("theme_id={}&limit=50", k.t)).await;
    assert!(
        theirs.contains(&("paper".to_string(), k.paper.to_string(), 4)),
        "{theirs:?}"
    );
    assert!(
        theirs.contains(&("web".to_string(), "example.org".to_string(), 3)),
        "{theirs:?}"
    );
    assert!(
        !theirs
            .iter()
            .any(|(kind, key, _)| kind == "agent" && *key == k.ingester.to_string()),
        "c5 is the paper's for a reader of its assertion: {theirs:?}"
    );

    // Unthemed, the paper's other claim counts too.
    let all = walk(&state, k.stranger, "kind=paper&limit=50").await;
    assert_eq!(
        all,
        vec![("paper".to_string(), k.paper.to_string(), 3)],
        "{all:?}"
    );

    // The detail of each kind.
    let (status, body) = get(&state, k.stranger, &format!("theme_id={}&limit=50", k.t)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let find = |kind: &str| {
        body["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["kind"] == json!(kind))
            .cloned()
            .unwrap_or_else(|| panic!("no {kind}: {body}"))
    };
    let p = find("paper");
    assert_eq!(p["paper"]["doi"], json!("10.5555/sources.p"), "{p}");
    assert_eq!(p["paper"]["title"], json!("Sources Paper"), "{p}");
    assert_eq!(p["paper"]["authors_ingested_by"], json!(k.ingester), "{p}");
    assert_eq!(
        p["paper"]["authors"],
        json!([
            {"id": k.lead, "display_name": "Lead Author", "position": 1},
            {"id": k.second, "display_name": "Second Author", "position": 2},
        ]),
        "the first ingest's plain authors in position order; no other ingest's: {p}"
    );
    assert_eq!(
        p["paper"]["pending_authors"],
        json!([{"id": k.pending, "display_name": "Pending Author", "position": 0}]),
        "the pending author is listed apart, not dropped: {p}"
    );
    assert_eq!(p["paper"]["authors_truncated"], json!(false), "{p}");
    assert!(
        !p.to_string().contains(&k.outsider.to_string()),
        "another ingest's author is not listed: {p}"
    );
    let a = find("agent");
    assert_eq!(
        a["agent"],
        json!({"id": k.filer, "display_name": "Direct Filer"}),
        "{a}"
    );
    let w = find("web");
    assert_eq!(w["domain"], json!("example.org"), "{w}");
    assert_eq!(body["next_cursor"], Value::Null, "{body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn kind_narrows_and_a_bad_kind_or_cursor_is_refused(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let k = corpus(&pool).await;

    let webs = walk(
        &state,
        k.stranger,
        &format!("theme_id={}&kind=web&limit=1", k.t),
    )
    .await;
    assert_eq!(
        webs,
        vec![
            ("web".to_string(), "example.org".to_string(), 2),
            ("web".to_string(), "other.net".to_string(), 1),
        ]
    );
    for bad in ["kind=book", "after=not-a-cursor"] {
        let (status, body) = get(&state, k.stranger, bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
}

async fn show_statement_timeout(conn: &mut sqlx::PgConnection) -> String {
    sqlx::query_scalar("SHOW statement_timeout")
        .fetch_one(conn)
        .await
        .expect("SHOW statement_timeout")
}

/// The unthemed overview aggregates every readable current claim per request,
/// so it runs under its own `statement_timeout`. Pinned deterministically by
/// a lock wait (a `statement_timeout` covers time spent waiting on a lock):
/// while another session holds `evidence` exclusively, the overview gives up
/// at its bound with `57014` instead of waiting, and the connection's own
/// `statement_timeout` is put back afterwards, on the error path.
#[sqlx::test(migrations = "../../migrations")]
async fn the_overview_gives_up_at_its_time_bound_and_restores_the_connection(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let k = corpus(&pool).await;
    // Resolved on the superuser pool (an unstamped downgraded session would
    // resolve an empty group set).
    let viewer = epigraph_db::Viewer::resolve(&pool, k.stranger)
        .await
        .expect("resolve the stranger");
    let query = epigraph_db::SourcesQuery {
        theme_id: Some(k.t),
        kinds: None,
        after: None,
        limit: 50,
    };

    let mut read = state.read_as(&viewer).await.expect("stamped read");
    let before = show_statement_timeout(&mut read).await;

    let mut locker = pool.begin().await.expect("locker tx");
    sqlx::query("LOCK TABLE evidence IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *locker)
        .await
        .expect("hold evidence");

    let bounded = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        epigraph_db::SourcesRepository::overview(
            &mut read,
            &viewer,
            &query,
            std::time::Duration::from_millis(300),
        ),
    )
    .await
    .expect("the overview waited on the lock past its bound: no statement_timeout applied");
    let err = bounded.expect_err("the overview cannot read evidence while it is locked");
    let code = match &err {
        epigraph_db::DbError::QueryFailed { source } => source
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map(|c| c.to_string()),
        _ => None,
    };
    assert_eq!(code.as_deref(), Some("57014"), "{err:?}");
    assert!(
        matches!(
            epigraph_api::routes::sources::overview_read_failed(&err),
            epigraph_api::errors::ApiError::ServiceUnavailable { .. }
        ),
        "a timed-out overview answers 503"
    );
    assert_eq!(
        show_statement_timeout(&mut read).await,
        before,
        "the connection's own statement_timeout is restored after a timeout"
    );

    locker.rollback().await.expect("release evidence");
    let (rows, _) = epigraph_db::SourcesRepository::overview(
        &mut read,
        &viewer,
        &query,
        epigraph_db::SOURCES_OVERVIEW_STATEMENT_TIMEOUT,
    )
    .await
    .expect("unlocked, the same connection reads the overview");
    assert!(!rows.is_empty(), "the theme has sources");
    assert_eq!(show_statement_timeout(&mut read).await, before);
    read.commit().await.expect("finish the read");
}

/// Any other read failure stays an opaque 500.
#[test]
fn a_failed_overview_read_that_did_not_time_out_is_a_500() {
    let err = epigraph_db::DbError::QueryFailed {
        source: sqlx::Error::RowNotFound,
    };
    assert!(matches!(
        epigraph_api::routes::sources::overview_read_failed(&err),
        epigraph_api::errors::ApiError::InternalError { .. }
    ));
}
