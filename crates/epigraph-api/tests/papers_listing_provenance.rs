#![cfg(feature = "db")]
//! `GET /api/v1/papers` carries each paper's authors and its claim count,
//! as the CALLER's viewer sees them (backlog fe75ef36).
//!
//! Every request goes through the full router with a real bearer, on an
//! `AppState` whose pools are both the APPLICATION ROLE, so a row the caller
//! may not read is filtered by the database as well as by the statement.
//!
//! What each test pins:
//!
//! * `authors` are ONE ingest's (the paper's first readable ingest principal,
//!   named in `authors_ingested_by`), in position order; an author that
//!   ingest named without speaking for them is under `pending_authors`, never
//!   `authors`; a retracted authorship and another principal's naming are
//!   not listed;
//! * `claim_count` counts each claim any ingest of the paper asserts once,
//!   only while the assertion is in force and both the assertion and the
//!   claim are readable by the caller.

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

async fn named(pool: &PgPool, agent: Uuid, name: &str) {
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(agent)
        .bind(name)
        .execute(pool)
        .await
        .expect("name the agent");
}

async fn agent(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (id, group) = viewer_fixture::seed_agent_with_group(pool, name).await;
    named(pool, id, name).await;
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

/// `by`'s ingest (under `tool`) asserts `claim` from `paper` and records it.
/// Returns `(asserts edge, record edge)`.
async fn ingest(
    pool: &PgPool,
    tool: &'static str,
    paper: Uuid,
    claim: Uuid,
    by: Uuid,
    created: bool,
) -> (Uuid, Uuid) {
    let mut conn = pool.acquire().await.expect("conn");
    let asserts = epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn, None, tool, by, paper, "paper", claim, "claim", "asserts", None,
    )
    .await
    .expect("asserts")
    .0
    .id;
    assert!(epigraph_db::ClaimIngestRepository::record_signed_conn(
        &mut conn,
        None,
        paper,
        claim,
        by,
        created,
        &[],
        tool,
        "test-pipeline",
    )
    .await
    .expect("record"));
    let record: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND target_id = $2 \
           AND relationship = 'ingested_claim' AND properties ->> 'ingested_by' = $3",
    )
    .bind(paper)
    .bind(claim)
    .bind(by.to_string())
    .fetch_one(pool)
    .await
    .expect("record id");
    (asserts, record)
}

/// `author`'s authorship of `paper`, as `by`'s document ingest writes it.
async fn authored(pool: &PgPool, author: Uuid, paper: Uuid, by: Uuid, props: Value) -> Uuid {
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
    .expect("authored edge")
    .0
    .id
}

async fn set_edge_created_at(pool: &PgPool, edge: Uuid, at: &str) {
    sqlx::query("UPDATE edges SET created_at = $2::timestamptz WHERE id = $1")
        .bind(edge)
        .bind(at)
        .execute(pool)
        .await
        .expect("set edge created_at");
}

async fn make_group_private(pool: &PgPool, edge: Uuid, group: Uuid) {
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(edge)
    .bind(group)
    .execute(pool)
    .await
    .expect("make the edge group-private");
}

async fn list(state: &AppState, caller: Uuid, query: &str) -> Value {
    let token = common::mint_token_with_agent(&["claims:read"], caller);
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/papers?{query}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn by_doi(state: &AppState, caller: Uuid, doi: &str) -> Value {
    let body = list(state, caller, &format!("doi={doi}")).await;
    assert_eq!(body["total"], json!(1), "{body}");
    body["items"][0].clone()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_paper_lists_one_ingests_authors_and_counts_only_readable_claims(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (ingester, _) = agent(&pool, "ingester").await;
    let (other, _) = agent(&pool, "other-ingester").await;
    let (stranger, _) = agent(&pool, "stranger").await;
    let (member, group) = agent(&pool, "member").await;
    let (first, _) = agent(&pool, "First Author").await;
    let (second, _) = agent(&pool, "Second Author").await;
    let (person, _) = agent(&pool, "Named Person").await;
    let (gone, _) = agent(&pool, "Retracted Author").await;
    let (intruder, _) = agent(&pool, "Intruder").await;
    let doc = paper(&pool, "10.5555/papers.listing", "Listing Paper").await;

    let c1 = viewer_fixture::seed_public_claim(&pool, ingester, "listing claim 1").await;
    let c2 = viewer_fixture::seed_public_claim(&pool, ingester, "listing claim 2").await;
    let hidden = viewer_fixture::seed_group_claim(&pool, member, group, "listing hidden").await;
    let hidden_public_edge =
        viewer_fixture::seed_group_claim(&pool, member, group, "listing hidden 2").await;
    let retracted = viewer_fixture::seed_public_claim(&pool, ingester, "listing retracted").await;
    let c5 = viewer_fixture::seed_public_claim(&pool, other, "listing other's claim").await;

    let (a1, _) = ingest(&pool, "ingest_document", doc, c1, ingester, true).await;
    ingest(&pool, "ingest_document", doc, c2, ingester, true).await;
    ingest(&pool, "ingest_document", doc, hidden, ingester, false).await;
    let (a4, _) = ingest(
        &pool,
        "ingest_document",
        doc,
        hidden_public_edge,
        ingester,
        false,
    )
    .await;
    // The assertion itself public, the claim not: still not the stranger's.
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(a4)
    .bind(viewer_fixture::world_group(&pool).await)
    .execute(&pool)
    .await
    .expect("make the assertion public");
    let (a5, _) = ingest(&pool, "ingest_document", doc, retracted, ingester, true).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 hour' WHERE id = $1")
        .bind(a5)
        .execute(&pool)
        .await
        .expect("retract the assertion");
    // A second ingest principal, later: re-asserts c1 and adds c5.
    let (o1, _) = ingest(&pool, "ingest_document", doc, c1, other, false).await;
    let (o5, _) = ingest(&pool, "ingest_document", doc, c5, other, true).await;
    set_edge_created_at(&pool, o1, "2099-01-01T00:00:00Z").await;
    set_edge_created_at(&pool, o5, "2099-01-01T00:00:00Z").await;
    set_edge_created_at(&pool, a1, "2026-01-01T00:00:00Z").await;

    let pos = |p: i64| json!({"position": p, "role": "author", "affiliations": []});
    authored(&pool, second, doc, ingester, pos(1)).await;
    authored(
        &pool,
        first,
        doc,
        ingester,
        json!({"position": 0, "role": "corresponding", "affiliations": ["Fixture Institute"]}),
    )
    .await;
    authored(
        &pool,
        person,
        doc,
        ingester,
        json!({"position": 2, "pending_countersign": true, "ingested_by": ingester.to_string()}),
    )
    .await;
    let g = authored(&pool, gone, doc, ingester, pos(3)).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 hour' WHERE id = $1")
        .bind(g)
        .execute(&pool)
        .await
        .expect("retract the authorship");
    // The other principal names an author of its own: not on the first
    // ingest's list.
    let i = authored(&pool, intruder, doc, other, pos(0)).await;
    set_edge_created_at(&pool, i, "2099-01-01T00:00:00Z").await;

    let item = by_doi(&state, stranger, "https://doi.org/10.5555/papers.listing").await;
    assert_eq!(item["id"], json!(doc), "{item}");
    assert_eq!(item["title"], json!("Listing Paper"), "{item}");
    assert_eq!(item["authors_ingested_by"], json!(ingester), "{item}");
    assert_eq!(
        item["authors"],
        json!([
            {"id": first, "display_name": "First Author", "position": 0,
             "role": "corresponding", "affiliations": ["Fixture Institute"]},
            {"id": second, "display_name": "Second Author", "position": 1,
             "role": "author", "affiliations": []},
        ]),
        "{item}"
    );
    assert_eq!(
        item["pending_authors"],
        json!([
            {"id": person, "display_name": "Named Person", "position": 2,
             "role": "author", "affiliations": [], "named_by": ingester},
        ]),
        "a pending author is apart, never an author: {item}"
    );
    assert_eq!(item["authors_truncated"], json!(false), "{item}");
    assert_eq!(
        item["claim_count"],
        json!(3),
        "c1 once, c2, c5; not the hidden claims nor the retracted assertion: {item}"
    );

    // The member reads both of its group's claims.
    let theirs = by_doi(&state, member, "10.5555/papers.listing").await;
    assert_eq!(theirs["claim_count"], json!(5), "{theirs}");

    // The full list carries the same blocks.
    let all = list(&state, stranger, "limit=100").await;
    let row = all["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|p| p["id"] == json!(doc))
        .cloned()
        .unwrap_or_else(|| panic!("the paper is listed: {all}"));
    assert_eq!(row["claim_count"], json!(3), "{row}");
    assert_eq!(row["authors"], item["authors"], "{row}");

    // The first ingest's assertion of c1 hidden from the stranger: c1 is
    // still counted, once, through the other ingest's own assertion.
    make_group_private(&pool, a1, group).await;
    let item = by_doi(&state, stranger, "10.5555/papers.listing").await;
    assert_eq!(
        item["claim_count"],
        json!(3),
        "c1 still via the other ingest: {item}"
    );
}
