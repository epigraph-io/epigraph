#![cfg(feature = "db")]
//! `POST /api/v1/edges` and the provenance relationships a document's
//! authorship is read from, through the full router (bearer middleware, scope
//! check, viewer extractor, the stamped write) with both pools of the
//! `AppState` on the APPLICATION ROLE.
//!
//! * `asserts` or `AUTHORED` from an AGENT source is accepted only when that
//!   agent is the caller itself or an agent the caller operates through a
//!   live binding. Anyone else's would put words in that agent's mouth: the
//!   edge lands world-owned, so neither the agent nor the writer could take
//!   it back.
//! * `paper -asserts-> claim`, any `authored` edge into a paper, and the
//!   ingest's own `ingested_claim` record are written only by the document
//!   ingest. Refused for every caller, the paper's own authors included.
//!
//! Every refusal writes nothing (the edge count is measured), and every
//! refusal has an accepted positive control. All names are invented.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{as_role, database_url_for, downgraded_pool};

async fn app_role_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(scoped.inner())
        .await
        .expect("epigraph_bypass on the scoped pool");
    assert!(
        !bypass,
        "CALIBRATION: the scoped pool must not be privileged"
    );
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("link");
    assert!(out.link_live, "CALIBRATION: the link is live");
}

async fn retire(pool: &PgPool, agent: Uuid) {
    let outcome: String = as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: String = sqlx::query_scalar(
            "SELECT outcome FROM public.epigraph_retire_operator_link($1, 'edge test', true)",
        )
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("retire the link");
        (conn, r)
    })
    .await;
    assert_eq!(outcome, "retired", "CALIBRATION: the link was live");
}

async fn paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, $1) RETURNING id")
        .bind(doi)
        .fetch_one(pool)
        .await
        .expect("paper")
}

async fn edge_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM edges")
        .fetch_one(pool)
        .await
        .expect("count edges")
}

/// `POST /api/v1/edges` as `caller` with `edges:write`.
async fn post_edge(
    state: &AppState,
    caller: Uuid,
    (source, source_type): (Uuid, &str),
    (target, target_type): (Uuid, &str),
    relationship: &str,
) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["edges:write"], caller);
    let body = json!({
        "source_id": source, "source_type": source_type,
        "target_id": target, "target_type": target_type,
        "relationship": relationship,
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/edges")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = create_router(state.clone())
        .oneshot(req)
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// An agent-sourced `asserts` or `AUTHORED` edge is the caller's only for
/// itself or an agent it operates (live). A stranger naming a registered
/// human, or the human after the binding is retired, is refused and nothing
/// is written; the self and operated controls are accepted.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_sourced_attribution_is_accepted_only_for_the_caller_or_its_live_agent(
    pool: PgPool,
) {
    let state = app_role_state(&pool).await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "edge-stranger").await;
    let (human, _) = viewer_fixture::seed_human_operator(&pool, "edge-human").await;
    let (bot, _) = viewer_fixture::seed_agent_with_group(&pool, "edge-bot").await;
    link(&pool, bot, human).await;
    let claims: Vec<Uuid> = {
        let mut v = Vec::new();
        for i in 0..8 {
            v.push(
                viewer_fixture::seed_public_claim(&pool, stranger, &format!("edge target {i}"))
                    .await,
            );
        }
        v
    };

    for (n, (source, relationship)) in [(human, "asserts"), (human, "AUTHORED"), (bot, "asserts")]
        .into_iter()
        .enumerate()
    {
        let before = edge_count(&pool).await;
        let (status, body) = post_edge(
            &state,
            stranger,
            (source, "agent"),
            (claims[n], "claim"),
            relationship,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a stranger's {relationship} from {source}: {body}"
        );
        assert!(
            body.to_string().contains("operates"),
            "the refusal says whose edge it may write: {body}"
        );
        assert_eq!(edge_count(&pool).await, before, "nothing written");
    }

    // CONTROLS: the caller itself, and the human for the agent it operates.
    for (n, (caller, source, relationship)) in [
        (stranger, stranger, "asserts"),
        (stranger, stranger, "AUTHORED"),
        (human, bot, "asserts"),
        (human, bot, "AUTHORED"),
        (human, human, "asserts"),
    ]
    .into_iter()
    .enumerate()
    {
        let (status, body) = post_edge(
            &state,
            caller,
            (source, "agent"),
            (claims[3 + n.min(4)], "claim"),
            relationship,
        )
        .await;
        assert!(
            status.is_success(),
            "CONTROL {n}: {caller} writes {relationship} from {source}: {status} {body}"
        );
    }

    // Once the binding is retired the human no longer operates the bot.
    retire(&pool, bot).await;
    let before = edge_count(&pool).await;
    let (status, body) = post_edge(
        &state,
        human,
        (bot, "agent"),
        (claims[7], "claim"),
        "asserts",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "after retirement: {body}");
    assert_eq!(edge_count(&pool).await, before, "nothing written");
}

/// `paper -asserts-> claim`, `authored` into a paper and the ingest record are
/// the document ingest's alone: refused for a stranger AND for an author of the
/// paper, in any spelling, and nothing is written. CONTROL: the same caller's
/// own agent-sourced `asserts` onto the same claim is accepted.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ingest_only_relationships_are_refused_for_every_caller(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "edge-stranger").await;
    let (author, _) = viewer_fixture::seed_human_operator(&pool, "edge-author").await;
    let claim = viewer_fixture::seed_public_claim(&pool, stranger, "a public claim").await;
    let doc = paper(&pool, "10.9999/ingest-only-edges").await;

    for caller in [stranger, author] {
        for (source, target, relationship) in [
            ((doc, "paper"), (claim, "claim"), "asserts"),
            ((doc, "paper"), (claim, "claim"), "ASSERTS"),
            ((doc, "paper"), (claim, "claim"), "ingested_claim"),
            ((caller, "agent"), (doc, "paper"), "AUTHORED"),
            ((caller, "agent"), (doc, "paper"), "authored"),
        ] {
            let before = edge_count(&pool).await;
            let (status, body) = post_edge(&state, caller, source, target, relationship).await;
            assert!(
                status.is_client_error(),
                "{caller}: {relationship} {source:?} -> {target:?}: {status} {body}"
            );
            assert_eq!(
                edge_count(&pool).await,
                before,
                "{relationship} {source:?} -> {target:?}: nothing written"
            );
        }
        let (status, body) = post_edge(
            &state,
            stranger,
            (doc, "paper"),
            (claim, "claim"),
            "asserts",
        )
        .await;
        assert!(
            body.to_string().contains("document ingest"),
            "the refusal names the only writer: {status} {body}"
        );
    }

    let (status, body) = post_edge(
        &state,
        author,
        (author, "agent"),
        (claim, "claim"),
        "asserts",
    )
    .await;
    assert!(
        status.is_success(),
        "CONTROL: the author's own asserts: {status} {body}"
    );
}
