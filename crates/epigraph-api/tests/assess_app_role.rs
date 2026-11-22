//! `POST /api/v1/claims/:id/assess` over HTTP on the APPLICATION ROLE
//! (backlog 74feb76b).
//!
//! Every other assess test runs on the `#[sqlx::test]` superuser pool, where
//! row security never refuses anything. On prod the server's raw `db_pool` is
//! the application pool (`AppState::with_scoped_pool` aliases it to
//! `ScopedPool::inner`), so a write the handler sends there runs UNSTAMPED
//! under FORCE row security. These arms build exactly that state: the raw pool
//! and the stamped `ScopedPool` are both `epigraph_app`.
//!
//! * A standalone claim the caller owns assesses: 200, its assessment row,
//!   its `claim.assessed` record and its cached belief all land.
//! * The compound guard (migration 193, backlog 0dc20fad) holds on the HTTP
//!   route: a compound whose only child (and the edge to it) the caller cannot
//!   read is assessed (200, the row lands) but its cache is not refolded from
//!   its own BBA, while a standalone twin's is.
//!
//! Expected cache values are sentinels no fold produces.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use serde_json::Value;
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

/// The app with BOTH pools on `epigraph_app`, as on prod.
async fn spawn_app(pool: &PgPool) -> (SocketAddr, oneshot::Sender<()>) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    let app = epigraph_api::routes::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    (addr, tx)
}

async fn claim(pool: &PgPool, author: Uuid, group: Uuid, visibility: &str, what: &str) -> Uuid {
    let content = format!("74feb76b assess {what} {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, $3, $4) RETURNING id",
    )
    .bind(&content)
    .bind(author)
    .bind(visibility)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// `parent -decomposes_to-> child`, in force, its tenancy forced to
/// `(visibility, group)`.
async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid, visibility: &str, group: Uuid) {
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                 now() - interval '1 day') RETURNING id",
    )
    .bind(parent)
    .bind(child)
    .fetch_one(pool)
    .await
    .expect("seed decomposes_to");
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("force edge tenancy");
}

/// A cache no fold of an assessment produces, recorded on `frame`.
async fn sentinel(pool: &PgPool, claim: Uuid, frame: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = 0.613, plausibility = 0.887, pignistic_prob = 0.741, \
                belief_frame_id = $2 WHERE id = $1",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("set the sentinel cache");
}

const SENTINEL: (Option<f64>, Option<f64>, Option<f64>) = (Some(0.613), Some(0.887), Some(0.741));

/// `(belief, plausibility, pignistic_prob, belief_frame_id)` of the cache.
async fn cache(
    pool: &PgPool,
    claim: Uuid,
) -> (Option<f64>, Option<f64>, Option<f64>, Option<Uuid>) {
    sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, belief_frame_id FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the cache")
}

/// POST an assessment of `claim` as `agent`; insist on 200.
async fn assess(addr: SocketAddr, agent: Uuid, claim: Uuid) -> Value {
    let token = common::mint_token_with_agent(&["claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{claim}/assess"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "evidence_type": "empirical",
            "methodology": "instrumental",
            "confidence": 0.9,
            "supports": true,
        }))
        .send()
        .await
        .expect("request");
    let status = resp.status();
    let text = resp.text().await.expect("body");
    assert_eq!(status, 200, "POST assess as {agent} must be 200: {text}");
    serde_json::from_str(&text).expect("json body")
}

/// Live assessment rows on (claim, canonical frame), by source agent.
async fn rows(pool: &PgPool, claim: Uuid) -> Vec<Option<Uuid>> {
    sqlx::query_scalar(
        "SELECT source_agent_id FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2 AND retracted_at IS NULL",
    )
    .bind(claim)
    .bind(epigraph_engine::edge_factor::CLAIM_VALIDITY_FRAME_ID)
    .fetch_all(pool)
    .await
    .expect("read assessment rows")
}

async fn assessed_events(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM events WHERE event_type = 'claim.assessed' \
           AND payload->>'claim_id' = $1::text",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("count claim.assessed")
}

/// A standalone claim the caller owns assesses on the application role: the
/// response is 200 and the row, the writer record and the cache all land.
#[sqlx::test(migrations = "../../migrations")]
async fn a_standalone_claim_assesses_on_the_application_role(pool: PgPool) {
    let (caller, mine) = fixture::seed_agent_with_group(&pool, "74feb76b-caller").await;
    let standalone = claim(&pool, caller, mine, "public", "standalone").await;
    let (addr, _shutdown) = spawn_app(&pool).await;

    let resp = assess(addr, caller, standalone).await;

    assert_eq!(rows(&pool, standalone).await, vec![Some(caller)], "{resp}");
    assert_eq!(assessed_events(&pool, standalone).await, 1, "{resp}");
    let (belief, _, betp, frame) = cache(&pool, standalone).await;
    assert_eq!(
        frame,
        Some(epigraph_engine::edge_factor::CLAIM_VALIDITY_FRAME_ID),
        "the cache records the canonical frame: {resp}"
    );
    assert!(
        belief.is_some() && betp.is_some(),
        "the cache was written: {resp}"
    );
}

/// The compound guard on the HTTP route, under row security: the caller's
/// public compound, whose only child (and the edge to it) is private to
/// another group, is assessed but its sentinel cache is not refolded from its
/// own BBA. CALIBRATION: a standalone twin with the same sentinel IS refolded
/// by the same call shape, so the session can write a cache.
#[sqlx::test(migrations = "../../migrations")]
async fn assess_leaves_a_compound_whose_decomposition_the_caller_cannot_see(pool: PgPool) {
    let (caller, mine) = fixture::seed_agent_with_group(&pool, "74feb76b-c-caller").await;
    let (other, theirs) = fixture::seed_agent_with_group(&pool, "74feb76b-c-other").await;
    let frame = epigraph_engine::edge_factor::CLAIM_VALIDITY_FRAME_ID;
    let hidden = claim(&pool, caller, mine, "public", "compound").await;
    let child = claim(&pool, other, theirs, "group", "private only child").await;
    decomposes_to(&pool, hidden, child, "group", theirs).await;
    let twin = claim(&pool, caller, mine, "public", "standalone twin").await;
    for c in [hidden, twin] {
        sentinel(&pool, c, frame).await;
    }
    let (addr, _shutdown) = spawn_app(&pool).await;

    let twin_resp = assess(addr, caller, twin).await;
    let twin_after = cache(&pool, twin).await;
    assert_ne!(
        (twin_after.0, twin_after.1, twin_after.2),
        SENTINEL,
        "calibration: assess refolds a standalone claim's cache: {twin_resp}"
    );

    let resp = assess(addr, caller, hidden).await;
    assert_eq!(rows(&pool, hidden).await, vec![Some(caller)], "{resp}");
    let after = cache(&pool, hidden).await;
    assert_eq!(
        (after.0, after.1, after.2),
        SENTINEL,
        "0dc20fad: assess refolded a compound's cache from its own BBA: {resp}"
    );
    assert_eq!(after.3, Some(frame), "the recorded owner is untouched");
}
