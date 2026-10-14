//! `POST /api/v1/frames/:id/evidence` on the APPLICATION ROLE (backlogs
//! 2bffdfdc / I075 and 82dcff9d / I228).
//!
//! `submit_evidence` writes the BBA, the claim's frame assignment, the cached
//! belief and its Beta parameters on ONE transaction stamped with the caller's
//! viewer (`AppState::write_as`). On a superuser harness every policy is
//! bypassed, so that transaction's refusals never happen and
//! `frames_evidence_recompute_parity.rs` cannot see them. Here they do:
//! * an owner's writes all land, and the cache records the frame;
//! * a NON-owner of a public claim (most public claims on prod are
//!   world-owned and memberless, so every REST caller is one) stores its own
//!   writer-owned BBA, but migration 114 keeps the claim's frame assignment and
//!   cached belief the owner's: the `claim_frames` INSERT is refused (it must
//!   not abort the transaction and roll the BBA back), and the definer
//!   `epigraph_foreign_belief_cache` refreshes the cache only on the frame it
//!   already carries (or seeds one on `binary_truth`). When it does not, the
//!   response must say so.
//!
//! # The instrument
//!
//! The shape of `writer_owned_edges_http.rs::privileged_raw_state`: the raw
//! `db_pool` is the harness superuser, so the handler's unstamped reads before
//! the transaction and its best-effort side effects after it cannot fail a
//! case for an unrelated reason; the stamped `ScopedPool` is `epigraph_app`
//! (`connect_downgraded_for_tests`), so only the transaction is under test.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

const EPS: f64 = 1e-9;

/// The warning `submit_evidence` gives when the claim's cache does not carry
/// this call's frame afterwards.
const CACHE_NOT_UPDATED: &str = "cached belief was NOT updated";

/// Which role the handler's raw `db_pool` connects as.
#[derive(Clone, Copy)]
enum RawPool {
    /// The harness superuser (`privileged_raw_state`'s shape): only the
    /// stamped transaction is held to the policies.
    Superuser,
    /// `epigraph_app` too (`app_role_state`'s shape), as on prod: an
    /// unstamped write through the alias is refused.
    AppRole,
}

async fn spawn_app(pool: &PgPool, raw: RawPool) -> (SocketAddr, oneshot::Sender<()>) {
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
    let raw = match raw {
        RawPool::Superuser => pool.clone(),
        RawPool::AppRole => fixture::downgraded_pool(pool, "epigraph_app").await,
    };
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

struct World {
    pool: PgPool,
    addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
    /// Owns the claim through its personal group.
    owner: Uuid,
    /// Neither owns the claim nor is a member of its group.
    stranger: Uuid,
    claim: Uuid,
    /// Not `binary_truth`, so a non-owner never seeds a cache on it.
    frame: Uuid,
}

async fn seed_frame(pool: &PgPool, tag: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) \
         RETURNING id",
    )
    .bind(format!("u024-app-{tag}-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

async fn world(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions, raw: RawPool) -> World {
    let pool = pool_opts
        .connect_with(conn_opts)
        .await
        .expect("seeding pool");
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "u024-owner").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "u024-stranger").await;

    let claim = Uuid::new_v4();
    let hash: Vec<u8> = claim.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, visibility, \
                             owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, 'public', $5)",
    )
    .bind(claim)
    .bind(format!("u024 app-role claim {claim}"))
    .bind(hash)
    .bind(owner)
    .bind(owner_group)
    .execute(&pool)
    .await
    .expect("seed claim");
    let frame = seed_frame(&pool, "target").await;

    let (addr, shutdown) = spawn_app(&pool, raw).await;
    World {
        pool,
        addr,
        _shutdown: shutdown,
        owner,
        stranger,
        claim,
        frame,
    }
}

/// POST `{0: 0.6, Θ: 0.4}` at reliability 1.0 as `agent`; insist on 201.
async fn submit(w: &World, agent: Uuid) -> Value {
    let token = common::mint_token_with_agent(&["claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{}/api/v1/frames/{}/evidence",
            w.addr, w.frame
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "claim_id": w.claim, "agent_id": agent, "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
        }))
        .send()
        .await
        .expect("request");
    let status = resp.status();
    let text = resp.text().await.expect("body");
    assert_eq!(status, 201, "POST evidence as {agent} must be 201: {text}");
    serde_json::from_str(&text).expect("json body")
}

/// The BBAs on (claim, this world's frame) after the commit, by source agent.
async fn bbas(w: &World) -> Vec<Option<Uuid>> {
    sqlx::query_scalar(
        "SELECT source_agent_id FROM mass_functions WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(w.claim)
    .bind(w.frame)
    .fetch_all(&w.pool)
    .await
    .expect("read BBAs")
}

async fn cache(w: &World) -> (Option<f64>, Option<Uuid>) {
    sqlx::query_as("SELECT belief, belief_frame_id FROM claims WHERE id = $1")
        .bind(w.claim)
        .fetch_one(&w.pool)
        .await
        .expect("read the cache")
}

/// Give the claim an owner's cache on `frame`: Bel 0.3, Pl 0.9, BetP 0.6.
async fn seed_cache(w: &World, frame: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = 0.3, plausibility = 0.9, pignistic_prob = 0.6, \
                           belief_frame_id = $2 WHERE id = $1",
    )
    .bind(w.claim)
    .bind(frame)
    .execute(&w.pool)
    .await
    .expect("seed the owner's cache");
}

fn warnings(resp: &Value) -> Vec<String> {
    resp.get("warnings")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|v| v.as_str().expect("warning string").to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn reported(resp: &Value) -> f64 {
    resp["updated_belief"].as_f64().expect("updated_belief")
}

/// The owner's writes all land on the application role: its BBA, its frame
/// assignment, and the cache, attributed to this frame.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owners_submission_lands_and_attributes_the_cache(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts, RawPool::Superuser).await;
    let resp = submit(&w, w.owner).await;

    assert_eq!(
        bbas(&w).await,
        vec![Some(w.owner)],
        "the owner's BBA persisted"
    );
    let (belief, frame) = cache(&w).await;
    assert_eq!(frame, Some(w.frame), "the cache records this frame");
    assert!(
        belief.is_some_and(|b| (b - 0.6).abs() < EPS),
        "the cache holds m({{0}}) = 0.6: {belief:?}"
    );
    assert!((reported(&resp) - 0.6).abs() < EPS, "{resp}");
    assert!(warnings(&resp).is_empty(), "nothing to warn about: {resp}");
    let assigned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claim_frames WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(w.claim)
    .bind(w.frame)
    .fetch_one(&w.pool)
    .await
    .expect("read claim_frames");
    assert_eq!(assigned, 1, "the owner's frame assignment landed");
}

/// A non-owner submitting on another frame than the one the claim's cache
/// carries: its BBA persists (the refused frame assignment did not roll it
/// back), the owner's cache is untouched, and the response says the cache was
/// not updated.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_owner_on_another_frame_keeps_the_owners_cache_and_is_told(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts, RawPool::Superuser).await;
    let other = seed_frame(&w.pool, "owners").await;
    seed_cache(&w, other).await;

    let resp = submit(&w, w.stranger).await;

    assert_eq!(
        bbas(&w).await,
        vec![Some(w.stranger)],
        "the non-owner's BBA persisted after the COMMIT"
    );
    let (belief, frame) = cache(&w).await;
    assert_eq!(
        frame,
        Some(other),
        "the cache still carries the owner's frame"
    );
    assert!(
        belief.is_some_and(|b| (b - 0.3).abs() < EPS),
        "the owner's cached belief is untouched: {belief:?}"
    );
    assert!(
        warnings(&resp)
            .iter()
            .any(|m| m.contains(CACHE_NOT_UPDATED)),
        "the response must say the cache was not updated: {resp}"
    );
    assert!(
        (reported(&resp) - 0.6).abs() < EPS,
        "the response reports this frame's combination: {resp}"
    );
    let assigned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claim_frames WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(w.claim)
    .bind(w.frame)
    .fetch_one(&w.pool)
    .await
    .expect("read claim_frames");
    assert_eq!(
        assigned, 0,
        "fixture: a non-owner's frame assignment is refused (migration 114), so this case \
         exercises the savepointed refusal"
    );
}

/// A non-owner submitting on the frame the cache already carries refreshes
/// it, with no warning.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_owner_on_the_carried_frame_refreshes_the_cache(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts, RawPool::Superuser).await;
    seed_cache(&w, w.frame).await;

    let resp = submit(&w, w.stranger).await;

    assert_eq!(bbas(&w).await, vec![Some(w.stranger)]);
    let (belief, frame) = cache(&w).await;
    assert_eq!(frame, Some(w.frame));
    assert!(
        belief.is_some_and(|b| (b - 0.6).abs() < EPS),
        "the cache now holds this frame's combination (0.6, was 0.3): {belief:?}"
    );
    assert!(warnings(&resp).is_empty(), "the cache was updated: {resp}");
}

/// A non-owner submitting on a claim with no cache, on a frame other than
/// `binary_truth`: the definer seeds nothing, the BBA still persists, and the
/// response says the cache was not updated.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_owner_seeds_no_cache_off_binary_truth_and_is_told(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts, RawPool::Superuser).await;

    let resp = submit(&w, w.stranger).await;

    assert_eq!(bbas(&w).await, vec![Some(w.stranger)], "the BBA persisted");
    assert_eq!(
        cache(&w).await,
        (None, None),
        "no cache is seeded off binary_truth"
    );
    assert!(
        warnings(&resp)
            .iter()
            .any(|m| m.contains(CACHE_NOT_UPDATED)),
        "the response must say the cache was not updated: {resp}"
    );
}

/// With the raw pool on the application role too, as on prod, the owner's
/// global scoped belief (`ds_combined_beliefs`, scope `global`) still lands:
/// it is written on the stamped transaction. On the unstamped raw pool FORCE
/// refused it without an error, and since no derived BBA is stored beside the
/// inputs any more it is the only record of a REST fold.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owners_global_scoped_belief_lands_when_the_raw_pool_is_the_app_role(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts, RawPool::AppRole).await;
    let resp = submit(&w, w.owner).await;

    assert_eq!(
        bbas(&w).await,
        vec![Some(w.owner)],
        "the owner's BBA persisted"
    );
    let scoped: Option<f64> = sqlx::query_scalar(
        "SELECT belief FROM ds_combined_beliefs \
          WHERE frame_id = $1 AND claim_id = $2 AND scope_type = 'global' AND scope_id IS NULL",
    )
    .bind(w.frame)
    .bind(w.claim)
    .fetch_optional(&w.pool)
    .await
    .expect("read ds_combined_beliefs");
    assert!(
        scoped.is_some_and(|b| (b - 0.6).abs() < EPS),
        "the global scoped belief must be stored with this frame's belief 0.6: {scoped:?} \
         (response {resp})"
    );
}
