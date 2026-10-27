//! `POST /api/v1/mass-functions/:id/retract` (operator ruling R-79, migration
//! 184) on the APPLICATION ROLE.
//!
//! The BBAs are written through the real `POST /api/v1/frames/:id/evidence`
//! route and retracted through the new one, both on transactions stamped from
//! the caller's viewer as `epigraph_app` (`connect_downgraded_for_tests`), so
//! the database's refusals happen here exactly as in production. The raw
//! `db_pool` is the harness superuser, used only to seed fixtures and to read
//! state back.
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
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
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
    owner: Uuid,
    stranger: Uuid,
    other: Uuid,
    other_group: Uuid,
    /// Holds two of the owner's BBAs on `frame`.
    claim: Uuid,
    /// The control: holds only the second of those BBAs.
    control: Uuid,
    frame: Uuid,
    p_support: Uuid,
    p_refute: Uuid,
}

async fn owned_claim(pool: &PgPool, agent: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, visibility, \
                             owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, 'public', $5)",
    )
    .bind(id)
    .bind(format!("r79 route claim {tag} {id}"))
    .bind(hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn perspective(pool: &PgPool, owner: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("r79-route-{}", Uuid::new_v4()))
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("seed perspective")
}

/// POST evidence as `agent` under `perspective`; insist on 201.
async fn submit(w: &World, agent: Uuid, claim: Uuid, perspective: Uuid, masses: Value) {
    let token = common::mint_token_with_agent(&["claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{}/api/v1/frames/{}/evidence",
            w.addr, w.frame
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "claim_id": claim, "agent_id": agent, "perspective_id": perspective,
            "reliability": 1.0, "masses": masses,
        }))
        .send()
        .await
        .expect("request");
    let status = resp.status();
    let text = resp.text().await.expect("body");
    assert_eq!(status, 201, "POST evidence as {agent} must be 201: {text}");
}

async fn world(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) -> World {
    let pool = pool_opts
        .connect_with(conn_opts)
        .await
        .expect("seeding pool");
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "r79-route-owner").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "r79-route-stranger").await;
    let (other, other_group) = fixture::seed_agent_with_group(&pool, "r79-route-other").await;
    let claim = owned_claim(&pool, owner, owner_group, "two").await;
    let control = owned_claim(&pool, owner, owner_group, "control").await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) \
         RETURNING id",
    )
    .bind(format!("r79-route-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    let p_support = perspective(&pool, owner).await;
    let p_refute = perspective(&pool, owner).await;
    let (addr, shutdown) = spawn_app(&pool).await;
    let w = World {
        pool,
        addr,
        _shutdown: shutdown,
        owner,
        stranger,
        other,
        other_group,
        claim,
        control,
        frame,
        p_support,
        p_refute,
    };
    let support = serde_json::json!({"0": 0.9, "0,1": 0.1});
    let refute = serde_json::json!({"1": 0.6, "0,1": 0.4});
    submit(&w, owner, claim, p_support, support).await;
    submit(&w, owner, claim, p_refute, refute.clone()).await;
    submit(&w, owner, control, p_refute, refute).await;
    w
}

async fn bba(w: &World, claim: Uuid, perspective: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT id FROM mass_functions WHERE claim_id = $1 AND perspective_id = $2")
        .bind(claim)
        .bind(perspective)
        .fetch_one(&w.pool)
        .await
        .expect("read the BBA id")
}

async fn cache(w: &World, claim: Uuid) -> (f64, f64, f64) {
    let (b, p, t): (Option<f64>, Option<f64>, Option<f64>) =
        sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&w.pool)
            .await
            .expect("read the cache");
    (
        b.expect("belief cached"),
        p.expect("plausibility cached"),
        t.expect("pignistic cached"),
    )
}

fn close(a: (f64, f64, f64), b: (f64, f64, f64)) -> bool {
    (a.0 - b.0).abs() < EPS && (a.1 - b.1).abs() < EPS && (a.2 - b.2).abs() < EPS
}

async fn retract(w: &World, token: &str, id: Uuid, reason: &str) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{}/api/v1/mass-functions/{id}/retract",
            w.addr
        ))
        .bearer_auth(token)
        .json(&serde_json::json!({ "reason": reason }))
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

async fn stored_scoped(w: &World, claim: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM ds_combined_beliefs WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(claim)
    .bind(w.frame)
    .fetch_one(&w.pool)
    .await
    .expect("count stored scoped beliefs")
}

async fn audit_count(w: &World, id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = 'mass_functions.retract' AND details->>'mass_function_id' = $1::text",
    )
    .bind(id)
    .fetch_one(&w.pool)
    .await
    .expect("count audit rows")
}

async fn retracted(w: &World, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT retracted_at IS NOT NULL FROM mass_functions WHERE id = $1")
        .bind(id)
        .fetch_one(&w.pool)
        .await
        .expect("read the row")
}

/// R-79's acceptance: once the owner retracts one of the claim's two BBAs,
/// the claim's cached belief is exactly the belief of a control claim that
/// only ever held the other BBA, and no longer the two-BBA fold. A repeat
/// retraction answers `already_retracted` and writes no second audit row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_bba_no_longer_moves_the_claims_belief(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let both = cache(&w, w.claim).await;
    let control = cache(&w, w.control).await;
    assert!(
        !close(both, control),
        "calibration: the two-BBA fold {both:?} must differ from the control {control:?}"
    );

    let target = bba(&w, w.claim, w.p_support).await;
    let stored_before = stored_scoped(&w, w.claim).await;
    assert!(
        stored_before > 0,
        "calibration: the evidence route stored a scoped belief for the claim"
    );
    let control_stored = stored_scoped(&w, w.control).await;
    let token = common::mint_token_with_agent(&["claims:write"], w.owner);
    let (status, body) = retract(&w, &token, target, "duplicate re-observation").await;
    assert_eq!(status, 200, "the owner retracts its BBA: {body}");
    assert_eq!(body["status"], "retracted", "{body}");
    assert_eq!(body["arm"], "owner", "{body}");
    assert_eq!(body["claim_id"], w.claim.to_string(), "{body}");
    assert_eq!(body["retracted_by"], w.owner.to_string(), "{body}");
    assert_eq!(body["belief_recomputed"], true, "{body}");
    assert_eq!(body["scoped_beliefs_cleared"], stored_before, "{body}");
    assert_eq!(
        stored_scoped(&w, w.claim).await,
        0,
        "the stored scoped beliefs that folded the retracted BBA are gone"
    );
    assert_eq!(
        stored_scoped(&w, w.control).await,
        control_stored,
        "another claim's are untouched"
    );

    let after = cache(&w, w.claim).await;
    assert!(
        close(after, control),
        "after the retraction the claim's belief {after:?} must be the remaining BBA's alone \
         {control:?} (it was {both:?})"
    );
    assert!(
        retracted(&w, target).await,
        "the row is kept, marked retracted"
    );
    assert_eq!(audit_count(&w, target).await, 1);

    let (status, body) = retract(&w, &token, target, "again").await;
    assert_eq!(status, 200, "a repeat is not an error: {body}");
    assert_eq!(body["status"], "already_retracted", "{body}");
    assert_eq!(body["retract_reason"], "duplicate re-observation", "{body}");
    assert_eq!(audit_count(&w, target).await, 1, "no second audit row");
    assert!(close(cache(&w, w.claim).await, control));
}

/// Who is refused, and with which status: a stranger that can read the
/// owner's public BBA gets 403; a BBA on a group-private claim it cannot read
/// gets 404, as a random id does; a token without `claims:write` gets 403;
/// a blank reason gets 400. Nothing is written in any case.
#[sqlx::test(migrations = "../../migrations")]
async fn non_owners_are_refused_with_404_or_403_and_nothing_is_written(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let target = bba(&w, w.claim, w.p_support).await;
    let private_claim =
        fixture::seed_group_claim(&w.pool, w.other, w.other_group, "r79 route private").await;
    let hidden: Uuid = sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, '{\"0\": 0.5, \"0,1\": 0.5}'::jsonb) RETURNING id",
    )
    .bind(private_claim)
    .bind(w.frame)
    .bind(w.other)
    .fetch_one(&w.pool)
    .await
    .expect("seed a group-private BBA");

    let stranger = common::mint_token_with_agent(&["claims:write"], w.stranger);
    let (status, body) = retract(&w, &stranger, target, "not mine").await;
    assert_eq!(status, 403, "a reader that does not own the BBA: {body}");
    let (status, body) = retract(&w, &stranger, hidden, "hidden").await;
    assert_eq!(status, 404, "an unreadable BBA: {body}");
    let (status, body) = retract(&w, &stranger, Uuid::new_v4(), "random").await;
    assert_eq!(status, 404, "a random id: {body}");

    let read_only = common::mint_token_with_agent(&["claims:read"], w.owner);
    let (status, body) = retract(&w, &read_only, target, "no write scope").await;
    assert_eq!(status, 403, "claims:write is required: {body}");
    let owner = common::mint_token_with_agent(&["claims:write"], w.owner);
    let (status, body) = retract(&w, &owner, target, "   ").await;
    assert_eq!(status, 400, "a blank reason: {body}");

    for id in [target, hidden] {
        assert!(!retracted(&w, id).await, "nothing written on {id}");
        assert_eq!(audit_count(&w, id).await, 0);
    }
}

/// A `claims:admin` token whose client record holds the grant retracts
/// another owner's BBA, recorded as the admin arm with the admin as
/// retractor.
#[sqlx::test(migrations = "../../migrations")]
async fn a_live_claims_admin_retracts_another_owners_bba(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let target = bba(&w, w.claim, w.p_refute).await;
    let (token, client) =
        common::test_bearer_token_with_seeded_client(&w.pool, &["claims:write", "claims:admin"])
            .await;
    let (status, body) = retract(&w, &token, target, "promotion duplicate").await;
    assert_eq!(status, 200, "a live claims:admin grant retracts: {body}");
    assert_eq!(body["arm"], "admin", "{body}");
    assert_ne!(
        body["retracted_by"],
        w.owner.to_string(),
        "the admin, not the owner: {body}"
    );
    let admin_client: String = sqlx::query_scalar(
        "SELECT details->>'admin_client_id' FROM security_events \
          WHERE event_type = 'mass_functions.retract' AND details->>'mass_function_id' = $1::text",
    )
    .bind(target)
    .fetch_one(&w.pool)
    .await
    .expect("the admin retraction's audit row");
    assert_eq!(admin_client, client.to_string());
}
