//! `POST /api/v1/challenges/:id/resolve`: the claim owner's HTTP route to
//! migration 168's `epigraph_resolve_challenge` (operator rulings R-3, R-13,
//! R-14, R-CH1b; backlog bcd55cad). The MCP twin is `resolve_challenge`
//! (`epigraph-mcp/tests/resolve_challenge_tool.rs`).
//!
//! * a writer of the challenged claim's owning group sets the status of an
//!   OUTSIDER's challenge; the resolver recorded is the token's own agent, and
//!   a body that names a resolver is refused (R-13);
//! * R-14: a pending challenge is accepted directly and a settled one
//!   re-resolved, every change audited;
//! * R-13: the outsider (the row's owner) is refused 403, `withdrawn` is not a
//!   resolution (400), a withdrawn challenge takes none (409), a token without
//!   `claims:write` is 403; nothing is written by any refusal;
//! * R-CH1b: a challenge on a claim the caller cannot read answers exactly as
//!   a random id (same 404 and body modulo the id).
//!
//! Both the raw `db_pool` and the stamped `ScopedPool` are `epigraph_app`, as
//! in production.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use serde_json::{json, Value};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

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

struct World {
    pool: PgPool,
    addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
    owner: Uuid,
    /// A member of nothing the owner owns: the challenger.
    outsider: Uuid,
    /// `('public', owner's group)`.
    public: Uuid,
    /// `('group', owner's group)`.
    private: Uuid,
}

async fn world(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) -> World {
    let pool = pool_opts
        .connect_with(conn_opts)
        .await
        .expect("seeding pool");
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "chr-owner").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "chr-outsider").await;
    let public = Uuid::new_v4();
    let hash: Vec<u8> = public.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(public)
    .bind(format!("challenge resolution public claim {public}"))
    .bind(hash)
    .bind(owner)
    .bind(owner_group)
    .execute(&pool)
    .await
    .expect("seed public claim");
    let private = fixture::seed_group_claim(&pool, owner, owner_group, "chr private claim").await;
    let (addr, shutdown) = spawn_app(&pool).await;
    World {
        pool,
        addr,
        _shutdown: shutdown,
        owner,
        outsider,
        public,
        private,
    }
}

async fn post(w: &World, agent: Uuid, scopes: &[&str], path: &str, body: Value) -> (u16, String) {
    let token = common::mint_token_with_agent(scopes, agent);
    let resp = reqwest::Client::new()
        .post(format!("http://{}{path}", w.addr))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    (status, resp.text().await.expect("body"))
}

/// The outsider files a challenge on `claim` through the real route.
async fn outsiders_challenge(w: &World, claim: Uuid) -> Uuid {
    let (status, text) = post(
        w,
        w.outsider,
        &["claims:write"],
        &format!("/api/v1/claims/{claim}/challenge"),
        json!({
            "challenge_type": "factual_error",
            "explanation": "the cited figure contradicts its own source",
        }),
    )
    .await;
    assert_eq!(
        status, 201,
        "the outsider's challenge lands (R-CH1): {text}"
    );
    let v: Value = serde_json::from_str(&text).expect("json");
    v["id"].as_str().expect("id").parse().expect("uuid")
}

async fn resolve_as(
    w: &World,
    agent: Uuid,
    scopes: &[&str],
    id: Uuid,
    body: Value,
) -> (u16, String) {
    post(
        w,
        agent,
        scopes,
        &format!("/api/v1/challenges/{id}/resolve"),
        body,
    )
    .await
}

/// `(state, resolved_by, resolved_at IS NOT NULL, resolution_details)`.
async fn resolution(w: &World, id: Uuid) -> (String, Option<Uuid>, bool, Option<Value>) {
    sqlx::query_as(
        "SELECT state::text, resolved_by, resolved_at IS NOT NULL, resolution_details \
           FROM challenges WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&w.pool)
    .await
    .expect("read challenge")
}

/// `(agent_id, state_after)` of every audited resolution of `id`, oldest first.
async fn audit(w: &World, id: Uuid) -> Vec<(Option<Uuid>, String)> {
    sqlx::query_as(
        "SELECT agent_id, details->>'state_after' FROM security_events \
          WHERE event_type = 'challenges.claim_owner_resolution' \
            AND details->>'challenge_id' = $1::text \
          ORDER BY created_at, id",
    )
    .bind(id)
    .fetch_all(&w.pool)
    .await
    .expect("read the resolution audit")
}

/// R-3 / R-14 / R-13 over HTTP. The claim's owner resolves an outsider's
/// challenge (pending -> accepted directly, then re-resolved), the resolver is
/// the token's agent, every change is audited; the outsider, a body naming a
/// resolver, `withdrawn`, and a `claims:read` token are all refused with
/// nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn the_claims_owner_resolves_an_outsiders_challenge_and_nobody_else_does(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let theirs = outsiders_challenge(&w, w.public).await;

    // Refusals first: nothing they do may land.
    let (s, b) = resolve_as(
        &w,
        w.outsider,
        &["claims:write"],
        theirs,
        json!({"state": "accepted"}),
    )
    .await;
    assert_eq!(
        s, 403,
        "the outsider owns the row but does not resolve it (R-13): {b}"
    );
    let (s, b) = resolve_as(
        &w,
        w.owner,
        &["claims:write"],
        theirs,
        json!({"state": "accepted", "resolved_by": w.outsider}),
    )
    .await;
    assert!(
        (400..500).contains(&s),
        "a body naming a resolver is refused, not silently ignored: {s} {b}"
    );
    let (s, b) = resolve_as(
        &w,
        w.owner,
        &["claims:write"],
        theirs,
        json!({"state": "withdrawn"}),
    )
    .await;
    assert_eq!(
        s, 400,
        "withdrawn is the challenger's act, not a resolution: {b}"
    );
    let (s, b) = resolve_as(
        &w,
        w.owner,
        &["claims:read"],
        theirs,
        json!({"state": "accepted"}),
    )
    .await;
    assert_eq!(s, 403, "resolving needs claims:write: {b}");
    assert_eq!(
        resolution(&w, theirs).await,
        ("pending".to_string(), None, false, None),
        "no refusal wrote anything"
    );
    assert!(audit(&w, theirs).await.is_empty(), "nor audited anything");

    // The owner: pending -> accepted directly (R-14), the resolver is the
    // token's own agent.
    let details = json!({"reason": "the figure is correct"});
    let (s, b) = resolve_as(
        &w,
        w.owner,
        &["claims:write"],
        theirs,
        json!({"state": "accepted", "resolution_details": details}),
    )
    .await;
    assert_eq!(s, 200, "the claim's owner resolves (R-3): {b}");
    let v: Value = serde_json::from_str(&b).expect("json");
    assert_eq!(v["challenge_id"], theirs.to_string(), "{v}");
    assert_eq!(v["claim_id"], w.public.to_string(), "{v}");
    assert_eq!(v["state"], "accepted", "{v}");
    assert_eq!(v["resolved_by"], w.owner.to_string(), "{v}");
    assert_eq!(v["resolution_details"], details, "{v}");
    assert_eq!(
        resolution(&w, theirs).await,
        ("accepted".to_string(), Some(w.owner), true, Some(details)),
    );

    // Re-resolution (R-14).
    let (s, b) = resolve_as(
        &w,
        w.owner,
        &["claims:write"],
        theirs,
        json!({"state": "rejected"}),
    )
    .await;
    assert_eq!(
        s, 200,
        "the owner re-resolves a settled challenge (R-14): {b}"
    );
    assert_eq!(resolution(&w, theirs).await.0, "rejected");
    assert_eq!(
        audit(&w, theirs).await,
        vec![
            (Some(w.owner), "accepted".to_string()),
            (Some(w.owner), "rejected".to_string())
        ],
        "every change is audited, naming the resolver"
    );
}

/// A withdrawn challenge takes no resolution status: 409, nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_withdrawn_challenge_is_409(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) {
    let w = world(pool_opts, conn_opts).await;
    let theirs = outsiders_challenge(&w, w.public).await;
    sqlx::query("UPDATE challenges SET state = 'withdrawn' WHERE id = $1")
        .bind(theirs)
        .execute(&w.pool)
        .await
        .expect("withdraw (as the harness)");
    let (s, b) = resolve_as(
        &w,
        w.owner,
        &["claims:write"],
        theirs,
        json!({"state": "rejected"}),
    )
    .await;
    assert_eq!(s, 409, "{b}");
    assert_eq!(
        resolution(&w, theirs).await,
        ("withdrawn".to_string(), None, false, None)
    );
}

/// R-CH1b: a challenge on a claim the caller cannot read answers EXACTLY like
/// a random id: same 404, same body with the id replaced; nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_challenge_answers_exactly_as_a_nonexistent_one(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let hidden: Uuid = sqlx::query_scalar(
        "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation, state) \
         VALUES ($1, $2, 'factual_error', 'an insider on a private claim', 'pending') \
         RETURNING id",
    )
    .bind(w.private)
    .bind(w.owner)
    .fetch_one(&w.pool)
    .await
    .expect("seed a challenge on the private claim");
    let missing = Uuid::new_v4();
    let (s_hidden, b_hidden) = resolve_as(
        &w,
        w.outsider,
        &["claims:write"],
        hidden,
        json!({"state": "accepted"}),
    )
    .await;
    let (s_missing, b_missing) = resolve_as(
        &w,
        w.outsider,
        &["claims:write"],
        missing,
        json!({"state": "accepted"}),
    )
    .await;
    assert_eq!(
        s_missing, 404,
        "a nonexistent challenge is 404: {b_missing}"
    );
    assert_eq!(
        (s_hidden, b_hidden.replace(&hidden.to_string(), "<id>")),
        (s_missing, b_missing.replace(&missing.to_string(), "<id>")),
        "an unreadable challenge answers exactly as a nonexistent one"
    );
    assert_eq!(
        resolution(&w, hidden).await,
        ("pending".to_string(), None, false, None),
        "nothing written"
    );
}
