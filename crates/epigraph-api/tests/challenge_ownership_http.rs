//! `POST /api/v1/claims/:id/challenge` under operator rulings R-CH1 and
//! R-CH1b (migration 168), on the APPLICATION ROLE (backlog 2f2eeaea).
//!
//! The handler used to INSERT on the raw, unstamped pool, so on a database
//! where `challenges` carries no orphan `*_privacy` policy every challenge was
//! refused by 077 and surfaced as a redacted 500. It now writes on ONE
//! transaction stamped with the caller's viewer (`AppState::write_as`), the
//! challenger is the authenticated principal, and:
//!
//! * an OUTSIDER's challenge on a PUBLIC claim lands, owned by the outsider's
//!   own write group, public, `writer_owned`; an insider's inherits the claim's
//!   tenancy as before;
//! * a group-private claim the caller can read but not write is 403 with
//!   nothing written;
//! * a claim the caller cannot read answers EXACTLY like a nonexistent id (same
//!   status, same body modulo the id), on the write route and on the listing;
//! * a body `challenger_id` naming another agent is refused (403).
//!
//! # The instrument
//!
//! Both the raw `db_pool` and the stamped `ScopedPool` are `epigraph_app`, as
//! in production: a write that slipped back onto the raw pool is refused by
//! row security and every success arm below fails.
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
    /// Owns `public` and `private` through its personal group.
    owner: Uuid,
    owner_group: Uuid,
    /// A member of nothing the owner owns.
    stranger: Uuid,
    stranger_group: Uuid,
    /// `('public', owner_group)`.
    public: Uuid,
    /// `('group', owner_group)`.
    private: Uuid,
}

async fn world(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) -> World {
    let pool = pool_opts
        .connect_with(conn_opts)
        .await
        .expect("seeding pool");
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "chh-owner").await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "chh-stranger").await;
    let public = Uuid::new_v4();
    let hash: Vec<u8> = public.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(public)
    .bind(format!("challenge http public claim {public}"))
    .bind(hash)
    .bind(owner)
    .bind(owner_group)
    .execute(&pool)
    .await
    .expect("seed public claim");
    let private = fixture::seed_group_claim(&pool, owner, owner_group, "chh private claim").await;
    let (addr, shutdown) = spawn_app(&pool).await;
    World {
        pool,
        addr,
        _shutdown: shutdown,
        owner,
        owner_group,
        stranger,
        stranger_group,
        public,
        private,
    }
}

/// POST a challenge on `claim` as `agent` with `body`; `(status, body text)`.
async fn post_as(
    w: &World,
    agent: Uuid,
    scopes: &[&str],
    claim: Uuid,
    body: Value,
) -> (u16, String) {
    let token = common::mint_token_with_agent(scopes, agent);
    let resp = reqwest::Client::new()
        .post(format!("http://{}/api/v1/claims/{claim}/challenge", w.addr))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    (status, resp.text().await.expect("body"))
}

fn body_as(challenger: Uuid) -> Value {
    json!({
        "challenger_id": challenger,
        "challenge_type": "factual_error",
        "explanation": "the cited figure contradicts its own source",
    })
}

async fn get_list_as(w: &World, agent: Uuid, claim: Uuid) -> (u16, String) {
    let token = common::mint_token_with_agent(&["claims:read"], agent);
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{}/api/v1/claims/{claim}/challenges",
            w.addr
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    (status, resp.text().await.expect("body"))
}

/// `(owner_group_id, visibility, writer_owned, challenger_id)` of every
/// challenge on `claim`, oldest first.
async fn rows(w: &World, claim: Uuid) -> Vec<(Uuid, String, bool, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, writer_owned, challenger_id FROM challenges \
          WHERE claim_id = $1 ORDER BY created_at, id",
    )
    .bind(claim)
    .fetch_all(&w.pool)
    .await
    .expect("read challenges")
}

/// R-CH1 over HTTP. The stranger's challenge on the owner's PUBLIC claim is
/// 201 and owned by the stranger's group, public and flagged; the owner's own
/// challenge (the insider control) inherits the claim's tenancy.
#[sqlx::test(migrations = "../../migrations")]
async fn an_outsiders_challenge_on_a_public_claim_is_201_and_owned_by_the_outsider(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;

    let (status, text) = post_as(
        &w,
        w.stranger,
        &["claims:write"],
        w.public,
        body_as(w.stranger),
    )
    .await;
    assert_eq!(
        status, 201,
        "an outsider's challenge on a public claim lands: {text}"
    );
    let resp: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(resp["challenger_id"], w.stranger.to_string(), "{resp}");
    assert_eq!(resp["claim_id"], w.public.to_string(), "{resp}");

    let (status, text) = post_as(&w, w.owner, &["claims:write"], w.public, body_as(w.owner)).await;
    assert_eq!(status, 201, "the insider's challenge lands: {text}");

    assert_eq!(
        rows(&w, w.public).await,
        vec![
            (
                w.stranger_group,
                "public".to_string(),
                true,
                Some(w.stranger)
            ),
            (w.owner_group, "public".to_string(), false, Some(w.owner)),
        ],
        "the outsider's row is the outsider's; the insider's inherits the claim's"
    );
}

/// The challenger is the authenticated principal. A body naming another agent
/// is 403 with nothing written; an omitted `challenger_id` is the caller's own.
/// A token without `claims:write` is 403 (the MCP tool's scope).
#[sqlx::test(migrations = "../../migrations")]
async fn the_challenger_is_the_authenticated_principal(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;

    let (status, text) = post_as(
        &w,
        w.stranger,
        &["claims:write"],
        w.public,
        body_as(w.owner),
    )
    .await;
    assert_eq!(
        status, 403,
        "naming another agent as the challenger is refused: {text}"
    );
    let (status, text) = post_as(
        &w,
        w.stranger,
        &["claims:read"],
        w.public,
        body_as(w.stranger),
    )
    .await;
    assert_eq!(status, 403, "a read-only token cannot challenge: {text}");
    assert!(rows(&w, w.public).await.is_empty(), "nothing written");

    let (status, text) = post_as(
        &w,
        w.stranger,
        &["claims:write"],
        w.public,
        json!({"challenge_type": "outdated_evidence", "explanation": "superseded by a 2026 survey"}),
    )
    .await;
    assert_eq!(
        status, 201,
        "an omitted challenger_id is the caller's own: {text}"
    );
    assert_eq!(
        rows(&w, w.public).await,
        vec![(
            w.stranger_group,
            "public".to_string(),
            true,
            Some(w.stranger)
        )]
    );
}

/// A group-private claim the caller can READ (a reader member of its group)
/// but not write: 403, not 500, and nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_readable_private_claim_the_caller_cannot_write_is_403(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(w.owner_group)
    .bind(w.stranger)
    .execute(&w.pool)
    .await
    .expect("reader membership");

    let (status, text) = post_as(
        &w,
        w.stranger,
        &["claims:write"],
        w.private,
        body_as(w.stranger),
    )
    .await;
    assert_eq!(
        status, 403,
        "a reader's challenge on a private claim is refused by name: {text}"
    );
    assert!(
        !text.contains("row-level security") && !text.contains(&w.owner_group.to_string()),
        "neither the raw policy text nor the owning group is disclosed: {text}"
    );
    assert!(rows(&w, w.private).await.is_empty(), "nothing written");
}

/// R-CH1b on the write route: a private claim the caller cannot read answers
/// exactly like a random id. Same status (404) and the same body with the id
/// replaced; nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_claim_is_indistinguishable_from_a_nonexistent_one(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let missing = Uuid::new_v4();

    let (s_hidden, b_hidden) = post_as(
        &w,
        w.stranger,
        &["claims:write"],
        w.private,
        body_as(w.stranger),
    )
    .await;
    let (s_missing, b_missing) = post_as(
        &w,
        w.stranger,
        &["claims:write"],
        missing,
        body_as(w.stranger),
    )
    .await;
    assert_eq!(s_missing, 404, "a nonexistent claim is 404: {b_missing}");
    assert_eq!(
        (s_hidden, b_hidden.replace(&w.private.to_string(), "<id>")),
        (s_missing, b_missing.replace(&missing.to_string(), "<id>")),
        "an unreadable claim must answer exactly as a nonexistent one"
    );
    assert!(rows(&w, w.private).await.is_empty(), "nothing written");
}

/// R-CH1b on the listing. An outsider's challenge stays public when the claim
/// is privatized (168), so `GET /claims/:id/challenges` on the now private
/// claim must answer a non-member exactly as a random id does. While the claim
/// is public the challenge is listed (the positive control).
#[sqlx::test(migrations = "../../migrations")]
async fn listing_a_privatized_claims_challenges_is_no_existence_oracle(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let (third, _) = fixture::seed_agent_with_group(&w.pool, "chh-third").await;
    let (status, text) = post_as(
        &w,
        w.stranger,
        &["claims:write"],
        w.public,
        body_as(w.stranger),
    )
    .await;
    assert_eq!(status, 201, "{text}");

    let (status, text) = get_list_as(&w, third, w.public).await;
    assert_eq!(status, 200, "{text}");
    let listed: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(
        listed["total"], 1,
        "control: a public claim's challenge is listed: {listed}"
    );

    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(w.public)
        .execute(&w.pool)
        .await
        .expect("privatize the claim");
    let on_private = get_list_as(&w, third, w.public).await;
    let on_random = get_list_as(&w, third, Uuid::new_v4()).await;
    assert_eq!(
        on_private, on_random,
        "a privatized claim's challenges answer a non-member exactly as a random id does"
    );
}
