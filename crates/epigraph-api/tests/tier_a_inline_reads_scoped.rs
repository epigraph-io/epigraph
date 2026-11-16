#![cfg(feature = "db")]
//! Three route reads that used to run inline on the raw pool with no viewer now
//! read through viewer-spliced repo methods on the caller's stamped connection
//! (backlog 67c905a3):
//!
//! | route | repo read |
//! |---|---|
//! | `GET /api/v1/conflicts/scan` (`high_conflict`) | `ConflictDensityRepository::high_conflict_claims` |
//! | `POST /api/v1/embeddings/neighborhood-density` | `ClaimRepository::{embedding_radius_density, embedding_radius_breakdown}` |
//! | `GET /api/v1/inflation-index/leaderboard` | `PoliticalRepository::get_inflation_leaderboard` |
//!
//! # The instrument, and the two proofs each route gets
//!
//! [`split_state`] is the instrument `dense_routes_scoped_read.rs` documents at
//! length. `AppState.db_pool` is a pool downgraded to `epigraph_app`: row
//! security applies to it and nothing stamps it. `AppState.scoped` is an
//! ordinary `ScopedPool` on the test's SUPERUSER login, so on that arm only the
//! in-query `$V` predicate filters anything. Each route gets two arms:
//!
//! * **The member sees its own group-private row.** Reverting the handler to
//!   the raw pool fails this arm: the unstamped `epigraph_app` session has no
//!   group GUCs, so row security hides the member's own row. That is the
//!   failure the OLD code produces, since the old handlers read `&state.db_pool`.
//! * **A stranger does not see it, and every number it gets is computed
//!   without it.** Deleting the visibility markers from the repo method fails
//!   this arm: the stamped arm is a superuser, so nothing but the predicate can
//!   remove the row. Each such arm carries a CALIBRATION assertion on a public
//!   row, so an empty answer cannot pass it.
//!
//! The leaderboard, which no other suite reaches through the router, also gets
//! an HTTP arm through `create_router`: an agentless bearer gets 401, and the
//! member and the stranger each see what the direct arms say they should.
//!
//! `#[sqlx::test]` hands every test a fresh database migrated from empty.

mod viewer_fixture;

use axum::extract::{Query, State};
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::conflicts::{scan_conflicts, ScanConflictsQuery};
use epigraph_api::routes::embeddings::{neighborhood_density, NeighborhoodDensityRequest};
use epigraph_api::routes::political::{inflation_leaderboard, InflationIndexParams};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use viewer_fixture::{
    downgraded_pool, scoped_pool, seed_agent_with_group, seed_group_claim, seed_public_claim,
    set_claim_embedding,
};

// ── The instrument ──

/// `scoped` is stamped but superuser, and `db_pool` is filtered but unstamped.
/// Copied from `dense_routes_scoped_read.rs::split_state`, whose doc explains
/// why the asymmetry is the instrument and why each calibration is needed.
async fn split_state(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let scoped = scoped_pool(pool).await;

    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);

    let raw_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&state.db_pool)
        .await
        .expect("current_user on the raw pool");
    assert_eq!(
        raw_user, "epigraph_app",
        "CALIBRATION: AppState.db_pool must be DOWNGRADED, or reverting a converted \
         site to it is invisible"
    );
    let raw_is_privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&state.db_pool)
    .await
    .expect("role privileges on the raw pool");
    assert!(
        !raw_is_privileged,
        "CALIBRATION: the raw pool's role must be subject to RLS"
    );
    let scoped_is_privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(state.scoped.as_ref().expect("scoped").inner())
    .await
    .expect("role privileges on the scoped pool");
    assert!(
        scoped_is_privileged,
        "CALIBRATION: the scoped pool must bypass RLS, so that only the in-query \
         predicate can hide a row from a stranger"
    );
    state
}

async fn viewer_for(pool: &PgPool, agent: Uuid) -> epigraph_db::visibility::Viewer {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
}

/// A member with its own group, a stranger with ITS own group, and the
/// member's group-private claim. The stranger holds a group so its viewer
/// binds a real `$V`, as a production caller's does.
struct Plant {
    member: Uuid,
    stranger: Uuid,
    private: Uuid,
    public: Uuid,
    public_author: Uuid,
}

async fn plant(pool: &PgPool, label: &str) -> Plant {
    let (member, group) = seed_agent_with_group(pool, &format!("{label}-member")).await;
    let (stranger, _) = seed_agent_with_group(pool, &format!("{label}-stranger")).await;
    let (public_author, _) = seed_agent_with_group(pool, &format!("{label}-author")).await;
    let private = seed_group_claim(pool, member, group, &format!("{label} private claim")).await;
    let public = seed_public_claim(pool, public_author, &format!("{label} public claim")).await;
    Plant {
        member,
        stranger,
        private,
        public,
        public_author,
    }
}

// ── routes/conflicts.rs::scan_conflicts ──

async fn seed_frame(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses) VALUES ($1, $2, ARRAY['h0','h1']::text[])",
    )
    .bind(id)
    .bind(format!("tier-a-scan-frame-{id}"))
    .execute(pool)
    .await
    .expect("seed frame");
    id
}

/// A live BBA on `claim` in `frame` carrying `conflict_k`. `mass_functions` is
/// one of migration 070's inheritors, so the row takes its claim's tenancy.
async fn seed_conflicted_bba(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, k: f64) {
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, conflict_k) \
         VALUES ($1, $2, $3, '{\"0\": 0.6, \"0,1\": 0.4}'::jsonb, $4)",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(k)
    .execute(pool)
    .await
    .expect("seed conflicted bba");
}

async fn scan_ids(state: &AppState, pool: &PgPool, agent: Uuid) -> Vec<(Uuid, String)> {
    let Json(resp) = scan_conflicts(
        ViewerExtractor(viewer_for(pool, agent).await),
        State(state.clone()),
        Query(ScanConflictsQuery {
            min_k: Some(0.3),
            frame_id: None,
            limit: Some(100),
        }),
    )
    .await
    .expect("scan_conflicts");
    resp.high_conflict
        .iter()
        .map(|v| {
            (
                v["claim_id"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .expect("claim_id"),
                v["content"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn conflict_scan_lists_the_members_own_private_claim(pool: PgPool) {
    let p = plant(&pool, "scan-own").await;
    let frame = seed_frame(&pool).await;
    seed_conflicted_bba(&pool, p.private, frame, p.member, 0.9).await;
    let state = split_state(&pool).await;

    let rows = scan_ids(&state, &pool, p.member).await;
    assert!(
        rows.iter()
            .any(|(id, content)| *id == p.private && content == "scan-own private claim"),
        "the member's own group-private high-conflict claim must be listed with its \
         content; the raw pool's row security hides it: {rows:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn conflict_scan_hides_a_strangers_private_claim_and_its_content(pool: PgPool) {
    let p = plant(&pool, "scan-hide").await;
    let frame = seed_frame(&pool).await;
    seed_conflicted_bba(&pool, p.private, frame, p.member, 0.9).await;
    seed_conflicted_bba(&pool, p.public, frame, p.public_author, 0.8).await;
    let state = split_state(&pool).await;

    let rows = scan_ids(&state, &pool, p.stranger).await;
    assert!(
        rows.iter().any(|(id, _)| *id == p.public),
        "CALIBRATION: the public high-conflict claim must be listed, or an empty scan \
         passes the assertion below: {rows:?}"
    );
    assert!(
        rows.iter()
            .all(|(id, content)| *id != p.private && !content.contains("scan-hide private")),
        "a claim the stranger cannot read must not be listed, nor its content returned: \
         {rows:?}"
    );
}

// ── routes/embeddings.rs::neighborhood_density ──

fn pgvec(v: &[f32]) -> String {
    format!(
        "[{}]",
        v.iter().map(f32::to_string).collect::<Vec<_>>().join(",")
    )
}

const DENSITY_QUERY: &str = "tier-a density probe";

/// Embeds the public and the private claim at exactly the query vector, so
/// both sit at distance zero, and gives them different `level`s so the
/// breakdown can tell them apart. Returns the state with the mock embedder.
async fn density_state(pool: &PgPool, p: &Plant) -> AppState {
    let embedder: Arc<dyn EmbeddingService> =
        Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
    let vector = pgvec(
        &embedder
            .generate(DENSITY_QUERY)
            .await
            .expect("mock embedding"),
    );
    for (claim, level) in [(p.public, "2"), (p.private, "3")] {
        set_claim_embedding(pool, claim, &vector).await;
        sqlx::query(
            "UPDATE claims SET properties = jsonb_build_object('level', $2::text) WHERE id = $1",
        )
        .bind(claim)
        .bind(level)
        .execute(pool)
        .await
        .expect("set level");
    }
    split_state(pool).await.with_embedding_service(embedder)
}

async fn density(
    state: &AppState,
    pool: &PgPool,
    agent: Uuid,
) -> epigraph_api::routes::embeddings::NeighborhoodDensityResponse {
    let Json(resp) = neighborhood_density(
        ViewerExtractor(viewer_for(pool, agent).await),
        State(state.clone()),
        Json(NeighborhoodDensityRequest {
            query: DENSITY_QUERY.to_string(),
            radius: Some(0.1),
            max_sample: Some(50),
        }),
    )
    .await
    .expect("neighborhood_density");
    resp
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_density_counts_the_members_own_private_claim(pool: PgPool) {
    let p = plant(&pool, "density-own").await;
    let state = density_state(&pool, &p).await;

    let resp = density(&state, &pool, p.member).await;
    assert_eq!(
        resp.n_claims, 2,
        "the aggregate must count the public claim AND the member's own private one; \
         the raw pool's row security drops the private one"
    );
    assert_eq!(
        resp.by_level.get("3").copied(),
        Some(1),
        "the breakdown must include the member's own private claim: {:?}",
        resp.by_level
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_density_is_computed_without_a_strangers_private_claim(pool: PgPool) {
    let p = plant(&pool, "density-hide").await;
    let state = density_state(&pool, &p).await;

    let resp = density(&state, &pool, p.stranger).await;
    assert_eq!(
        resp.by_level.get("2").copied(),
        Some(1),
        "CALIBRATION: the public claim must be in the breakdown: {:?}",
        resp.by_level
    );
    assert_eq!(
        resp.n_claims, 1,
        "the aggregate must not count a claim the stranger cannot read"
    );
    assert_eq!(
        resp.by_level.get("3"),
        None,
        "the breakdown must not describe a claim the stranger cannot read: {:?}",
        resp.by_level
    );
}

// ── routes/political.rs::inflation_leaderboard ──

async fn set_inflation(pool: &PgPool, claim: Uuid, factor: f64) {
    sqlx::query(
        "UPDATE claims SET properties = jsonb_build_object('inflation_factor', $2::float8) \
         WHERE id = $1",
    )
    .bind(claim)
    .bind(factor)
    .execute(pool)
    .await
    .expect("set inflation_factor");
}

/// Two inflation claims per agent clear the route's `HAVING COUNT(*) >= 2`.
/// The member's are group-private; the public author's are public.
async fn leaderboard_plant(pool: &PgPool, label: &str) -> (Plant, AppState) {
    let p = plant(pool, label).await;
    let group: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(p.private)
        .fetch_one(pool)
        .await
        .expect("private claim's group");
    let second_private =
        seed_group_claim(pool, p.member, group, &format!("{label} private claim 2")).await;
    let second_public =
        seed_public_claim(pool, p.public_author, &format!("{label} public claim 2")).await;
    for c in [p.private, second_private] {
        set_inflation(pool, c, 3.0).await;
    }
    for c in [p.public, second_public] {
        set_inflation(pool, c, 1.5).await;
    }
    let state = split_state(pool).await;
    (p, state)
}

async fn leaderboard(state: &AppState, pool: &PgPool, agent: Uuid) -> Vec<(Uuid, i64)> {
    let Json(items) = inflation_leaderboard(
        ViewerExtractor(viewer_for(pool, agent).await),
        State(state.clone()),
        Query(InflationIndexParams { topic: None }),
    )
    .await
    .expect("inflation_leaderboard");
    items
        .iter()
        .map(|v| {
            (
                v["agent_id"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .expect("agent_id"),
                v["claim_count"].as_i64().expect("claim_count"),
            )
        })
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn inflation_leaderboard_ranks_the_member_on_its_own_private_claims(pool: PgPool) {
    let (p, state) = leaderboard_plant(&pool, "board-own").await;

    let rows = leaderboard(&state, &pool, p.member).await;
    assert!(
        rows.contains(&(p.member, 2)),
        "the member must be ranked on its own two private claims; the raw pool's row \
         security hides them: {rows:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn inflation_leaderboard_does_not_rank_on_a_strangers_private_claims(pool: PgPool) {
    let (p, state) = leaderboard_plant(&pool, "board-hide").await;

    let rows = leaderboard(&state, &pool, p.stranger).await;
    assert!(
        rows.contains(&(p.public_author, 2)),
        "CALIBRATION: the public author must be ranked on its two public claims: {rows:?}"
    );
    assert!(
        rows.iter().all(|(agent, _)| *agent != p.member),
        "an agent whose only inflation claims the stranger cannot read must not be \
         ranked: {rows:?}"
    );
}

// ── The leaderboard through the router ──
//
// The arms above call the handler directly, so they cannot see what the live
// router does before it: the bearer middleware, and the `ViewerExtractor` this
// change added. This arm sends real HTTP through `create_router` on the same
// split state. On the old handler (no extractor, raw pool) its first assertion
// fails, because an agentless bearer got 200, and so does its member
// assertion, because the raw pool's row security hides the member's own rows.

/// A bearer for the in-process app, signed with the dev secret
/// `ApiConfig::default()` verifies. `agent: None` is a token that
/// authenticates but names no agent, which has no `Viewer`.
fn bearer(agent: Option<Uuid>) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".to_string()],
            "agent",
            None,
            agent,
            chrono::Duration::minutes(60),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("test JWT issued");
    token
}

async fn serve(state: AppState) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let app = epigraph_api::routes::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .expect("serve");
    });
    (addr, tx)
}

async fn leaderboard_http(
    client: &reqwest::Client,
    addr: std::net::SocketAddr,
    token: &str,
) -> (u16, serde_json::Value) {
    let resp = client
        .get(format!("http://{addr}/api/v1/inflation-index/leaderboard"))
        .bearer_auth(token)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

fn ranked_agents(body: &serde_json::Value) -> Vec<Uuid> {
    body.as_array()
        .unwrap_or_else(|| panic!("leaderboard body must be an array: {body}"))
        .iter()
        .map(|v| {
            v["agent_id"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .expect("agent_id")
        })
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn inflation_leaderboard_over_http_needs_an_agent_and_reads_as_the_caller(pool: PgPool) {
    let (p, state) = leaderboard_plant(&pool, "board-http").await;
    let (addr, _shutdown) = serve(state).await;
    let client = reqwest::Client::new();

    let (status, body) = leaderboard_http(&client, addr, &bearer(None)).await;
    assert_eq!(
        status, 401,
        "a bearer that names no agent has no viewer to read as: {body}"
    );

    let (status, body) = leaderboard_http(&client, addr, &bearer(Some(p.stranger))).await;
    assert_eq!(status, 200, "stranger: {body}");
    let stranger_sees = ranked_agents(&body);
    assert!(
        stranger_sees.contains(&p.public_author),
        "CALIBRATION: the public author must be ranked for the stranger: {body}"
    );
    assert!(
        !stranger_sees.contains(&p.member),
        "the stranger must not see an agent ranked only on claims it cannot read: {body}"
    );

    let (status, body) = leaderboard_http(&client, addr, &bearer(Some(p.member))).await;
    assert_eq!(status, 200, "member: {body}");
    assert!(
        ranked_agents(&body).contains(&p.member),
        "the member must be ranked on its own private claims over HTTP too: {body}"
    );
}
