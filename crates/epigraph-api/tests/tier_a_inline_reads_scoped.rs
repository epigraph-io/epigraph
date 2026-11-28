#![cfg(feature = "db")]
//! Two route reads that used to run inline on the raw pool with no viewer now
//! read through viewer-spliced repo methods on the caller's stamped connection
//! (backlog 67c905a3). A third, `GET /api/v1/inflation-index/leaderboard`, had
//! its arms here until the political module was deleted (backlog bd13e0e0):
//!
//! | route | repo read |
//! |---|---|
//! | `GET /api/v1/conflicts/scan` (`high_conflict`) | `ConflictDensityRepository::high_conflict_claims` |
//! | `POST /api/v1/embeddings/neighborhood-density` | `ClaimRepository::{embedding_radius_density, embedding_radius_breakdown}` |
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
//! `#[sqlx::test]` hands every test a fresh database migrated from empty.

mod viewer_fixture;

use axum::extract::{Query, State};
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::conflicts::{scan_conflicts, ScanConflictsQuery};
use epigraph_api::routes::embeddings::{neighborhood_density, NeighborhoodDensityRequest};
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
