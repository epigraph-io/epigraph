//! The handlers `F-inline-claim-content-reads` carried in
//! `viewer_route_table_lint.rs::UNCOMPENSATED_INLINE_READS` now read through
//! the caller's `Viewer`, in BOTH directions.
//!
//! # What the register was
//!
//! Twelve `sqlx::query*` calls in seven route files selected `tier_a` claim
//! content inline, on the raw pool, with no `Viewer` spliced into the
//! statement. PR-14 deleted the post-pass they were once believed to sit
//! behind, so they were live disclosure rather than latent. Each converted
//! handler now calls a repo function carrying a `/* {VISIBILITY:…} */` marker.
//!
//! # The instrument
//!
//! Every arm here plants a STRANGER row (private to a group the viewer is not
//! in) and asserts it ABSENT, and plants the viewer's OWN group-private row and
//! asserts it PRESENT, on the same call. A file of "a stranger sees nothing"
//! assertions alone cannot tell a correct filter from a handler that returns
//! nothing at all.
//!
//! [`split_state`] is the same instrument `shard7_routes_scoped_read.rs` uses,
//! and this is another hand copy of its body (`F-SHARD6-A2` owns the
//! duplication). `AppState.db_pool` is a pool whose every connection is
//! `SET SESSION AUTHORIZATION epigraph_app`, and `AppState.scoped` is an
//! ordinary `ScopedPool`. So:
//!
//! * the OWNER-VISIBLE leg fails if a handler reads through `&state.db_pool`
//!   instead of `AppState::read_as`: the RLS policy on that unstamped session
//!   hides the viewer's own private row;
//! * the STRANGER-HIDDEN leg fails if the in-query predicate is missing or
//!   widened: the scoped pool is a superuser session, so only the spliced `$V`
//!   predicate can withhold the stranger's row.
//!
//! Handlers are invoked as plain `async fn`s with a `ViewerExtractor` built from
//! a resolved `Viewer`, the template the shard files established.

#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::State;
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::state::{ApiConfig, AppState};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    downgraded_pool, scoped_pool, seed_agent_with_group, seed_group_claim, seed_public_claim,
    set_claim_embedding,
};

// ── The instrument ──

/// An `AppState` whose `scoped` pool is stamped-but-superuser and whose raw
/// `db_pool` is filtered-but-unstamped. See the module doc.
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
         site to it is invisible and the owner-visible leg proves nothing"
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
    state
}

/// Resolved on the superuser pool; see `shard7_routes_scoped_read.rs::viewer_for`.
async fn viewer_for(pool: &PgPool, agent: Uuid) -> epigraph_db::visibility::Viewer {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
}

/// Merge `props` into a seeded claim's `properties`.
async fn set_properties(pool: &PgPool, claim: Uuid, props: serde_json::Value) {
    sqlx::query("UPDATE claims SET properties = properties || $2 WHERE id = $1")
        .bind(claim)
        .bind(props)
        .execute(pool)
        .await
        .expect("set properties");
}

/// A viewer, a stranger, and one claim of each tenancy: public, private to
/// the viewer's group, private to the stranger's group.
struct Plant {
    viewer_agent: Uuid,
    public: Uuid,
    mine: Uuid,
    theirs: Uuid,
}

async fn plant(pool: &PgPool, label: &str) -> Plant {
    let (viewer_agent, viewer_group) = seed_agent_with_group(pool, &format!("{label}-v")).await;
    let (stranger_agent, stranger_group) = seed_agent_with_group(pool, &format!("{label}-s")).await;
    let public = seed_public_claim(pool, viewer_agent, &format!("{label} public")).await;
    let mine = seed_group_claim(pool, viewer_agent, viewer_group, &format!("{label} mine")).await;
    let theirs = seed_group_claim(
        pool,
        stranger_agent,
        stranger_group,
        &format!("{label} theirs"),
    )
    .await;
    Plant {
        viewer_agent,
        public,
        mine,
        theirs,
    }
}

// ── routes/embeddings.rs ──

/// `POST /embeddings/neighborhood-density`: the count, the similarity stats and
/// the level/source-type histogram are all computed over the viewer's claims.
///
/// All three planted claims carry the EXACT vector the mock embedder produces
/// for the query, so each sits at distance 0 and only the tenancy predicate can
/// decide which are counted. Each carries a distinct `source_type`, so the
/// histogram names which rows were counted, not just how many.
#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_density_counts_only_what_the_viewer_can_read(pool: PgPool) {
    use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
    use std::sync::Arc;

    let p = plant(&pool, "density").await;
    let query = format!("density viewer probe {}", Uuid::new_v4());
    let provider = MockProvider::new(EmbeddingConfig::openai(1536));
    let vector = provider.generate(&query).await.expect("mock embed");
    let pgvec = format!(
        "[{}]",
        vector
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    for (claim, source) in [(p.public, "public"), (p.mine, "mine"), (p.theirs, "theirs")] {
        set_claim_embedding(&pool, claim, &pgvec).await;
        set_properties(
            &pool,
            claim,
            serde_json::json!({ "level": "2", "source_type": source }),
        )
        .await;
    }

    let viewer = viewer_for(&pool, p.viewer_agent).await;
    let svc: Arc<dyn EmbeddingService> = Arc::new(provider);
    let state = split_state(&pool).await.with_embedding_service(svc);

    let body = epigraph_api::routes::embeddings::neighborhood_density(
        ViewerExtractor(viewer),
        State(state),
        Json(
            epigraph_api::routes::embeddings::NeighborhoodDensityRequest {
                query,
                radius: Some(0.05),
                max_sample: Some(50),
            },
        ),
    )
    .await
    .expect("neighborhood_density")
    .0;

    assert_eq!(
        body.n_claims, 2,
        "the aggregate must count the public claim and the viewer's own private \
         claim, and not the stranger's. 3 means the predicate is missing; 1 means \
         the read ran on the unstamped raw pool. Got by_source_type {:?}",
        body.by_source_type
    );
    assert_eq!(
        body.by_source_type.get("public").copied(),
        Some(1),
        "the public claim must be in the breakdown: {:?}",
        body.by_source_type
    );
    assert_eq!(
        body.by_source_type.get("mine").copied(),
        Some(1),
        "the viewer's own private claim must be in the breakdown: {:?}",
        body.by_source_type
    );
    assert_eq!(
        body.by_source_type.get("theirs"),
        None,
        "the stranger's private claim must not shape the breakdown: {:?}",
        body.by_source_type
    );
    assert_eq!(body.by_level.get("2").copied(), Some(2));
}
