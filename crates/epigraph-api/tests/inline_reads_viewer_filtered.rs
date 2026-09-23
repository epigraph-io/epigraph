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

/// Force a row's tenancy columns after insert, and check they held.
///
/// Derived rows (`mass_functions`, `edges`) inherit their tenancy from the
/// parent claim through migration 070's triggers. An arm that needs a derived
/// row whose tenancy DIFFERS from its parent's — so that exactly one predicate
/// can withhold it — has to force it afterwards. `co_owner_group_id` is
/// cleared on `edges` so the single-owner arm of the edge predicate applies.
async fn force_tenancy(pool: &PgPool, table: &str, id: Uuid, visibility: &str, group: Uuid) {
    // `table` is a test-local literal at every call site, never caller data.
    let extra = if table == "edges" {
        ", co_owner_group_id = NULL"
    } else {
        ""
    };
    let sql =
        format!("UPDATE {table} SET visibility = $2, owner_group_id = $3{extra} WHERE id = $1");
    sqlx::query(&sql)
        .bind(id)
        .bind(visibility)
        .bind(group)
        .execute(pool)
        .await
        .expect("force tenancy");
    let (v, g): (String, Uuid) = sqlx::query_as(&format!(
        "SELECT visibility::text, owner_group_id FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read back tenancy");
    assert_eq!(
        (v.as_str(), g),
        (visibility, group),
        "CALIBRATION: the {table} row did not keep the tenancy it was given"
    );
}

/// A viewer, a stranger, and one claim of each tenancy: public, private to
/// the viewer's group, private to the stranger's group.
struct Plant {
    viewer_agent: Uuid,
    viewer_group: Uuid,
    stranger_agent: Uuid,
    stranger_group: Uuid,
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
        viewer_group,
        stranger_agent,
        stranger_group,
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

// ── routes/conflicts.rs ──

/// A public frame, owned by the world group.
async fn seed_public_frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, visibility, owner_group_id) \
         VALUES ($1, ARRAY['supported','contradicted'], 'public', \
                 (SELECT id FROM groups WHERE kind = 'world' LIMIT 1)) \
         RETURNING id",
    )
    .bind(format!("inline-reads-frame-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

/// A BBA on `(claim, frame)` from `agent` with conflict coefficient `k`,
/// forced to `(visibility, group)`.
async fn seed_bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Uuid,
    k: f64,
    visibility: &str,
    group: Uuid,
) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, conflict_k) \
         VALUES ($1, $2, $3, '{}'::jsonb, $4) RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(k)
    .fetch_one(pool)
    .await
    .expect("seed mass function");
    force_tenancy(pool, "mass_functions", id, visibility, group).await;
    id
}

/// A `CONTRADICTS` edge `source -> target`, forced to `(visibility, group)`.
async fn seed_contradicts(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    visibility: &str,
    group: Uuid,
) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'CONTRADICTS') RETURNING id",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("seed CONTRADICTS edge");
    force_tenancy(pool, "edges", id, visibility, group).await;
    id
}

/// The conflict fixture: one public frame, and four claims with a
/// high-conflict BBA each.
///
/// * `public` — public claim, public BBA. Visible.
/// * `mine` — the viewer's private claim, BBA private to the viewer's group.
///   Visible only on a viewer-stamped connection.
/// * `theirs` — the stranger's private claim, whose BBA is forced PUBLIC, so
///   only the `claims` predicate can withhold it.
/// * `public_with_private_bba` — a public claim whose only BBA is private to
///   the stranger's group, so only the `mass_functions` predicate can withhold
///   it.
struct ConflictPlant {
    p: Plant,
    frame: Uuid,
    public_with_private_bba: Uuid,
}

async fn plant_conflicts(pool: &PgPool, label: &str) -> ConflictPlant {
    let p = plant(pool, label).await;
    let world: Uuid = sqlx::query_scalar("SELECT id FROM groups WHERE kind = 'world' LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("world group");
    let frame = seed_public_frame(pool).await;
    let public_with_private_bba = seed_public_claim(
        pool,
        p.stranger_agent,
        &format!("{label} public/private-bba"),
    )
    .await;

    seed_bba(pool, p.public, frame, p.viewer_agent, 0.9, "public", world).await;
    seed_bba(
        pool,
        p.mine,
        frame,
        p.viewer_agent,
        0.9,
        "group",
        p.viewer_group,
    )
    .await;
    seed_bba(
        pool,
        p.theirs,
        frame,
        p.stranger_agent,
        0.9,
        "public",
        world,
    )
    .await;
    seed_bba(
        pool,
        public_with_private_bba,
        frame,
        p.stranger_agent,
        0.9,
        "group",
        p.stranger_group,
    )
    .await;
    ConflictPlant {
        p,
        frame,
        public_with_private_bba,
    }
}

/// `GET /conflicts/scan`'s high-conflict list returns claim CONTENT, so it is
/// the sharpest of the register's sites.
#[sqlx::test(migrations = "../../migrations")]
async fn scan_conflicts_lists_only_claims_and_bbas_the_viewer_can_read(pool: PgPool) {
    let cp = plant_conflicts(&pool, "scan").await;
    let viewer = viewer_for(&pool, cp.p.viewer_agent).await;
    let state = split_state(&pool).await;

    let body = epigraph_api::routes::conflicts::scan_conflicts(
        ViewerExtractor(viewer),
        State(state),
        axum::extract::Query(epigraph_api::routes::conflicts::ScanConflictsQuery {
            min_k: Some(0.5),
            frame_id: None,
            limit: Some(100),
        }),
    )
    .await
    .expect("scan_conflicts")
    .0;

    let ids: Vec<Uuid> = body
        .high_conflict
        .iter()
        .map(|r| {
            r["claim_id"]
                .as_str()
                .expect("claim_id")
                .parse()
                .expect("uuid")
        })
        .collect();
    assert!(
        ids.contains(&cp.p.public) && ids.contains(&cp.p.mine),
        "the public claim and the viewer's own private claim must both be listed; \
         the second is absent when the read runs on the unstamped raw pool. Got {ids:?}"
    );
    assert!(
        !ids.contains(&cp.p.theirs),
        "the stranger's private claim must not be listed. Its BBA is public, so \
         only the `claims` predicate can withhold it. Got {ids:?}"
    );
    assert!(
        !ids.contains(&cp.public_with_private_bba),
        "a public claim whose only high-conflict BBA is private to another group \
         must not be listed: only the `mass_functions` predicate can withhold it. \
         Got {ids:?}"
    );
    assert_eq!(ids.len(), 2, "exactly two rows: got {ids:?}");
    let contents: Vec<&str> = body
        .high_conflict
        .iter()
        .filter_map(|r| r["content"].as_str())
        .collect();
    assert!(
        !contents.iter().any(|c| c.ends_with("theirs")),
        "the stranger's content must not be served: {contents:?}"
    );
}

/// The silence-alarm densities are counts, not content, and the register never
/// counted them. Every one of the three numbers is asserted exactly, on the
/// same plant plus one `CONTRADICTS` edge per case.
///
/// Driven through the repo function on a `read_as` connection, the one both
/// `scan_conflicts` and `silence_check` call: an alarm fires only for a frame
/// with twenty or more claims, so a handler-level arm would assert over a
/// filtered-away list and prove nothing about the counts.
#[sqlx::test(migrations = "../../migrations")]
async fn frame_conflict_densities_count_only_what_the_viewer_can_read(pool: PgPool) {
    let cp = plant_conflicts(&pool, "density").await;
    let world: Uuid = sqlx::query_scalar("SELECT id FROM groups WHERE kind = 'world' LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("world group");
    let target = seed_public_claim(&pool, cp.p.viewer_agent, "density target").await;

    // Counted: public edge from the public claim, and the viewer's own edge
    // from the viewer's own claim.
    seed_contradicts(&pool, cp.p.public, target, "public", world).await;
    seed_contradicts(&pool, cp.p.mine, target, "group", cp.p.viewer_group).await;
    // Not counted, each withheld by exactly one predicate: the source claim
    // (`claims`), the source's only BBA (`mass_functions`), the edge itself
    // (`edges`).
    seed_contradicts(&pool, cp.p.theirs, target, "public", world).await;
    seed_contradicts(&pool, cp.public_with_private_bba, target, "public", world).await;
    seed_contradicts(&pool, cp.p.public, target, "group", cp.p.stranger_group).await;

    let viewer = viewer_for(&pool, cp.p.viewer_agent).await;
    let state = split_state(&pool).await;
    let mut read = state.read_as(&viewer).await.expect("read_as");
    let rows = epigraph_db::MassFunctionRepository::frame_conflict_densities(&mut *read, &viewer)
        .await
        .expect("frame_conflict_densities");
    let row = rows
        .iter()
        .find(|r| r.frame_id == cp.frame)
        .expect("the public frame must be listed");

    assert_eq!(
        row.total_claims, 2,
        "claims with a BBA in the frame: the public one and the viewer's own. \
         4 means neither the claim nor the BBA predicate is applied"
    );
    assert_eq!(
        row.contradicts_edges, 2,
        "CONTRADICTS edges leaving those claims: 5 are planted, 3 of them \
         unreadable, each through a different relation"
    );
    assert_eq!(
        row.distinct_sources, 1,
        "only the viewer contributed a readable BBA; the stranger's two are \
         withheld by the claim and the BBA predicate respectively"
    );
}

// ── routes/policies.rs ──

/// Give a seeded claim a label set (the fixture's seeders write none).
async fn set_labels(pool: &PgPool, claim: Uuid, labels: &[&str]) {
    let owned: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query("UPDATE claims SET labels = $2 WHERE id = $1")
        .bind(claim)
        .bind(&owned)
        .execute(pool)
        .await
        .expect("set labels");
}

/// `GET /policies/network` returns each policy's `properties` (host, port,
/// protocol), so a policy private to another group must not be listed.
#[sqlx::test(migrations = "../../migrations")]
async fn list_network_policies_lists_only_policies_the_viewer_can_read(pool: PgPool) {
    let p = plant(&pool, "policy").await;
    for (claim, host) in [
        (p.public, "public.example"),
        (p.mine, "mine.example"),
        (p.theirs, "theirs.example"),
    ] {
        set_labels(&pool, claim, &["policy", "policy:active", "policy:network"]).await;
        set_properties(
            &pool,
            claim,
            serde_json::json!({ "host": host, "port": 443 }),
        )
        .await;
    }

    let viewer = viewer_for(&pool, p.viewer_agent).await;
    let state = split_state(&pool).await;
    let body = epigraph_api::routes::policies::list_network_policies(
        ViewerExtractor(viewer),
        State(state),
        axum::extract::Query(epigraph_api::routes::policies::ListPoliciesQuery { min_truth: 0.5 }),
    )
    .await
    .expect("list_network_policies")
    .0;

    let hosts: Vec<&str> = body["policies"]
        .as_array()
        .expect("policies array")
        .iter()
        .filter_map(|p| p["host"].as_str())
        .collect();
    assert!(
        hosts.contains(&"public.example") && hosts.contains(&"mine.example"),
        "the public policy and the viewer's own private policy must both be listed; \
         the second is absent on the unstamped raw pool. Got {hosts:?}"
    );
    assert!(
        !hosts.contains(&"theirs.example"),
        "a policy private to another group must not be listed. Got {hosts:?}"
    );
    assert_eq!(hosts.len(), 2, "exactly two policies: got {hosts:?}");
}

/// `GET /policy-challenges/:id`: the viewer's own private challenge is served,
/// another group's is a 404 — the same answer as a challenge that does not
/// exist.
#[sqlx::test(migrations = "../../migrations")]
async fn get_challenge_serves_own_private_challenge_and_404s_a_strangers(pool: PgPool) {
    let p = plant(&pool, "challenge").await;
    for (claim, host) in [(p.mine, "mine.example"), (p.theirs, "theirs.example")] {
        set_labels(&pool, claim, &["policy", "policy:challenge"]).await;
        set_properties(
            &pool,
            claim,
            serde_json::json!({ "host": host, "port": 22, "status": "pending" }),
        )
        .await;
    }
    let state = split_state(&pool).await;

    let mine = epigraph_api::routes::policies::get_challenge(
        ViewerExtractor(viewer_for(&pool, p.viewer_agent).await),
        State(state.clone()),
        axum::extract::Path(p.mine),
    )
    .await;
    let mine = mine
        .expect("the viewer's own private challenge must be served")
        .0;
    assert_eq!(mine["host"], "mine.example");

    let theirs = epigraph_api::routes::policies::get_challenge(
        ViewerExtractor(viewer_for(&pool, p.viewer_agent).await),
        State(state.clone()),
        axum::extract::Path(p.theirs),
    )
    .await;
    assert!(
        matches!(theirs, Err(epigraph_api::errors::ApiError::NotFound { .. })),
        "a challenge private to another group must be a 404, not its properties"
    );

    let missing = epigraph_api::routes::policies::get_challenge(
        ViewerExtractor(viewer_for(&pool, p.viewer_agent).await),
        State(state),
        axum::extract::Path(Uuid::new_v4()),
    )
    .await;
    assert!(
        matches!(
            missing,
            Err(epigraph_api::errors::ApiError::NotFound { .. })
        ),
        "CALIBRATION: an absent id is a 404 too, so the two cases are indistinguishable"
    );
}

// ── routes/political.rs ──

/// `GET /inflation-index/leaderboard`: each agent's mean and count are
/// computed over the claims the caller can read.
///
/// All three scored claims are AUTHORED by the same agent, so they land in one
/// leaderboard row and its numbers say exactly which were counted: the
/// readable pair averages 3.0 over 2, all three 6.0 over 3. On the unstamped
/// raw pool only the public claim is readable, the `HAVING COUNT(*) >= 2`
/// threshold drops the agent, and the row is missing.
#[sqlx::test(migrations = "../../migrations")]
async fn inflation_leaderboard_aggregates_only_claims_the_viewer_can_read(pool: PgPool) {
    let p = plant(&pool, "inflation").await;
    let authored_by_viewer_owned_by_stranger = seed_group_claim(
        &pool,
        p.viewer_agent,
        p.stranger_group,
        "inflation authored-by-viewer, owned-by-stranger",
    )
    .await;
    for (claim, factor) in [
        (p.public, 2.0),
        (p.mine, 4.0),
        (authored_by_viewer_owned_by_stranger, 12.0),
    ] {
        set_properties(
            &pool,
            claim,
            serde_json::json!({ "inflation_factor": factor }),
        )
        .await;
    }

    let viewer = viewer_for(&pool, p.viewer_agent).await;
    let state = split_state(&pool).await;
    let rows = epigraph_api::routes::political::inflation_leaderboard(
        ViewerExtractor(viewer),
        State(state),
        axum::extract::Query(epigraph_api::routes::political::InflationIndexParams { topic: None }),
    )
    .await
    .expect("inflation_leaderboard")
    .0;

    let row = rows
        .iter()
        .find(|r| r["agent_id"].as_str() == Some(p.viewer_agent.to_string().as_str()))
        .unwrap_or_else(|| {
            panic!(
                "the author must be on the board with its two readable claims; it is \
                 missing when the read runs on the unstamped raw pool. Got {rows:?}"
            )
        });
    assert_eq!(
        row["claim_count"].as_i64(),
        Some(2),
        "the claim owned by another group must not be counted: {row}"
    );
    let mean = row["mean_inflation_index"].as_f64().expect("mean");
    assert!(
        (mean - 3.0).abs() < 1e-9,
        "the mean must be over the two readable claims (3.0), not all three (6.0): {row}"
    );
}

// ── routes/search.rs ──

/// The diverse search path's full-claim fetch, `semantic_search_selected`.
///
/// The handler cannot hand this statement a stranger's id today: its id set
/// comes out of the viewer-filtered `claims_in_themes_at_dim_since`. That
/// derivation was the only thing standing between it and a leak, which is why
/// the register kept it. So the arm drives the repo function directly with an
/// id set that DOES include a stranger's claim, which is the case the predicate
/// now covers if the derivation ever changes.
#[sqlx::test(migrations = "../../migrations")]
async fn semantic_search_selected_drops_ids_the_viewer_cannot_read(pool: PgPool) {
    let p = plant(&pool, "selected").await;
    let pgvec = format!(
        "[{}]",
        (0..1536)
            .map(|i| if i == 0 { "1" } else { "0" })
            .collect::<Vec<_>>()
            .join(",")
    );
    for claim in [p.public, p.mine, p.theirs] {
        set_claim_embedding(&pool, claim, &pgvec).await;
    }

    // Cluster memberships, which carry their own tenancy: the PUBLIC claim's
    // membership is private to the stranger's group, so its cluster must not
    // be named; the viewer's own claim's membership is the viewer's own.
    let run_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded, algo) \
         VALUES ($1, 2, FALSE, 'louvain')",
    )
    .bind(run_id)
    .execute(&pool)
    .await
    .expect("seed run");
    let mut cluster_of = std::collections::HashMap::new();
    for (claim, visibility, group) in [
        (p.public, "group", p.stranger_group),
        (p.mine, "group", p.viewer_group),
    ] {
        let cluster = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO graph_clusters \
             (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded) \
             VALUES ($1, $2, 'probe', 1, NULL, 'claim', NULL, FALSE)",
        )
        .bind(cluster)
        .bind(run_id)
        .execute(&pool)
        .await
        .expect("seed cluster");
        sqlx::query(
            "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(claim)
        .bind(cluster)
        .bind(run_id)
        .execute(&pool)
        .await
        .expect("seed membership");
        sqlx::query(
            "UPDATE claim_cluster_membership SET visibility = $3, owner_group_id = $4 \
             WHERE claim_id = $1 AND run_id = $2",
        )
        .bind(claim)
        .bind(run_id)
        .bind(visibility)
        .bind(group)
        .execute(&pool)
        .await
        .expect("force membership tenancy");
        cluster_of.insert(claim, cluster);
    }

    let viewer = viewer_for(&pool, p.viewer_agent).await;
    let state = split_state(&pool).await;
    let mut read = state.read_as(&viewer).await.expect("read_as");
    let rows = epigraph_db::ClaimRepository::semantic_search_selected(
        &mut *read,
        &viewer,
        "embedding",
        &pgvec,
        &[p.public, p.mine, p.theirs],
    )
    .await
    .expect("semantic_search_selected");
    let ids: Vec<Uuid> = rows.iter().map(|r| r.claim_id).collect();

    assert!(
        ids.contains(&p.public) && ids.contains(&p.mine),
        "the public and the viewer's own private claim must be returned: {ids:?}"
    );
    assert!(
        !ids.contains(&p.theirs),
        "a stranger's private claim must be dropped even when the caller names \
         its id: {ids:?}"
    );
    assert_eq!(ids.len(), 2, "{ids:?}");
    let mine = rows.iter().find(|r| r.claim_id == p.mine).expect("mine");
    assert!(
        (mine.similarity - 1.0).abs() < 1e-6,
        "CALIBRATION: an identical vector has similarity 1.0, got {}",
        mine.similarity
    );
    assert_eq!(
        mine.cluster_id,
        cluster_of.get(&p.mine).copied(),
        "the viewer's own cluster membership must name its cluster"
    );
    let public = rows
        .iter()
        .find(|r| r.claim_id == p.public)
        .expect("public");
    assert_eq!(
        public.cluster_id, None,
        "a membership row private to another group must not name the public \
         claim's cluster"
    );
}

// ── routes/workflows.rs ──

/// Label `claim` a flat workflow whose JSON content carries `goal`.
async fn make_flat_workflow(pool: &PgPool, claim: Uuid, goal: &str) {
    set_labels(pool, claim, &["workflow"]).await;
    sqlx::query("UPDATE claims SET content = $2 WHERE id = $1")
        .bind(claim)
        .bind(serde_json::json!({ "goal": goal }).to_string())
        .execute(pool)
        .await
        .expect("set workflow content");
}

/// `GET /workflows/:id`, flat path: the viewer's own private workflow is
/// served, another group's is a 404 like a missing id.
#[sqlx::test(migrations = "../../migrations")]
async fn get_workflow_serves_own_private_flat_workflow_and_404s_a_strangers(pool: PgPool) {
    let p = plant(&pool, "wf-get").await;
    make_flat_workflow(&pool, p.mine, "mine goal").await;
    make_flat_workflow(&pool, p.theirs, "theirs goal").await;
    let state = split_state(&pool).await;

    let served = epigraph_api::routes::workflows::get_workflow(
        ViewerExtractor(viewer_for(&pool, p.viewer_agent).await),
        State(state.clone()),
        axum::extract::Path(p.mine),
    )
    .await
    .expect("the viewer's own private workflow must be served")
    .0;
    assert_eq!(served["content"]["goal"], "mine goal");

    for (id, what) in [
        (p.theirs, "a workflow private to another group"),
        (Uuid::new_v4(), "CALIBRATION: an absent id"),
    ] {
        let got = epigraph_api::routes::workflows::get_workflow(
            ViewerExtractor(viewer_for(&pool, p.viewer_agent).await),
            State(state.clone()),
            axum::extract::Path(id),
        )
        .await;
        assert!(
            matches!(got, Err(epigraph_api::errors::ApiError::NotFound { .. })),
            "{what} must be a 404"
        );
    }
}

/// `POST /workflows/:id/outcome`: the existence gate reads through the viewer.
///
/// A stranger's private workflow is a 404 and is NOT written — its truth value
/// and counters are asserted unchanged on the superuser pool. The viewer's own
/// private workflow passes the gate (the handler reads its truth value back as
/// `before_truth`).
#[sqlx::test(migrations = "../../migrations")]
async fn report_outcome_gates_on_a_workflow_the_viewer_can_read(pool: PgPool) {
    let p = plant(&pool, "wf-outcome").await;
    make_flat_workflow(&pool, p.mine, "mine goal").await;
    make_flat_workflow(&pool, p.theirs, "theirs goal").await;
    let state = split_state(&pool).await;
    let request = || epigraph_api::routes::workflows::ReportOutcomeRequest {
        success: true,
        outcome_details: "probe".to_string(),
        quality: Some(1.0),
        step_executions: None,
        goal_text: None,
    };

    let refused = epigraph_api::routes::workflows::report_outcome(
        ViewerExtractor(viewer_for(&pool, p.viewer_agent).await),
        State(state.clone()),
        axum::extract::Path(p.theirs),
        Json(request()),
    )
    .await;
    assert!(
        matches!(
            refused,
            Err(epigraph_api::errors::ApiError::NotFound { .. })
        ),
        "an outcome against a workflow private to another group must be a 404"
    );
    let (truth, props): (f64, serde_json::Value) =
        sqlx::query_as("SELECT truth_value, properties FROM claims WHERE id = $1")
            .bind(p.theirs)
            .fetch_one(&pool)
            .await
            .expect("read the stranger's workflow back");
    assert!(
        (truth - 0.8).abs() < 1e-9 && props.get("use_count").is_none(),
        "the refused report must not have written: truth {truth}, properties {props}"
    );

    let served = epigraph_api::routes::workflows::report_outcome(
        ViewerExtractor(viewer_for(&pool, p.viewer_agent).await),
        State(state),
        axum::extract::Path(p.mine),
        Json(request()),
    )
    .await
    .expect(
        "the viewer's own private workflow must pass the gate; it 404s when the \
         gate runs on the unstamped raw pool",
    )
    .0;
    assert_eq!(served["workflow_id"], p.mine.to_string());
    assert_eq!(
        served["before_truth"].as_f64(),
        Some(0.8),
        "before_truth comes from the gate's own read of the private row"
    );
}

/// `POST /workflows/hierarchical/:id/outcome` resolves each reported
/// `step_index` against the steps the CALLER can read, in plan order — the same
/// list `find_workflow_hierarchical` gave it.
///
/// Three steps in plan order: public, the stranger's private step (its
/// `executes` edge forced PUBLIC, so only the `claims` predicate hides it), and
/// the viewer's own private step. The viewer sees `[public, mine]`, so it
/// reports indices 0 and 1 and they must land on those two claims. Unfiltered,
/// index 1 would land on the stranger's step; on the unstamped raw pool the
/// viewer's own step is hidden and index 1 resolves to nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn report_hierarchical_outcome_resolves_steps_the_viewer_can_read(pool: PgPool) {
    let p = plant(&pool, "wf-hier").await;
    let world: Uuid = sqlx::query_scalar("SELECT id FROM groups WHERE kind = 'world' LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("world group");
    let workflow_id = Uuid::new_v4();
    epigraph_db::WorkflowRepository::insert_root(
        &pool,
        workflow_id,
        &format!("inline-reads-hier-{workflow_id}"),
        0,
        "hierarchical outcome probe",
        None,
        serde_json::json!({}),
    )
    .await
    .expect("seed workflow root");

    for (offset, (step, visibility, group)) in [
        (p.public, "public", world),
        (p.theirs, "public", world),
        (p.mine, "group", p.viewer_group),
    ]
    .into_iter()
    .enumerate()
    {
        set_properties(&pool, step, serde_json::json!({ "level": 2 })).await;
        let edge: Uuid = sqlx::query_scalar(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, \
                                relationship, created_at) \
             VALUES (gen_random_uuid(), $1, 'workflow', $2, 'claim', 'executes', \
                     now() - make_interval(secs => $3)) \
             RETURNING id",
        )
        .bind(workflow_id)
        .bind(step)
        .bind(f64::from(10 - i32::try_from(offset).expect("small")))
        .fetch_one(&pool)
        .await
        .expect("seed executes edge");
        force_tenancy(&pool, "edges", edge, visibility, group).await;
    }

    let step = |i: usize| epigraph_api::routes::workflows::StepExecution {
        step_index: i,
        planned: format!("step {i}"),
        actual: format!("step {i} done"),
        deviated: false,
        deviation_reason: None,
    };
    let state = split_state(&pool).await;
    let served = epigraph_api::routes::workflows::report_hierarchical_outcome(
        ViewerExtractor(viewer_for(&pool, p.viewer_agent).await),
        State(state),
        axum::extract::Path(workflow_id),
        Json(epigraph_api::routes::workflows::ReportOutcomeRequest {
            success: true,
            outcome_details: "probe".to_string(),
            quality: Some(1.0),
            step_executions: Some(vec![step(0), step(1)]),
            goal_text: None,
        }),
    )
    .await
    .expect("report_hierarchical_outcome")
    .0;
    assert_eq!(served["use_count"].as_i64(), Some(1));

    let attributed: Vec<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT tool_pattern[1], step_claim_id FROM behavioral_executions \
         WHERE workflow_id = $1 ORDER BY tool_pattern[1]",
    )
    .bind(workflow_id)
    .fetch_all(&pool)
    .await
    .expect("read behavioral_executions");
    assert_eq!(
        attributed,
        vec![
            ("step 0".to_string(), Some(p.public)),
            ("step 1".to_string(), Some(p.mine)),
        ],
        "index 1 must resolve to the viewer's own step, the second step it can \
         read — not to the stranger's step (predicate missing) and not to \
         nothing (read on the unstamped raw pool)"
    );
}
