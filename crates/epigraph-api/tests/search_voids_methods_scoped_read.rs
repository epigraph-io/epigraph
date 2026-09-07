//! `routes/search.rs::semantic_search`, `routes/voids.rs::{detect_voids,
//! embedding_density}` and `routes/methods.rs::get_method` each serve every
//! statement of their request on ONE viewer-stamped connection, and every read
//! that HAS a viewer to spend suppresses on it.
//!
//! # What this file is, in the series
//!
//! PR-29 is conversion shard 3 against
//! `D-PR17-request-path-never-stamps-session-gucs`, and the first MULTI-FILE
//! shard: 11 sites across three route files. It copies the template PR-28
//! established in `crates/epigraph-api/tests/claims_query_scoped_read.rs` —
//! direct `async fn` invocation, a CALIBRATION arm on every negative assertion,
//! and `viewer_fixture::downgraded_pool` for `AppState.db_pool`.
//!
//! # Why ONE file for three routes
//!
//! The brief asks for filtered-session coverage of each of the three converted
//! files, which this has: every arm below names the route it drives, and no
//! route is left to be inferred from another's. It is one FILE because
//! [`split_state`] is the instrument and `F-PR28-viewer-fixture-duplication` is
//! open — copying it into three test files would be a third and fourth hand-sync
//! of the same fixture, which is the thing that finding asks the next shard not
//! to do. The seeding helpers are file-local for the same reason: neither copy
//! of `viewer_fixture.rs` was edited.
//!
//! # THE AUTHORITY TRAP, AND WHAT THIS FILE DOES ABOUT IT
//!
//! `#[sqlx::test]` connects as `epigraph`, which is superuser, `BYPASSRLS` AND
//! the table owner, so **no RLS policy filters anything on the pool it hands
//! you**. Worse for a conversion shard: `AppState::with_scoped_pool` sets
//! `db_pool = scoped.inner().clone()`, so on that fixture the converted and the
//! unconverted arms are the SAME POOL and reverting a site to `&state.db_pool`
//! changes not one observable row.
//!
//! So [`split_state`] gives `AppState.db_pool` its own pool whose every
//! connection is `SET SESSION AUTHORIZATION epigraph_app` in `after_connect`,
//! while `AppState.scoped` holds an ordinary `ScopedPool`. `db_pool !=
//! scoped.inner()`, the raw arm is FILTERED and unstamped, and reverting a
//! converted site is observable.
//!
//! # The 11 sites, and which arm drives each
//!
//! | route | site | driven by |
//! |---|---|---|
//! | `search.rs` | inline `frac_3072` on `claim_themes` | [`the_diverse_path_runs_the_centroid_autodetect_on_the_stamped_connection`] |
//! | `search.rs` | `ClaimThemeRepository::find_similar_themes_at_dim` | the same |
//! | `search.rs` | `ClaimThemeRepository::claims_in_themes_at_dim_since` | [`the_diverse_path_serves_the_viewers_own_group_private_claim`] |
//! | `search.rs` | inline `full_sql` claim fetch | the same |
//! | `search.rs` | `ClaimRepository::semantic_graph_neighbors` | the same |
//! | `search.rs` | `ClaimRepository::semantic_search_flat` | [`the_flat_path_serves_the_viewers_own_group_private_claim`] and [`the_diverse_path_falls_through_to_flat_on_the_same_connection`] |
//! | `voids.rs` | `ClaimRepository::semantic_search_flat` | [`detect_voids_covers_the_concept_the_viewer_can_actually_see`] |
//! | `voids.rs` | `ClaimRepository::embedding_density_stats` | [`embedding_density_separates_its_two_reads`] |
//! | `voids.rs` | `ClaimRepository::semantic_search_flat` | the same |
//! | `methods.rs` | `MethodRepository::get_evidence_strength` | [`method_evidence_counts_only_the_claims_the_viewer_can_see`] |
//! | `methods.rs` | `MethodRepository::get` | [`method_lookup_serves_on_the_stamped_connection`] and [`method_lookup_fails_when_the_unstamped_role_cannot_read_methods`] |
//!
//! # THE DIRECTION OF THE SEARCH ASSERTIONS, STATED SO IT IS NOT ASKED FOR
//!
//! For the diverse path's candidate/full-fetch/neighbour sites the only
//! available direction is FAIL-CLOSED — "the viewer's own claim survives". A
//! stranger's claim cannot be shown absent from those three sites because it
//! never becomes a candidate in the first place: `claims_in_themes_at_dim_since`
//! is itself viewer-filtered and is the sole source of the id list the other two
//! are bounded by. Asking for a stranger-absent assertion there is asking for
//! one that cannot be constructed. The flat path, which reads the whole corpus,
//! carries the stranger-absent assertion instead.
//!
//! # TWO SITES HAVE NO ROW DIFFERENTIAL AT ALL, AND ARE PINNED DIFFERENTLY
//!
//! Measured on the throwaway at migration head 91: `claim_themes` and `methods`
//! both have `relrowsecurity = f` / `relforcerowsecurity = f` and no tenancy
//! columns, and migration 077 grants `epigraph_app` SELECT on both. So reverting
//! `search.rs`'s `frac_3072` site, its theme lookup, or `methods.rs`'s
//! `MethodRepository::get` to `&state.db_pool` changes NOT ONE ROW on this
//! fixture — no RLS to filter and no `42501` to raise. A mutation proof built
//! only on row differentials reports a FALSE PASS for those three.
//!
//! [`method_lookup_fails_when_the_unstamped_role_cannot_read_methods`] and
//! [`the_diverse_path_runs_the_centroid_autodetect_on_the_stamped_connection`]
//! close that by REVOKING the grant inside the test's own database — which
//! `#[sqlx::test]` creates fresh per test and connects to as owner. The scoped
//! arm is unaffected (`viewer_fixture::scoped_pool` builds its own pool on the
//! `DATABASE_URL` credentials, i.e. `epigraph`), so the revoke is a clean seam
//! between the two arms. It is a PLUMBING assertion, not a tenancy one, which is
//! the honest thing to assert about a table that has no tenancy.
//!
//! # What is still NOT proven here
//!
//! `ScopedPoolOptions` exposes no `after_connect`, so the SCOPED arm is still a
//! superuser session and the assertions below observe the in-query `$V`
//! predicate, not migration 077's policies. The policy half — that a STAMPED
//! connection and an UNSTAMPED one disagree about the viewer's OWN rows once the
//! session is filtered — is pinned on the repo primitives in
//! `epigraph-db/tests/search_voids_methods_scoped_read_policy.rs`, on both
//! `SessionGucMode` arms. Neither file is sufficient alone.

mod viewer_fixture;

use axum::extract::{Path, Query, State};
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::methods::get_method;
use epigraph_api::routes::search::{
    semantic_search, SemanticSearchRequest, SemanticSearchResponse,
};
use epigraph_api::routes::voids::{
    detect_voids, embedding_density, DensityQuery, DetectVoidsRequest,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use viewer_fixture::{downgraded_pool, scoped_pool, seed_agent_with_group, seed_group_claim};

/// The dimension every seeded vector and every mock embedding in this file uses.
///
/// It must equal `routes/search.rs::EMBEDDING_DIM` and the `claims.embedding`
/// column width, or `generate_query_embedding` silently discards the configured
/// service and falls back to its private deterministic mock — which the test
/// cannot call, so every seeded vector would be uncorrelated with the probe and
/// the arms would pass or fail for reasons unrelated to tenancy.
const DIM: usize = 1536;

// ── The instrument ──

/// An `AppState` whose `scoped` pool is stamped-but-superuser and whose raw
/// `db_pool` is filtered-but-unstamped.
///
/// The asymmetry is the instrument: a converted site reads through `scoped` and
/// works; the same site reverted to `&state.db_pool` reads through a session the
/// RLS policies filter, with no `epigraph.group_ids` to admit the viewer's own
/// group, and loses the rows.
async fn split_state(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let scoped = scoped_pool(pool).await;

    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);

    // CALIBRATION: the two arms must really be different sessions, or every
    // assertion below is about one pool wearing two names.
    assert!(
        state.scoped.is_some(),
        "CALIBRATION: AppState.scoped must be populated, or read_as refuses and \
         the handler cannot serve at all"
    );
    let raw_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&state.db_pool)
        .await
        .expect("current_user on the raw pool");
    assert_eq!(
        raw_user, "epigraph_app",
        "CALIBRATION: AppState.db_pool must be DOWNGRADED, or reverting a converted \
         site to it is invisible and the mutation proof is vacuous"
    );
    let scoped_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(state.scoped.as_ref().expect("scoped").inner())
        .await
        .expect("current_user on the scoped pool");
    assert_ne!(
        scoped_user, raw_user,
        "CALIBRATION: the scoped and raw arms must not be the same session — that \
         sameness is exactly what makes with_scoped_pool useless as a conversion fixture"
    );

    state
}

/// A deterministic 1536d embedding service, and the same provider the test can
/// query itself.
///
/// Both `voids.rs` handlers return `InternalError` at
/// `state.embedding_service()` BEFORE any SQL runs, so without this they are
/// untestable and the shard would prove two thirds of itself. `search.rs` does
/// not require one, but gets it anyway: with a service whose `dimension()`
/// matches the target dim, `generate_query_embedding` takes the service branch,
/// so the test can compute the EXACT probe vector the handler will use and seed
/// a claim at cosine similarity ~1.0. Hand-writing a vector and hoping would
/// leave the arms' outcome dependent on the sign of a dot product.
///
/// `MockProvider` does not override `EmbeddingService::generate_query`, whose
/// default delegates to `generate`, so the vector this returns for a string is
/// the one both handlers compute for it.
fn mock_embedder() -> Arc<MockProvider> {
    Arc::new(MockProvider::new(EmbeddingConfig::openai(DIM)))
}

async fn split_state_with_embedder(pool: &PgPool, embedder: Arc<MockProvider>) -> AppState {
    split_state(pool).await.with_embedding_service(embedder)
}

fn pgvec(v: &[f32]) -> String {
    format!(
        "[{}]",
        v.iter().map(f32::to_string).collect::<Vec<_>>().join(",")
    )
}

/// The exact vector the handlers will compute for `text`.
async fn probe(embedder: &Arc<MockProvider>, text: &str) -> String {
    pgvec(&embedder.generate(text).await.expect("mock embed"))
}

// ── File-local seeding (deliberately NOT added to `viewer_fixture.rs`) ──

/// Give a seeded claim an `embedding`, so the vector-ranked reads can find it.
///
/// `viewer_fixture::seed_group_claim` writes no embedding and every read this
/// shard converts is embedding-ranked. Kept file-local rather than pushed into
/// the fixture because both copies of `viewer_fixture.rs` are byte-identical and
/// `F-PR28-viewer-fixture-duplication` is open; this mirrors what
/// `tests/tenant_isolation_http.rs` already does.
async fn set_embedding(pool: &PgPool, claim: Uuid, vec: &str) {
    sqlx::query("UPDATE claims SET embedding = $2::vector WHERE id = $1")
        .bind(claim)
        .bind(vec)
        .execute(pool)
        .await
        .expect("set claim embedding");
}

/// A `claim_themes` row with a 1536d centroid, and the claims attached to it.
async fn seed_theme(pool: &PgPool, label: &str, centroid: &str) -> Uuid {
    let theme: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ($1, $2) RETURNING id",
    )
    .bind(label)
    .bind("PR-29 scoped-read fixture theme")
    .fetch_one(pool)
    .await
    .expect("insert theme");

    sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
        .bind(theme)
        .bind(centroid)
        .execute(pool)
        .await
        .expect("set centroid");
    theme
}

async fn attach_theme(pool: &PgPool, claim: Uuid, theme: Uuid) {
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .execute(pool)
        .await
        .expect("attach theme");
}

async fn seed_method(pool: &PgPool, name: &str, source_claims: &[Uuid]) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO methods (id, name, canonical_name, technique_type, source_claim_ids) \
         VALUES ($1, $2, $3, 'measurement', $4)",
    )
    .bind(id)
    .bind(name)
    .bind(name.to_lowercase())
    .bind(source_claims)
    .execute(pool)
    .await
    .expect("insert method");
    id
}

/// Resolved on the SUPERUSER pool, never the downgraded one: `Viewer::resolve`
/// reads `group_memberships`, and on a filtered unstamped session it resolves to
/// an EMPTY group set — which would satisfy every "a stranger is absent"
/// assertion here for entirely the wrong reason.
async fn viewer_for(pool: &PgPool, agent: Uuid) -> epigraph_db::visibility::Viewer {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
}

fn search_request(query: &str, diverse: bool) -> SemanticSearchRequest {
    SemanticSearchRequest {
        query: query.to_string(),
        limit: Some(20),
        min_similarity: None,
        claim_type: None,
        created_after: None,
        created_before: None,
        agent_id: None,
        diverse: Some(diverse),
        max_themes: Some(5),
        diversity_weight: Some(0.5),
        centroid_dim: None,
        candidate_pool: None,
    }
}

async fn search(
    pool: &PgPool,
    state: AppState,
    agent: Uuid,
    request: SemanticSearchRequest,
) -> Result<SemanticSearchResponse, ApiError> {
    let viewer = viewer_for(pool, agent).await;
    semantic_search(ViewerExtractor(viewer), State(state), axum::Json(request))
        .await
        .map(|j| j.0)
}

fn hit_ids(r: &SemanticSearchResponse) -> Vec<Uuid> {
    r.results.iter().map(|h| h.claim_id).collect()
}

// ── search.rs ──

/// THE FLAT PATH — `ClaimRepository::semantic_search_flat`, the default request
/// shape and the site five of the other six can never stand in for.
///
/// The over-suppression direction is the one that catches a reversion to the raw
/// pool: with the handler reading `&state.db_pool`, the filtered unstamped
/// session has no `epigraph.group_ids` to admit the viewer's own group and the
/// claim silently disappears. That direction is permanent and looks like data
/// loss rather than like a leak.
#[sqlx::test(migrations = "../../migrations")]
async fn the_flat_path_serves_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "svm-flat-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "svm-flat-theirs").await;

    let embedder = mock_embedder();
    let query = "flat path probe";
    let vec = probe(&embedder, query).await;

    let mine = seed_group_claim(&pool, agent, group, "flat: my claim").await;
    let theirs = seed_group_claim(&pool, stranger, stranger_group, "flat: their claim").await;
    // BOTH at the probe vector: the stranger's claim is the single most
    // relevant row in the corpus, so its absence below cannot be explained by
    // ranking or by the limit.
    set_embedding(&pool, mine, &vec).await;
    set_embedding(&pool, theirs, &vec).await;

    let state = split_state_with_embedder(&pool, embedder).await;
    let out = search(&pool, state, agent, search_request(query, false))
        .await
        .expect(
            "the viewer is entitled to read its own group-private claim, so the search \
             must SERVE. A failure here is the conversion itself: either `read_as` refused \
             because the AppState carries no ScopedPool, or a statement errored on the \
             stamped connection",
        );

    let got = hit_ids(&out);
    assert!(
        got.contains(&mine),
        "CALIBRATION: a group-private claim the viewer is a MEMBER of must be served. \
         Absence here is the fail-closed drift that reads as data loss — and if the \
         handler is reading the raw pool instead of a stamped connection, this is where \
         it shows; got {got:?}"
    );
    assert!(
        !got.contains(&theirs),
        "a claim owned by a group the viewer is not in must be ABSENT from the results, \
         not present with its content blanked; got {got:?}"
    );
}

/// THE DIVERSE PATH, with themes — drives the candidate pull, the `full_sql`
/// claim fetch and the graph-neighbour read, all three bounded by the id list
/// the first of them produces.
///
/// Fail-closed direction only, for the reason the module doc gives: a stranger's
/// claim cannot become a candidate, so the three sites downstream of the
/// candidate pull have no stranger row to lose.
#[sqlx::test(migrations = "../../migrations")]
async fn the_diverse_path_serves_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "svm-diverse-mine").await;

    let embedder = mock_embedder();
    let query = "diverse path probe";
    let vec = probe(&embedder, query).await;

    let theme = seed_theme(&pool, "svm-diverse-theme", &vec).await;
    let mine = seed_group_claim(&pool, agent, group, "diverse: my claim").await;
    set_embedding(&pool, mine, &vec).await;
    attach_theme(&pool, mine, theme).await;

    let state = split_state_with_embedder(&pool, embedder).await;
    let out = search(&pool, state, agent, search_request(query, true))
        .await
        .expect(
            "the diverse path must serve on the stamped connection. A failure here is \
             a statement that did not get the viewer-stamped handle",
        );

    assert_eq!(
        out.centroid_dim_used,
        Some(1536),
        "CALIBRATION: the response must show the DIVERSE branch ran. `centroid_dim_used` \
         is None on the flat tail, so a None here means the corpus had no themes and \
         this arm silently proved the flat path a second time; got {:?}",
        out.centroid_dim_used
    );
    let got = hit_ids(&out);
    assert!(
        got.contains(&mine),
        "the viewer's own group-private claim is the only candidate in the only theme, \
         so it must survive the candidate pull, the full-row fetch and the neighbour \
         join. Its absence means one of those three ran on a session that could not see \
         it; got {got:?}"
    );
}

/// THE FALL-THROUGH — `diverse=true` against a corpus with NO themes.
///
/// This is the shape that catches a per-path acquire. The diverse branch runs
/// the `frac_3072` auto-detect and the theme lookup, finds nothing, and falls
/// through to the flat search; an implementation that acquired separately for
/// the two branches would serve this request from two connections and two
/// transactions, and PR-29's headline claim would be false for exactly this
/// shape while every other arm stayed green.
#[sqlx::test(migrations = "../../migrations")]
async fn the_diverse_path_falls_through_to_flat_on_the_same_connection(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "svm-fallthrough-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "svm-fallthrough-theirs").await;

    let embedder = mock_embedder();
    let query = "fall-through probe";
    let vec = probe(&embedder, query).await;

    // No `claim_themes` rows at all — that is the point of this arm.
    let mine = seed_group_claim(&pool, agent, group, "fall-through: my claim").await;
    let theirs = seed_group_claim(&pool, stranger, stranger_group, "fall-through: theirs").await;
    set_embedding(&pool, mine, &vec).await;
    set_embedding(&pool, theirs, &vec).await;

    let themes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claim_themes")
        .fetch_one(&pool)
        .await
        .expect("count themes");
    assert_eq!(
        themes, 0,
        "CALIBRATION: this arm is only the fall-through shape while `claim_themes` is \
         empty. With themes present it degenerates into a duplicate of the diverse arm"
    );

    let state = split_state_with_embedder(&pool, embedder).await;
    let out = search(&pool, state, agent, search_request(query, true))
        .await
        .expect("the fall-through must serve on the one connection acquired above the branch");

    assert_eq!(
        out.centroid_dim_used, None,
        "CALIBRATION: `centroid_dim_used` is Some(..) only on the diverse return, so a \
         Some here means the request never fell through and this arm proves nothing \
         about the fall-through; got {:?}",
        out.centroid_dim_used
    );
    let got = hit_ids(&out);
    assert!(
        got.contains(&mine),
        "after falling through, the flat search must still run on the SAME stamped \
         connection the theme lookup used; got {got:?}"
    );
    assert!(
        !got.contains(&theirs),
        "the fall-through's flat search must suppress on the viewer exactly as the \
         default shape does; got {got:?}"
    );
}

/// THE TWO `claim_themes` SITES, pinned by a GRANT rather than by rows.
///
/// `claim_themes` has no RLS and no tenancy columns, so reverting either the
/// inline `frac_3072` auto-detect or the theme lookup to `&state.db_pool`
/// produces an IDENTICAL response on every other arm in this file. Revoking the
/// app role's SELECT inside this test's own database gives those two sites the
/// only differential they can have: on the raw arm they raise `42501` and the
/// handler answers `InternalError`; on the stamped arm they are untouched,
/// because `viewer_fixture::scoped_pool` connects with the `DATABASE_URL`
/// credentials rather than as `epigraph_app`.
///
/// This is a PLUMBING assertion — "the statement ran on the connection we think
/// it ran on" — and not a tenancy one. Asserting tenancy on a table that has
/// none would be an assertion that cannot fail.
///
/// No unconverted statement in this request reads `claim_themes`:
/// `claims_in_themes_at_dim_since` filters `c.theme_id = ANY($1)` on `claims`
/// with no join back to the theme table, and the `full_sql` fetch reads `claims`
/// plus the cluster tables. So a pass here is attributable to these two sites.
#[sqlx::test(migrations = "../../migrations")]
async fn the_diverse_path_runs_the_centroid_autodetect_on_the_stamped_connection(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "svm-themes-grant").await;

    let embedder = mock_embedder();
    let query = "centroid autodetect probe";
    let vec = probe(&embedder, query).await;

    let theme = seed_theme(&pool, "svm-grant-theme", &vec).await;
    let mine = seed_group_claim(&pool, agent, group, "grant: my claim").await;
    set_embedding(&pool, mine, &vec).await;
    attach_theme(&pool, mine, theme).await;

    sqlx::query("REVOKE SELECT ON claim_themes FROM epigraph_app")
        .execute(&pool)
        .await
        .expect("revoke SELECT on claim_themes");

    // CALIBRATION: the revoke must actually bite on the arm a reversion would
    // use, or this test asserts nothing.
    let raw = downgraded_pool(&pool, "epigraph_app").await;
    let denied = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM claim_themes")
        .fetch_one(&raw)
        .await;
    assert!(
        denied.is_err(),
        "CALIBRATION: the downgraded role must be DENIED SELECT on claim_themes after \
         the revoke. If it still reads, the differential this arm depends on does not \
         exist and a reverted site would pass"
    );

    let state = split_state_with_embedder(&pool, embedder).await;
    let out = search(&pool, state, agent, search_request(query, true))
        .await
        .expect(
            "both `claim_themes` reads must run on the stamped connection, which the \
             revoke does not touch. An InternalError here means one of them reached for \
             the raw pool and was refused by the grant",
        );

    assert_eq!(
        out.centroid_dim_used,
        Some(1536),
        "CALIBRATION: the diverse branch must have run — the auto-detect and the theme \
         lookup are the two sites under test and both live in it; got {:?}",
        out.centroid_dim_used
    );
}

// ── voids.rs ──

/// `detect_voids` — `ClaimRepository::semantic_search_flat`.
///
/// The differential is a BUCKET MIGRATION, not a count: with the viewer's own
/// claim at similarity ~1.0 the concept is `covered` and carries a
/// `nearest_claim`. Reverted to the raw pool, RLS empties the result, `sim`
/// falls to the hard-coded `0.0`, and the same concept appears under
/// `void_concepts` with `nearest_claim: null`.
#[sqlx::test(migrations = "../../migrations")]
async fn detect_voids_covers_the_concept_the_viewer_can_actually_see(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "svm-voids-mine").await;

    let embedder = mock_embedder();
    let concept = "photothermal ablation threshold";
    let vec = probe(&embedder, concept).await;

    let mine = seed_group_claim(&pool, agent, group, "voids: my claim").await;
    set_embedding(&pool, mine, &vec).await;

    let state = split_state_with_embedder(&pool, embedder).await;
    let viewer = viewer_for(&pool, agent).await;
    let out = detect_voids(
        ViewerExtractor(viewer),
        State(state),
        axum::Json(DetectVoidsRequest {
            concepts: vec![concept.to_string()],
            threshold: None,
        }),
    )
    .await
    .expect("detect_voids must serve on the stamped connection")
    .0;

    let covered = out["covered_concepts"]
        .as_array()
        .expect("covered_concepts is an array");
    assert_eq!(
        covered.len(),
        1,
        "the viewer's own group-private claim sits at the probe point, so the concept \
         must be COVERED. An empty `covered_concepts` means the nearest-claim read ran \
         on a session that could not see it and the concept fell into `void_concepts`; \
         got {out}"
    );
    assert!(
        !covered[0]["nearest_claim"].is_null(),
        "a covered concept must carry the excerpt of the claim that covers it; a null \
         here is the same reversion showing up as a missing row rather than a moved \
         bucket; got {out}"
    );
    assert_eq!(
        out["void_concepts"].as_array().map(Vec::len),
        Some(0),
        "CALIBRATION: nothing may be in `void_concepts` — that is the bucket the \
         reverted implementation puts this concept in; got {out}"
    );
}

/// `embedding_density` — BOTH of its sites, separated by ONE response.
///
/// `claim_count` comes from `embedding_density_stats` and `nearest_claim` from
/// `semantic_search_flat`, so reverting either one alone is individually
/// visible: only the count drops, or only the excerpt goes null. That is the
/// "revert one site alone" requirement satisfied without a second test.
#[sqlx::test(migrations = "../../migrations")]
async fn embedding_density_separates_its_two_reads(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "svm-density-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "svm-density-theirs").await;

    let embedder = mock_embedder();
    let query = "density probe";
    let vec = probe(&embedder, query).await;

    let mine = seed_group_claim(&pool, agent, group, "density: my claim").await;
    let theirs = seed_group_claim(&pool, stranger, stranger_group, "density: their claim").await;
    set_embedding(&pool, mine, &vec).await;
    set_embedding(&pool, theirs, &vec).await;

    let state = split_state_with_embedder(&pool, embedder).await;
    let viewer = viewer_for(&pool, agent).await;
    let out = embedding_density(
        ViewerExtractor(viewer),
        State(state),
        Query(DensityQuery {
            query: query.to_string(),
            radius: None,
        }),
    )
    .await
    .expect("embedding_density must serve on the stamped connection")
    .0;

    assert_eq!(
        out["claim_count"].as_i64(),
        Some(1),
        "`claim_count` is the READER's count, from `embedding_density_stats`. Both \
         claims sit at the probe point, so a 2 means the stats read saw the stranger's \
         claim and a 0 means it saw neither — the second is what a reversion to the raw \
         pool produces; got {out}"
    );
    assert!(
        !out["nearest_claim"].is_null(),
        "`nearest_claim` comes from a DIFFERENT statement than `claim_count`. A null \
         here with the count intact pins `semantic_search_flat` alone; got {out}"
    );
    let nearest = out["nearest_claim"].as_str().unwrap_or_default();
    assert!(
        nearest.starts_with("density: my claim"),
        "the nearest VISIBLE claim must be the viewer's own, not the stranger's, even \
         though both are equidistant from the probe; got {nearest:?}"
    );

    // Guard against the arm passing because the stranger's row was never seeded.
    let seeded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE id = ANY($1)")
        .bind(vec![mine, theirs])
        .fetch_one(&pool)
        .await
        .expect("count seeded claims");
    assert_eq!(
        seeded, 2,
        "CALIBRATION: both claims must exist, or `claim_count == 1` is arithmetic \
         rather than suppression"
    );
}

// ── methods.rs ──

/// `MethodRepository::get_evidence_strength` — the one site in `methods.rs` that
/// HAS a tenancy differential.
///
/// `methods` itself is un-scoped, but this statement `JOIN`s `claims` (RLS
/// `t`/`t`) through `unnest(m.source_claim_ids)` and splices `{VISIBILITY:c}`.
/// A method whose sources span two groups therefore reports a `claim_count` that
/// is the reader's share, not the total.
#[sqlx::test(migrations = "../../migrations")]
async fn method_evidence_counts_only_the_claims_the_viewer_can_see(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "svm-method-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "svm-method-theirs").await;

    let mine = seed_group_claim(&pool, agent, group, "method evidence: mine").await;
    let theirs = seed_group_claim(&pool, stranger, stranger_group, "method evidence: theirs").await;
    let method = seed_method(&pool, "PR29 Cross Group Method", &[mine, theirs]).await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;
    let out = get_method(ViewerExtractor(viewer), State(state), Path(method))
        .await
        .expect("get_method must serve on the stamped connection")
        .0;

    assert_eq!(
        out["evidence"]["claim_count"].as_i64(),
        Some(1),
        "the method names TWO source claims and the viewer may read ONE. A 2 means the \
         `claims` join ran without the viewer's predicate; a 0 means the statement ran \
         on the filtered unstamped session, which is what reverting this site to \
         `&state.db_pool` produces; got {out}"
    );

    // CALIBRATION: the arithmetic above is only suppression if both sources exist.
    let sources: i64 = sqlx::query_scalar(
        "SELECT array_length(source_claim_ids, 1)::bigint FROM methods WHERE id = $1",
    )
    .bind(method)
    .fetch_one(&pool)
    .await
    .expect("read source_claim_ids length");
    assert_eq!(
        sources, 2,
        "CALIBRATION: the method must name two source claims, or `claim_count == 1` is \
         not evidence of anything"
    );
    assert_ne!(mine, theirs, "CALIBRATION: the two claims must be distinct");
}

/// `MethodRepository::get` — BEHAVIOUR PRESERVATION, because no tenancy
/// assertion is available or honest.
///
/// `methods` has no `visibility` column, no `owner_group_id` and no RLS, so
/// there is nothing for a viewer to suppress and an "a stranger sees less"
/// assertion here would be one that cannot fail. What CAN be asserted is that
/// the widened signature returns the same row through the handler that the repo
/// returns directly, and that the not-found path still answers `NotFound` rather
/// than the `InternalError` a refused `read_as` produces.
#[sqlx::test(migrations = "../../migrations")]
async fn method_lookup_serves_on_the_stamped_connection(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "svm-method-get").await;
    let source = seed_group_claim(&pool, agent, group, "method get: source").await;
    let method = seed_method(&pool, "PR29 Preserved Method", &[source]).await;

    let direct = epigraph_db::MethodRepository::get(&pool, method)
        .await
        .expect("direct repo read")
        .expect("the method exists");

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;
    let out = get_method(ViewerExtractor(viewer), State(state), Path(method))
        .await
        .expect("get_method must serve on the stamped connection")
        .0;

    assert_eq!(out["id"].as_str(), Some(method.to_string().as_str()));
    assert_eq!(out["name"].as_str(), Some(direct.name.as_str()));
    assert_eq!(
        out["canonical_name"].as_str(),
        Some(direct.canonical_name.as_str()),
        "the widened executor must not change the projection; got {out}"
    );
    assert_eq!(
        out["technique_type"].as_str(),
        Some(direct.technique_type.as_str())
    );

    // The 404 path: still a NotFound, not the InternalError a refused `read_as`
    // would give. This is the fail-CLOSED direction for a handler that acquires
    // a connection before it knows the row exists.
    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;
    let missing = get_method(ViewerExtractor(viewer), State(state), Path(Uuid::new_v4())).await;
    assert!(
        matches!(missing, Err(ApiError::NotFound { .. })),
        "an unknown method id must still answer NotFound. An InternalError here means \
         the acquire failed and the handler never reached the lookup at all"
    );
}

/// `MethodRepository::get`, pinned by a GRANT rather than by rows.
///
/// The arm above proves the projection is unchanged but would pass identically
/// on a reverted tree, because `methods` has no RLS and `epigraph_app` holds
/// SELECT on it. Revoking that grant inside this test's own database is the only
/// differential this site can have: reverted to `&state.db_pool` the lookup
/// raises `42501` and `get_method` maps it to `InternalError`; on the stamped
/// connection it is untouched.
///
/// The revoke is scoped to `methods` alone so that the OTHER site in this
/// handler, `get_evidence_strength`, is not what fails — and that site swallows
/// its error with `.ok()` anyway, so it could not produce this outcome.
#[sqlx::test(migrations = "../../migrations")]
async fn method_lookup_fails_when_the_unstamped_role_cannot_read_methods(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "svm-method-grant").await;
    let source = seed_group_claim(&pool, agent, group, "method grant: source").await;
    let method = seed_method(&pool, "PR29 Revoked Method", &[source]).await;

    sqlx::query("REVOKE SELECT ON methods FROM epigraph_app")
        .execute(&pool)
        .await
        .expect("revoke SELECT on methods");

    // CALIBRATION: the revoke must bite on the arm a reversion would use.
    let raw = downgraded_pool(&pool, "epigraph_app").await;
    let denied = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM methods")
        .fetch_one(&raw)
        .await;
    assert!(
        denied.is_err(),
        "CALIBRATION: the downgraded role must be DENIED SELECT on methods after the \
         revoke. If it still reads, this arm cannot distinguish the converted site from \
         the reverted one"
    );

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;
    let out = get_method(ViewerExtractor(viewer), State(state), Path(method))
        .await
        .expect(
            "the method lookup must run on the stamped connection, which the revoke does \
             not touch. An error here means it reached for the raw pool",
        )
        .0;

    assert_eq!(
        out["name"].as_str(),
        Some("PR29 Revoked Method"),
        "the row must come back in full from the stamped connection; got {out}"
    );
}
