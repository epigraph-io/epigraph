//! Conversion shard 6's converted handlers serve every statement of a request on
//! ONE viewer-stamped connection, and a read that has a viewer to spend
//! suppresses on it.
//!
//! # What this file is, in the series
//!
//! Conversion shard 6 against `D-PR17-read-guards-widen-under-rls`: 25 sites
//! across six route files (`routes/edges.rs` 7, `routes/hypothesis.rs` 6,
//! `routes/agents.rs` 5, `routes/experiments.rs` 3, `routes/community.rs` 2,
//! `routes/rag.rs` 2). It copies the template PR-28 established in
//! `claims_query_scoped_read.rs`, PR-29 carried into
//! `search_voids_methods_scoped_read.rs`, shard 4 into
//! `belief_computation_scoped_read.rs` and shard 5 into
//! `dense_routes_scoped_read.rs` — direct `async fn` invocation, a CALIBRATION
//! arm on every assertion, and `viewer_fixture::downgraded_pool` for
//! `AppState.db_pool`.
//!
//! # THE AUTHORITY TRAP, AND WHAT THIS FILE DOES ABOUT IT
//!
//! `#[sqlx::test]` connects as `epigraph`, which is superuser, `BYPASSRLS` AND
//! the table owner, so **no RLS policy filters anything on the pool it hands
//! you**. And `AppState::with_scoped_pool` sets `db_pool = scoped.inner()`, so on
//! a `spawn_app` fixture the converted and the unconverted arms are the SAME
//! POOL and reverting a site to `&state.db_pool` changes not one observable row.
//!
//! That is why the pre-existing HTTP binaries over these endpoints —
//! `read_path_authz_test.rs` (which drives `claim_provenance` four times,
//! `list_edges`, `get_evidence`, `graph_full` and `supporting_evidence`) and
//! `tenant_isolation_http.rs` (`hypothesis_status`) — **are this shard's
//! COUNTERFACTUAL and not its instrument.** They stay green on a planted tree by
//! construction, which is precisely what makes them useful: they show the control
//! added here is load-bearing rather than redundant.
//!
//! [`split_state`] is the instrument. It gives `AppState.db_pool` its own pool
//! whose every connection is `SET SESSION AUTHORIZATION epigraph_app` in
//! `after_connect`, while `AppState.scoped` holds an ordinary `ScopedPool`. So
//! `db_pool != scoped.inner()`, the raw arm is FILTERED and unstamped, and
//! reverting a converted site is observable.
//!
//! # Every arm asserts a COUNT, and that is a constraint the shape had to meet
//!
//! The acceptance for this series requires the negative direction to fail on a
//! named test's own `assert_eq!` — never inside an `.expect(...)`, because a
//! panic in `.expect` is only the downgraded role erroring and proves nothing
//! about suppression. Several converted handlers 404 when their PRIMARY object
//! is withheld, so an arm built on a private primary object would fail in
//! `.expect` on a reverted tree and prove exactly nothing. Every arm below is
//! therefore built with a PUBLIC primary object and a group-private CHILD, so
//! the handler still answers `Ok` on the reverted tree and it is a cardinality
//! that moves.
//!
//! # Coverage, stated per SITE because the fraction is otherwise ambiguous
//!
//! FOURTEEN of the shard's twenty-five converted `.db_pool` sites — the unit the
//! ratchet uses — are driven by an arm here. Note the unit before re-deriving
//! that number: `.db_pool` SITES, not handlers and not repo functions.
//! `get_community` for instance held ONE `let pool = &state.db_pool;` alias and
//! spends it on two repo calls, so it is one site and not two.
//!
//! | route | sites driven | arm |
//! |---|--:|---|
//! | `edges.rs::list_edges` | 1 | [`list_edges_serves_the_viewers_own_group_private_edge`] |
//! | `edges.rs::claim_neighborhood` | 1 | [`claim_neighborhood_serves_the_viewers_own_group_private_edge`] |
//! | `edges.rs::graph_edges` | 1 | [`graph_edges_serves_the_viewers_own_group_private_edge`] |
//! | `edges.rs::graph_full` | 1 | [`graph_full_serves_the_viewers_own_group_private_claim`] |
//! | `edges.rs::claim_provenance` | 1 | [`claim_provenance_chains_through_the_viewers_own_group_private_evidence`] |
//! | `edges.rs::evidence_by_relationship` | 1 | [`supporting_evidence_serves_the_viewers_own_group_private_evidence`] |
//! | `community.rs::list_communities` | 1 | [`list_communities_serves_the_viewers_own_group_private_community`] |
//! | `community.rs::get_community` | 1 | [`get_community_serves_a_member_perspective_the_viewer_may_read`] |
//! | `agents.rs::get_agent_reputation` | 2 | [`agent_reputation_counts_the_viewers_own_group_private_claim`] |
//! | `agents.rs::agent_claims` | 3 | [`agent_claims_counts_the_viewers_own_group_private_claim`] |
//! | `rag.rs::rag_context` | 1 | [`rag_context_returns_the_viewers_own_group_private_claim`] |
//!
//! **THE UNCOVERED SET, NAMED BY SITE AND WITH THE REASON, rather than implied
//! by subtraction.** Eleven sites carry no behavioural arm here:
//!
//! * `hypothesis.rs::hypothesis_status` (6) — the largest single prize in the
//!   shard and the worst fixture story in it. It reads `frames`, `experiments`,
//!   `mass_functions` and `analyses`; `epigraph-db/tests/viewer_fixture.rs`
//!   seeds NONE of the four, and there is no inline precedent anywhere in this
//!   workspace for the last three. Authoring four seeders is a larger and
//!   separable piece of work than the conversion it would cover. Recorded rather
//!   than glossed — this is the `F-SHARD4-A4` shape, which already owns the gap.
//!   `tenant_isolation_http.rs::hypothesis_status_http_hides_a_group_private_claim_from_a_stranger`
//!   does exercise the handler end to end, but through `spawn_app`, so it cannot
//!   observe suppression; it is a counterfactual, not coverage.
//! * `experiments.rs::method_gap_analysis` (3) — needs `methods`,
//!   `method_capabilities` and `papers` seeded before either of its two
//!   narrowing reads returns anything. One of the three narrows nothing at all
//!   (`methods`/`method_capabilities` carry no RLS), so an arm would cover two.
//! * `edges.rs::get_evidence` (1) — its primary object IS the private one, so
//!   the only cardinality it exposes moves between "a row" and "a 404", which is
//!   the `.expect(...)` shape this file's acceptance rules out. Its sibling site
//!   through the same repo function, `detail_by_id`, IS driven by the
//!   `claim_provenance` arm.
//! * `rag.rs::search_evidence` (1) — needs `evidence.embedding` populated, which
//!   the canonical fixture does not do (`set_claim_embedding` writes
//!   `claims.embedding` only).
//!
//! # One arm here found a pre-existing 500, and it is fixed rather than routed around
//!
//! [`get_community_serves_a_member_perspective_the_viewer_may_read`] is the first
//! test anywhere in this workspace to drive `GET /api/v1/communities/:id` against
//! a community that HAS a member, and it failed on its first run —
//! `CommunityRepository::get_members` projected nine columns into a
//! ten-field `#[derive(FromRow)]` struct, so the decode failed and the endpoint
//! returned 500 for every populated community. Fixed in
//! `epigraph-db/src/repos/community.rs` by projecting the missing column; the
//! statement's viewer marker, its bind and its filtering are untouched, and the
//! route maps only `id`/`name`/`owner_agent_id` into its response, so nothing new
//! reaches a caller. Recorded here because it is a defect this shard did not
//! cause and would not otherwise have been asked to fix.
//!
//! # BOTH DIRECTIONS ARE ASSERTED, and the split matters
//!
//! Each arm asserts an EXACT count and then names a row by id in each
//! direction. That is deliberate: a file of lower bounds detects only the
//! fail-CLOSED regression (a site reverted to `&state.db_pool` loses the
//! viewer's own private row) and is blind to the fail-OPEN one (a
//! `{VISIBILITY:c}` / `{EDGE_VISIBILITY:e}` marker deleted from a repo function,
//! a predicate widened, a broader `Viewer` handed to `read_as`).
//!
//! Four arms therefore plant a STRANGER row — an object owned by a group the
//! viewer is not in — and assert it ABSENT by id:
//!
//! | arm | stranger row | the control it observes |
//! |---|---|---|
//! | [`list_edges_serves_the_viewers_own_group_private_edge`] | an edge between the same two PUBLIC claims | the edge marker in `EdgeRepository::list_filtered` |
//! | [`graph_full_serves_the_viewers_own_group_private_claim`] | a claim reached by a PUBLIC edge | the claim marker in `graph_query_utils::load_subgraph_conn` |
//! | [`get_community_serves_a_member_perspective_the_viewer_may_read`] | a member perspective | the `{VISIBILITY:p}` marker in `CommunityRepository::get_members` |
//! | [`agent_claims_counts_the_viewers_own_group_private_claim`] | a claim with a PUBLIC attribution edge | the claim marker in `EdgeRepository::{get,count}_claims_attributed_to` |
//!
//! In each case the stranger row is reachable through a PUBLIC parent, so no
//! other predicate can be what withholds it, and the exact `assert_eq!` moves
//! from 2 to 3 when the control is removed — failing on its own `assert_eq!`
//! rather than inside an `.expect(...)`.
//!
//! # What is still NOT proven here
//!
//! `ScopedPoolOptions` exposes no `after_connect`, so the SCOPED arm is still a
//! superuser, `BYPASSRLS` session. Everything the stranger arms above observe is
//! therefore the IN-QUERY `$V` predicate that `Viewer::splice` writes into the
//! SQL text — which is the control the conversion actually threads, and is why
//! those arms work at all. What no arm here can observe is drift in migration
//! 077's POLICIES on the converted path: dropping a policy leaves every arm
//! green. That limitation is inherited from every file this one copies, is
//! recorded on
//! `D-PR17-request-path-never-stamps-session-gucs::pr26_disposition`, and the
//! shape that would close it is a `ScopedPoolOptions::after_connect` — named as
//! a follow-up in `viewer_fixture::downgraded_pool`'s own doc, not taken here.
//!
//! **The UNCONVERTED side is what these arms prove, and they prove it directly.**
//! Reverting a converted site to `&state.db_pool` puts the read on a session the
//! RLS policies filter with no `epigraph.group_ids` to admit the viewer's own
//! group — while the viewer's group is still bound into `$V` on that same
//! statement, so the in-query predicate would have returned the row. Only a
//! row-level policy can have removed it. That is the non-bypass-role,
//! principal-set, groups-deliberately-empty condition the acceptance asks for,
//! observed rather than deferred.

mod viewer_fixture;

use axum::extract::{Path, Query, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::agents::{agent_claims, get_agent_reputation, AgentClaimsParams};
use epigraph_api::routes::community::{get_community, list_communities, ListCommunitiesQuery};
use epigraph_api::routes::edges::{
    claim_neighborhood, claim_provenance, graph_edges, graph_full, list_edges, supporting_evidence,
    EdgeQueryParams, EvidenceAccessParams, GraphAccessParams, NeighborhoodParams,
};
use epigraph_api::routes::rag::{rag_context, RagQueryParams};
use epigraph_api::state::{ApiConfig, AppState};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    downgraded_pool, scoped_pool, seed_agent_with_group, seed_evidence, seed_group_claim,
    seed_public_claim, seed_reasoning_trace, set_claim_embedding, world_group,
};

// ── The instrument ──

/// An `AppState` whose `scoped` pool is stamped-but-superuser and whose raw
/// `db_pool` is filtered-but-unstamped.
///
/// The asymmetry IS the instrument: a converted site reads through `scoped` and
/// works; the same site reverted to `&state.db_pool` reads through a session the
/// RLS policies filter, with no `epigraph.group_ids` to admit the viewer's own
/// group, and loses the rows.
///
/// This is the eighth hand-copy of this body in `crates/epigraph-api/tests/`.
///
/// **It is registered as `F-SHARD6-A2`, and the id it used to be cited under was
/// the wrong one.** `F-PR28-viewer-fixture-duplication` — carried by
/// `search_voids_methods_scoped_read.rs` and `privatization_fixture.rs`, and the
/// citation this file inherited — is CLOSED, its subject is the
/// `viewer_fixture.rs` BODIES rather than this one, and its ratchet
/// (`epigraph-db/tests/viewer_fixture_single_source.rs`) asserts only that one
/// path carries a fixture body: it cannot see a `split_state` copy at all. The
/// open entry `F-viewer-fixture-collapse-widens-helper-reach` has a different
/// subject again (`downgraded_pool`'s reach from three extra crates). So this
/// duplication had no register entry while two files said it did;
/// `F-SHARD6-A2` is that entry, filed at shard 6's land phase, and the two
/// pre-existing copies are named in it as the inherited source rather than
/// edited from here.
///
/// Still copied rather than canonicalised in this shard: promoting it is a
/// change to the shared fixture whose reach IS the subject of an open entry, and
/// bundling that into a conversion shard would put two unrelated decisions in one
/// diff.
async fn split_state(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let scoped = scoped_pool(pool).await;

    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);

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
    // Role IDENTITY is not role PRIVILEGE, and only the second is what makes
    // this instrument work. If `epigraph_app` were ever granted BYPASSRLS or
    // superuser, the raw arm would stop being filtered, every mutation proof in
    // this file -- and in the five predecessor files it copies this body from --
    // would pass while proving nothing, and no assertion above would notice.
    // Runtime `query_scalar`, deliberately not the macro, so `.sqlx/` is
    // unaffected.
    let raw_is_privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&state.db_pool)
    .await
    .expect("role privileges on the raw pool");
    assert!(
        !raw_is_privileged,
        "CALIBRATION: the raw pool's role must be subject to RLS -- neither superuser \
         nor BYPASSRLS. A privileged role here makes every negative arm in this file \
         vacuous while leaving them all green"
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

/// Resolved on the SUPERUSER pool. `Viewer::resolve` reads live memberships
/// through a `SECURITY DEFINER` helper, so the downgraded pool would resolve the
/// same viewer; the superuser pool is a convenience and no assertion here rests
/// on the difference. `dense_routes_scoped_read.rs::viewer_for` documents the
/// measurement.
async fn viewer_for(pool: &PgPool, agent: Uuid) -> epigraph_db::visibility::Viewer {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
}

// ── File-local seeders ──

/// An edge with an explicit `source_type` / `target_type` and its tenancy
/// columns FORCED to `(visibility, owner_group_id)`.
///
/// File-local rather than a `viewer_fixture` addition because
/// `viewer_fixture::seed_edge` hardcodes both endpoint types to `'claim'` and
/// three arms here need `'evidence'` or `'agent'` on one end. Widening the shared
/// helper's signature is a change to a fixture whose reach is the subject of an
/// open entry; a conversion shard is not the place for it.
///
/// The UPDATE after the INSERT is not redundant, for the reason
/// `seed_edge_owned_by` documents at length: migration 070's trigger is
/// `BEFORE INSERT OR UPDATE **OF source_id, target_id**`, so it rewrites the
/// tenancy columns on every INSERT and does not fire for an update that touches
/// only `visibility` / `owner_group_id`. An edge left to the trigger inherits its
/// ENDPOINTS' visibility — and a count assertion built that way can be satisfied
/// by the endpoint predicate alone and stay green with the edge predicate
/// deleted, which is a mutation proof that reports a false pass.
/// `co_owner_group_id` is cleared to stay inside migration 072's
/// `edges_co_owner_shape` check.
#[allow(clippy::too_many_arguments)]
async fn seed_typed_edge(
    pool: &PgPool,
    source: Uuid,
    source_type: &str,
    target: Uuid,
    target_type: &str,
    relationship: &str,
    visibility: &str,
    owner_group_id: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(target_type)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed typed edge");

    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .bind(visibility)
    .bind(owner_group_id)
    .execute(pool)
    .await
    .expect("force typed edge tenancy");
    id
}

/// A `communities` row with its tenancy columns declared.
///
/// Declared and not left to the insert trigger ON PURPOSE. `communities` has
/// `visibility` and `owner_group_id` NOT NULL with no DEFAULT (D1), and migration
/// 074's seed escape hatch stamps an undeclared insert made by a member of the
/// `epigraph_seed` role — which the `#[sqlx::test]` superuser is. So an
/// undeclared insert here would land on the SEED group, invisible to the viewer
/// these arms resolve, and every count below would be zero for the wrong reason.
async fn seed_community(pool: &PgPool, name: &str, visibility: &str, group: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO communities (name, visibility, owner_group_id) \
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(name)
    .bind(visibility)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed community")
}

/// A `perspectives` row with its tenancy columns declared, joined to
/// `community`. Same declaration argument as [`seed_community`].
async fn seed_community_member(
    pool: &PgPool,
    community: Uuid,
    agent: Uuid,
    name: &str,
    visibility: &str,
    group: Uuid,
) -> Uuid {
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id, visibility, owner_group_id) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(name)
    .bind(agent)
    .bind(visibility)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed perspective");

    sqlx::query("INSERT INTO community_members (community_id, perspective_id) VALUES ($1, $2)")
        .bind(community)
        .bind(perspective)
        .execute(pool)
        .await
        .expect("seed community membership");

    perspective
}

// ── routes/edges.rs ──

/// `GET /api/v1/edges` — the primary mutation target for this shard.
///
/// Two edges between the same two PUBLIC claims: one forced public, one forced
/// group-private to the viewer's own group. The viewer must see both. Reverting
/// the single converted site in `list_edges` to `&state.db_pool` puts the read on
/// a filtered, unstamped session with no `epigraph.group_ids`, the `edges_tenancy`
/// policy drops the private edge, and this arm fails on its own `assert_eq!`
/// below rather than inside an `.expect(...)`.
///
/// The private edge is seeded with FORCED tenancy rather than left to migration
/// 070's trigger. Between two public endpoints the trigger stamps
/// `('public', world)`, and an arm built that way would be satisfied by the
/// endpoint predicate alone and stay green with the edge predicate deleted.
#[sqlx::test(migrations = "../../migrations")]
async fn list_edges_serves_the_viewers_own_group_private_edge(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s6-le-mine").await;
    let world = world_group(&pool).await;

    let (_other_agent, other_group) = seed_agent_with_group(&pool, "s6-le-other").await;

    let a = seed_public_claim(&pool, agent, "s6 le: source").await;
    let b = seed_public_claim(&pool, agent, "s6 le: target").await;

    let public_edge =
        seed_typed_edge(&pool, a, "claim", b, "claim", "supports", "public", world).await;
    let private_edge =
        seed_typed_edge(&pool, a, "claim", b, "claim", "refutes", "group", group).await;
    // THE STRANGER ROW. Owned by a group this viewer is not in, between the same
    // two PUBLIC endpoints so nothing but the EDGE predicate can withhold it.
    // It is what makes the `assert_eq!` below two-sided.
    let stranger_edge = seed_typed_edge(
        &pool,
        a,
        "claim",
        b,
        "claim",
        "contradicts",
        "group",
        other_group,
    )
    .await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = list_edges(
        ViewerExtractor(viewer),
        State(state),
        Query(EdgeQueryParams {
            source_id: Some(a),
            target_id: None,
            relationship: None,
            source_type: None,
            target_type: None,
            agent_id: None,
        }),
    )
    .await
    .expect(
        "the viewer is entitled to read both of these edges, so this must SERVE. A \
         failure here is the conversion itself: either `read_as` refused because the \
         AppState carries no ScopedPool, or the statement errored on the stamped \
         connection",
    )
    .0;

    assert_eq!(
        out.len(),
        2,
        "the viewer must see BOTH its own public edge ({public_edge}) and its own \
         group-private edge ({private_edge}). A length of 1 is the fail-closed drift \
         this arm exists to catch — the viewer's group is bound into $V on that same \
         statement, so the in-query predicate would have returned the row, and only a \
         row-level policy on an unstamped session can have removed it"
    );
    assert!(
        out.iter().any(|e| e.id == private_edge),
        "over-suppression check: the specific group-private edge must be present by \
         id, not merely the right count"
    );
    assert!(
        !out.iter().any(|e| e.id == stranger_edge),
        "UNDER-suppression check: {stranger_edge} belongs to a group this viewer is not \
         in and must be absent. Deleting the edge-visibility marker from \
         `EdgeRepository::list_filtered` admits it, the count above goes to 3, and both \
         assertions fail on their own `assert!`"
    );
}

/// `GET /api/v1/claims/:id/neighborhood` — the loop case: one stamped connection
/// reborrowed per hop, rather than one checkout per `get_by_source`.
#[sqlx::test(migrations = "../../migrations")]
async fn claim_neighborhood_serves_the_viewers_own_group_private_edge(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s6-nb-mine").await;
    let world = world_group(&pool).await;

    let centre = seed_public_claim(&pool, agent, "s6 nb: centre").await;
    let near = seed_public_claim(&pool, agent, "s6 nb: neighbour").await;

    seed_typed_edge(
        &pool, centre, "claim", near, "claim", "supports", "public", world,
    )
    .await;
    let private_edge = seed_typed_edge(
        &pool, centre, "claim", near, "claim", "refutes", "group", group,
    )
    .await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = claim_neighborhood(
        ViewerExtractor(viewer),
        State(state),
        Path(centre),
        Query(NeighborhoodParams {
            depth: Some(1),
            agent_id: None,
        }),
    )
    .await
    .expect("the viewer may read its own neighborhood, so this must SERVE")
    .0;

    assert_eq!(
        out.edges.len(),
        2,
        "a 1-hop neighborhood of {centre} must carry both the public edge and the \
         viewer's own group-private edge ({private_edge}); 1 is the fail-closed drift \
         a reverted site produces"
    );
    assert!(
        out.edges.iter().any(|e| e.id == private_edge),
        "over-suppression check: the group-private edge must be present by id"
    );
}

/// `GET /api/v1/graph/edges` — has no HTTP coverage anywhere in this workspace,
/// which makes this its first behavioural assertion of any kind.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_edges_serves_the_viewers_own_group_private_edge(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s6-ge-mine").await;
    let world = world_group(&pool).await;

    let a = seed_public_claim(&pool, agent, "s6 ge: source").await;
    let b = seed_public_claim(&pool, agent, "s6 ge: target").await;

    seed_typed_edge(&pool, a, "claim", b, "claim", "supports", "public", world).await;
    let private_edge =
        seed_typed_edge(&pool, a, "claim", b, "claim", "refutes", "group", group).await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = graph_edges(
        ViewerExtractor(viewer),
        State(state),
        Query(GraphAccessParams { agent_id: None }),
    )
    .await
    .expect("the viewer may read its own graph, so this must SERVE")
    .0;

    assert_eq!(
        out.total, 2,
        "the claim-to-claim graph must carry both the public edge and the viewer's own \
         group-private edge ({private_edge})"
    );
    assert!(
        out.edges.iter().any(|e| e.id == private_edge),
        "over-suppression check: the group-private edge must be present by id"
    );
}

/// `GET /api/v1/graph/full` — the arm that drives `load_subgraph_conn`, the
/// route-layer primitive this shard split out of `load_subgraph`.
///
/// Both halves of that function's node/edge consistency argument run on the one
/// stamped connection: the node projections and the final edge fetch narrowed to
/// the ids that survived them.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_full_serves_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s6-gf-mine").await;
    let (other_agent, other_group) = seed_agent_with_group(&pool, "s6-gf-other").await;
    let world = world_group(&pool).await;

    let public = seed_public_claim(&pool, agent, "s6 gf: public claim").await;
    let private = seed_group_claim(&pool, agent, group, "s6 gf: my group-private claim").await;

    // `seed_typed_edge` FORCES the tenancy columns, here to ('group', group) —
    // the same reason every other arm in this file forces its own: an edge left
    // to migration 070's trigger inherits the MEET of its endpoints, and a count
    // assertion built that way can be satisfied by the endpoint predicate alone
    // and stay green with the edge predicate deleted.
    seed_typed_edge(
        &pool, public, "claim", private, "claim", "supports", "group", group,
    )
    .await;

    // THE STRANGER NODE, reachable only through a PUBLIC edge so that the edge
    // predicate cannot be what withholds it. Only `load_subgraph_conn`'s claim
    // node projection can drop it, which is what makes the node count two-sided.
    let stranger = seed_group_claim(
        &pool,
        other_agent,
        other_group,
        "s6 gf: a stranger's group-private claim",
    )
    .await;
    seed_typed_edge(
        &pool, public, "claim", stranger, "claim", "supports", "public", world,
    )
    .await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = graph_full(
        ViewerExtractor(viewer),
        State(state),
        Query(GraphAccessParams { agent_id: None }),
    )
    .await
    .expect("the viewer may read its own subgraph, so this must SERVE")
    .0;

    assert_eq!(
        out.total_nodes, 2,
        "exactly two nodes must survive the projections: the public claim ({public}) \
         and the viewer's own group-private claim ({private}). ONE is the fail-closed \
         drift a reverted site produces; THREE is the stranger claim ({stranger}) \
         leaking, which is what a deleted or widened claim-visibility marker in \
         `load_subgraph_conn` produces"
    );
    assert!(
        !out.nodes.iter().any(|n| n.id == stranger),
        "UNDER-suppression check: {stranger} belongs to a group this viewer is not in \
         and must be absent by id, even though the edge that reaches it is public"
    );
    assert_eq!(
        out.total_edges, 1,
        "the edge fetch runs over the ids that SURVIVED the node projections, so the \
         edge must survive exactly when both endpoints did — and the public edge to \
         the stranger node must NOT, because its far endpoint did not survive"
    );
}

/// `GET /api/v1/claims/:id/provenance` — the arm over the nested
/// `build_evidence_chains`, which this shard moved from `&PgPool` to
/// `&mut PgConnection` so its per-evidence loop runs on the caller's connection.
///
/// The subject claim and its trace are PUBLIC, so the handler still answers `Ok`
/// on a reverted tree and the assertion below is a cardinality rather than a
/// 404 inside an `.expect(...)`.
#[sqlx::test(migrations = "../../migrations")]
async fn claim_provenance_chains_through_the_viewers_own_group_private_evidence(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s6-pv-mine").await;
    let world = world_group(&pool).await;

    let subject = seed_public_claim(&pool, agent, "s6 pv: the subject claim").await;
    seed_reasoning_trace(&pool, subject, "deductive").await;

    // Two evidence rows. `seed_evidence` declares no tenancy columns, so
    // migration 070's inheritance arm stamps each from the claim it hangs off —
    // which is how a real ingestion writes them.
    let public_host = seed_public_claim(&pool, agent, "s6 pv: public host").await;
    let private_host = seed_group_claim(&pool, agent, group, "s6 pv: private host").await;
    let public_ev = seed_evidence(&pool, public_host, "figure").await;
    let private_ev = seed_evidence(&pool, private_host, "figure").await;

    seed_typed_edge(
        &pool,
        subject,
        "claim",
        public_ev,
        "evidence",
        "derived_from",
        "public",
        world,
    )
    .await;
    seed_typed_edge(
        &pool,
        subject,
        "claim",
        private_ev,
        "evidence",
        "derived_from",
        "group",
        group,
    )
    .await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = claim_provenance(
        State(state),
        Path(subject),
        Query(EvidenceAccessParams { agent_id: None }),
        ViewerExtractor(viewer),
    )
    .await
    .expect("the subject claim is public and the viewer may read it, so this must SERVE")
    .0;

    assert_eq!(
        out.chains.len(),
        2,
        "provenance must chain through BOTH the public evidence ({public_ev}) and the \
         evidence on the viewer's own group-private claim ({private_ev}). A length of \
         1 is the fail-closed drift this arm exists to catch"
    );
    assert!(
        out.chains
            .iter()
            .any(|c| c.path.iter().any(|s| s.id == private_ev)),
        "over-suppression check: the group-private evidence must appear in a chain by \
         id, not merely be counted"
    );
}

/// `GET /api/v1/claims/:id/supporting-evidence` — the arm over
/// `evidence_by_relationship`, the twenty-fifth site.
///
/// It was filed unconvertible as an "unrouted private helper". It is unrouted as
/// a symbol and reachable as a function: this arm drives it through
/// `supporting_evidence`, one of its two routed GET callers, and that caller
/// hands it the `&Viewer` the conversion spends.
#[sqlx::test(migrations = "../../migrations")]
async fn supporting_evidence_serves_the_viewers_own_group_private_evidence(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s6-se-mine").await;
    let world = world_group(&pool).await;

    let subject = seed_public_claim(&pool, agent, "s6 se: the subject claim").await;

    let public_host = seed_public_claim(&pool, agent, "s6 se: public host").await;
    let private_host = seed_group_claim(&pool, agent, group, "s6 se: private host").await;
    let public_ev = seed_evidence(&pool, public_host, "figure").await;
    let private_ev = seed_evidence(&pool, private_host, "figure").await;

    seed_typed_edge(
        &pool, public_ev, "evidence", subject, "claim", "SUPPORTS", "public", world,
    )
    .await;
    seed_typed_edge(
        &pool, private_ev, "evidence", subject, "claim", "SUPPORTS", "group", group,
    )
    .await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = supporting_evidence(
        State(state),
        Path(subject),
        Query(EvidenceAccessParams { agent_id: None }),
        ViewerExtractor(viewer),
    )
    .await
    .expect("the subject claim is public, so this must SERVE")
    .0;

    assert_eq!(
        out.total, 2,
        "supporting evidence must include BOTH the public row ({public_ev}) and the \
         one on the viewer's own group-private claim ({private_ev})"
    );
    assert!(
        out.evidence.iter().any(|e| e.evidence_id == private_ev),
        "over-suppression check: the group-private evidence must be present by id"
    );
}

// ── routes/community.rs ──

/// `GET /api/v1/communities` — no HTTP coverage existed for this endpoint.
#[sqlx::test(migrations = "../../migrations")]
async fn list_communities_serves_the_viewers_own_group_private_community(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s6-lc-mine").await;
    let world = world_group(&pool).await;

    let public = seed_community(&pool, "s6 lc: public", "public", world).await;
    let private = seed_community(&pool, "s6 lc: mine", "group", group).await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = list_communities(
        ViewerExtractor(viewer),
        State(state),
        Query(ListCommunitiesQuery {
            limit: 50,
            offset: 0,
        }),
    )
    .await
    .expect("the viewer may read its own communities, so this must SERVE")
    .0;

    assert_eq!(
        out.len(),
        2,
        "the viewer must see the public community ({public}) and its own group-private \
         one ({private})"
    );
    assert!(
        out.iter().any(|c| c.id == private),
        "over-suppression check: the group-private community must be present by id"
    );
}

/// `GET /api/v1/communities/:id` — the arm over BOTH of this file's converted
/// sites, and the one that shows why `community.rs` is not "counter-only".
///
/// The community itself is PUBLIC, so `get_by_id` still answers on a reverted
/// tree and the handler does not 404 into an `.expect(...)`. What moves is the
/// MEMBER count — and the suppression there comes from `perspectives`, which is
/// FORCEd, and not from `community_members`, which carries no RLS at all.
#[sqlx::test(migrations = "../../migrations")]
async fn get_community_serves_a_member_perspective_the_viewer_may_read(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s6-gc-mine").await;
    let world = world_group(&pool).await;

    let community = seed_community(&pool, "s6 gc: public community", "public", world).await;
    seed_community_member(
        &pool,
        community,
        agent,
        "s6 gc: public perspective",
        "public",
        world,
    )
    .await;
    let private_member = seed_community_member(
        &pool,
        community,
        agent,
        "s6 gc: my group-private perspective",
        "group",
        group,
    )
    .await;
    // THE STRANGER MEMBER. `community_members` carries no RLS at migration head
    // 92, so the ONLY thing that can withhold this row is the `{VISIBILITY:p}`
    // marker `get_members` splices over `perspectives`. That makes this the arm
    // that actually observes the control on this path.
    let (other_agent, other_group) = seed_agent_with_group(&pool, "s6-gc-other").await;
    let stranger_member = seed_community_member(
        &pool,
        community,
        other_agent,
        "s6 gc: a stranger's group-private perspective",
        "group",
        other_group,
    )
    .await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = get_community(ViewerExtractor(viewer), State(state), Path(community))
        .await
        .expect("the community is public, so this must SERVE")
        .0;

    assert_eq!(
        out.members.len(),
        2,
        "exactly two member perspectives are readable by this viewer: the public one \
         and its own group-private one ({private_member}). ONE is the fail-closed \
         drift a reverted site produces; THREE is the stranger perspective \
         ({stranger_member}) leaking, which is what a deleted or widened \
         `{{VISIBILITY:p}}` marker in `CommunityRepository::get_members` produces"
    );
    assert!(
        out.members
            .iter()
            .any(|m| m.perspective_id == private_member),
        "over-suppression check: the group-private perspective must be present by id"
    );
    assert!(
        !out.members
            .iter()
            .any(|m| m.perspective_id == stranger_member),
        "UNDER-suppression check: {stranger_member} belongs to a group this viewer is \
         not in and must be absent by id. This is the only assertion anywhere in the \
         workspace that observes the member-list control, and it is load-bearing \
         because this shard takes `GET /api/v1/communities/:id` from a decode-time 500 \
         to a serving endpoint"
    );
}

// ── routes/agents.rs ──

/// `GET /agents/:id/reputation` — the arm over both of this handler's sites.
///
/// Note which half it rests on. The `AgentRepository::get_by_id` site is NOT
/// provable by construction: migration 077 section 9 gives `agents` the policy
/// `agents_identity FOR SELECT USING (true)`, so stamping that statement narrows
/// nothing and the agent is found either way. `total_claims` — a
/// `ClaimRepository::get_by_agent` read over FORCEd `claims` — is the provable
/// half, and is what is asserted.
#[sqlx::test(migrations = "../../migrations")]
async fn agent_reputation_counts_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s6-rep-mine").await;

    let public = seed_public_claim(&pool, agent, "s6 rep: my public claim").await;
    let private = seed_group_claim(&pool, agent, group, "s6 rep: my group-private claim").await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = get_agent_reputation(ViewerExtractor(viewer), State(state), Path(agent))
        .await
        .expect("the agent exists and the viewer may read its own claims, so this must SERVE")
        .0;

    assert_eq!(
        out.total_claims, 2,
        "an agent's own reputation must be computed over BOTH its public claim \
         ({public}) and the group-private claim ({private}) it authored in a group it \
         belongs to. A count of 1 is the fail-closed drift this arm exists to catch, \
         and this exact equality is also what would catch a conversion that refuses \
         every caller — an `assert!(> 0)` beneath it would be dead"
    );
}

/// `GET /api/v1/agents/:id/claims` — the arm over all three of this handler's
/// sites, and the one that shows why the page and its total must carry the same
/// tenancy stamp: `total` is asserted to the same exact value as `items`.
///
/// Note what that does and does not establish. One connection gives both
/// statements the SAME `epigraph.group_ids` / `principal_id` stamp; it does not
/// give them a shared snapshot, because `ScopedRead` is a bare connection under
/// `SessionGucMode::Session` and a READ COMMITTED transaction under
/// `Transaction` — a concurrent writer can still move the total. The stamp is
/// the property asserted.
#[sqlx::test(migrations = "../../migrations")]
async fn agent_claims_counts_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s6-ac-mine").await;
    let world = world_group(&pool).await;

    let public = seed_public_claim(&pool, agent, "s6 ac: my public claim").await;
    let private = seed_group_claim(&pool, agent, group, "s6 ac: my group-private claim").await;

    seed_typed_edge(
        &pool,
        public,
        "claim",
        agent,
        "agent",
        "ATTRIBUTED_TO",
        "public",
        world,
    )
    .await;
    seed_typed_edge(
        &pool,
        private,
        "claim",
        agent,
        "agent",
        "ATTRIBUTED_TO",
        "group",
        group,
    )
    .await;

    // THE STRANGER ATTRIBUTION. The claim belongs to a group this viewer is not
    // in; the EDGE is public, so the edge predicate cannot be what withholds it
    // and only the claim-visibility marker in
    // `EdgeRepository::{get,count}_claims_attributed_to` can. `total` is a
    // cardinality channel of its own, so both halves are asserted.
    let (other_agent, other_group) = seed_agent_with_group(&pool, "s6-ac-other").await;
    let stranger = seed_group_claim(
        &pool,
        other_agent,
        other_group,
        "s6 ac: a stranger's group-private claim",
    )
    .await;
    seed_typed_edge(
        &pool,
        stranger,
        "claim",
        agent,
        "agent",
        "ATTRIBUTED_TO",
        "public",
        world,
    )
    .await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = agent_claims(
        ViewerExtractor(viewer),
        State(state),
        Path(agent),
        Query(AgentClaimsParams {
            limit: 50,
            offset: 0,
            min_truth: 0.0,
        }),
    )
    .await
    .expect("the agent exists and the viewer may read its own attributions, so this must SERVE")
    .0;

    assert_eq!(
        out.total, 2,
        "exactly two attributions are countable by this viewer: the public one \
         ({public}) and its own group-private one ({private}). THREE is the stranger \
         claim ({stranger}) being counted — `total` discloses a cardinality even when \
         the page does not, so it is asserted exactly"
    );
    assert_eq!(
        out.items.len(),
        2,
        "the page and the total are read off ONE connection and carry the same marker, \
         so they must agree; a total larger than the page is itself a cardinality \
         disclosure"
    );
    assert!(
        !out.items.iter().any(|i| i.claim.id == stranger),
        "UNDER-suppression check: {stranger} belongs to a group this viewer is not in \
         and must be absent by id, even though its attribution edge is public"
    );
}

// ── routes/rag.rs ──

/// `GET /api/v1/query/rag` — the single read in the handler whose unfiltered
/// ancestor `ClaimRepository::rag_hybrid_context`'s own doc calls the
/// highest-value exfiltration primitive in the API.
///
/// `min_truth` is passed as `0.0` because the fixture's seeded claims carry the
/// default truth value and the handler's own default threshold is 0.7 — at the
/// default this arm would be empty for both viewers and pass vacuously.
#[sqlx::test(migrations = "../../migrations")]
async fn rag_context_returns_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s6-rag-mine").await;

    let public = seed_public_claim(&pool, agent, "s6 rag: my public claim").await;
    let private = seed_group_claim(&pool, agent, group, "s6 rag: my group-private claim").await;

    // Any non-null embedding makes a claim a candidate: the statement filters on
    // `c.embedding IS NOT NULL` and then RANKS by cosine distance. Two distinct
    // vectors so the ordering is defined.
    let mut v1 = vec!["0"; 1536];
    v1[0] = "1";
    let mut v2 = vec!["0"; 1536];
    v2[1] = "1";
    set_claim_embedding(&pool, public, &format!("[{}]", v1.join(","))).await;
    set_claim_embedding(&pool, private, &format!("[{}]", v2.join(","))).await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = rag_context(
        ViewerExtractor(viewer),
        State(state),
        Query(RagQueryParams {
            query: Some("s6 rag".to_string()),
            limit: Some(20),
            min_truth: Some(0.0),
            domain: None,
        }),
    )
    .await
    .expect("the viewer may read its own claims, so this must SERVE")
    .0;

    assert_eq!(
        out.count, 2,
        "RAG context must return BOTH the public claim ({public}) and the viewer's own \
         group-private claim ({private}). A count of 1 is the fail-closed drift this \
         arm exists to catch"
    );
    assert!(
        out.results.iter().any(|r| r.claim_id == private),
        "over-suppression check: the group-private claim must be present by id"
    );
}
