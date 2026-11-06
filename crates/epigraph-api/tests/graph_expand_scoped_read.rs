//! The three graph-expand handlers serve only the claims the caller's `Viewer`
//! may read, and say so by OMISSION rather than by blanking.
//!
//! # Why this file exists, and what it replaces
//!
//! It is the replacement coverage for `crates/epigraph-api/tests/redaction_sweep_test.rs`,
//! deleted in this branch's port. That file had nine arms; six of them
//! duplicated absence tests `origin/main` already ships —
//! `search_voids_methods_scoped_read.rs` (semantic search, flat and diverse),
//! `shard7_routes_scoped_read.rs` (`list_by_labels`, `claim_history`),
//! `shard6_routes_scoped_read.rs` (`agent_claims`) and
//! `belief_computation_scoped_read.rs` (`frame_claims_sorted`) — and porting
//! them would also have re-imported the shared-`$DATABASE_URL` +
//! unfiltered-`DELETE FROM graph_cluster_runs` fixture pattern main's
//! `common/mod.rs` explicitly de-fanged.
//!
//! The other three covered a real gap, and they are the three arms here:
//!
//! | handler | route | status on main before this file |
//! |---|---|---|
//! | `graph::expand` | `GET /api/v1/graph/communities/:id/expand` | no tenancy test |
//! | `graph_neighborhood::expand` | `GET /api/v1/graph/neighborhoods/:id/expand` | `graph_neighborhoods_test.rs` drives it for FUNCTION, and its own doc says explicitly not for tenancy |
//! | `graph_neighborhood::claim_compound_neighborhood` | `GET /api/v1/claims/:id/compound_neighborhood` | named in `dense_routes_scoped_read.rs:61`'s THE UNCOVERED SET — executed by no test in the workspace |
//!
//! The last row is the reason this file is not optional. Our branch's commit
//! `035ceca1` swept that handler with a redaction pass; main's own version of
//! the handler is strictly stronger (a 404 on an invisible centre instead of a
//! blanked 200, plus edges constrained to endpoints that survived the node
//! filter), so the MECHANISM is dropped — but nothing in the workspace executes
//! it. Deleting `redaction_sweep_test.rs` without writing this file would lose
//! the only coverage that route has ever had on either branch.
//!
//! # The instrument
//!
//! [`split_state`] is the seventh-or-so hand copy of the body
//! `dense_routes_scoped_read.rs` and `shard7_routes_scoped_read.rs` carry, and
//! it is copied rather than shared for the reason recorded there. It gives
//! `AppState.db_pool` a pool whose every connection is
//! `SET SESSION AUTHORIZATION epigraph_app`, while `AppState.scoped` holds an
//! ordinary `ScopedPool`. `#[sqlx::test]` hands out a `epigraph` superuser
//! connection that BYPASSRLS, so without that asymmetry the converted and
//! unconverted arms would be the same pool and reverting a site to
//! `&state.db_pool` would change not one observable row.
//!
//! # Every negative assertion here has a CALIBRATION partner
//!
//! A handler that refuses everyone satisfies "the stranger's claim is absent"
//! perfectly. So each arm asserts, on the SAME response, that the viewer's own
//! group-private claim IS served — the over-suppression direction, which is
//! what a reversion to the raw unstamped pool actually produces.

mod viewer_fixture;

use axum::extract::{Path, Query, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::graph::{expand as communities_expand, ExpandParams};
use epigraph_api::routes::graph_neighborhood::{
    claim_compound_neighborhood, expand as neighborhood_expand, CompoundNeighborhoodParams,
    ExpandParams as NeighborhoodExpandParams, NeighborhoodExpandResponse,
};
use epigraph_api::state::{ApiConfig, AppState};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    downgraded_pool, scoped_pool, seed_agent_with_group, seed_edge_owned_by, seed_group_claim,
    seed_public_claim, world_group,
};

// ── the instrument ──

/// An `AppState` whose `scoped` pool is stamped-but-superuser and whose raw
/// `db_pool` is filtered-but-unstamped.
async fn split_state(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let scoped = scoped_pool(pool).await;

    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);

    assert!(
        state.scoped.is_some(),
        "CALIBRATION: AppState.scoped must be populated, or read_as refuses and the \
         handler cannot serve at all"
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
    // Role IDENTITY is not role PRIVILEGE, and only the second makes this
    // instrument work: if `epigraph_app` were ever granted BYPASSRLS or
    // superuser the raw arm would stop being filtered, every negative arm here
    // would pass while proving nothing, and no other assertion would notice.
    let raw_is_privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&state.db_pool)
    .await
    .expect("role privileges on the raw pool");
    assert!(
        !raw_is_privileged,
        "CALIBRATION: the raw pool's role must be subject to RLS — neither superuser \
         nor BYPASSRLS"
    );

    state
}

/// Resolved on the SUPERUSER pool, which is the simpler of two arms that both
/// work: `Viewer::resolve` reads through `public.epigraph_live_memberships`,
/// a `SECURITY DEFINER` function, so a downgraded session resolves the same
/// viewer. See `dense_routes_scoped_read.rs::viewer_for`, which measured it.
async fn viewer_for(pool: &PgPool, agent: Uuid) -> epigraph_db::visibility::Viewer {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
}

// ── fixtures the shared `viewer_fixture` has no seeder for ──

/// One completed clustering run holding one cluster and one neighborhood.
struct Run {
    run_id: Uuid,
    cluster_id: Uuid,
    neighborhood_id: Uuid,
}

/// Seed a clustering run, a cluster and a neighborhood in it.
///
/// `graph_cluster_runs`, `graph_clusters` and `graph_neighborhoods` carry NO
/// tenancy columns (they are not in migration 062's tier_a array), which is why
/// there is nothing to stamp here and why `ClusterRunRepository::latest` takes
/// no `Viewer`. The membership rows are a different matter — see
/// [`join_cluster`] and [`join_neighborhood`].
async fn seed_run(pool: &PgPool, size: i32) -> Run {
    let run_id = Uuid::new_v4();
    let cluster_id = Uuid::new_v4();
    let neighborhood_id = Uuid::new_v4();
    let theme_id = Uuid::new_v4();

    sqlx::query("INSERT INTO claim_themes (id, label) VALUES ($1, 'graph-expand-scoped-theme')")
        .bind(theme_id)
        .execute(pool)
        .await
        .expect("seed theme");
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 1, FALSE)",
    )
    .bind(run_id)
    .execute(pool)
    .await
    .expect("seed run");
    sqlx::query(
        "INSERT INTO graph_clusters (id, run_id, label, size, mean_betp, dominant_type, degraded) \
         VALUES ($1, $2, 'cluster-0', $3, 0.5, 'claim', FALSE)",
    )
    .bind(cluster_id)
    .bind(run_id)
    .bind(size)
    .execute(pool)
    .await
    .expect("seed cluster");
    sqlx::query(
        "INSERT INTO graph_neighborhoods (id, run_id, theme_id, label, size, mean_betp) \
         VALUES ($1, $2, $3, 'neighborhood-0', $4, 0.5)",
    )
    .bind(neighborhood_id)
    .bind(run_id)
    .bind(theme_id)
    .bind(size)
    .execute(pool)
    .await
    .expect("seed neighborhood");

    Run {
        run_id,
        cluster_id,
        neighborhood_id,
    }
}

/// Put `claim` in the run's cluster, and assert the membership row INHERITED
/// the claim's tenancy.
///
/// The read-back is the point. `claim_cluster_membership` is in migration 062's
/// tier_a array and `expand_cluster_nodes` marks it `/* {VISIBILITY:m} */`
/// alongside the `claims` marker, so a membership row left `('public', world)`
/// behind a group-private claim would make the arm below pass through the
/// claims predicate alone — and stay green if the membership predicate were
/// deleted. Migration 070's statement-level `_inherit_tenancy` trigger stamps
/// it on INSERT; a fixture that silently did not would leave this file green
/// while testing half of what it says it tests.
async fn join_cluster(pool: &PgPool, run: &Run, claim: Uuid) {
    sqlx::query(
        "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) VALUES ($1, $2, $3)",
    )
    .bind(claim)
    .bind(run.cluster_id)
    .bind(run.run_id)
    .execute(pool)
    .await
    .expect("seed cluster membership");
    assert_tenancy_inherited(pool, "claim_cluster_membership", claim).await;
}

/// Put `claim` in the run's neighborhood, with the same inheritance assertion.
async fn join_neighborhood(pool: &PgPool, run: &Run, claim: Uuid) {
    sqlx::query(
        "INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) \
         VALUES ($1, $2, $3)",
    )
    .bind(run.run_id)
    .bind(claim)
    .bind(run.neighborhood_id)
    .execute(pool)
    .await
    .expect("seed neighborhood membership");
    assert_tenancy_inherited(pool, "claim_neighborhood_membership", claim).await;
}

async fn assert_tenancy_inherited(pool: &PgPool, table: &str, claim: Uuid) {
    let row: (String, Option<Uuid>, String, Option<Uuid>) = sqlx::query_as(&format!(
        "SELECT m.visibility::text, m.owner_group_id, c.visibility::text, c.owner_group_id \
           FROM {table} m JOIN claims c ON c.id = m.claim_id WHERE m.claim_id = $1"
    ))
    .bind(claim)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read back {table} tenancy: {e}"));
    assert_eq!(
        (row.0, row.1),
        (row.2, row.3),
        "CALIBRATION: {table} must INHERIT claim {claim}'s tenancy on insert \
         (migration 070). Without it the marker on that table is untested here"
    );
}

/// A `decomposes_to` edge `compound -> atom`, with its own tenancy columns
/// FORCED to `('public', world)`.
///
/// `viewer_fixture::seed_edge` hardcodes `relationship = 'supports'`, so this
/// is file-local rather than a widening of the shared helper. The forcing is
/// the same trap `seed_edge_owned_by` documents: migration 070's trigger derives
/// an edge's tenancy from its ENDPOINTS, so an edge left to the trigger tracks
/// the private claim it points at, and an absence assertion built that way can
/// be satisfied by the edge predicate alone. Here the hierarchy edges are
/// deliberately PUBLIC so that the only thing which can withhold a node is the
/// `claims` predicate the handler is being tested for.
async fn seed_decomposes_to(pool: &PgPool, compound: Uuid, atom: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'decomposes_to')",
    )
    .bind(id)
    .bind(compound)
    .bind(atom)
    .execute(pool)
    .await
    .expect("seed decomposes_to edge");
    // `co_owner_group_id` is cleared to stay inside migration 072's
    // `edges_co_owner_shape` check: the trigger's cross-group arm sets one, and
    // forcing `('public', world)` while leaving it raises 23514.
    let world = world_group(pool).await;
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .bind(world)
    .execute(pool)
    .await
    .expect("force decomposes_to edge public");
    id
}

// ── arm 1: GET /api/v1/graph/communities/:id/expand ──

/// `graph::expand` — its node projection is `GraphViewRepository::expand_cluster_nodes`,
/// which marks BOTH `claim_cluster_membership` and `claims`.
///
/// `total_size` is asserted at 3 on purpose, and it is NOT a bug. It comes from
/// `graph_clusters.size`, raw cluster metadata on a table with no tenancy
/// columns, and main deliberately stopped deriving `truncated` from it
/// (`truncated` is now `nodes.len() >= budget`) precisely because
/// `total_size - nodes.len()` was an exact count of the claims the caller
/// cannot see. Pinning the number here records that the residual is KNOWN and
/// bounded to one integer on untenanted metadata, rather than letting a future
/// change quietly turn it back into a per-viewer count.
#[sqlx::test(migrations = "../../migrations")]
async fn communities_expand_omits_a_stranger_claim_and_serves_the_viewers_own(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "gx-expand-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "gx-expand-theirs").await;

    let open = seed_public_claim(&pool, viewer_agent, "gx expand: the public member").await;
    let mine = seed_group_claim(
        &pool,
        viewer_agent,
        viewer_group,
        "gx expand: my group-private member",
    )
    .await;
    let theirs = seed_group_claim(
        &pool,
        stranger,
        stranger_group,
        "gx expand: their group-private member",
    )
    .await;

    let run = seed_run(&pool, 3).await;
    join_cluster(&pool, &run, open).await;
    join_cluster(&pool, &run, mine).await;
    join_cluster(&pool, &run, theirs).await;

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, viewer_agent).await;

    let out = communities_expand(
        ViewerExtractor(viewer),
        State(state),
        Path(run.cluster_id),
        Query(ExpandParams {
            budget: 200,
            relationships: None,
        }),
    )
    .await
    .expect(
        "the cluster is in the latest run and the viewer can see two of its three \
         members, so this must SERVE. A failure here is the conversion itself: either \
         read_as refused because the AppState carries no ScopedPool, or a statement \
         errored on the stamped connection",
    )
    .0;

    let ids: Vec<Uuid> = out.nodes.iter().map(|n| n.id).collect();

    assert!(
        ids.contains(&open),
        "CALIBRATION: the public member must be served; got {ids:?}"
    );
    assert!(
        ids.contains(&mine),
        "CALIBRATION: a member private to a group the VIEWER BELONGS TO must be served. \
         Absence here is the fail-closed drift a reversion to the raw pool produces — \
         the viewer's group is bound into $V on that same statement, so the in-query \
         predicate would have returned the row, and only a row-level policy on an \
         unstamped session can have removed it. Got {ids:?}"
    );
    assert!(
        !ids.contains(&theirs),
        "a member private to a group the viewer is NOT in must be ABSENT from `nodes`, \
         not present with its label blanked; got {ids:?}"
    );
    assert_eq!(
        ids.len(),
        2,
        "exactly the two visible members, in both directions; got {ids:?}"
    );
    assert!(
        !out.nodes.iter().any(|n| n.label.contains("their")),
        "no node label may carry the stranger's claim text; got {:?}",
        out.nodes.iter().map(|n| &n.label).collect::<Vec<_>>()
    );
    assert!(
        !out.truncated,
        "two nodes against a budget of 200 is not budget-truncation"
    );
    assert_eq!(
        out.total_size, 3,
        "`total_size` is raw `graph_clusters` metadata and is deliberately NOT \
         viewer-filtered; this pins the known residual rather than asserting it away"
    );
}

// ── arm 2: GET /api/v1/graph/neighborhoods/:id/expand, both modes ──

/// `graph_neighborhood::expand` in BOTH modes off one fixture.
///
/// The fixture is shaped so each mode's filtering is exercised by a different
/// repo method:
///
/// - `open` and `mine` are standalone atoms (no `decomposes_to` either way), so
///   compound mode reaches them through `neighborhood_compound_nodes`'s
///   `standalone_nodes` arm and atomic mode through `neighborhood_atomic_nodes`.
/// - `theirs` is an atom parented by `their_compound`, so compound mode reaches
///   it through the `compound_nodes` arm — a DIFFERENT `UNION ALL` branch, with
///   its own marker, which is exactly why `neighborhood_compound_nodes`'s doc
///   says the marker is written per-`FROM` and not per-statement.
/// - atomic mode additionally must drop `their_compound`'s entry from
///   `compound_groups` rather than return it with an empty `member_atom_ids`:
///   an empty group still discloses that a compound exists and parents
///   something here.
///
/// The single `decomposes_to` edge is forced PUBLIC so the edge predicate
/// cannot be what withholds a node.
///
/// # MEASURED: compound mode's `compound_nodes` branch is defended twice over
///
/// Neutralising ONLY the `claims` marker on that branch leaves this arm green —
/// the `atoms` CTE's `/* {VISIBILITY:m} */` on `claim_neighborhood_membership`
/// already keeps the stranger's atom out, so the compound never acquires a
/// member and never reaches the projection. The arm fails when BOTH go, which
/// is what was measured rather than assumed. Atomic mode is not like that: one
/// statement, and neutralising its `claims` marker alone fails the arm. That
/// asymmetry is recorded here because a reader checking whether this file is
/// load-bearing will otherwise mutate one marker, see green, and conclude it is
/// not.
#[sqlx::test(migrations = "../../migrations")]
async fn neighborhoods_expand_omits_a_stranger_claim_in_both_modes(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "gx-nbhd-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "gx-nbhd-theirs").await;

    let open = seed_public_claim(&pool, viewer_agent, "gx nbhd: the public atom").await;
    let mine = seed_group_claim(
        &pool,
        viewer_agent,
        viewer_group,
        "gx nbhd: my group-private atom",
    )
    .await;
    let theirs = seed_group_claim(
        &pool,
        stranger,
        stranger_group,
        "gx nbhd: their group-private atom",
    )
    .await;
    let their_compound = seed_group_claim(
        &pool,
        stranger,
        stranger_group,
        "gx nbhd: their group-private compound",
    )
    .await;
    seed_decomposes_to(&pool, their_compound, theirs).await;

    let run = seed_run(&pool, 3).await;
    join_neighborhood(&pool, &run, open).await;
    join_neighborhood(&pool, &run, mine).await;
    join_neighborhood(&pool, &run, theirs).await;

    // ── compound mode ──
    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, viewer_agent).await;
    let out = neighborhood_expand(
        ViewerExtractor(viewer),
        State(state),
        Path(run.neighborhood_id),
        Query(NeighborhoodExpandParams {
            budget: 200,
            mode: "compound".to_string(),
        }),
    )
    .await
    .expect("the neighborhood is in the latest run, so this must SERVE")
    .0;
    let NeighborhoodExpandResponse::Compound(compound) = out else {
        panic!("mode=compound must select the compound arm of the untagged enum");
    };
    let ids: Vec<Uuid> = compound.nodes.iter().map(|n| n.id).collect();

    assert!(
        ids.contains(&open),
        "CALIBRATION (compound): the public standalone atom must be served; got {ids:?}"
    );
    assert!(
        ids.contains(&mine),
        "CALIBRATION (compound): an atom private to a group the VIEWER BELONGS TO must \
         be served; got {ids:?}"
    );
    assert!(
        !ids.contains(&their_compound),
        "compound mode must omit a compound the viewer cannot read — it is reached \
         through the OTHER UNION ALL arm, which carries its own marker; got {ids:?}"
    );
    assert!(
        !ids.contains(&theirs),
        "compound mode must not surface the stranger's atom either; got {ids:?}"
    );
    assert_eq!(
        ids.len(),
        2,
        "exactly the two visible standalone atoms; got {ids:?}"
    );
    assert!(
        !compound
            .nodes
            .iter()
            .any(|n| n.label.contains("their") || n.label.contains("compound")),
        "no compound-mode label may carry the stranger's claim text; got {:?}",
        compound.nodes.iter().map(|n| &n.label).collect::<Vec<_>>()
    );

    // ── atomic mode, same fixture ──
    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, viewer_agent).await;
    let out = neighborhood_expand(
        ViewerExtractor(viewer),
        State(state),
        Path(run.neighborhood_id),
        Query(NeighborhoodExpandParams {
            budget: 200,
            mode: "atomic".to_string(),
        }),
    )
    .await
    .expect("atomic mode must SERVE the same neighborhood")
    .0;
    let NeighborhoodExpandResponse::Atomic(atomic) = out else {
        panic!("mode=atomic must select the atomic arm of the untagged enum");
    };
    let ids: Vec<Uuid> = atomic.nodes.iter().map(|n| n.id).collect();

    assert!(
        ids.contains(&open),
        "CALIBRATION (atomic): the public atom must be served; got {ids:?}"
    );
    assert!(
        ids.contains(&mine),
        "CALIBRATION (atomic): the viewer's own group-private atom must be served; got {ids:?}"
    );
    assert!(
        !ids.contains(&theirs),
        "atomic mode must omit an atom the viewer cannot read; got {ids:?}"
    );
    assert_eq!(ids.len(), 2, "exactly the two visible atoms; got {ids:?}");
    assert!(
        atomic.compound_groups.is_empty(),
        "the stranger's compound group must be DROPPED, not returned with an empty \
         `member_atom_ids` — an empty group still discloses that a compound exists \
         and parents something in this neighborhood; got {:?}",
        atomic
            .compound_groups
            .iter()
            .map(|g| (g.compound_id, &g.label))
            .collect::<Vec<_>>()
    );
    for e in &atomic.edges {
        assert!(
            ids.contains(&e.source) && ids.contains(&e.target),
            "every returned edge's endpoints must appear in `nodes`; {e:?} does not"
        );
    }
}

// ── arm 3: GET /api/v1/claims/:id/compound_neighborhood ──

/// `graph_neighborhood::claim_compound_neighborhood` — the handler
/// `dense_routes_scoped_read.rs:61` names as executed by NO test in the
/// workspace, and the one our branch's `035ceca1` swept with redaction.
///
/// The `supports` edges are forced PUBLIC. That is load-bearing here in a way
/// it is not elsewhere: `GraphViewRepository::compound_neighbors` carries NO
/// marker on its `edges` traversal — only `/* {VISIBILITY:c} */` on the final
/// `JOIN claims c` — so the claims predicate is the sole filter, and a
/// trigger-stamped edge would have let this arm pass for a reason the handler
/// does not actually implement.
#[sqlx::test(migrations = "../../migrations")]
async fn compound_neighborhood_omits_a_neighbour_the_viewer_cannot_read(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "gx-cn-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "gx-cn-theirs").await;

    let center = seed_public_claim(&pool, viewer_agent, "gx cn: the centre").await;
    let open = seed_public_claim(&pool, viewer_agent, "gx cn: the public neighbour").await;
    let mine = seed_group_claim(
        &pool,
        viewer_agent,
        viewer_group,
        "gx cn: my group-private neighbour",
    )
    .await;
    let theirs = seed_group_claim(
        &pool,
        stranger,
        stranger_group,
        "gx cn: their group-private neighbour",
    )
    .await;

    let world = world_group(&pool).await;
    for neighbour in [open, mine, theirs] {
        seed_edge_owned_by(&pool, neighbour, center, "public", world).await;
    }

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, viewer_agent).await;

    let out = claim_compound_neighborhood(
        ViewerExtractor(viewer),
        State(state),
        Path(center),
        Query(CompoundNeighborhoodParams { budget: 50 }),
    )
    .await
    .expect("the centre is public, so this must SERVE")
    .0;

    let ids: Vec<Uuid> = out.nodes.iter().map(|n| n.id).collect();
    // The handler inserts the CENTRE at index 0 of `nodes`, after the neighbour
    // rows; it is not one of them, so the count below is taken over the rest.
    assert_eq!(
        out.nodes.first().map(|n| n.id),
        Some(center),
        "the centre is `nodes[0]` by construction; got {ids:?}"
    );
    let neighbours: Vec<Uuid> = ids.iter().copied().filter(|id| *id != center).collect();

    assert!(
        neighbours.contains(&open),
        "CALIBRATION: the public neighbour must be served; got {neighbours:?}"
    );
    assert!(
        neighbours.contains(&mine),
        "CALIBRATION: a neighbour private to a group the VIEWER BELONGS TO must be \
         served — the edges here are public, so only the claims predicate can act, and \
         its absence would be over-suppression rather than a leak; got {neighbours:?}"
    );
    assert!(
        !neighbours.contains(&theirs),
        "a neighbour private to a group the viewer is NOT in must be ABSENT, not \
         present with its label blanked; got {neighbours:?}"
    );
    assert_eq!(
        neighbours.len(),
        2,
        "exactly the two visible neighbours beside the centre; got {:?}",
        out.nodes
            .iter()
            .map(|n| (n.id, &n.label))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        out.edges.len(),
        2,
        "one edge per VISIBLE neighbour — an edge to a claim the viewer cannot read is \
         as much a disclosure as the claim's text; got {:?}",
        out.edges
            .iter()
            .map(|e| (e.source, e.target))
            .collect::<Vec<_>>()
    );
    assert!(
        !out.nodes.iter().any(|n| n.label.contains("their")),
        "no node label may carry the stranger's claim text; got {:?}",
        out.nodes.iter().map(|n| &n.label).collect::<Vec<_>>()
    );
    for e in &out.edges {
        assert!(
            ids.contains(&e.target),
            "every returned edge must land on a node that survived the filter; \
             {} -> {} does not",
            e.source,
            e.target
        );
    }
}

/// The centre itself, when the viewer cannot read it: `404`, identically to a
/// claim that does not exist.
///
/// This is the arm that makes the handler not an existence oracle, and it is
/// asserted by comparing the WHOLE error payload against a fresh random uuid's,
/// not by comparing status codes. A status-only assertion passes while the
/// oracle stands — that is the finding `read_path_authz_test.rs::
/// get_claim_private_and_nonexistent_are_indistinguishable_to_a_stranger`
/// records, and this handler returns a bare `(StatusCode, String)` pair whose
/// String is the entire body, so the comparison is exact rather than modulo an
/// echoed id.
#[sqlx::test(migrations = "../../migrations")]
async fn compound_neighborhood_of_an_invisible_centre_is_the_same_404_as_a_missing_one(
    pool: PgPool,
) {
    let (viewer_agent, _viewer_group) = seed_agent_with_group(&pool, "gx-cn404-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "gx-cn404-theirs").await;

    let secret = seed_group_claim(
        &pool,
        stranger,
        stranger_group,
        "gx cn: a centre that is none of the viewer's business",
    )
    .await;

    async fn refusal(pool: &PgPool, agent: Uuid, id: Uuid) -> (axum::http::StatusCode, String) {
        let state = split_state(pool).await;
        let viewer = viewer_for(pool, agent).await;
        claim_compound_neighborhood(
            ViewerExtractor(viewer),
            State(state),
            Path(id),
            Query(CompoundNeighborhoodParams { budget: 50 }),
        )
        .await
        .expect_err("a centre the viewer cannot read must not produce a 200")
    }

    let invisible = refusal(&pool, viewer_agent, secret).await;
    let nonexistent = refusal(&pool, viewer_agent, Uuid::new_v4()).await;

    assert_eq!(
        invisible.0,
        axum::http::StatusCode::NOT_FOUND,
        "an invisible centre is an absence, not a 403 and not a blanked 200"
    );
    assert_eq!(
        invisible, nonexistent,
        "the response for a claim the viewer cannot read must be BYTE-IDENTICAL to the \
         response for a uuid that names no row. Any difference — status, message, \
         punctuation — is an existence oracle over private claim ids"
    );

    // CALIBRATION: the owner of that same claim gets a 200, so the assertion
    // above cannot be satisfied by a handler that 404s everybody.
    let state = split_state(&pool).await;
    let owner_viewer = viewer_for(&pool, stranger).await;
    let out = claim_compound_neighborhood(
        ViewerExtractor(owner_viewer),
        State(state),
        Path(secret),
        Query(CompoundNeighborhoodParams { budget: 50 }),
    )
    .await
    .expect("the claim's own owner must be served, or the 404 above proves nothing")
    .0;
    assert_eq!(out.center_id, secret);
}
