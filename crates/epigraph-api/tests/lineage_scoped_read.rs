//! `routes/lineage.rs::get_lineage` serves the whole lineage walk on ONE
//! viewer-stamped connection, and the walk suppresses on the viewer.
//!
//! # What this file is, in the series
//!
//! PR-26 is the FIRST conversion shard against
//! `D-PR17-request-path-never-stamps-session-gucs`, and its job is to establish
//! the template ~50 later shards copy. `routes/conflicts.rs::classify_conflict`
//! is the pilot this copies: direct `async fn` invocation, a CALIBRATION arm on
//! every negative assertion, an explicit `read.commit()`, and `ApiError::NotFound`
//! as the shape of "not visible" (a non-visible row is ABSENT, not blanked —
//! PR-14).
//!
//! # THE TRAP THE PILOT DOCUMENTS, AND WHAT THIS FILE DOES ABOUT IT
//!
//! `#[sqlx::test]` connects as `epigraph`, which is superuser, `BYPASSRLS` AND
//! the table owner, so **no RLS policy filters anything on the pool it hands
//! you**. Both halves of the pilot's negative assertion therefore observe the
//! in-query `$V` predicate and never the policy. Worse for a *conversion*
//! shard: `AppState::with_scoped_pool` sets `db_pool = scoped.inner().clone()`,
//! so on that fixture the converted and unconverted arms are the SAME POOL and
//! reverting a site to `&state.db_pool` changes not one observable row. A
//! mutation proof built on it reports a false pass — in the PR whose entire
//! purpose is to be copied.
//!
//! So [`viewer_fixture::downgraded_pool`] gives `AppState.db_pool` its own pool
//! whose every connection is `SET SESSION AUTHORIZATION epigraph_app` in
//! `after_connect`, while `AppState.scoped` holds an ordinary `ScopedPool`.
//! `db_pool != scoped.inner()`, the raw arm is FILTERED and unstamped, and
//! reverting any of the seven converted sites is observable. 079's own
//! preconditions state that `current_user` on the production API pool is
//! exactly `epigraph_app`, so this fixture is MORE production-faithful than the
//! superuser default, not less.
//!
//! # What is still NOT proven here, stated rather than left to be discovered
//!
//! `ScopedPoolOptions` exposes `max_connections` / `acquire_timeout` /
//! `statement_timeout` and no `after_connect`, so the SCOPED arm is still a
//! superuser session. The assertions below therefore observe the in-query
//! `$V` predicate on the converted path, exactly as the pilot's do. The policy
//! half — that a STAMPED connection and an UNSTAMPED one disagree about the
//! viewer's own rows once the session is filtered — is pinned on the repo
//! primitives in
//! `epigraph-db/tests/lineage_scoped_read_policy.rs`, on both `SessionGucMode`
//! arms. Neither file is sufficient alone.
//!
//! The handler is called directly rather than over HTTP, and what remains owed
//! at the HTTP level is NARROWER than this paragraph said before conversion
//! shard 4. **Corrected by that shard, which falsified the premise:** `spawn_app`
//! no longer builds `AppState` through a non-scoped constructor —
//! `build_app_for_tests` goes through `AppState::with_scoped_pool`, so an HTTP
//! fixture CAN reach a stamped read today and a converted route no longer 500s
//! there. What it still cannot do is tell a converted site from an unconverted
//! one: `with_scoped_pool` sets `db_pool = scoped.inner().clone()`, so both arms
//! are the SAME pool and a mutation proof built on it reports a false pass.
//! The owed thing is therefore a FILTERED pool for the fixture's `db_pool`,
//! which is exactly how `docs/tenancy/progress.json`'s `prs.next` re-specified
//! it — "give the api test fixture a filtered pool", re-specified away from "an
//! HTTP fixture that builds AppState through with_scoped_pool" precisely
//! because that half would have been cosmetic. It is still open. The instrument
//! that can see the difference remains `viewer_fixture::downgraded_pool`, used
//! by this file and by `belief_computation_scoped_read.rs`.
//!
//! Finally: `crates/epigraph-api/tests/integration/lineage_integration_tests.rs`
//! shares this endpoint's NAME and covers none of it — it declares its own DTOs
//! and routes `/lineage/:claim_id` to a `mock_lineage_handler`, importing
//! nothing from `epigraph_api`. A green run there is not evidence about this
//! shard.

mod viewer_fixture;

use axum::extract::{Path, Query, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::lineage::{
    get_lineage, LineageDirection, LineageParams, LineageResponse,
};
use epigraph_api::state::{ApiConfig, AppState};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    downgraded_pool, scoped_pool, seed_agent_with_group, seed_edge, seed_edge_owned_by,
    seed_group_claim, seed_public_claim, world_group,
};

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

fn params(direction: Option<LineageDirection>) -> LineageParams {
    LineageParams {
        max_depth: None,
        direction, // `None` defaults to Ancestors
        include_evidence: None,
        include_traces: None,
    }
}

async fn walk(pool: &PgPool, state: AppState, agent: Uuid, root: Uuid) -> LineageResponse {
    walk_in(pool, state, agent, root, None).await
}

async fn walk_in(
    pool: &PgPool,
    state: AppState,
    agent: Uuid,
    root: Uuid,
    direction: Option<LineageDirection>,
) -> LineageResponse {
    // Resolved on the SUPERUSER pool, never the downgraded one: `Viewer::resolve`
    // reads `group_memberships`, and on a filtered unstamped session it resolves
    // to an EMPTY group set — which would satisfy every "a stranger is absent"
    // assertion here for entirely the wrong reason.
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve");

    get_lineage(
        ViewerExtractor(viewer),
        State(state),
        Path(root),
        Query(params(direction)),
    )
    .await
    .expect(
        "the viewer can see the root claim, so the walk must SERVE. Two different \
         defects surface here rather than in an assertion below, and both are real \
         findings: (a) the handler read the raw pool, so a filtered, unstamped session \
         could not see the viewer's own group-private root at all; (b) the recursive \
         term admitted a claim the per-node `get_by_id_conn` then refuses, which is the \
         half-conversion — the walk and the point read disagreeing about the same \
         viewer. Read the entity id against the fixture to tell them apart",
    )
    .0
}

fn node_ids(r: &LineageResponse) -> Vec<Uuid> {
    r.nodes.iter().map(|n| n.claim_id).collect()
}

/// THE OVER-SUPPRESSION DIRECTION, and the one that catches a reversion to the
/// raw pool.
///
/// A group-private ancestor the viewer IS entitled to read must still come back.
/// This direction is silent and permanent — it looks like data loss, not like a
/// leak — and it is the one PR-24's Mutation B broke.
///
/// It is also the mutation-1 detector: with the handler reverted to
/// `&state.db_pool`, the existence probe runs on a filtered, unstamped session
/// that cannot see the viewer's own group-private root, and the call 404s.
#[sqlx::test(migrations = "../../migrations")]
async fn the_walk_serves_the_viewers_own_group_private_ancestor(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "lineage-mine").await;

    let root = seed_group_claim(&pool, agent, group, "lineage root").await;
    let ancestor = seed_group_claim(&pool, agent, group, "my private ancestor").await;
    // Left exactly as the 070 trigger stamps it: both endpoints are private to
    // the SAME group, so the edge inherits that group and the viewer can see it.
    // Forcing this one public would destroy the calibration.
    seed_edge(&pool, ancestor, root).await;

    let state = split_state(&pool).await;
    let out = walk(&pool, state, agent, root).await;

    let ids = node_ids(&out);
    assert!(
        ids.contains(&root),
        "the root claim must be in its own lineage; got {ids:?}"
    );
    assert!(
        ids.contains(&ancestor),
        "a group-private ancestor the viewer is a MEMBER of must be served. Absence \
         here is the fail-closed drift that reads as data loss — and if the handler \
         is reading the raw pool instead of a stamped connection, this is where it \
         shows. got {ids:?}"
    );
}

/// THE SUPPRESSION DIRECTION, through the RECURSIVE term.
///
/// The stranger's ancestor is reachable over an edge the viewer CAN see, so the
/// only thing keeping it out of the walk is `/* {VISIBILITY:c} */` on the
/// recursive term. Marking only the anchor is the classic half-conversion, and
/// `visibility_lint.rs` checks that a marker is present, not WHERE.
///
/// The edge is forced public on purpose. Left as the 070 trigger stamps it, a
/// stranger-owned ancestor yields a stranger-owned edge, `{EDGE_VISIBILITY:e}`
/// suppresses the row independently, and this assertion passes with the
/// recursive claim predicate deleted.
#[sqlx::test(migrations = "../../migrations")]
async fn the_walk_does_not_serve_a_strangers_group_private_ancestor(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "lineage-recursive-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "lineage-recursive-theirs").await;
    let world = world_group(&pool).await;

    let root = seed_group_claim(&pool, agent, group, "recursive root").await;
    let mine = seed_group_claim(&pool, agent, group, "my ancestor").await;
    let theirs = seed_group_claim(&pool, stranger, stranger_group, "not my ancestor").await;

    seed_edge(&pool, mine, root).await;
    seed_edge_owned_by(&pool, theirs, root, "public", world).await;

    let state = split_state(&pool).await;
    let out = walk(&pool, state, agent, root).await;

    let ids = node_ids(&out);
    // CALIBRATION: the same walk, at the same depth, over an edge of the same
    // shape, DOES return an ancestor this viewer may read — so the absence below
    // is about tenancy and not about the graph, the depth cap or the fixture.
    assert!(
        ids.contains(&mine),
        "CALIBRATION: the viewer's own depth-1 ancestor must be reachable, or the \
         assertion below proves only that the walk found nothing; got {ids:?}"
    );
    assert!(
        !ids.contains(&theirs),
        "a claim owned by a group the viewer is not in must be ABSENT from the walk, \
         not present with its content blanked. It is reachable over a PUBLIC edge, so \
         the only control excluding it is the visibility predicate on the RECURSIVE \
         term; got {ids:?}"
    );
}

/// THE OTHER WALK. `get_descendants_conn` is a SEPARATE recursive CTE with its
/// own six markers, and the assertions above exercise none of it —
/// `direction` defaults to `ancestors`.
///
/// The shard converts both, and the register's own rule is that one function
/// being correct does not cover its twin. The two are also deliberately NOT
/// unified: the descendant walk sorts depth ASCENDING where the ancestor walk
/// sorts DESCENDING, has no `max_nodes` cap and hardcodes `truncated: false`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_descendant_walk_does_not_serve_a_strangers_group_private_descendant(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "lineage-desc-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "lineage-desc-theirs").await;
    let world = world_group(&pool).await;

    let root = seed_group_claim(&pool, agent, group, "descendant root").await;
    let mine = seed_group_claim(&pool, agent, group, "my descendant").await;
    let theirs = seed_group_claim(&pool, stranger, stranger_group, "not my descendant").await;

    // The descendant walk follows edges FORWARD: root is the SOURCE.
    seed_edge(&pool, root, mine).await;
    seed_edge_owned_by(&pool, root, theirs, "public", world).await;

    let state = split_state(&pool).await;
    let out = walk_in(
        &pool,
        state,
        agent,
        root,
        Some(LineageDirection::Descendants),
    )
    .await;

    let ids = node_ids(&out);
    assert!(
        ids.contains(&mine),
        "CALIBRATION: the viewer's own depth-1 DESCENDANT must be reachable, or the \
         assertion below proves only that the descendant walk found nothing; got {ids:?}"
    );
    assert!(
        !ids.contains(&theirs),
        "a descendant owned by a group the viewer is not in must be ABSENT. It is \
         reachable over a PUBLIC edge, so the only control excluding it is the \
         visibility predicate on get_descendants' RECURSIVE term; got {ids:?}"
    );
}

/// THE `Both` ARM — the only one that runs two walks on one connection, and
/// the arm the handler's atomicity prose is about.
///
/// Every other test here passes `None` (which defaults to `Ancestors`) or
/// `Descendants`, so before this test the `Both` branch was NEVER EXECUTED:
/// neither the second `get_ancestor_lineage`/`get_descendant_lineage` pair on
/// the same handle nor the node/edge merge that follows them. A later shard
/// re-introducing a second `state.read_as(&viewer)` inside
/// `get_descendant_lineage` — the single most likely regression, because that
/// is what the pre-conversion shape looked like — would have falsified the
/// handler's central claim and left every assertion in this file green.
///
/// This does NOT prove single-connection-ness; nothing here can observe the
/// checkout. It makes the arm executable, so the stronger assertion has
/// somewhere to hang, and it pins the dedup (nodes by `claim_id`, edges by
/// `(source_id, target_id)`) that is otherwise unexercised.
#[sqlx::test(migrations = "../../migrations")]
async fn the_both_arm_merges_one_ancestor_and_one_descendant_without_duplicating_the_root(
    pool: PgPool,
) {
    let (agent, group) = seed_agent_with_group(&pool, "lineage-both").await;

    let root = seed_group_claim(&pool, agent, group, "both root").await;
    let ancestor = seed_group_claim(&pool, agent, group, "both ancestor").await;
    let descendant = seed_group_claim(&pool, agent, group, "both descendant").await;

    // Left as the 070 trigger stamps them: all three claims are private to the
    // SAME group, so both edges inherit it and the viewer can traverse them.
    seed_edge(&pool, ancestor, root).await;
    seed_edge(&pool, root, descendant).await;

    let state = split_state(&pool).await;
    let out = walk_in(&pool, state, agent, root, Some(LineageDirection::Both)).await;

    let ids = node_ids(&out);
    assert!(
        ids.contains(&ancestor) && ids.contains(&descendant),
        "the Both arm must merge the results of BOTH walks — an ancestor from one and \
         a descendant from the other. A missing side means one walk did not run or its \
         nodes were dropped by the merge; got {ids:?}"
    );

    // The root is returned by BOTH walks, so it is the only row the node merge
    // can duplicate. Counting is the assertion: `contains` would pass on a
    // merge that appends blindly.
    assert_eq!(
        ids.iter().filter(|i| **i == root).count(),
        1,
        "the root appears in both walks, so the HashSet dedup on claim_id is what keeps \
         it single. A duplicate here is a merge regression, not a tenancy one; got {ids:?}"
    );
    let edge_keys: Vec<(Uuid, Uuid)> = out
        .edges
        .iter()
        .map(|e| (e.source_id, e.target_id))
        .collect();
    let mut unique = edge_keys.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        edge_keys.len(),
        unique.len(),
        "the edge merge dedups on (source_id, target_id); got {edge_keys:?}"
    );
    assert!(
        edge_keys.contains(&(ancestor, root)) && edge_keys.contains(&(root, descendant)),
        "both edges must survive the merge, or the dedup above is passing over an empty \
         set; got {edge_keys:?}"
    );
}

/// THE EDGE AXIS, which neither assertion above covers.
///
/// Both endpoints are PUBLIC, so `/* {VISIBILITY:c} */` admits the ancestor on
/// every term. The only thing stopping the walk is
/// `/* {EDGE_VISIBILITY:e} */` on the `edges` join that carries it. Without this
/// arm the shard would claim a three-part control (anchor + recursive claims +
/// edges join) while pinning two parts of it.
///
/// The private edge between two public endpoints is the ONE declaration
/// migration 070's trigger honours on INSERT — it is the case where the
/// endpoint meet would WIDEN a declared-private row — so the forced UPDATE is
/// belt-and-braces here rather than load-bearing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_walk_does_not_traverse_an_edge_outside_the_viewers_groups(pool: PgPool) {
    let (agent, _group) = seed_agent_with_group(&pool, "lineage-edge-mine").await;
    let (_stranger, stranger_group) = seed_agent_with_group(&pool, "lineage-edge-theirs").await;

    let root = seed_public_claim(&pool, agent, "edge-arm root").await;
    let reachable = seed_public_claim(&pool, agent, "ancestor over a public edge").await;
    let blocked = seed_public_claim(&pool, agent, "ancestor over a private edge").await;

    seed_edge(&pool, reachable, root).await;
    seed_edge_owned_by(&pool, blocked, root, "group", stranger_group).await;

    let state = split_state(&pool).await;
    let out = walk(&pool, state, agent, root).await;

    let ids = node_ids(&out);
    // CALIBRATION: an identical public ancestor IS reached, so the absence below
    // is about the edge's tenancy and not about the claim's or the walk's.
    assert!(
        ids.contains(&reachable),
        "CALIBRATION: a public ancestor over a public edge must be reachable; got {ids:?}"
    );
    assert!(
        !ids.contains(&blocked),
        "a PUBLIC claim reachable only over an edge owned by a group the viewer is not \
         in must not enter the walk: the edge itself is the tenanted object, and its \
         existence discloses a relationship. got {ids:?}"
    );
}

/// The edge axis on the OTHER walk. `get_descendants` has its own
/// `/* {EDGE_VISIBILITY:e} */`, on its own reversed join, and the ancestor arm
/// above does not reach it — MEASURED: with only that assertion, deleting the
/// descendant walk's edge marker left every test in this shard green.
#[sqlx::test(migrations = "../../migrations")]
async fn the_descendant_walk_does_not_traverse_an_edge_outside_the_viewers_groups(pool: PgPool) {
    let (agent, _group) = seed_agent_with_group(&pool, "lineage-desc-edge-mine").await;
    let (_stranger, stranger_group) =
        seed_agent_with_group(&pool, "lineage-desc-edge-theirs").await;

    let root = seed_public_claim(&pool, agent, "descendant edge-arm root").await;
    let reachable = seed_public_claim(&pool, agent, "descendant over a public edge").await;
    let blocked = seed_public_claim(&pool, agent, "descendant over a private edge").await;

    seed_edge(&pool, root, reachable).await;
    seed_edge_owned_by(&pool, root, blocked, "group", stranger_group).await;

    let state = split_state(&pool).await;
    let out = walk_in(
        &pool,
        state,
        agent,
        root,
        Some(LineageDirection::Descendants),
    )
    .await;

    let ids = node_ids(&out);
    assert!(
        ids.contains(&reachable),
        "CALIBRATION: a public descendant over a public edge must be reachable; got {ids:?}"
    );
    assert!(
        !ids.contains(&blocked),
        "the descendant walk must not traverse an edge owned by a group the viewer is \
         not in, for the same reason the ancestor walk must not; got {ids:?}"
    );
}
