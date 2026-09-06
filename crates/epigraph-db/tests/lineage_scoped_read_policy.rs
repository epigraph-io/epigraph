//! The POLICY half of PR-26: on a genuinely filtered session, the lineage walk
//! served through a viewer-stamped connection returns the viewer's own rows and
//! the same walk on an UNSTAMPED connection returns nothing.
//!
//! # Why this file exists separately from the api-crate one
//!
//! `crates/epigraph-api/tests/lineage_scoped_read.rs` asserts the SUPPRESSION
//! properties of the converted handler, and says plainly that it observes the
//! in-query `$V` predicate rather than migration 077's policies: its scoped arm
//! is a superuser session, because `ScopedPoolOptions` has no `after_connect`
//! knob to downgrade it with.
//!
//! This file pins the other half, and it is the half the CONVERSION is for. The
//! two filters — the `$V` bind that `Viewer::splice` renders, and the
//! `epigraph.group_ids` GUC that 077's policies read — are populated by two
//! independent code paths. An unstamped connection has the first and not the
//! second, so under 079's `FORCE` they disagree and **rows vanish from their own
//! owners with a 200 and no log line**. That is the §9.2 step 11d outage
//! `D-PR17-request-path-never-stamps-session-gucs` blocks on, and it is
//! invisible to any assertion written as "a stranger cannot read".
//!
//! # The control arm IS the mutation
//!
//! Both arms below call the SAME function — `LineageRepository::get_lineage_conn`
//! — with the same viewer, the same seeded graph, and the same
//! `SET SESSION AUTHORIZATION epigraph_app` downgrade. Exactly one variable
//! differs: whether the connection was stamped by `ScopedPool::read_as` first.
//! So no separate mutant is needed to show the assertion is not tautological;
//! the unstamped arm is an inline mutation of the thing under test, and it is
//! asserted to fail in the direction the conversion fixes.
//!
//! This shape is only expressible because PR-26 inverted the usual `*_conn`
//! duplication: the connection-taking form is the PRIMITIVE, so both arms
//! genuinely execute the same SQL text rather than two texts that are believed
//! to match.
//!
//! # Both `SessionGucMode` arms
//!
//! Factored over the mode, following
//! `qual_guc_coherence.rs::read_as_filtered_case`. `Session` alone would prove
//! the half that already worked: in `Session` mode a `ScopedRead` is a bare
//! connection, so "the five statements run in one transaction" is simply false
//! there, while the identical code in `Transaction` mode is atomic. A shard
//! claiming atomicity has to drive both.
//!
//! # No `grant_app_privileges`
//!
//! Migration 077 issues the app-role grants itself. Re-granting here would paper
//! over a missing grant; a `42501` from these calls is a finding about the
//! migration, not a fixture bug.

mod viewer_fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{LineageRepository, SessionGucMode};
use sqlx::{Executor, PgPool};
use uuid::Uuid;
use viewer_fixture::{scoped_pool_with_mode, seed_agent_with_group, seed_edge, seed_group_claim};

/// What one arm saw.
#[derive(Debug)]
struct Observation {
    ids: Vec<Uuid>,
    /// `false` would make every assertion here pass vacuously.
    bypass: bool,
}

impl Observation {
    fn has(&self, id: Uuid) -> bool {
        self.ids.contains(&id)
    }
}

/// A group-private root with one group-private ancestor, both owned by a group
/// `agent` is an `admin` of.
///
/// The edge is left exactly as migration 070's `edges_tenancy` trigger stamps
/// it: both endpoints are private to the same group, so it inherits that group.
/// It must NOT be forced public here — this fixture's whole subject is whether
/// the viewer's OWN rows survive, and a public edge would make the ancestor
/// reachable for a reason other than the one under test.
async fn seed_graph(pool: &PgPool, label: &str) -> (Uuid, Uuid, Uuid) {
    let (agent, group) = seed_agent_with_group(pool, label).await;
    let root = seed_group_claim(pool, agent, group, "policy-half root").await;
    let ancestor = seed_group_claim(pool, agent, group, "policy-half ancestor").await;
    seed_edge(pool, ancestor, root).await;
    (agent, root, ancestor)
}

/// The walk through a `read_as` connection, downgraded to `epigraph_app` AFTER
/// the stamp lands.
///
/// The stamp is issued by the superuser session `read_as` opens, then the role
/// is switched on that same connection — the only idiom that composes with
/// `AppState::read_as`, which acquires its own connection internally and offers
/// no seam a `viewer_fixture::as_role` closure could be routed through.
async fn stamped(pool: &PgPool, mode: SessionGucMode, agent: Uuid, root: Uuid) -> Observation {
    let scoped = scoped_pool_with_mode(pool, mode).await;
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");

    let mut r = scoped.read_as(&viewer).await.expect("read_as");
    assert_eq!(
        r.mode(),
        mode,
        "CALIBRATION: read_as must dispatch on the pool's mode, or the two arms of \
         this file are the same arm"
    );
    r.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("SET SESSION AUTHORIZATION requires a superuser connection");

    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *r)
        .await
        .expect("epigraph_bypass()");

    let result = LineageRepository::get_lineage_conn(&mut r, &viewer, root, Some(10), None)
        .await
        .expect("the stamped walk must SERVE — a failure here is the outage, not the fix");

    r.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    // Explicit: `ScopedRead` has no `Drop` impl, so the transaction arm would
    // roll back silently on drop.
    r.commit().await.expect("commit");

    Observation {
        ids: result.claims.keys().copied().collect(),
        bypass,
    }
}

/// The same walk, the same viewer, the same primitive — on a connection nothing
/// stamped. This is the pre-conversion request path.
async fn unstamped(pool: &PgPool, agent: Uuid, root: Uuid) -> Observation {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("SET SESSION AUTHORIZATION");

    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_bypass()");

    let result = LineageRepository::get_lineage_conn(&mut conn, &viewer, root, Some(10), None)
        .await
        .expect(
            "the unstamped walk must not ERROR — it must return FEWER rows, which is \
                 precisely why the defect is invisible",
        );

    // Mandatory: this pool has no `after_release` scrub, so a connection left as
    // `epigraph_app` would fail an unrelated later test somewhere else entirely.
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");

    Observation {
        ids: result.claims.keys().copied().collect(),
        bypass,
    }
}

async fn coherence_case(pool: PgPool, mode: SessionGucMode) {
    let (agent, root, ancestor) = seed_graph(&pool, &format!("policy-half-{mode:?}")).await;

    let stamped = stamped(&pool, mode, agent, root).await;
    let unstamped = unstamped(&pool, agent, root).await;

    assert!(
        !stamped.bypass,
        "CALIBRATION ({mode:?}): the stamped session must NOT hold bypass, or the \
         policies filter nothing and this test passes vacuously"
    );
    assert!(
        !unstamped.bypass,
        "CALIBRATION ({mode:?}): the unstamped session must NOT hold bypass either — \
         if it did, the differential below would be an artifact of the role switch \
         rather than of the stamp"
    );

    assert!(
        stamped.has(root) && stamped.has(ancestor),
        "COHERENCE ({mode:?}): the group whose id the walk binds as $V is in the GUC \
         read_as stamped, so 077's policies must admit that group's private root AND \
         the ancestor the recursive term reaches through its own private edge. \
         Missing rows here are the fail-closed drift that is indistinguishable from \
         data loss. got {:?}",
        stamped.ids
    );

    assert!(
        unstamped.ids.is_empty(),
        "THE DIFFERENTIAL ({mode:?}): the identical call on an UNSTAMPED connection \
         must return nothing — the $V predicate admits the rows and the policy, seeing \
         no epigraph.group_ids, does not. If this is non-empty the fixture is not \
         filtering and the assertion above proves nothing about the conversion. got {:?}",
        unstamped.ids
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_walk_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_session_mode(
    pool: PgPool,
) {
    coherence_case(pool, SessionGucMode::Session).await;
}

// ---------------------------------------------------------------------------
// The ANCHOR term, which no handler-level test can reach
// ---------------------------------------------------------------------------
//
// Both walks carry the visibility predicate in three places: the anchor term,
// the recursive term's `claims` alias, and the `edges` join. The api-crate
// tests pin the second and the third. They CANNOT pin the first: the handler's
// existence probe runs `get_by_id_conn` on the root before the walk and 404s, so
// a root the viewer may not read never reaches the CTE at all.
//
// MEASURED, not assumed: with the anchor marker deleted from
// `get_lineage_conn`, every test in this shard and all 19 in `lineage_tests.rs`
// stayed GREEN. The repo function has a non-handler caller —
// `epigraph-mcp/src/tools/provenance.rs::get_provenance` — with no such probe in
// front of it, so the anchor is load-bearing on a live surface. These two are
// what fail when it is dropped.
//
// A superuser session is the right fixture here and is deliberate: with no
// policy filtering, the marker is the ONLY thing that can produce the empty
// result, so a pass is attributable. The filtered-session property is the
// business of the two tests above.

/// Assert `walk` returns nothing for a stranger's root and something for the
/// viewer's own, on a session where only the spliced predicate can be filtering.
async fn anchor_case<F, Fut>(pool: &PgPool, label: &str, walk: F)
where
    F: Fn(Uuid, Uuid) -> Fut,
    Fut: std::future::Future<Output = Vec<Uuid>>,
{
    let (agent, group) = seed_agent_with_group(pool, &format!("anchor-mine-{label}")).await;
    let (stranger, stranger_group) =
        seed_agent_with_group(pool, &format!("anchor-theirs-{label}")).await;

    let mine = seed_group_claim(pool, agent, group, "anchor: my root").await;
    let theirs = seed_group_claim(pool, stranger, stranger_group, "anchor: their root").await;

    // CALIBRATION: the same call over the viewer's OWN root returns it, so the
    // emptiness below is about the predicate and not about the fixture, the
    // depth cap, or a root that simply has no rows.
    let own = walk(agent, mine).await;
    assert!(
        own.contains(&mine),
        "CALIBRATION ({label}): the viewer's own root must appear in its own walk; got {own:?}"
    );

    let foreign = walk(agent, theirs).await;
    assert!(
        foreign.is_empty(),
        "the ANCHOR term must suppress a root the viewer cannot see. There is no \
         existence probe in front of the repo layer's non-handler callers, so a walk \
         seeded from a stranger's claim would return that claim's CONTENT in full. \
         ({label}); got {foreign:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_ancestor_walks_anchor_term_suppresses_a_root_the_viewer_cannot_see(pool: PgPool) {
    anchor_case(&pool, "ancestors", |agent, root| {
        let pool = pool.clone();
        async move {
            let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
            let mut conn = pool.acquire().await.expect("acquire");
            LineageRepository::get_lineage_conn(&mut conn, &viewer, root, Some(10), None)
                .await
                .expect("walk")
                .claims
                .keys()
                .copied()
                .collect()
        }
    })
    .await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_descendant_walks_anchor_term_suppresses_a_root_the_viewer_cannot_see(pool: PgPool) {
    anchor_case(&pool, "descendants", |agent, root| {
        let pool = pool.clone();
        async move {
            let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
            let mut conn = pool.acquire().await.expect("acquire");
            LineageRepository::get_descendants_conn(&mut conn, &viewer, root, Some(10))
                .await
                .expect("walk")
                .claims
                .keys()
                .copied()
                .collect()
        }
    })
    .await;
}

/// The arm `viewer_fixture::scoped_pool` cannot reach.
///
/// `ScopedPool::acquire_as` hard-refuses `Transaction` mode, so this is also the
/// arm that proves the converted handler is servable behind the transaction-mode
/// pooler `bin/server.rs` advertises to operators — the reason the conversion
/// targets `AppState::read_as` and not a literal `acquire_as`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_walk_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_transaction_mode(
    pool: PgPool,
) {
    coherence_case(pool, SessionGucMode::Transaction).await;
}
