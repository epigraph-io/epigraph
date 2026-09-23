//! The repo half of `F-FAH-A1` (deferred-commitment screen key
//! `f-fah-a1-reasoning-analyze`). `EdgeRepository::claim_edges_for_reasoning`
//! is the edge read `POST /api/v1/reasoning/analyze` runs. It returns only
//! edges in force that the caller's `Viewer` may read, and only between claims
//! the caller may read.
//!
//! Before this function existed, the read ran inline in the route layer, on the
//! raw pool, with no viewer predicate and no retraction filter. With no claim
//! set given, it scanned every tenant's claim-to-claim edges up to its cap.
//!
//! # Two halves, as the sibling `_policy` files split them
//!
//! The PREDICATE half runs on the `#[sqlx::test]` superuser pool. No RLS policy
//! filters anything there, so what it observes is the in-query predicate
//! alone. Every stranger arm is paired with an owner arm over the same rows, so
//! "the stranger saw nothing" cannot pass just because the fixture was empty.
//! The stranger is a real principal with a non-empty group set of its own, so
//! the group array is bound with members in it. It is bound at `$3` on the
//! restricted branch and at `$2` on the unrestricted one. Both branches are
//! driven, so a bind on the wrong index would be a type error or a wrong row
//! set, not a silent pass.
//!
//! Edge tenancy is FORCED with `seed_edge_owned_by` wherever a single
//! predicate is under test, for the reason that helper documents. Left to
//! migration 070's trigger, an edge touching a private claim is private too.
//! An assertion that the hidden claim is absent would then be satisfied by the
//! EDGE predicate alone, even with the claim predicate deleted.
//!
//! The POLICY half downgrades a connection to `epigraph_app` with
//! `SET SESSION AUTHORIZATION`, which is where migration 077's policies filter.
//! It runs the read twice with the same viewer and rows: once on a connection
//! `ScopedPool::read_as` stamped, once on a connection nothing stamped. The
//! unstamped arm is an inline mutation of the conversion. The owner's own
//! private edge must vanish there. That is what the unconverted handler
//! computed under the application role: a 200 with the caller's own edges
//! left out.
//!
//! # No `grant_app_privileges`
//!
//! Migration 077 issues the app-role grants itself. Re-granting here would
//! paper over a missing grant; a `42501` from these calls is a finding about
//! the migration, not a fixture bug.

mod viewer_fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{EdgeRepository, SessionGucMode};
use sqlx::{Executor, PgPool};
use uuid::Uuid;
use viewer_fixture::{
    bypass, scoped_pool_with_mode, seed_agent_with_group, seed_edge, seed_edge_owned_by,
    seed_group_claim, seed_public_claim, world_group,
};

/// The cap the route passes. Large enough that no arm below is truncated
/// except the one that sets its own.
const CAP: i64 = 10_000;

type Pair = (Uuid, Uuid);

/// `(source, target)` pairs, sorted, restricted to `keep`. The restriction is
/// for the unrestricted branch, which also returns whatever the migrations
/// seeded. Every edge this file seeds has both endpoints in `keep`.
fn pairs(rows: Vec<(Uuid, Uuid, String, serde_json::Value)>, keep: &[Uuid]) -> Vec<Pair> {
    let mut out: Vec<Pair> = rows
        .into_iter()
        .filter(|(s, t, _, _)| keep.contains(s) && keep.contains(t))
        .map(|(s, t, _, _)| (s, t))
        .collect();
    out.sort();
    out
}

fn sorted(mut v: Vec<Pair>) -> Vec<Pair> {
    v.sort();
    v
}

async fn read(
    pool: &PgPool,
    viewer: &Viewer,
    among: Option<&[Uuid]>,
    limit: i64,
) -> Vec<(Uuid, Uuid, String, serde_json::Value)> {
    EdgeRepository::claim_edges_for_reasoning(pool, viewer, among, limit)
        .await
        .expect("the reasoning edge read must not error; a filtered read returns fewer rows")
}

/// The owner's graph, one hazard per edge:
///
/// ```text
///   p0 --public edge--> h (private claim)     only the claim predicate drops it
///   h  --public edge--> p1                    only the claim predicate drops it
///   p0 --private edge-> p2 (public claim)     only the edge predicate drops it
///   p0 --public edge--> p3 (public claim)     the control a stranger must see
///   p3 --RETRACTED----> p4 (public claim)     dropped for every viewer
/// ```
///
/// Returns `(owner, stranger, [p0, h, p1, p2, p3, p4])`.
async fn seed_hazard_graph(pool: &PgPool) -> (Uuid, Uuid, [Uuid; 6]) {
    let (owner, group) = seed_agent_with_group(pool, "reasoning-owner").await;
    let (stranger, _) = seed_agent_with_group(pool, "reasoning-stranger").await;
    let world = world_group(pool).await;
    let tag = Uuid::new_v4();

    let p0 = seed_public_claim(pool, owner, &format!("reasoning p0 {tag}")).await;
    let h = seed_group_claim(pool, owner, group, &format!("reasoning h {tag}")).await;
    let p1 = seed_public_claim(pool, owner, &format!("reasoning p1 {tag}")).await;
    let p2 = seed_public_claim(pool, owner, &format!("reasoning p2 {tag}")).await;
    let p3 = seed_public_claim(pool, owner, &format!("reasoning p3 {tag}")).await;
    let p4 = seed_public_claim(pool, owner, &format!("reasoning p4 {tag}")).await;

    // Forced PUBLIC, so only the endpoint predicates can drop them.
    seed_edge_owned_by(pool, p0, h, "public", world).await;
    seed_edge_owned_by(pool, h, p1, "public", world).await;
    // Forced PRIVATE between two public claims, so only the edge predicate can
    // drop it.
    seed_edge_owned_by(pool, p0, p2, "group", group).await;
    // Left to the trigger: public/public stays public.
    let control = seed_edge(pool, p0, p3).await;
    sqlx::query("UPDATE edges SET properties = '{\"strength\": 0.9}'::jsonb WHERE id = $1")
        .bind(control)
        .execute(pool)
        .await
        .expect("set the control edge's strength");
    // Public, then retracted through the production retraction path.
    let retracted = seed_edge(pool, p3, p4).await;
    let closed = EdgeRepository::retract(pool, &[retracted])
        .await
        .expect("retract");
    assert_eq!(
        closed,
        vec![retracted],
        "CALIBRATION: the retraction landed"
    );

    (owner, stranger, [p0, h, p1, p2, p3, p4])
}

// ── Predicate half: the superuser pool, where only the in-query predicate filters ──

/// A stranger reads only the public control edge, on both branches. The owner
/// reads every edge in force over the same rows, which is what makes the
/// stranger's result a filter and not an empty fixture. Nobody reads the
/// retracted edge.
#[sqlx::test(migrations = "../../migrations")]
async fn the_read_returns_only_edges_in_force_the_viewer_may_read_between_claims_it_may_read(
    pool: PgPool,
) {
    let (owner, stranger, ids) = seed_hazard_graph(&pool).await;
    let [p0, h, p1, p2, p3, _p4] = ids;
    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");
    assert!(
        !stranger_v.group_bind().expect("scoped").is_empty(),
        "CALIBRATION: the stranger must hold a group of its own, so the group array \
         is bound with members in it"
    );

    let everything_in_force = sorted(vec![(p0, h), (h, p1), (p0, p2), (p0, p3)]);

    // Restricted branch: `$1` is the set, `$2` the cap, `$3` the group array.
    assert_eq!(
        pairs(read(&pool, &owner_v, Some(&ids[..]), CAP).await, &ids),
        everything_in_force,
        "CALIBRATION: the owner reads its own private claim's edges and its own \
         private edge, but not the retracted one"
    );
    assert_eq!(
        pairs(read(&pool, &stranger_v, Some(&ids[..]), CAP).await, &ids),
        vec![(p0, p3)],
        "a stranger must read neither edge touching the owner's private claim h, nor \
         the owner's private edge p0->p2, nor the retracted edge p3->p4, and must \
         still read the public control p0->p3"
    );

    // Unrestricted branch: `$1` is the cap, `$2` the group array. This is the
    // branch that scanned every tenant's edges.
    assert_eq!(
        pairs(read(&pool, &owner_v, None, CAP).await, &ids),
        everything_in_force,
        "CALIBRATION: with no claim set the owner reads the same edges"
    );
    assert_eq!(
        pairs(read(&pool, &stranger_v, None, CAP).await, &ids),
        vec![(p0, p3)],
        "with no claim set, a stranger must still read only the public control"
    );

    // Both endpoints must be in the set, as the route always required.
    assert_eq!(
        pairs(read(&pool, &owner_v, Some(&[p0, p3][..]), CAP).await, &ids),
        vec![(p0, p3)],
        "an edge with one endpoint outside the set must not be returned"
    );

    // A `Bypass` viewer renders no predicate and binds nothing, so each
    // statement has one parameter fewer. On the superuser pool it reads every
    // edge in force, and still not the retracted one.
    let (_scoped, bypass_v) = bypass(&pool).await;
    assert_eq!(
        pairs(read(&pool, &bypass_v, Some(&ids[..]), CAP).await, &ids),
        everything_in_force,
        "a Bypass viewer's restricted read must bind no group array and filter \
         nothing but retraction"
    );
    assert_eq!(
        pairs(read(&pool, &bypass_v, None, CAP).await, &ids),
        everything_in_force,
        "a Bypass viewer's unrestricted read must bind no group array and filter \
         nothing but retraction"
    );
}

/// The row carries the edge's relationship and `properties` through untouched,
/// and the cap cuts the same rows on every call.
#[sqlx::test(migrations = "../../migrations")]
async fn the_read_carries_relationship_and_properties_and_honours_the_cap(pool: PgPool) {
    let (owner, _stranger, ids) = seed_hazard_graph(&pool).await;
    let [p0, _h, _p1, _p2, p3, _p4] = ids;
    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");

    let rows = read(&pool, &owner_v, Some(&[p0, p3][..]), CAP).await;
    assert_eq!(rows.len(), 1, "CALIBRATION: one edge p0->p3; got {rows:?}");
    let (s, t, relationship, properties) = &rows[0];
    assert_eq!((*s, *t), (p0, p3));
    assert_eq!(relationship, "supports");
    assert_eq!(
        properties
            .get("strength")
            .and_then(serde_json::Value::as_f64),
        Some(0.9),
        "the edge's properties must reach the caller, which reads the strength \
         out of them; got {properties}"
    );

    let first = read(&pool, &owner_v, Some(&ids[..]), 1).await;
    assert_eq!(
        first.len(),
        1,
        "a cap of 1 must return one row; got {first:?}"
    );
    assert_eq!(
        read(&pool, &owner_v, Some(&ids[..]), 1).await,
        first,
        "the cap must cut the same row on every call"
    );
}

// ── Policy half: a connection downgraded to `epigraph_app` ──

async fn bypass_held(conn: &mut sqlx::PgConnection) -> bool {
    sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_bypass()")
}

async fn read_on(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    among: Option<&[Uuid]>,
    keep: &[Uuid],
) -> Vec<Pair> {
    pairs(
        EdgeRepository::claim_edges_for_reasoning(&mut *conn, viewer, among, CAP)
            .await
            .expect("the read must not error under the policy; a filtered read returns fewer rows"),
        keep,
    )
}

/// The owner's own group-private pair `x -> y`, the edge stamped private by
/// the trigger, read on a stamped and on an unstamped connection.
async fn policy_differential(pool: PgPool, mode: SessionGucMode) {
    let (owner, group) = seed_agent_with_group(&pool, "reasoning-policy-owner").await;
    let (stranger, _) = seed_agent_with_group(&pool, "reasoning-policy-stranger").await;
    let tag = Uuid::new_v4();
    let x = seed_group_claim(&pool, owner, group, &format!("reasoning policy x {tag}")).await;
    let y = seed_group_claim(&pool, owner, group, &format!("reasoning policy y {tag}")).await;
    seed_edge(&pool, x, y).await;
    let keep = [x, y];

    // Resolve BEFORE downgrading anything, on the superuser pool: resolving on
    // a filtered unstamped session yields an empty group set.
    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");
    let arm = format!("{mode:?}");
    let scoped = scoped_pool_with_mode(&pool, mode).await;

    // Stamped: the connection `AppState::read_as` hands the handler.
    let mut read = scoped.read_as(&owner_v).await.expect("read_as owner");
    read.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    assert!(
        !bypass_held(&mut read).await,
        "CALIBRATION ({arm}): the stamped session must not hold bypass"
    );
    let stamped_owner_among = read_on(&mut read, &owner_v, Some(&keep[..]), &keep).await;
    let stamped_owner_all = read_on(&mut read, &owner_v, None, &keep).await;
    read.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    read.commit().await.expect("commit");

    let mut read = scoped.read_as(&stranger_v).await.expect("read_as stranger");
    read.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    let stamped_stranger = read_on(&mut read, &stranger_v, None, &keep).await;
    read.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    read.commit().await.expect("commit");

    // Unstamped: the same call on a connection nothing stamped.
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    assert!(
        !bypass_held(&mut conn).await,
        "CALIBRATION ({arm}): the unstamped session must not hold bypass, or the \
         policies filter nothing"
    );
    let unstamped_owner = read_on(&mut conn, &owner_v, Some(&keep[..]), &keep).await;
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");

    assert_eq!(
        (stamped_owner_among, stamped_owner_all),
        (vec![(x, y)], vec![(x, y)]),
        "COHERENCE ({arm}): on the stamped connection the owner reads its own private \
         edge, on both branches"
    );
    assert!(
        stamped_stranger.is_empty(),
        "({arm}): a stamped stranger must read nothing of the owner's private graph; \
         got {stamped_stranger:?}"
    );
    assert!(
        unstamped_owner.is_empty(),
        "THE DIFFERENTIAL ({arm}): on an unstamped connection the owner's own private \
         edge must vanish, which is what the unconverted handler computed under the \
         application role. Got {unstamped_owner:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_read_serves_the_owners_edge_and_an_unstamped_one_does_not_in_session_mode(
    pool: PgPool,
) {
    policy_differential(pool, SessionGucMode::Session).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_read_serves_the_owners_edge_and_an_unstamped_one_does_not_in_transaction_mode(
    pool: PgPool,
) {
    policy_differential(pool, SessionGucMode::Transaction).await;
}
