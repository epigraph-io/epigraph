//! The repo half of `F-SHARD4-A1` (deferred-commitment screen key
//! `f-shard4-a1-compose-subgraphs`): the neighborhood walk
//! `POST /api/v1/graph/compose` runs, `SheafRepository::epistemic_neighborhood_ids`,
//! is filtered by the caller's `Viewer` at the seed, at every edge and at every
//! far endpoint.
//!
//! The walk ran inline in the route layer, on a `&PgPool` parameter, with no
//! viewer predicate. Its seed was a bare `$1::uuid` literal, so an id the
//! caller cannot read was counted as a node too. The handler's third read,
//! `ClaimRepository::pignistic_probs_for`, is already pinned by
//! `bp_propagate_scoped_policy.rs` and is not re-tested here.
//!
//! # Two halves, as the sibling `_policy` files split them
//!
//! The PREDICATE half runs on the `#[sqlx::test]` superuser pool, where no RLS
//! policy filters anything, so what it observes is the in-query predicate
//! alone. Every stranger arm is paired with an owner arm over the same rows,
//! so "the stranger saw nothing" cannot pass because the fixture was empty.
//! The stranger is a real principal with a non-empty group set of its own, so
//! the group array is bound as `$3` with members in it. `$1` and `$2` are the
//! center and the depth, and a bind placed on the wrong index would be a type
//! error or a wrong walk rather than a silent pass.
//!
//! Edge tenancy is FORCED with `seed_edge_owned_by` wherever a single
//! predicate is under test, for the reason that helper documents: left to
//! migration 070's trigger, an edge touching a private claim is private too,
//! and a "the hidden claim is absent" assertion would then be satisfied by the
//! EDGE predicate alone, with the claim predicate deleted.
//!
//! The POLICY half downgrades a connection to `epigraph_app` with
//! `SET SESSION AUTHORIZATION`, which is where migration 077's policies filter.
//! The walk is run twice with the same viewer and rows: once on a connection
//! `ScopedPool::read_as` stamped, once on one nothing stamped. The unstamped
//! arm is an inline mutation of the conversion. The owner's own private
//! neighborhood must vanish there, which is what the unconverted handler
//! computed from under the application role: a 200 with the caller's own
//! claims left out.
//!
//! # No `grant_app_privileges`
//!
//! Migration 077 issues the app-role grants itself. Re-granting here would
//! paper over a missing grant; a `42501` from these calls is a finding about
//! the migration, not a fixture bug.

mod viewer_fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{SessionGucMode, SheafRepository};
use sqlx::{Executor, PgPool};
use uuid::Uuid;
use viewer_fixture::{
    bypass, scoped_pool_with_mode, seed_agent_with_group, seed_edge, seed_edge_owned_by,
    seed_group_claim, seed_public_claim, world_group,
};

fn sorted(mut v: Vec<Uuid>) -> Vec<Uuid> {
    v.sort();
    v
}

async fn walk(pool: &PgPool, viewer: &Viewer, center: Uuid, depth: i32) -> Vec<Uuid> {
    sorted(
        SheafRepository::epistemic_neighborhood_ids(pool, viewer, center, depth)
            .await
            .expect("the neighborhood walk must not error; a filtered walk returns fewer ids"),
    )
}

/// The owner's graph around a public center `p0`, one hazard per spoke:
///
/// ```text
///   p0 --public edge-- h (private claim) --public edge-- p1
///   p0 --private edge-- p2 (public claim)
///   p0 --public edge-- p3 (public claim)      the control a stranger must see
/// ```
///
/// Returns `(owner, stranger, [p0, h, p1, p2, p3])`.
async fn seed_hazard_graph(pool: &PgPool) -> (Uuid, Uuid, [Uuid; 5]) {
    let (owner, group) = seed_agent_with_group(pool, "compose-owner").await;
    let (stranger, _) = seed_agent_with_group(pool, "compose-stranger").await;
    let world = world_group(pool).await;
    let tag = Uuid::new_v4();

    let p0 = seed_public_claim(pool, owner, &format!("compose p0 {tag}")).await;
    let h = seed_group_claim(pool, owner, group, &format!("compose h {tag}")).await;
    let p1 = seed_public_claim(pool, owner, &format!("compose p1 {tag}")).await;
    let p2 = seed_public_claim(pool, owner, &format!("compose p2 {tag}")).await;
    let p3 = seed_public_claim(pool, owner, &format!("compose p3 {tag}")).await;

    // Forced PUBLIC, so only the far-endpoint predicate can stop the walk at h.
    seed_edge_owned_by(pool, p0, h, "public", world).await;
    seed_edge_owned_by(pool, h, p1, "public", world).await;
    // Forced PRIVATE between two public claims, so only the edge predicate can
    // keep p2 out.
    seed_edge_owned_by(pool, p0, p2, "group", group).await;
    // Left to the trigger: public/public stays public.
    seed_edge(pool, p0, p3).await;

    (owner, stranger, [p0, h, p1, p2, p3])
}

// ── Predicate half: the superuser pool, where only the in-query predicate filters ──

/// A stranger's walk never counts, or passes through, a claim or an edge it
/// cannot read. The owner's walk over the same rows reaches all five, which is
/// what makes the stranger's result a filter and not an empty fixture.
#[sqlx::test(migrations = "../../migrations")]
async fn the_walk_visits_only_claims_and_edges_the_viewer_may_read(pool: PgPool) {
    let (owner, stranger, [p0, h, p1, p2, p3]) = seed_hazard_graph(&pool).await;
    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");
    assert!(
        !stranger_v.group_bind().expect("scoped").is_empty(),
        "CALIBRATION: the stranger must hold a group of its own, so the group array \
         is bound with members in it"
    );

    assert_eq!(
        walk(&pool, &owner_v, p0, 2).await,
        sorted(vec![p0, h, p1, p2, p3]),
        "CALIBRATION: the owner walks every spoke, including through its own private \
         claim to p1 and along its own private edge to p2"
    );
    assert_eq!(
        walk(&pool, &stranger_v, p0, 2).await,
        sorted(vec![p0, p3]),
        "a stranger's walk must stop at the private claim h (and so never reach p1, \
         which only h connects), must not follow the private edge to p2, and must \
         still reach the public control p3"
    );

    // The depth bound is the one the route always had.
    assert_eq!(
        walk(&pool, &owner_v, p0, 1).await,
        sorted(vec![p0, h, p2, p3]),
        "CALIBRATION: at depth 1 the owner reaches p0's direct neighbors only"
    );

    // A `Bypass` viewer renders no predicate and binds nothing, so the
    // statement has two parameters, not three. On the superuser pool it walks
    // everything.
    let (_scoped, bypass_v) = bypass(&pool).await;
    assert_eq!(
        walk(&pool, &bypass_v, p0, 2).await,
        sorted(vec![p0, h, p1, p2, p3]),
        "a Bypass viewer's walk must bind no group array and filter nothing"
    );
}

/// A center the viewer cannot read yields an EMPTY neighborhood, not one that
/// counts the center. The route reads that as a 404.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_center_yields_an_empty_neighborhood(pool: PgPool) {
    let (owner, stranger, [p0, h, p1, _p2, _p3]) = seed_hazard_graph(&pool).await;
    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");

    assert!(
        walk(&pool, &stranger_v, h, 2).await.is_empty(),
        "a stranger walking from the owner's private claim must get nothing back, \
         not the claim itself and not its public neighbors"
    );
    let from_h = walk(&pool, &owner_v, h, 1).await;
    assert!(
        from_h.contains(&h) && from_h.contains(&p0) && from_h.contains(&p1),
        "CALIBRATION: the owner's walk from its own private claim includes the claim \
         and its neighbors; got {from_h:?}"
    );

    assert!(
        walk(&pool, &owner_v, Uuid::new_v4(), 2).await.is_empty(),
        "an id that names no claim must yield an empty neighborhood too, so the route \
         answers it exactly as it answers an unreadable one"
    );
}

// ── Policy half: a connection downgraded to `epigraph_app` ──

async fn bypass_held(conn: &mut sqlx::PgConnection) -> bool {
    sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_bypass()")
}

async fn walk_on(conn: &mut sqlx::PgConnection, viewer: &Viewer, center: Uuid) -> Vec<Uuid> {
    sorted(
        SheafRepository::epistemic_neighborhood_ids(&mut *conn, viewer, center, 2)
            .await
            .expect("the walk must not error under the policy; a filtered walk returns fewer ids"),
    )
}

/// The owner's own group-private pair `x -- y`, the edge stamped private by the
/// trigger, walked by the owner on a stamped and on an unstamped connection.
async fn policy_differential(pool: PgPool, mode: SessionGucMode) {
    let (owner, group) = seed_agent_with_group(&pool, "compose-policy-owner").await;
    let (stranger, _) = seed_agent_with_group(&pool, "compose-policy-stranger").await;
    let tag = Uuid::new_v4();
    let x = seed_group_claim(&pool, owner, group, &format!("compose policy x {tag}")).await;
    let y = seed_group_claim(&pool, owner, group, &format!("compose policy y {tag}")).await;
    seed_edge(&pool, x, y).await;

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
    let stamped_owner = walk_on(&mut read, &owner_v, x).await;
    read.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    read.commit().await.expect("commit");

    let mut read = scoped.read_as(&stranger_v).await.expect("read_as stranger");
    read.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    let stamped_stranger = walk_on(&mut read, &stranger_v, x).await;
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
    let unstamped_owner = walk_on(&mut conn, &owner_v, x).await;
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");

    assert_eq!(
        stamped_owner,
        sorted(vec![x, y]),
        "COHERENCE ({arm}): on the stamped connection the owner walks its own private \
         claim and edge"
    );
    assert!(
        stamped_stranger.is_empty(),
        "({arm}): a stamped stranger must get nothing from the owner's private graph; \
         got {stamped_stranger:?}"
    );
    assert!(
        unstamped_owner.is_empty(),
        "THE DIFFERENTIAL ({arm}): on an unstamped connection the owner's own private \
         neighborhood must vanish, which is what the unconverted handler computed from \
         under the application role. Got {unstamped_owner:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_walk_serves_the_owners_graph_and_an_unstamped_one_does_not_in_session_mode(
    pool: PgPool,
) {
    policy_differential(pool, SessionGucMode::Session).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_walk_serves_the_owners_graph_and_an_unstamped_one_does_not_in_transaction_mode(
    pool: PgPool,
) {
    policy_differential(pool, SessionGucMode::Transaction).await;
}
