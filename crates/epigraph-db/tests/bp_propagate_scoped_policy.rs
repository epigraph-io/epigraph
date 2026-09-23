//! The repo half of `F-SHARD4-A2` (deferred-commitment screen key
//! `f-shard4-a2-propagate-beliefs`): the four reads and the one write
//! `POST /api/v1/bp/propagate` now runs, each filtered by the caller's `Viewer`.
//!
//! * `FactorRepository::list_readable`: a factor is returned only when EVERY
//!   variable is a claim the viewer may read. `factors` has no tenancy columns
//!   and no RLS, so the predicate on its `claims` subquery is its only gate.
//! * `ClaimRepository::pignistic_probs_for`: prior beliefs, `{VISIBILITY:c}`.
//! * `AlternativeSetRepository::members_for_claims`: the `alternative_of`
//!   closure over readable edges AND readable endpoints.
//! * `ClaimRepository::apply_propagated_belief`: the write, `{WRITABLE:c}`.
//!
//! # Two halves, as the sibling `_policy` files split them
//!
//! The PREDICATE half runs on the `#[sqlx::test]` superuser pool, where no RLS
//! policy filters anything, so what it observes is the in-query predicate
//! alone. Every stranger arm there is paired with a member arm on the same
//! rows, so "the stranger saw nothing" cannot pass because the fixture was
//! empty.
//!
//! The POLICY half downgrades a connection to `epigraph_app` with
//! `SET SESSION AUTHORIZATION`, which is where migration 077's policies filter.
//! Each function is called twice with the same viewer and rows: once on a
//! connection `ScopedPool` stamped, once on one nothing stamped. The unstamped
//! arm is an inline mutation of the conversion, and it is asserted to fail the
//! way the unconverted handler failed after §9.2 step 11d: the owner's own
//! rows vanish, and the owner's own write matches nothing, with no error.
//!
//! # No `grant_app_privileges`
//!
//! Migration 077 issues the app-role grants itself. Re-granting here would
//! paper over a missing grant; a `42501` from these calls is a finding about
//! the migration, not a fixture bug.

mod viewer_fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{AlternativeSetRepository, ClaimRepository, FactorRepository, SessionGucMode};
use sqlx::{Executor, PgPool};
use uuid::Uuid;
use viewer_fixture::{scoped_pool, scoped_pool_with_mode, seed_agent_with_group, world_group};

/// The cached belief this file seeds on every claim, so a write that should
/// not have happened is visible as a change.
const SEEDED: (f64, f64, f64) = (0.3, 0.9, 0.8);

/// A frame of this test's own, so `belief_frame_id` has something to name.
async fn seed_frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, visibility, owner_group_id) \
         VALUES ($1, ARRAY['supported','unsupported'], 'public', $2) RETURNING id",
    )
    .bind(format!("bp-propagate-policy-{}", Uuid::new_v4()))
    .bind(world_group(pool).await)
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

/// A claim authored by `agent`, declared `(visibility, group)`, carrying the
/// [`SEEDED`] cached belief summarizing `frame`.
async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    visibility: &str,
    group: Uuid,
    frame: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, belief, plausibility, \
                             pignistic_prob, belief_frame_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(format!("bp-propagate policy claim {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(visibility)
    .bind(group)
    .bind(SEEDED.0)
    .bind(SEEDED.1)
    .bind(SEEDED.2)
    .bind(frame)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// A `mutual_exclusion` factor over `vars` in `frame`.
async fn seed_factor(pool: &PgPool, frame: Uuid, vars: &[Uuid]) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO factors (factor_type, variable_ids, potential, frame_id) \
         VALUES ('mutual_exclusion', $1, '{}'::jsonb, $2) RETURNING id",
    )
    .bind(vars)
    .bind(frame)
    .fetch_one(pool)
    .await
    .expect("seed factor")
}

/// `a --alternative_of--> b`, with the edge's own tenancy FORCED to
/// `(visibility, owner)` after the trigger stamps it.
///
/// Forced for the reason `viewer_fixture::seed_edge_owned_by` gives: left to
/// migration 070's trigger, an edge touching a private claim is private too,
/// and an assertion that a hidden ENDPOINT keeps a claim out of a class would
/// then be satisfied by the EDGE predicate alone.
async fn seed_alternative_of(
    pool: &PgPool,
    a: Uuid,
    b: Uuid,
    visibility: &str,
    owner: Uuid,
) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'alternative_of') RETURNING id",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("seed alternative_of edge");
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .bind(visibility)
    .bind(owner)
    .execute(pool)
    .await
    .expect("force edge tenancy");
    id
}

/// `(belief, plausibility, pignistic_prob, belief_frame_id)` on the superuser
/// pool.
async fn cached(pool: &PgPool, id: Uuid) -> (f64, f64, f64, Option<Uuid>) {
    sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, belief_frame_id FROM claims WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read cached belief")
}

fn ids_of(rows: &[epigraph_db::FactorRow]) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    ids.sort();
    ids
}

fn sorted(mut v: Vec<Uuid>) -> Vec<Uuid> {
    v.sort();
    v
}

// ── Predicate half: the superuser pool, where only the in-query predicate filters ──

/// A factor is returned only when every variable is readable. The
/// half-hidden factor is dropped whole, and a factor naming a claim that does
/// not exist is dropped for everyone, including the owner.
#[sqlx::test(migrations = "../../migrations")]
async fn list_readable_drops_a_factor_unless_every_variable_is_readable(pool: PgPool) {
    let (owner, group) = seed_agent_with_group(&pool, "bp-owner").await;
    let (stranger, _) = seed_agent_with_group(&pool, "bp-stranger").await;
    let frame = seed_frame(&pool).await;

    let public_a = seed_claim(&pool, owner, "public", group, frame).await;
    let public_b = seed_claim(&pool, owner, "public", group, frame).await;
    let private = seed_claim(&pool, owner, "group", group, frame).await;

    let all_public = seed_factor(&pool, frame, &[public_a, public_b]).await;
    let half_hidden = seed_factor(&pool, frame, &[public_a, private]).await;
    let dangling = seed_factor(&pool, frame, &[public_a, Uuid::new_v4()]).await;
    // A factor in another frame, so the frame filter is observed too.
    let other_frame = seed_frame(&pool).await;
    seed_factor(&pool, other_frame, &[public_a, public_b]).await;

    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");

    let for_owner = FactorRepository::list_readable(&pool, &owner_v, Some(frame))
        .await
        .expect("owner read");
    assert_eq!(
        ids_of(&for_owner),
        sorted(vec![all_public, half_hidden]),
        "CALIBRATION: the owner reads both claims-backed factors in this frame. The \
         dangling one names no claim at all and is dropped for everyone"
    );
    assert!(
        !ids_of(&for_owner).contains(&dangling),
        "a variable naming no claim must fail the predicate: under RLS it is \
         indistinguishable from a claim the session cannot see"
    );

    let for_stranger = FactorRepository::list_readable(&pool, &stranger_v, Some(frame))
        .await
        .expect("stranger read");
    assert_eq!(
        ids_of(&for_stranger),
        vec![all_public],
        "the factor naming the owner's group-private claim must be dropped WHOLE for a \
         stranger; keeping it would carry the hidden claim's belief into a visible one"
    );
}

/// Prior beliefs are returned only for readable claims.
#[sqlx::test(migrations = "../../migrations")]
async fn pignistic_probs_for_returns_only_readable_claims(pool: PgPool) {
    let (owner, group) = seed_agent_with_group(&pool, "bp-owner").await;
    let (stranger, _) = seed_agent_with_group(&pool, "bp-stranger").await;
    let frame = seed_frame(&pool).await;
    let public = seed_claim(&pool, owner, "public", group, frame).await;
    let private = seed_claim(&pool, owner, "group", group, frame).await;

    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");

    let seen =
        |rows: Vec<(Uuid, Option<f64>)>| sorted(rows.into_iter().map(|(id, _)| id).collect());

    let for_owner = ClaimRepository::pignistic_probs_for(&pool, &owner_v, &[public, private])
        .await
        .expect("owner read");
    assert_eq!(
        seen(for_owner),
        sorted(vec![public, private]),
        "CALIBRATION"
    );

    let for_stranger = ClaimRepository::pignistic_probs_for(&pool, &stranger_v, &[public, private])
        .await
        .expect("stranger read");
    assert_eq!(
        seen(for_stranger),
        vec![public],
        "a stranger must get no prior belief for the owner's group-private claim"
    );
}

/// The `alternative_of` class is computed over readable edges AND readable
/// endpoints, and for a viewer who can read everything it is exactly the
/// `alternative_set` view's class.
#[sqlx::test(migrations = "../../migrations")]
async fn members_for_claims_keeps_hidden_structure_out_of_the_class(pool: PgPool) {
    let (owner, group) = seed_agent_with_group(&pool, "bp-owner").await;
    let (stranger, _) = seed_agent_with_group(&pool, "bp-stranger").await;
    let world = world_group(&pool).await;
    let frame = seed_frame(&pool).await;

    // A and B are public and linked only THROUGH the owner's private claim H.
    // Both edges are forced PUBLIC, so only the claim predicate on H can be
    // what keeps A and B apart for the stranger.
    let a = seed_claim(&pool, owner, "public", group, frame).await;
    let b = seed_claim(&pool, owner, "public", group, frame).await;
    let h = seed_claim(&pool, owner, "group", group, frame).await;
    seed_alternative_of(&pool, a, h, "public", world).await;
    seed_alternative_of(&pool, h, b, "public", world).await;

    // C and D are public and linked DIRECTLY, by an edge private to the owner's
    // group: only the EDGE predicate can keep them apart for the stranger.
    let c = seed_claim(&pool, owner, "public", group, frame).await;
    let d = seed_claim(&pool, owner, "public", group, frame).await;
    seed_alternative_of(&pool, c, d, "group", group).await;

    let seeds = [a, b, c, d];
    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");

    let mut for_owner = AlternativeSetRepository::members_for_claims(&pool, &owner_v, &seeds)
        .await
        .expect("owner read");
    for_owner.sort();
    let mut from_view: Vec<(Uuid, Vec<Uuid>)> = sqlx::query_as(
        "SELECT claim_id, alt_members FROM alternative_set WHERE claim_id = ANY($1)",
    )
    .bind(&seeds[..])
    .fetch_all(&pool)
    .await
    .expect("read the alternative_set view");
    from_view.sort();
    assert_eq!(
        for_owner, from_view,
        "CALIBRATION: for a viewer who can read every row, the re-derived closure must \
         equal migration 042's view, or this is a different relation and not a filtered one"
    );
    assert_eq!(
        for_owner.len(),
        4,
        "CALIBRATION: all four seeds have a class"
    );

    let for_stranger = AlternativeSetRepository::members_for_claims(&pool, &stranger_v, &seeds)
        .await
        .expect("stranger read");
    assert!(
        for_stranger.is_empty(),
        "a stranger must get no class: A-B runs only through a claim it cannot read, and \
         C-D only through an edge it cannot read. Got {for_stranger:?}"
    );
}

// ── Policy half: a connection downgraded to `epigraph_app` ──

/// What one arm saw on a downgraded connection.
#[derive(Debug)]
struct PolicyObservation {
    bypass: bool,
    factors: Vec<Uuid>,
    priors: Vec<Uuid>,
    classes: Vec<Uuid>,
}

async fn run_reads(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    frame: Uuid,
    claims: &[Uuid],
) -> PolicyObservation {
    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_bypass()");
    let factors = FactorRepository::list_readable(&mut *conn, viewer, Some(frame))
        .await
        .expect("the factor read must not error; a filtered read returns fewer rows");
    let priors = ClaimRepository::pignistic_probs_for(&mut *conn, viewer, claims)
        .await
        .expect("the prior read must not error");
    let classes = AlternativeSetRepository::members_for_claims(&mut *conn, viewer, claims)
        .await
        .expect("the alt-set read must not error");
    PolicyObservation {
        bypass,
        factors: ids_of(&factors),
        priors: sorted(priors.into_iter().map(|(id, _)| id).collect()),
        classes: sorted(classes.into_iter().map(|(id, _)| id).collect()),
    }
}

/// The owner's own group-private graph: two private claims, a factor over
/// them, and an `alternative_of` edge between them.
async fn seed_private_graph(pool: &PgPool) -> (Uuid, Uuid, Uuid, [Uuid; 2], Uuid) {
    let (owner, group) = seed_agent_with_group(pool, "bp-policy-owner").await;
    let frame = seed_frame(pool).await;
    let x = seed_claim(pool, owner, "group", group, frame).await;
    let y = seed_claim(pool, owner, "group", group, frame).await;
    let factor = seed_factor(pool, frame, &[x, y]).await;
    seed_alternative_of(pool, x, y, "group", group).await;
    (owner, group, frame, [x, y], factor)
}

async fn read_differential(pool: PgPool, mode: SessionGucMode) {
    let (owner, _group, frame, claims, factor) = seed_private_graph(&pool).await;
    let viewer = Viewer::resolve(&pool, owner).await.expect("resolve");

    // Stamped: the connection `AppState::read_as` would hand the handler.
    let scoped = scoped_pool_with_mode(&pool, mode).await;
    let mut read = scoped.read_as(&viewer).await.expect("read_as");
    read.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    let stamped = run_reads(&mut read, &viewer, frame, &claims).await;
    read.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    read.commit().await.expect("commit");

    // Unstamped: the same calls on a connection nothing stamped.
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    let unstamped = run_reads(&mut conn, &viewer, frame, &claims).await;
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");

    let arm = format!("{mode:?}");
    assert!(
        !stamped.bypass && !unstamped.bypass,
        "CALIBRATION ({arm}): neither session may hold bypass, or the policies filter \
         nothing"
    );
    assert_eq!(
        stamped.factors,
        vec![factor],
        "COHERENCE ({arm}): the stamped read must serve the owner's own factor"
    );
    assert_eq!(stamped.priors, sorted(claims.to_vec()), "COHERENCE ({arm})");
    assert_eq!(
        stamped.classes,
        sorted(claims.to_vec()),
        "COHERENCE ({arm})"
    );

    assert!(
        unstamped.factors.is_empty() && unstamped.priors.is_empty() && unstamped.classes.is_empty(),
        "THE DIFFERENTIAL ({arm}): on an unstamped connection the owner's own rows must \
         vanish, which is what the unconverted handler would have computed from after \
         step 11d. Got {unstamped:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_reads_serve_the_owners_graph_and_unstamped_ones_do_not_in_session_mode(
    pool: PgPool,
) {
    read_differential(pool, SessionGucMode::Session).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_reads_serve_the_owners_graph_and_unstamped_ones_do_not_in_transaction_mode(
    pool: PgPool,
) {
    read_differential(pool, SessionGucMode::Transaction).await;
}

/// The write, on a `begin_as` transaction downgraded to `epigraph_app`: the
/// owner's own private claim is written, another group's PUBLIC claim is
/// refused with `false` and NO error, and on an unstamped connection the
/// owner's own write silently matches nothing.
///
/// The public claim is the sharp arm. The policy's `USING` admits it, because
/// it is public, and its `WITH CHECK` would then raise `42501`. So `false` with
/// no error can only come from the in-query `{WRITABLE:c}` predicate refusing
/// the row first. That is what lets the handler count it in `apply_failures`
/// instead of aborting the whole transaction.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_propagated_belief_writes_only_what_the_viewer_may_write(pool: PgPool) {
    let (owner, group) = seed_agent_with_group(&pool, "bp-write-owner").await;
    let (other, other_group) = seed_agent_with_group(&pool, "bp-write-other").await;
    let frame = seed_frame(&pool).await;
    let own = seed_claim(&pool, owner, "group", group, frame).await;
    let foreign = seed_claim(&pool, other, "public", other_group, frame).await;
    let viewer = Viewer::resolve(&pool, owner).await.expect("resolve");

    let scoped = scoped_pool(&pool).await;
    let mut tx = scoped.begin_as(&viewer).await.expect("begin_as");
    tx.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *tx)
        .await
        .expect("epigraph_bypass()");
    assert!(!bypass, "CALIBRATION: the session must not hold bypass");

    let wrote_own =
        ClaimRepository::apply_propagated_belief(&mut *tx, &viewer, own, 0.25, Some((0.1, 0.4)))
            .await
            .expect("the owner's own write must not error");
    let wrote_foreign = ClaimRepository::apply_propagated_belief(
        &mut *tx,
        &viewer,
        foreign,
        0.25,
        Some((0.1, 0.4)),
    )
    .await
    .expect(
        "a claim the viewer may read but not write must be refused by the predicate, \
         not raised by the policy: an error here aborts the handler's whole transaction",
    );
    tx.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    tx.commit().await.expect("commit");

    assert!(wrote_own, "the owner's own claim must be written");
    assert!(!wrote_foreign, "another group's claim must be refused");
    assert_eq!(
        cached(&pool, own).await,
        (0.1, 0.4, 0.25, None),
        "the written row carries the result and NULLs belief_frame_id: a propagation \
         run is not one frame's combined belief"
    );
    assert_eq!(
        cached(&pool, foreign).await,
        (SEEDED.0, SEEDED.1, SEEDED.2, Some(frame)),
        "the refused row must be unchanged"
    );

    // Unstamped: the same write on a connection nothing stamped.
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    let wrote_unstamped =
        ClaimRepository::apply_propagated_belief(&mut *conn, &viewer, own, 0.75, None)
            .await
            .expect("the unstamped write must not error: it matches nothing, silently");
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    assert!(
        !wrote_unstamped,
        "THE DIFFERENTIAL: unstamped, the owner's own group-private row is invisible to \
         the policy, so the write matches nothing and says so only through its row count"
    );
    assert_eq!(
        cached(&pool, own).await,
        (0.1, 0.4, 0.25, None),
        "the unstamped write must have changed nothing"
    );
}

/// The scalar arm leaves `belief` and `plausibility` alone, and every value is
/// clamped at the write boundary: `NaN` and out-of-range floats would otherwise
/// trip `claims_{belief,plausibility}_bounds` or be persisted verbatim.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_propagated_belief_clamps_and_leaves_the_interval_alone_in_the_scalar_arm(
    pool: PgPool,
) {
    let (owner, group) = seed_agent_with_group(&pool, "bp-clamp-owner").await;
    let frame = seed_frame(&pool).await;
    let scalar = seed_claim(&pool, owner, "public", group, frame).await;
    let interval = seed_claim(&pool, owner, "public", group, frame).await;
    let viewer = Viewer::resolve(&pool, owner).await.expect("resolve");

    assert!(
        ClaimRepository::apply_propagated_belief(&pool, &viewer, scalar, f64::NAN, None)
            .await
            .expect("scalar write")
    );
    assert_eq!(
        cached(&pool, scalar).await,
        (SEEDED.0, SEEDED.1, 0.0, None),
        "the scalar arm writes only pignistic_prob (NaN clamped to 0.0) and NULLs \
         belief_frame_id"
    );

    assert!(ClaimRepository::apply_propagated_belief(
        &pool,
        &viewer,
        interval,
        1.0 + 1e-12,
        Some((-1e-17, 1.0 + 1e-15)),
    )
    .await
    .expect("interval write"));
    assert_eq!(
        cached(&pool, interval).await,
        (0.0, 1.0, 1.0, None),
        "every value is clamped onto [0, 1]"
    );
}
