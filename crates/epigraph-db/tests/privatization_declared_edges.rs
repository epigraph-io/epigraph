//! A DECLARED edge keeps its declaration through a privatization (backlog
//! 969f01f6, migration 260).
//!
//! An edge whose author declared `('group', H)` between two public endpoints
//! is the one edge whose tenancy is not its endpoints' meet (072's
//! no-widening arm). Before 260 nothing recorded that, so the privatization
//! re-meet (`PrivatizationRepository::recompute_boundary_meet_conn`) treated
//! it as derived:
//!
//! * apply narrowed an endpoint into the target group G and the edge was
//!   RE-OWNED to `('group', G)` (H's readers lost it, G's gained it);
//! * revert recomputed it from its public endpoints and WIDENED it to public;
//! * a moved workflow's edges (219) went the same way.
//!
//! After 260 the edge keeps owner H and visibility `group` through a single
//! restrict and its revert: on apply it is narrowed to the intersection
//! (co-owner G), on revert it is put back on its exact declaration. It is
//! never readable by a session that cannot read its endpoints' meet: a meet
//! that cannot be expressed next to the declaration (a co-owned declaration,
//! or stacked plans) is bounded by the meet and reported `unmet`.
//!
//! Every edge here is written, and every read is made, on the application
//! role (`epigraph_app`) with a stamped session, so the real row policies and
//! triggers decide.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::privatization::{BoundaryMeet, PrivatizationRepository};
use epigraph_db::visibility::Viewer;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

const WORLD: Uuid = Uuid::nil();

/// `(owner_group_id, visibility, co_owner_group_id)`.
type Tuple = (Uuid, String, Option<Uuid>);

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

async fn set_gucs(conn: &mut PgConnection, groups: &str, writable: &str, principal: &str) {
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(groups)
    .bind(writable)
    .bind(principal)
    .execute(&mut *conn)
    .await
    .expect("stamp session gucs");
}

/// Stamp `conn` for `agent` exactly as `ScopedPool::begin_as` would.
async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
    set_gucs(conn, &groups, &writable, &agent.to_string()).await;
}

fn code(e: &sqlx::Error) -> String {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.to_string())
        .unwrap_or_else(|| e.to_string())
}

/// INSERT an edge naming its tenancy columns AND a declaration (which the
/// trigger must ignore: it is never the caller's to set).
#[allow(clippy::too_many_arguments)]
async fn insert_edge(
    conn: &mut PgConnection,
    source: (Uuid, &str),
    target: (Uuid, &str),
    visibility: &str,
    owner: Uuid,
    forged_declaration: Option<Uuid>,
) -> Result<Uuid, String> {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id, declared_owner_group_id) \
         VALUES ($1, $2, $3, $4, 'supports', $5, $6, $7) RETURNING id",
    )
    .bind(source.0)
    .bind(source.1)
    .bind(target.0)
    .bind(target.1)
    .bind(visibility)
    .bind(owner)
    .bind(forged_declaration)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| code(&e))
}

/// `writer` declares an edge `('group', its own group)` on the app role.
async fn declare(
    pool: &PgPool,
    writer: Uuid,
    group: Uuid,
    src: (Uuid, &'static str),
    tgt: (Uuid, &'static str),
) -> Uuid {
    let p = pool.clone();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, writer).await;
        let e = insert_edge(&mut conn, src, tgt, "group", group, None)
            .await
            .expect("the writer declares its edge private to its own group");
        (conn, e)
    })
    .await
}

async fn tuple(pool: &PgPool, edge: Uuid) -> Tuple {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, co_owner_group_id FROM edges WHERE id = $1",
    )
    .bind(edge)
    .fetch_one(pool)
    .await
    .expect("edge tuple")
}

async fn declaration(pool: &PgPool, edge: Uuid) -> (Option<Uuid>, Option<Uuid>) {
    sqlx::query_as(
        "SELECT declared_owner_group_id, declared_co_owner_group_id FROM edges WHERE id = $1",
    )
    .bind(edge)
    .fetch_one(pool)
    .await
    .expect("edge declaration")
}

fn t(owner: Uuid, vis: &str, co: Option<Uuid>) -> Tuple {
    (owner, vis.to_string(), co)
}

/// Whether an `epigraph_app` session whose READ set is `groups` reads `edge`.
async fn reads(pool: &PgPool, groups: &[Uuid], edge: Uuid) -> bool {
    let groups = csv(groups);
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        set_gucs(&mut conn, &groups, "", "").await;
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE id = $1")
            .bind(edge)
            .fetch_one(&mut *conn)
            .await
            .expect("read the edge on the app role");
        (conn, n == 1)
    })
    .await
}

/// The readability of `edge` to sessions reading {}, {H}, {G}, {H, G}.
async fn readers(pool: &PgPool, h: Uuid, g: Uuid, edge: Uuid) -> [bool; 4] {
    [
        reads(pool, &[], edge).await,
        reads(pool, &[h], edge).await,
        reads(pool, &[g], edge).await,
        reads(pool, &[h, g], edge).await,
    ]
}

/// Move `claims` into `group` and re-meet, on one transaction, as an apply
/// batch does (the claims UPDATE fires the propagation trigger first).
async fn restrict(pool: &PgPool, claims: &[Uuid], group: Uuid) -> BoundaryMeet {
    let mut tx = pool.begin().await.expect("begin");
    let moved = PrivatizationRepository::restrict_claims_conn(&mut tx, claims, group)
        .await
        .expect("restrict");
    assert_eq!(moved.len(), claims.len(), "fixture: every claim moved");
    let meet = PrivatizationRepository::recompute_boundary_meet_conn(&mut tx, claims)
        .await
        .expect("re-meet (apply)");
    tx.commit().await.expect("commit apply");
    meet
}

/// Put `claims` back to `('public', world)` and re-meet, as a revert batch
/// does (`restore_claims_conn` arms the same declassification GUC).
async fn unrestrict(pool: &PgPool, claims: &[Uuid]) -> BoundaryMeet {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL epigraph.allow_declassify = 'yes'")
        .execute(&mut *tx)
        .await
        .expect("allow declassify");
    sqlx::query("UPDATE claims SET visibility = 'public', owner_group_id = $2 WHERE id = ANY($1)")
        .bind(claims)
        .bind(WORLD)
        .execute(&mut *tx)
        .await
        .expect("restore the claims");
    let meet = PrivatizationRepository::recompute_boundary_meet_conn(&mut tx, claims)
        .await
        .expect("re-meet (revert)");
    tx.commit().await.expect("commit revert");
    meet
}

fn held(meet: &BoundaryMeet) -> Vec<(Uuid, String, bool)> {
    meet.held
        .iter()
        .map(|h| (h.edge_id, h.meet_visibility.clone(), h.unmet))
        .collect()
}

// ===========================================================================
// 1. The record (migration 260's trigger)
// ===========================================================================

/// A declaration is recorded from what `edges_tenancy` KEPT, never from what
/// the caller bound: a group edge between two public claims records its
/// tuple; a forged declaration on a derived edge (public, or a mixed edge the
/// meet re-owns) records nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_trigger_records_a_declaration_and_never_a_forged_one(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, h) = fixture::seed_agent_with_group(&pool, "writer-h").await;
    let (_g_agent, g) = fixture::seed_agent_with_group(&pool, "group-g").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let private = fixture::seed_group_claim(&pool, w, h, "H's private claim").await;

    let p = pool.clone();
    let (declared, public_forged, mixed_forged) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let declared = insert_edge(&mut conn, (a, "claim"), (b, "claim"), "group", h, None)
                .await
                .expect("W declares its edge private to H");
            let public_forged = insert_edge(
                &mut conn,
                (a, "claim"),
                (b, "claim"),
                "public",
                WORLD,
                Some(g),
            )
            .await
            .expect("W links two public claims, forging a declaration");
            let mixed_forged = insert_edge(
                &mut conn,
                (private, "claim"),
                (a, "claim"),
                "group",
                h,
                Some(g),
            )
            .await
            .expect("W links its private claim, forging a declaration");
            (conn, (declared, public_forged, mixed_forged))
        })
        .await;

    assert_eq!(tuple(&pool, declared).await, t(h, "group", None));
    assert_eq!(declaration(&pool, declared).await, (Some(h), None));
    assert_eq!(
        declaration(&pool, public_forged).await,
        (None, None),
        "a public edge records no declaration, whatever the caller bound"
    );
    assert_eq!(tuple(&pool, mixed_forged).await, t(h, "group", None));
    assert_eq!(
        declaration(&pool, mixed_forged).await,
        (None, None),
        "a mixed edge takes the meet: derived, whatever the caller bound"
    );

    // A co-owned declaration records its co-owner (privileged: no single
    // writer writes two personal groups).
    let co: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id, co_owner_group_id) \
         VALUES ($1, 'claim', $2, 'claim', 'supports', 'group', $3, $4) RETURNING id",
    )
    .bind(b)
    .bind(a)
    .bind(h)
    .bind(g)
    .fetch_one(&pool)
    .await
    .expect("a co-owned declaration");
    assert_eq!(declaration(&pool, co).await, (Some(h), Some(g)));
}

/// The declaration is immutable to a non-privileged session, as the owner
/// columns and the author record are (`edges_owner_immutable`).
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_privileged_session_cannot_rewrite_a_declaration(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, h) = fixture::seed_agent_with_group(&pool, "writer-h").await;
    let (_z, z) = fixture::seed_agent_with_group(&pool, "other-z").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let edge = declare(&pool, w, h, (a, "claim"), (b, "claim")).await;

    let p = pool.clone();
    let (rewrite, clear) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let rewrite = sqlx::query("UPDATE edges SET declared_owner_group_id = $2 WHERE id = $1")
            .bind(edge)
            .bind(z)
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected())
            .map_err(|e| code(&e));
        let clear = sqlx::query(
            "UPDATE edges SET declared_owner_group_id = NULL, \
                              declared_co_owner_group_id = NULL WHERE id = $1",
        )
        .bind(edge)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| code(&e));
        (conn, (rewrite, clear))
    })
    .await;
    assert_eq!(
        rewrite,
        Err("42501".to_string()),
        "re-pointing the declaration"
    );
    assert_eq!(clear, Err("42501".to_string()), "erasing the declaration");
    assert_eq!(declaration(&pool, edge).await, (Some(h), None));
}

/// A re-point never CREATES a declaration. A derived `('group', G)` edge
/// between a claim private to G and a public claim, re-pointed (as a dedup
/// does) onto another public claim, is kept narrow by 072's no-widening arm,
/// but it is still derived: no declaration is recorded, so a later re-meet
/// is not bound to G by a record nobody declared.
#[sqlx::test(migrations = "../../migrations")]
async fn a_re_point_never_records_a_declaration(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, g) = fixture::seed_agent_with_group(&pool, "writer-g").await;
    let private = fixture::seed_group_claim(&pool, w, g, "G's private claim").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B, the dedup survivor").await;
    let edge = fixture::seed_edge(&pool, private, a).await;
    assert_eq!(tuple(&pool, edge).await, t(g, "group", None));
    assert_eq!(declaration(&pool, edge).await, (None, None));

    sqlx::query("UPDATE edges SET source_id = $2 WHERE id = $1")
        .bind(edge)
        .bind(b)
        .execute(&pool)
        .await
        .expect("re-point the edge onto a public claim");
    assert_eq!(
        tuple(&pool, edge).await.1,
        "group",
        "CALIBRATION: the no-widening arm keeps the re-pointed edge narrow"
    );
    assert_eq!(
        declaration(&pool, edge).await,
        (None, None),
        "a re-point must not turn a derived edge into a declared one"
    );
}

// ===========================================================================
// 2. The privatization re-meet honours it
// ===========================================================================

/// A claim -> claim edge declared `('group', H)`: an apply into G narrows it
/// to the intersection (owner H, co-owner G: read only by a reader of both),
/// never re-owns it to G; the revert puts back EXACTLY the declaration, never
/// widens it to public. Both directions report the edge as held.
#[sqlx::test(migrations = "../../migrations")]
async fn a_declared_claim_edge_is_narrowed_on_apply_and_restored_exactly_on_revert(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, h) = fixture::seed_agent_with_group(&pool, "writer-h").await;
    let (_g_agent, g) = fixture::seed_agent_with_group(&pool, "target-g").await;
    let a = fixture::seed_public_claim(&pool, author, "public A, to privatize").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let edge = declare(&pool, w, h, (a, "claim"), (b, "claim")).await;
    // A derived edge on the same claim, the control: it takes the meet.
    let derived = fixture::seed_edge(&pool, b, a).await;

    assert_eq!(tuple(&pool, edge).await, t(h, "group", None));
    assert_eq!(
        readers(&pool, h, g, edge).await,
        [false, true, false, true],
        "CALIBRATION: before, only H's readers read the declared edge"
    );

    let applied = restrict(&pool, &[a], g).await;
    assert_eq!(
        tuple(&pool, edge).await,
        t(h, "group", Some(g)),
        "apply must narrow the declared edge to H AND G, not re-own it to G"
    );
    assert_eq!(
        readers(&pool, h, g, edge).await,
        [false, false, false, true],
        "after apply: only a reader of BOTH H and G (G's members never gain H's edge)"
    );
    assert_eq!(
        tuple(&pool, derived).await,
        t(g, "group", None),
        "control: a derived edge takes the meet"
    );
    assert_eq!(held(&applied), vec![(edge, "group".to_string(), false)]);

    let reverted = unrestrict(&pool, &[a]).await;
    assert_eq!(
        tuple(&pool, edge).await,
        t(h, "group", None),
        "revert must restore the declaration exactly, never widen it to public"
    );
    assert_eq!(
        readers(&pool, h, g, edge).await,
        [false, true, false, true],
        "after revert: H's readers again, and never the public"
    );
    assert_eq!(declaration(&pool, edge).await, (Some(h), None));
    assert_eq!(held(&reverted), vec![(edge, "public".to_string(), false)]);
    assert_eq!(
        tuple(&pool, derived).await.1,
        "public",
        "control: a derived edge widens back with its endpoints"
    );
}

/// A declared co-owned edge `(H, co K)` whose apply adds a THIRD group G
/// cannot be expressed in one owner plus one co-owner. The endpoints' meet
/// bounds it: it becomes `(H, co G)` (owner and visibility kept, K dropped),
/// so a session that cannot read G (A is now private to G) never reads it,
/// and it is reported `unmet`. The revert puts back exactly `(H, co K)`.
///
/// Before the fix the edge was HELD on `(H, co K)`: a reader of H and K who
/// is not in G read an edge naming a claim private to G.
#[sqlx::test(migrations = "../../migrations")]
async fn a_meet_inexpressible_next_to_the_declaration_is_bounded_by_the_meet(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (_h_agent, h) = fixture::seed_agent_with_group(&pool, "declarer-h").await;
    let (_k_agent, k) = fixture::seed_agent_with_group(&pool, "co-owner-k").await;
    let (_g_agent, g) = fixture::seed_agent_with_group(&pool, "target-g").await;
    let a = fixture::seed_public_claim(&pool, author, "public A, to privatize").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id, co_owner_group_id) \
         VALUES ($1, 'claim', $2, 'claim', 'supports', 'group', $3, $4) RETURNING id",
    )
    .bind(a)
    .bind(b)
    .bind(h)
    .bind(k)
    .fetch_one(&pool)
    .await
    .expect("a co-owned declaration");
    assert_eq!(declaration(&pool, edge).await, (Some(h), Some(k)));
    assert!(
        reads(&pool, &[h, k], edge).await,
        "CALIBRATION: a reader of H and K reads the declared edge"
    );

    let applied = restrict(&pool, &[a], g).await;
    assert!(
        !reads(&pool, &[h, k], edge).await,
        "a reader of H and K who cannot read G must not read an edge naming G's private claim"
    );
    for (who, groups) in [("H", vec![h]), ("K", vec![k]), ("G", vec![g])] {
        assert!(
            !reads(&pool, &groups, edge).await,
            "a reader of {who} alone must not read the edge"
        );
    }
    assert_eq!(
        tuple(&pool, edge).await,
        t(h, "group", Some(g)),
        "bounded by the meet, keeping the declared owner: (H, co G)"
    );
    assert!(reads(&pool, &[h, g], edge).await);
    assert_eq!(held(&applied), vec![(edge, "group".to_string(), true)]);

    let reverted = unrestrict(&pool, &[a]).await;
    assert_eq!(
        tuple(&pool, edge).await,
        t(h, "group", Some(k)),
        "the revert restores the declaration exactly"
    );
    assert_eq!(declaration(&pool, edge).await, (Some(h), Some(k)));
    assert_eq!(held(&reverted), vec![(edge, "public".to_string(), false)]);
}

/// Two stacked plans: a declared `('group', H)` edge A -> B; plan 1 moves A
/// into G (the edge narrows to `(H, co G)`), plan 2 moves B into G2. The meet
/// is now `(G, co G2)`, which cannot sit next to H in one tuple: the meet
/// wins, so a session reading only H (or H and G) reads nothing of an edge
/// whose endpoints are private to G and G2. Reverting plan 2 and then plan 1
/// walks it back to EXACTLY its declaration.
///
/// Before the fix plan 2 wrote `('group', H)`: an H-only reader read an edge
/// between a claim private to G and one private to G2.
#[sqlx::test(migrations = "../../migrations")]
async fn two_stacked_plans_never_let_the_declaration_outread_the_meet(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, h) = fixture::seed_agent_with_group(&pool, "writer-h").await;
    let (_g_agent, g) = fixture::seed_agent_with_group(&pool, "target-g").await;
    let (_g2_agent, g2) = fixture::seed_agent_with_group(&pool, "target-g2").await;
    let a = fixture::seed_public_claim(&pool, author, "public A, plan 1").await;
    let b = fixture::seed_public_claim(&pool, author, "public B, plan 2").await;
    let edge = declare(&pool, w, h, (a, "claim"), (b, "claim")).await;

    let plan1 = restrict(&pool, &[a], g).await;
    assert_eq!(tuple(&pool, edge).await, t(h, "group", Some(g)));
    assert_eq!(held(&plan1), vec![(edge, "group".to_string(), false)]);

    let plan2 = restrict(&pool, &[b], g2).await;
    for (who, groups) in [("H", vec![h]), ("H+G", vec![h, g]), ("H+G2", vec![h, g2])] {
        assert!(
            !reads(&pool, &groups, edge).await,
            "a reader of {who} cannot read both endpoints and must not read the edge"
        );
    }
    assert!(
        reads(&pool, &[g, g2], edge).await,
        "the meet's readers read it (the declaration is reported unmet, not enforced)"
    );
    assert_eq!(tuple(&pool, edge).await, t(g, "group", Some(g2)));
    assert_eq!(held(&plan2), vec![(edge, "group".to_string(), true)]);
    assert_eq!(declaration(&pool, edge).await, (Some(h), None));

    // Revert plan 2, then plan 1.
    let back2 = unrestrict(&pool, &[b]).await;
    assert_eq!(tuple(&pool, edge).await, t(h, "group", Some(g)));
    assert_eq!(held(&back2), vec![(edge, "group".to_string(), false)]);
    let back1 = unrestrict(&pool, &[a]).await;
    assert_eq!(
        tuple(&pool, edge).await,
        t(h, "group", None),
        "both reverts walk the edge back to exactly its declaration"
    );
    assert_eq!(readers(&pool, h, g, edge).await, [false, true, false, true]);
    assert_eq!(held(&back1), vec![(edge, "public".to_string(), false)]);
}

/// A declared edge re-tenanted OUTSIDE the privatization re-meet (a claim
/// UPDATE whose propagation trigger, since migration 284, narrows the edge to
/// `(H, co G)`; below 284 it re-owned it to `('group', G)`) and then re-met
/// by a plan moving its other endpoint into G2: the recorded declaration must
/// not be written back over the meet. No H-only reader reads it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_declaration_re_owned_by_a_sibling_path_is_still_bounded_by_the_meet(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, h) = fixture::seed_agent_with_group(&pool, "writer-h").await;
    let (_g_agent, g) = fixture::seed_agent_with_group(&pool, "group-g").await;
    let (_g2_agent, g2) = fixture::seed_agent_with_group(&pool, "target-g2").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let edge = declare(&pool, w, h, (a, "claim"), (b, "claim")).await;

    // The sibling path: A re-tenanted with no privatization re-meet.
    let mut tx = pool.begin().await.expect("begin");
    PrivatizationRepository::restrict_claims_conn(&mut tx, &[a], g)
        .await
        .expect("restrict A without a re-meet");
    tx.commit().await.expect("commit");
    assert_eq!(
        tuple(&pool, edge).await,
        t(h, "group", Some(g)),
        "CALIBRATION: the propagation trigger narrowed the declared edge to H AND G (284)"
    );
    assert!(
        !reads(&pool, &[h], edge).await,
        "CALIBRATION: H-only reads nothing"
    );

    let meet = restrict(&pool, &[b], g2).await;
    assert!(
        !reads(&pool, &[h], edge).await,
        "the stale declaration must not widen the edge to an H-only reader"
    );
    assert!(!reads(&pool, &[h, g], edge).await);
    assert_eq!(tuple(&pool, edge).await, t(g, "group", Some(g2)));
    assert_eq!(held(&meet), vec![(edge, "group".to_string(), true)]);
}

/// A declared edge onto a WORKFLOW (219's endpoint): the plan's move into G
/// narrows it (owner H, co-owner G), and the workflow's way back restores the
/// declaration exactly instead of making it `('public', world)`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_declared_workflow_edge_keeps_its_declaration_through_the_plan_move(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, h) = fixture::seed_agent_with_group(&pool, "writer-h").await;
    let (_g_agent, g) = fixture::seed_agent_with_group(&pool, "target-g").await;
    let step = fixture::seed_public_claim(&pool, author, "the plan's level-0 step").await;
    sqlx::query("UPDATE claims SET properties = jsonb_build_object('level', 0) WHERE id = $1")
        .bind(step)
        .execute(&pool)
        .await
        .expect("make the step structural");
    let wf = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, generation, metadata, visibility, \
                                owner_group_id) \
         VALUES ($1, 'declared-edge-plan', 'a plan', 0, '{}'::jsonb, 'public', $2)",
    )
    .bind(wf)
    .bind(WORLD)
    .execute(&pool)
    .await
    .expect("seed the public workflow");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'workflow', $2, 'claim', 'executes')",
    )
    .bind(wf)
    .bind(step)
    .execute(&pool)
    .await
    .expect("the plan executes its step");
    let citer = fixture::seed_public_claim(&pool, author, "a public claim citing the plan").await;
    let edge = declare(&pool, w, h, (citer, "claim"), (wf, "workflow")).await;
    assert_eq!(declaration(&pool, edge).await, (Some(h), None));

    // Apply: the step moves, then the plan moves with it (its own re-meet).
    let mut tx = pool.begin().await.expect("begin");
    let moved = PrivatizationRepository::restrict_claims_conn(&mut tx, &[step], g)
        .await
        .expect("restrict the step");
    let moves = PrivatizationRepository::restrict_plan_workflows_conn(&mut tx, &moved, g)
        .await
        .expect("move the plan");
    assert_eq!(moves.len(), 1, "fixture: the plan moved");
    tx.commit().await.expect("commit apply");
    assert_eq!(
        tuple(&pool, edge).await,
        t(h, "group", Some(g)),
        "the plan's move must narrow the declared edge, not re-own it to G"
    );
    assert_eq!(
        readers(&pool, h, g, edge).await,
        [false, false, false, true]
    );

    // Revert: the step goes back, then the plan, then the plan's edges are
    // re-met (what `restore_plan_workflows_conn` does after its UPDATE).
    unrestrict(&pool, &[step]).await;
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("UPDATE workflows SET visibility = 'public', owner_group_id = $2 WHERE id = $1")
        .bind(wf)
        .bind(WORLD)
        .execute(&mut *tx)
        .await
        .expect("restore the plan");
    let meet = PrivatizationRepository::recompute_boundary_meet_conn(&mut tx, &[wf])
        .await
        .expect("re-meet the plan's edges");
    tx.commit().await.expect("commit revert");
    assert_eq!(
        tuple(&pool, edge).await,
        t(h, "group", None),
        "the plan's way back must restore the declaration, never ('public', world)"
    );
    assert_eq!(readers(&pool, h, g, edge).await, [false, true, false, true]);
    assert_eq!(held(&meet), vec![(edge, "public".to_string(), false)]);
}

// ===========================================================================
// 3. The backfill and the undo
// ===========================================================================

fn up_to(max: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= max)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// 260 records the declarations that exist when it runs: a group edge whose
/// endpoints are both public. A derived group edge (a private endpoint) and a
/// public edge record none.
#[sqlx::test(migrations = false)]
async fn the_260_backfill_records_the_existing_declarations_only(pool: PgPool) {
    migrate(&pool, &up_to(259)).await;
    let (author, h) = fixture::seed_agent_with_group(&pool, "author").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let private = fixture::seed_group_claim(&pool, author, h, "private C").await;
    let mut wf = Vec::new();
    for (name, vis, owner) in [("public-plan", "public", WORLD), ("group-plan", "group", h)] {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO workflows (id, canonical_name, goal, generation, metadata, visibility, \
                                    owner_group_id) \
             VALUES ($1, $2, 'a plan', 0, '{}'::jsonb, $3, $4)",
        )
        .bind(id)
        .bind(name)
        .bind(vis)
        .bind(owner)
        .execute(&pool)
        .await
        .expect("seed a workflow below 260");
        wf.push(id);
    }
    let mut ids = Vec::new();
    for (s, tg, tg_type, vis) in [
        (a, b, "claim", "group"),
        (private, a, "claim", "group"),
        (b, a, "claim", "public"),
        (a, wf[0], "workflow", "group"),
        (a, wf[1], "workflow", "group"),
    ] {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                                visibility, owner_group_id) \
             VALUES ($1, 'claim', $2, $3, 'supports', $4, $5) RETURNING id",
        )
        .bind(s)
        .bind(tg)
        .bind(tg_type)
        .bind(vis)
        .bind(if vis == "group" { h } else { WORLD })
        .fetch_one(&pool)
        .await
        .expect("seed an edge below 260");
        ids.push(id);
    }
    migrate(&pool, &MIGRATOR).await;
    assert_eq!(
        declaration(&pool, ids[0]).await,
        (Some(h), None),
        "declared"
    );
    assert_eq!(
        declaration(&pool, ids[1]).await,
        (None, None),
        "derived (mixed)"
    );
    assert_eq!(declaration(&pool, ids[2]).await, (None, None), "public");
    assert_eq!(
        declaration(&pool, ids[3]).await,
        (Some(h), None),
        "declared onto a public workflow"
    );
    assert_eq!(
        declaration(&pool, ids[4]).await,
        (None, None),
        "derived from a group workflow (219's endpoint)"
    );
}

/// Migration 258's `epigraph_node_tenancy` (its section 1, byte for byte, on
/// `origin/fix/triage-t70`): the four registries are met with their own row.
/// Applied here only while this tree's migrations do not carry 258 itself;
/// once they do, `up_to(259)` installs the real one.
const ORACLE_258: &str = r#"
CREATE OR REPLACE FUNCTION public.epigraph_node_tenancy(p_id uuid, p_type text)
RETURNS TABLE (g uuid, v character varying(16))
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF p_type = 'claim' THEN
        RETURN QUERY SELECT c.owner_group_id, c.visibility FROM public.claims c WHERE c.id = p_id;
    ELSIF p_type = 'evidence' THEN
        RETURN QUERY SELECT e.owner_group_id, e.visibility FROM public.evidence e WHERE e.id = p_id;
    ELSIF p_type = 'workflow' THEN
        -- 219: a plan's row carries its tenancy since 183.
        RETURN QUERY SELECT w.owner_group_id, w.visibility FROM public.workflows w WHERE w.id = p_id;
    ELSIF p_type = 'frame' THEN
        -- 258: the four registries carry their tenancy since 062.
        RETURN QUERY SELECT f.owner_group_id, f.visibility FROM public.frames f WHERE f.id = p_id;
    ELSIF p_type = 'context' THEN
        RETURN QUERY SELECT x.owner_group_id, x.visibility FROM public.contexts x WHERE x.id = p_id;
    ELSIF p_type = 'perspective' THEN
        RETURN QUERY SELECT p.owner_group_id, p.visibility FROM public.perspectives p WHERE p.id = p_id;
    ELSIF p_type = 'community' THEN
        RETURN QUERY SELECT m.owner_group_id, m.visibility FROM public.communities m WHERE m.id = p_id;
    END IF;
    -- An edge pointing at an agent/paper/task has no tenancy of its own,
    -- so it contributes 'public' to the meet and never BLOCKS privatization.
    IF NOT FOUND THEN
        RETURN QUERY SELECT '00000000-0000-0000-0000-000000000000'::uuid,
                            'public'::character varying(16);
    END IF;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_node_tenancy(uuid, text) FROM PUBLIC;
"#;

const REGISTRY_TYPES: [&str; 4] = ["frame", "context", "perspective", "community"];

/// A registry row of entity type `ty` (harness superuser: a legacy re-stamp
/// or a group writer's direct write, the only sources of a private one).
async fn registry_row(pool: &PgPool, ty: &str, owner: Uuid, visibility: &str) -> Uuid {
    let id = Uuid::new_v4();
    let sql = match ty {
        "frame" => {
            "INSERT INTO frames (id, name, hypotheses, owner_group_id, visibility) \
             VALUES ($1, $2, ARRAY['a','b'], $3, $4)"
        }
        "context" => {
            "INSERT INTO contexts (id, name, context_type, owner_group_id, visibility) \
             VALUES ($1, $2, 'domain', $3, $4)"
        }
        "perspective" => {
            "INSERT INTO perspectives (id, name, owner_group_id, visibility) \
             VALUES ($1, $2, $3, $4)"
        }
        "community" => {
            "INSERT INTO communities (id, name, owner_group_id, visibility) \
             VALUES ($1, $2, $3, $4)"
        }
        other => panic!("no seeder for {other}"),
    };
    sqlx::query(sql)
        .bind(id)
        .bind(format!("{ty}-{id}"))
        .bind(owner)
        .bind(visibility)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("seed {ty}: {e}"));
    id
}

/// An edge from claim `a` stamped `('group', h)` (harness superuser).
async fn group_edge(pool: &PgPool, a: Uuid, target: (Uuid, &str), h: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id) \
         VALUES ($1, 'claim', $2, $3, 'supports', 'group', $4) RETURNING id",
    )
    .bind(a)
    .bind(target.0)
    .bind(target.1)
    .bind(h)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed an edge onto a {}: {e}", target.1))
}

/// The seed both oracle states are measured on: from a public claim, one
/// `('group', H)` edge onto each registry type's H-private row, plus the
/// controls: onto a public claim, a public frame and an agent (all public in
/// every oracle, so each is a declaration).
struct RegistrySeed {
    h: Uuid,
    private_registry: Vec<(&'static str, Uuid)>,
    controls: Vec<(&'static str, Uuid)>,
}

async fn seed_registry_endpoints(pool: &PgPool) -> RegistrySeed {
    let (author, h) = fixture::seed_agent_with_group(pool, "author").await;
    let a = fixture::seed_public_claim(pool, author, "public A").await;
    let b = fixture::seed_public_claim(pool, author, "public B").await;
    let mut private_registry = Vec::new();
    for ty in REGISTRY_TYPES {
        let row = registry_row(pool, ty, h, "group").await;
        private_registry.push((ty, group_edge(pool, a, (row, ty), h).await));
    }
    let public_frame = registry_row(pool, "frame", WORLD, "public").await;
    let controls = vec![
        ("claim", group_edge(pool, a, (b, "claim"), h).await),
        (
            "public frame",
            group_edge(pool, a, (public_frame, "frame"), h).await,
        ),
        ("agent", group_edge(pool, a, (author, "agent"), h).await),
    ];
    RegistrySeed {
        h,
        private_registry,
        controls,
    }
}

async fn assert_controls_declared(pool: &PgPool, seed: &RegistrySeed) {
    for (what, edge) in &seed.controls {
        assert_eq!(
            declaration(pool, *edge).await,
            (Some(seed.h), None),
            "CALIBRATION: a ('group', H) edge onto a public {what} is a declaration, \
             and is recorded (not skipped as dangling)"
        );
    }
}

/// Once 258 meets a frame, context, perspective or community endpoint with
/// its own row, a `('group', H)` edge from a public claim onto one private to
/// H is DERIVED (the meet), not declared: 260's backfill must ask the same
/// oracle as its trigger and record nothing, or the edge keeps H as a
/// declaration forever (a revert or a publicized registry row would then put
/// it back on H instead of re-meeting it).
#[sqlx::test(migrations = false)]
async fn the_260_backfill_never_records_a_private_registry_endpoint_edge(pool: PgPool) {
    migrate(&pool, &up_to(259)).await;
    if !MIGRATOR.migrations.iter().any(|m| m.version == 258) {
        sqlx::raw_sql(ORACLE_258)
            .execute(&pool)
            .await
            .expect("install 258's epigraph_node_tenancy");
    }
    let seed = seed_registry_endpoints(&pool).await;
    for (ty, edge) in &seed.private_registry {
        assert_eq!(
            tuple(&pool, *edge).await,
            t(seed.h, "group", None),
            "CALIBRATION: the {ty} edge is ('group', H), the meet 258 stamps"
        );
    }
    migrate(&pool, &MIGRATOR).await;
    for (ty, edge) in &seed.private_registry {
        assert_eq!(
            declaration(&pool, *edge).await,
            (None, None),
            "an edge ('group', H) because its {ty} endpoint is private to H is derived, \
             never a declaration"
        );
    }
    assert_controls_declared(&pool, &seed).await;
}

/// Below 258 the oracle meets every registry row as public, so the same
/// edges ARE declarations (the trigger records them too until 258 applies):
/// the backfill follows the oracle that is installed, not the registries'
/// own `visibility` columns. 260 is applied by hand on a database below 258.
#[sqlx::test(migrations = false)]
async fn below_258_the_260_backfill_follows_the_oracle_that_is_installed(pool: PgPool) {
    migrate(&pool, &up_to(257)).await;
    let seed = seed_registry_endpoints(&pool).await;
    let m260 = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../migrations/260_edge_declared_tenancy.sql"),
    )
    .expect("migration 260");
    sqlx::raw_sql(&m260)
        .execute(&pool)
        .await
        .expect("apply 260 below 258");
    for (ty, edge) in &seed.private_registry {
        assert_eq!(
            declaration(&pool, *edge).await,
            (Some(seed.h), None),
            "below 258 the oracle calls the {ty} row public: the edge is a declaration"
        );
    }
    assert_controls_declared(&pool, &seed).await;
}

async fn catalog(pool: &PgPool) -> std::collections::BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'col edges.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) \
           FROM pg_attribute a \
          WHERE a.attrelid = 'public.edges'::regclass AND a.attnum > 0 AND NOT a.attisdropped \
         UNION ALL \
         SELECT 'trg ' || t.tgname || ' ' || pg_get_triggerdef(t.oid) \
           FROM pg_trigger t WHERE t.tgrelid = 'public.edges'::regclass AND NOT t.tgisinternal \
         UNION ALL \
         SELECT 'fn ' || p.oid::regprocedure::text FROM pg_proc p \
          WHERE p.pronamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

/// `docs/runbooks/260-undo.sql` returns the `edges` catalog (columns,
/// triggers) and the function list exactly to below 260, twice.
#[sqlx::test(migrations = false)]
async fn the_260_undo_returns_the_catalog_below_260(pool: PgPool) {
    migrate(&pool, &up_to(259)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(260)).await;
    let through = catalog(&pool).await;
    assert!(
        through
            .iter()
            .any(|r| r.starts_with("trg edges_tenancy_declared "))
            && through.contains("col edges.declared_owner_group_id uuid"),
        "CALIBRATION: 260 adds its trigger and its columns"
    );
    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/260-undo.sql"),
    )
    .expect("the undo runbook");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 260"
        );
    }
}
