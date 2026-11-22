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
//! After 260 the edge keeps owner H and visibility `group` throughout: on
//! apply it is narrowed to the intersection (co-owner G), on revert it is put
//! back on its exact declaration, and a meet that cannot be expressed next
//! to the declaration HOLDS the declaration and reports it.
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

/// A declared co-owned edge whose apply adds a THIRD group cannot be
/// expressed in one owner plus one co-owner. It is held on its declaration
/// (owner, visibility and co-owner unchanged) and reported `unmet`; the
/// revert leaves it exactly as declared.
#[sqlx::test(migrations = "../../migrations")]
async fn a_meet_inexpressible_next_to_the_declaration_holds_it_and_reports_unmet(pool: PgPool) {
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

    let applied = restrict(&pool, &[a], g).await;
    assert_eq!(
        tuple(&pool, edge).await,
        t(h, "group", Some(k)),
        "held on its declaration: neither re-owned to G nor stripped of K"
    );
    assert_eq!(held(&applied), vec![(edge, "group".to_string(), true)]);

    let reverted = unrestrict(&pool, &[a]).await;
    assert_eq!(tuple(&pool, edge).await, t(h, "group", Some(k)));
    assert_eq!(held(&reverted), vec![(edge, "public".to_string(), false)]);
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
    let mut ids = Vec::new();
    for (s, tg, vis) in [(a, b, "group"), (private, a, "group"), (b, a, "public")] {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                                visibility, owner_group_id) \
             VALUES ($1, 'claim', $2, 'claim', 'supports', $3, $4) RETURNING id",
        )
        .bind(s)
        .bind(tg)
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
