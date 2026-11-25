//! A DECLARED edge is only ever narrowed by the re-meets outside the
//! privatization (migration 284).
//!
//! Migration 260 recorded an edge's declared tenancy (`('group', H)` between
//! two public endpoints, kept by 072's no-widening arm) and taught the
//! privatization re-meet (`PrivatizationRepository::
//! recompute_boundary_meet_conn`) to honour it. Three other re-meets still
//! treated the edge as derived:
//!
//! * the propagation trigger (`epigraph_propagate_tenancy`, arm (d)): a
//!   claim re-tenanted outside the privatization re-owned the declared edge
//!   to the claim's group, so H's readers lost it and the new group's gained
//!   an edge H's author had kept from them;
//! * 206's publicize re-meet (re-stated by 242): an edge whose tuple equalled
//!   its meet was WIDENED with the claim, so a declared `('group', H)` edge
//!   went public when H's admin publicized its endpoint;
//! * 206's share re-meet (re-stated by 242): an edge on a moved claim's
//!   evidence was re-owned to the target team;
//! * 120's re-point (`epigraph_edges_tenancy` on `UPDATE OF source_id,
//!   target_id`): a declared edge re-pointed onto a private endpoint took the
//!   meet, dropping its declared owner.
//!
//! After 284 each of them computes a declared edge's tuple exactly as the
//! privatization re-meet does (`epigraph_edge_declared_meet`): the
//! intersection of the declaration and the endpoints' meet where one owner
//! plus one co-owner expresses it, the meet (keeping the declared owner where
//! it can) where it does not, and the exact declaration when the meet is
//! public.
//!
//! The visibility acts run on the application role (`epigraph_app`) with a
//! stamped session, and every read is made there, so the real policies,
//! grants and triggers decide. The re-tenant and the re-point are privileged
//! writes, as their production paths are.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::privatization::PrivatizationRepository;
use epigraph_db::visibility::Viewer;
use sqlx::{PgConnection, PgPool};
use std::collections::BTreeSet;
use uuid::Uuid;

const WORLD: Uuid = Uuid::nil();

/// `(owner_group_id, visibility, co_owner_group_id)`.
type Tuple = (Uuid, String, Option<Uuid>);

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

fn t(owner: Uuid, vis: &str, co: Option<Uuid>) -> Tuple {
    (owner, vis.to_string(), co)
}

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

/// `writer` declares an edge `('group', group)` on the app role.
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
        let e: Uuid = sqlx::query_scalar(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                                visibility, owner_group_id) \
             VALUES ($1, $2, $3, $4, 'supports', 'group', $5) RETURNING id",
        )
        .bind(src.0)
        .bind(src.1)
        .bind(tgt.0)
        .bind(tgt.1)
        .bind(group)
        .fetch_one(&mut *conn)
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

/// Move `claims` into `group` with NO privatization re-meet: only the claims
/// UPDATE and its propagation trigger run (a re-tenant outside the
/// privatization). Privileged, as every such path is.
async fn re_tenant(pool: &PgPool, claims: &[Uuid], group: Uuid) {
    let mut tx = pool.begin().await.expect("begin");
    let moved = PrivatizationRepository::restrict_claims_conn(&mut tx, claims, group)
        .await
        .expect("re-tenant");
    assert_eq!(moved.len(), claims.len(), "fixture: every claim moved");
    tx.commit().await.expect("commit");
}

/// `(claim_id, outcome)` rows of a visibility act.
type Outcomes = Vec<(Uuid, String)>;

/// `agent` publicizes `claims` on the app role, stamped as itself.
async fn publicize(pool: &PgPool, agent: Uuid, claims: &[Uuid]) -> Outcomes {
    let p = pool.clone();
    let claims = claims.to_vec();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, agent).await;
        let out: Outcomes = sqlx::query_as(
            "SELECT claim_id, outcome FROM public.epigraph_publicize_claims($1, 'open it up')",
        )
        .bind(&claims)
        .fetch_all(&mut *conn)
        .await
        .expect("publicize on the app role");
        (conn, out)
    })
    .await
}

/// `agent` shares `claims` with `team` on the app role, stamped as itself.
async fn share(pool: &PgPool, agent: Uuid, claims: &[Uuid], team: Uuid) -> Outcomes {
    let p = pool.clone();
    let claims = claims.to_vec();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, agent).await;
        let out: Outcomes = sqlx::query_as(
            "SELECT claim_id, outcome \
               FROM public.epigraph_share_claims_with_team($1, $2, 'share the draft')",
        )
        .bind(&claims)
        .bind(team)
        .fetch_all(&mut *conn)
        .await
        .expect("share on the app role");
        (conn, out)
    })
    .await
}

/// A keyed TEAM group with `agent` as a writer.
async fn team_with_writer(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, 'team', 'did:epigraph:test-team:' || $1::text, $2, 'team')",
    )
    .bind(id)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(id)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed team membership");
    id
}

/// The `details` of the last security event of `event_type`.
async fn last_event(pool: &PgPool, event_type: &str) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = $1 \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(event_type)
    .fetch_one(pool)
    .await
    .expect("the act's audit row")
}

// ===========================================================================
// 1. The propagation trigger (a re-tenant outside the privatization)
// ===========================================================================

/// A claim moved into G with no privatization re-meet: the propagation must
/// narrow a declared `('group', H)` edge on it to the intersection `(H, co
/// G)`, never re-own it to G (G's members would read an edge H's author kept
/// from them, and H's readers would lose it to a group they cannot read).
/// A derived edge on the same claim still takes the meet.
#[sqlx::test(migrations = "../../migrations")]
async fn a_re_tenant_outside_privatization_narrows_a_declared_edge(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, h) = fixture::seed_agent_with_group(&pool, "writer-h").await;
    let (_g_agent, g) = fixture::seed_agent_with_group(&pool, "group-g").await;
    let a = fixture::seed_public_claim(&pool, author, "public A, to re-tenant").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let edge = declare(&pool, w, h, (a, "claim"), (b, "claim")).await;
    let derived = fixture::seed_edge(&pool, b, a).await;
    assert_eq!(declaration(&pool, edge).await, (Some(h), None));
    assert!(
        reads(&pool, &[h], edge).await,
        "CALIBRATION: H reads its edge"
    );

    re_tenant(&pool, &[a], g).await;

    assert_eq!(
        tuple(&pool, edge).await,
        t(h, "group", Some(g)),
        "the propagation must narrow the declared edge to H AND G, not re-own it to G"
    );
    assert!(
        !reads(&pool, &[g], edge).await,
        "a G-only reader must not gain H's declared edge"
    );
    assert!(!reads(&pool, &[h], edge).await, "A is private to G now");
    assert!(reads(&pool, &[h, g], edge).await);
    assert!(!reads(&pool, &[], edge).await);
    assert_eq!(
        tuple(&pool, derived).await,
        t(g, "group", None),
        "control: a derived edge takes the meet"
    );
    assert_eq!(declaration(&pool, edge).await, (Some(h), None));
}

/// The propagation and the privatization re-meet compute ONE rule. On the
/// apply path the re-meet runs after the propagation, so a disagreement would
/// be masked by its rewrite: here the re-meet must find nothing to change
/// after a bare re-tenant, for a single-group meet, a co-owned declaration
/// next to a third group (`unmet`), and a stacked two-group meet.
#[sqlx::test(migrations = "../../migrations")]
async fn the_propagation_agrees_with_the_privatization_re_meet(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, h) = fixture::seed_agent_with_group(&pool, "writer-h").await;
    let (_k_agent, k) = fixture::seed_agent_with_group(&pool, "co-owner-k").await;
    let (_g_agent, g) = fixture::seed_agent_with_group(&pool, "group-g").await;
    let (_g2_agent, g2) = fixture::seed_agent_with_group(&pool, "group-g2").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let c = fixture::seed_public_claim(&pool, author, "public C").await;
    let single = declare(&pool, w, h, (a, "claim"), (b, "claim")).await;
    // A co-owned declaration (privileged: no single writer writes two
    // personal groups).
    let co: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id, co_owner_group_id) \
         VALUES ($1, 'claim', $2, 'claim', 'supports', 'group', $3, $4) RETURNING id",
    )
    .bind(a)
    .bind(c)
    .bind(h)
    .bind(k)
    .fetch_one(&pool)
    .await
    .expect("a co-owned declaration");
    assert_eq!(declaration(&pool, co).await, (Some(h), Some(k)));

    re_tenant(&pool, &[a], g).await;
    assert_eq!(tuple(&pool, single).await, t(h, "group", Some(g)));
    assert_eq!(
        tuple(&pool, co).await,
        t(h, "group", Some(g)),
        "unmet: bounded by the meet, the declared owner kept"
    );
    let mut tx = pool.begin().await.expect("begin");
    let meet = PrivatizationRepository::recompute_boundary_meet_conn(&mut tx, &[a])
        .await
        .expect("re-meet");
    tx.rollback().await.expect("rollback");
    assert_eq!(
        meet.updated, 0,
        "the privatization re-meet must agree with the propagation (single, unmet)"
    );

    // Stacked: B into G2, so the single edge's meet is (G, co G2).
    re_tenant(&pool, &[b], g2).await;
    assert_eq!(tuple(&pool, single).await, t(g, "group", Some(g2)));
    assert!(!reads(&pool, &[h, g], single).await);
    let mut tx = pool.begin().await.expect("begin");
    let meet = PrivatizationRepository::recompute_boundary_meet_conn(&mut tx, &[a, b])
        .await
        .expect("re-meet");
    tx.rollback().await.expect("rollback");
    assert_eq!(
        meet.updated, 0,
        "the privatization re-meet must agree with the propagation (stacked)"
    );
}

// ===========================================================================
// 2. Publicize (206, re-stated by 242)
// ===========================================================================

/// H's admin publicizes the claim at one end of an edge it DECLARED
/// `('group', H)`. The edge's tuple equals its meet before the act (the
/// claim is private to H), which is exactly the edge publicize used to widen:
/// it must stay `('group', H)`, never become readable by the world. A second
/// declared edge, by another group W, narrowed to `(W, co H)` by the
/// re-tenant, goes back on its exact declaration `(W)`.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_never_widens_a_declared_edge(pool: PgPool) {
    let (x, p) = fixture::seed_agent_with_group(&pool, "publicizer-p").await;
    let (w, h) = fixture::seed_agent_with_group(&pool, "writer-h").await;
    let a = fixture::seed_public_claim(&pool, x, "public A, to publicize").await;
    let a2 = fixture::seed_public_claim(&pool, x, "public A2, to publicize").await;
    let b = fixture::seed_public_claim(&pool, x, "public B").await;
    let own = declare(&pool, x, p, (a, "claim"), (b, "claim")).await;
    let other = declare(&pool, w, h, (a2, "claim"), (b, "claim")).await;
    let derived = fixture::seed_edge(&pool, b, a).await;

    re_tenant(&pool, &[a, a2], p).await;
    assert_eq!(
        tuple(&pool, own).await,
        t(p, "group", None),
        "CALIBRATION: the declared edge sits on its meet before the act"
    );
    assert_eq!(tuple(&pool, other).await, t(h, "group", Some(p)));

    let out = publicize(&pool, x, &[a, a2]).await;
    let expected: BTreeSet<(Uuid, String)> = [
        (a, "publicized".to_string()),
        (a2, "publicized".to_string()),
    ]
    .into_iter()
    .collect();
    assert_eq!(out.into_iter().collect::<BTreeSet<_>>(), expected);

    assert_eq!(
        tuple(&pool, own).await,
        t(p, "group", None),
        "publicize must keep the declared edge on its declaration, not widen it"
    );
    assert!(
        !reads(&pool, &[], own).await,
        "the world must not read an edge its author declared private to P"
    );
    assert!(reads(&pool, &[p], own).await);
    assert_eq!(
        tuple(&pool, other).await,
        t(h, "group", None),
        "both endpoints public again: the declaration exactly"
    );
    assert!(!reads(&pool, &[], other).await);
    assert!(!reads(&pool, &[p], other).await);
    assert!(reads(&pool, &[h], other).await);
    assert_eq!(
        tuple(&pool, derived).await.1,
        "public",
        "control: a derived edge widens with its endpoints"
    );
    let d = last_event(&pool, "claim.publicized").await;
    assert_eq!(d["declared_edges_held"], 2, "{d}");
    assert_eq!(d["migration"], 284, "{d}");
}

// ===========================================================================
// 3. Share (206, re-stated by 242)
// ===========================================================================

/// X shares a claim from its home group P with team T. Three declared edges:
///
/// * claim A -> B, declared `('group', P)` (re-met by the propagation): it
///   must narrow to `(P, co T)`, not be re-owned to T;
/// * A's evidence -> B, declared `('group', P)` (re-met by share's own
///   evidence re-meet, which picks the edges on their meet): the same;
/// * A's evidence -> B2, declared `('group', H)` by another writer (off its
///   meet before the act, so share used to leave it on H, where an H-only
///   reader read an edge naming T's evidence): bounded by the meet, `(H, co
///   T)`.
///
/// A T-only reader reads none of them.
#[sqlx::test(migrations = "../../migrations")]
async fn share_never_re_owns_a_declared_edge_to_the_team(pool: PgPool) {
    let (x, p) = fixture::seed_agent_with_group(&pool, "sharer-p").await;
    let (w, h) = fixture::seed_agent_with_group(&pool, "writer-h").await;
    let team = team_with_writer(&pool, x).await;
    let a = fixture::seed_public_claim(&pool, x, "public A, to share").await;
    let ev = fixture::seed_evidence(&pool, a, "observation").await;
    let b = fixture::seed_public_claim(&pool, x, "public B").await;
    let b2 = fixture::seed_public_claim(&pool, x, "public B2").await;
    let claim_edge = declare(&pool, x, p, (a, "claim"), (b, "claim")).await;
    let ev_edge = declare(&pool, x, p, (ev, "evidence"), (b, "claim")).await;
    let foreign = declare(&pool, w, h, (ev, "evidence"), (b2, "claim")).await;
    for e in [claim_edge, ev_edge, foreign] {
        assert!(
            declaration(&pool, e).await.0.is_some(),
            "CALIBRATION: every fixture edge is declared"
        );
    }

    re_tenant(&pool, &[a], p).await;
    assert_eq!(tuple(&pool, claim_edge).await, t(p, "group", None));
    assert_eq!(
        tuple(&pool, ev_edge).await,
        t(p, "group", None),
        "CALIBRATION: the evidence edge sits on its meet before the act"
    );

    let out = share(&pool, x, &[a], team).await;
    assert_eq!(out, vec![(a, "shared".to_string())]);

    assert_eq!(
        tuple(&pool, claim_edge).await,
        t(p, "group", Some(team)),
        "the claim's declared edge narrows to P AND T, never re-owned to T"
    );
    assert_eq!(
        tuple(&pool, ev_edge).await,
        t(p, "group", Some(team)),
        "the evidence's declared edge narrows to P AND T, never re-owned to T"
    );
    assert_eq!(
        tuple(&pool, foreign).await,
        t(h, "group", Some(team)),
        "a declared edge off its meet is still bounded by the new meet"
    );
    for e in [claim_edge, ev_edge] {
        assert!(!reads(&pool, &[team], e).await, "a T-only reader");
        assert!(reads(&pool, &[p, team], e).await);
    }
    assert!(
        !reads(&pool, &[h], foreign).await,
        "an H-only reader must not read an edge naming T's evidence"
    );
    assert!(!reads(&pool, &[team], foreign).await);
    let d = last_event(&pool, "claim.shared_with_team").await;
    assert_eq!(d["declared_evidence_edges_held"], 2, "{d}");
    assert_eq!(d["migration"], 284, "{d}");
}

// ===========================================================================
// 4. A re-point (120's `edges_tenancy` on UPDATE OF source_id, target_id)
// ===========================================================================

/// A declared `('group', H)` edge re-pointed (as a merge or dedup does) onto
/// a claim private to G must narrow to `(H, co G)`, not take the meet `G`.
/// The declaration consulted is the row's RECORD (OLD), never a value bound
/// in the same UPDATE.
#[sqlx::test(migrations = "../../migrations")]
async fn a_re_point_onto_a_private_endpoint_only_narrows_a_declared_edge(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, h) = fixture::seed_agent_with_group(&pool, "writer-h").await;
    let (g_agent, g) = fixture::seed_agent_with_group(&pool, "group-g").await;
    let (_z_agent, z) = fixture::seed_agent_with_group(&pool, "forged-z").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let c = fixture::seed_group_claim(&pool, g_agent, g, "C, private to G").await;
    let c2 = fixture::seed_group_claim(&pool, g_agent, g, "C2, private to G").await;
    let edge = declare(&pool, w, h, (a, "claim"), (b, "claim")).await;
    let forged = declare(&pool, w, h, (a, "claim"), (b, "claim")).await;

    sqlx::query("UPDATE edges SET target_id = $2 WHERE id = $1")
        .bind(edge)
        .bind(c)
        .execute(&pool)
        .await
        .expect("re-point onto a private claim");
    assert_eq!(
        tuple(&pool, edge).await,
        t(h, "group", Some(g)),
        "a re-point must narrow the declared edge to H AND G, not re-own it to G"
    );
    assert!(!reads(&pool, &[g], edge).await);
    assert!(!reads(&pool, &[h], edge).await);
    assert!(reads(&pool, &[h, g], edge).await);
    assert_eq!(declaration(&pool, edge).await, (Some(h), None));

    sqlx::query("UPDATE edges SET target_id = $2, declared_owner_group_id = $3 WHERE id = $1")
        .bind(forged)
        .bind(c2)
        .bind(z)
        .execute(&pool)
        .await
        .expect("re-point binding another declaration");
    assert_eq!(
        tuple(&pool, forged).await,
        t(h, "group", Some(g)),
        "the re-point reads the RECORDED declaration, not one bound in the UPDATE"
    );
    assert_eq!(declaration(&pool, forged).await, (Some(h), None));

    // Re-pointed back onto a public claim: never widened (072's no-widening
    // arm keeps the narrower tuple; fail-closed).
    sqlx::query("UPDATE edges SET target_id = $2 WHERE id = $1")
        .bind(edge)
        .bind(b)
        .execute(&pool)
        .await
        .expect("re-point back onto a public claim");
    assert!(!reads(&pool, &[], edge).await);
    assert!(!reads(&pool, &[g], edge).await);
    assert_eq!(tuple(&pool, edge).await.1, "group");
}

// ===========================================================================
// 5. The precondition and the undo
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

/// Run `migrator` on one connection and reset it: 001's pg_dump header leaves
/// session-level SETs behind.
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) -> Result<(), String> {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = migrator.run(&mut *conn).await.map_err(|e| format!("{e:?}"));
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    out
}

/// The `public` catalog by name: relations, functions (whole definition,
/// owner and ACL), policies, triggers and constraints.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' \
                || COALESCE(p.proacl::text, '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'pol ' || c.relname || '.' || pol.polname \
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'con ' || c.relname || '.' || k.conname \
           FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
          WHERE c.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

const RESTATED: [&str; 4] = [
    "fn epigraph_propagate_tenancy()",
    "fn epigraph_edges_tenancy()",
    "fn epigraph_publicize_claims(p_claim_ids uuid[], p_reason text)",
    "fn epigraph_share_claims_with_team(p_claim_ids uuid[], p_group_id uuid, p_reason text)",
];
const HELPER: &str = "fn epigraph_edge_declared_meet(";

/// `docs/runbooks/284-undo.sql` returns the catalog to what it was below 284
/// (the four bodies byte for byte, with owner and ACL; the helper dropped),
/// and a second run changes nothing. Mutation: a re-statement dropped from
/// the undo, or edited by one character -> its md5 is named in the diff.
#[sqlx::test(migrations = false)]
async fn the_284_undo_returns_the_catalog_below_284(pool: PgPool) {
    migrate(&pool, &up_to(283)).await.expect("below 284");
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(284)).await.expect("through 284");
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    let removed: BTreeSet<&String> = before.difference(&through).collect();
    assert_eq!(
        added.len(),
        5,
        "CALIBRATION: 284 re-states four bodies and adds one helper: {added:?}"
    );
    for name in RESTATED.iter().chain([HELPER].iter()) {
        assert!(
            added.iter().any(|e| e.starts_with(name)),
            "CALIBRATION: 284 changes {name}: {added:?}"
        );
    }
    assert_eq!(removed.len(), 4, "CALIBRATION: {removed:?}");
    let undo = repo_file("docs/runbooks/284-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 284"
        );
    }
}

/// 284 refuses to apply over a body other than the one it re-states (here a
/// publicize body re-stated by another migration), with 55000, and changes
/// nothing. Mutation: the precondition block removed -> 284 applies and the
/// helper exists.
#[sqlx::test(migrations = false)]
async fn migration_284_refuses_a_body_it_was_not_written_from(pool: PgPool) {
    migrate(&pool, &up_to(283)).await.expect("below 284");
    let def: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('public.epigraph_publicize_claims(uuid[], text)'::regprocedure)",
    )
    .fetch_one(&pool)
    .await
    .expect("publicize definition");
    let rebodied = def.replacen("BEGIN\n", "BEGIN\n    -- another migration's delta\n", 1);
    assert_ne!(rebodied, def, "CALIBRATION: the body changed");
    sqlx::raw_sql(&rebodied)
        .execute(&pool)
        .await
        .expect("re-body publicize");
    let before = catalog(&pool).await;
    let err = migrate(&pool, &up_to(284))
        .await
        .expect_err("284 must refuse a body it was not written from");
    assert!(
        err.contains("55000") && err.contains("284"),
        "refused with 284's 55000: {err}"
    );
    assert_eq!(
        catalog(&pool)
            .await
            .symmetric_difference(&before)
            .collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "a refused 284 changes nothing"
    );
}

/// The declared-edge helper itself: the four cases the privatization re-meet
/// distinguishes, read directly (a derived edge keeps the meet; a public meet
/// gives the declaration; a one-group meet gives the intersection; a meet the
/// declaration cannot sit next to gives the meet, `unmet`).
#[sqlx::test(migrations = "../../migrations")]
async fn the_helper_computes_the_privatization_rule(pool: PgPool) {
    let h = Uuid::new_v4();
    let k = Uuid::new_v4();
    let g = Uuid::new_v4();
    let g2 = Uuid::new_v4();
    type Row = (String, Option<Uuid>, Option<Uuid>, bool);
    let ask =
        |dg: Option<Uuid>, dco: Option<Uuid>, mv: &'static str, mg: Uuid, mco: Option<Uuid>| {
            let pool = pool.clone();
            async move {
                let r: Row = sqlx::query_as(
                    "SELECT v::text, g, co, unmet \
                   FROM public.epigraph_edge_declared_meet($1, $2, $3, $4, $5)",
                )
                .bind(dg)
                .bind(dco)
                .bind(mv)
                .bind(mg)
                .bind(mco)
                .fetch_one(&pool)
                .await
                .expect("helper");
                r
            }
        };
    assert_eq!(
        ask(None, None, "group", g, Some(g2)).await,
        ("group".to_string(), Some(g), Some(g2), false),
        "derived: the meet"
    );
    assert_eq!(
        ask(None, None, "public", WORLD, None).await,
        ("public".to_string(), Some(WORLD), None, false),
        "derived: the meet"
    );
    assert_eq!(
        ask(Some(h), Some(k), "public", WORLD, None).await,
        ("group".to_string(), Some(h), Some(k), false),
        "public meet: the declaration"
    );
    assert_eq!(
        ask(Some(h), None, "group", g, None).await,
        ("group".to_string(), Some(h), Some(g), false),
        "one-group meet: the intersection"
    );
    assert_eq!(
        ask(Some(h), None, "group", h, None).await,
        ("group".to_string(), Some(h), None, false),
        "the meet is the declaration"
    );
    assert_eq!(
        ask(Some(h), None, "group", g, Some(h)).await,
        ("group".to_string(), Some(h), Some(g), false),
        "a two-group meet naming H"
    );
    assert_eq!(
        ask(Some(h), Some(k), "group", g, None).await,
        ("group".to_string(), Some(h), Some(g), true),
        "unmet, one-group meet: owner kept, the declared co-owner dropped"
    );
    assert_eq!(
        ask(Some(h), None, "group", g, Some(g2)).await,
        ("group".to_string(), Some(g), Some(g2), true),
        "unmet, two-group meet without H: the meet"
    );
}

/// Make `claims` public again in ONE privileged UPDATE, which does not re-meet
/// an edge between them (the propagation never widens an edge).
async fn declassify(pool: &PgPool, claims: &[Uuid]) {
    let world = fixture::world_group(pool).await;
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('epigraph.allow_declassify', 'yes', true)")
        .execute(&mut *tx)
        .await
        .expect("allow the declassification");
    sqlx::query("UPDATE claims SET visibility = 'public', owner_group_id = $2 WHERE id = ANY($1)")
        .bind(claims)
        .bind(world)
        .execute(&mut *tx)
        .await
        .expect("declassify");
    tx.commit().await.expect("commit");
}

/// 284's one-time repair: the declared edges the re-meets below 284 re-owned
/// or widened are put back within their declaration where that narrows them
/// (or where the declaration and the current tuple fit one owner plus one
/// co-owner), and one that would need three groups is left and counted.
/// The exposures are made by the OLD bodies (migrated to 283), then 284
/// applies. Mutation: section 7 removed -> every exposed tuple survives.
#[sqlx::test(migrations = false)]
async fn the_284_repair_narrows_what_the_old_re_meets_exposed(pool: PgPool) {
    migrate(&pool, &up_to(283)).await.expect("below 284");
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, h) = fixture::seed_agent_with_group(&pool, "writer-h").await;
    let (_g_agent, g) = fixture::seed_agent_with_group(&pool, "group-g").await;
    let (_g2_agent, g2) = fixture::seed_agent_with_group(&pool, "group-g2").await;
    let (x, p) = fixture::seed_agent_with_group(&pool, "publicizer-p").await;
    let claim = |label: &'static str, who: Uuid| {
        let pool = pool.clone();
        async move { fixture::seed_public_claim(&pool, who, label).await }
    };

    // (1) re-owned to G by the old propagation.
    let (a, b) = (claim("A", author).await, claim("B", author).await);
    let reowned = declare(&pool, w, h, (a, "claim"), (b, "claim")).await;
    re_tenant(&pool, &[a], g).await;
    assert_eq!(
        tuple(&pool, reowned).await,
        t(g, "group", None),
        "CALIBRATION: below 284 the propagation re-owns the declared edge to G"
    );

    // (2) widened to the world by the old publicize.
    let (c, d) = (claim("C", x).await, claim("D", x).await);
    let widened = declare(&pool, x, p, (c, "claim"), (d, "claim")).await;
    re_tenant(&pool, &[c], p).await;
    let out = publicize(&pool, x, &[c]).await;
    assert_eq!(out, vec![(c, "publicized".to_string())]);
    assert_eq!(
        tuple(&pool, widened).await.1,
        "public",
        "CALIBRATION: below 284 publicize widens the declared edge"
    );

    // (3) incomparable with its declaration: re-owned to G, then its endpoint
    // made public again with no re-meet. Rule (H) and current (G) fit one
    // owner plus one co-owner: (H, co G).
    let (e, f) = (claim("E", author).await, claim("F", author).await);
    let stale = declare(&pool, w, h, (e, "claim"), (f, "claim")).await;
    re_tenant(&pool, &[e], g).await;
    declassify(&pool, &[e]).await;
    assert_eq!(
        tuple(&pool, stale).await,
        t(g, "group", None),
        "CALIBRATION"
    );

    // (4) needs three groups (H declared, current G and G2): left, counted.
    let (i, j) = (claim("I", author).await, claim("J", author).await);
    let three = declare(&pool, w, h, (i, "claim"), (j, "claim")).await;
    re_tenant(&pool, &[i], g).await;
    re_tenant(&pool, &[j], g2).await;
    declassify(&pool, &[i, j]).await;
    assert_eq!(
        tuple(&pool, three).await,
        t(g, "group", Some(g2)),
        "CALIBRATION"
    );

    migrate(&pool, &up_to(284)).await.expect("through 284");

    assert_eq!(
        tuple(&pool, reowned).await,
        t(h, "group", Some(g)),
        "the repair narrows a re-owned declared edge to H AND G"
    );
    assert!(!reads(&pool, &[g], reowned).await);
    assert_eq!(
        tuple(&pool, widened).await,
        t(p, "group", None),
        "the repair puts a widened declared edge back on its declaration"
    );
    assert!(!reads(&pool, &[], widened).await);
    assert_eq!(tuple(&pool, stale).await, t(h, "group", Some(g)));
    assert!(!reads(&pool, &[g], stale).await);
    assert_eq!(
        tuple(&pool, three).await,
        t(g, "group", Some(g2)),
        "three groups: no tuple narrows it within its declaration; left as it is"
    );
}
