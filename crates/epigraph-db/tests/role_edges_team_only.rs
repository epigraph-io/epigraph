//! The role-holding projection edges are team-only (migration 292; operator
//! ruling 2026-11-24, human-identity visibility spec section 7 row K1).
//!
//! # What is under test
//!
//! * The OWNER RULE on every path that writes the projection: a grant (the
//!   `role_assignments` audit trigger), a bind / unbind (the
//!   `group_role_bindings` re-own trigger), and the 292 backfill of existing
//!   rows. One live binding to an active team/community: that group owns the
//!   edge; zero, or more than one: the holder's personal group (minted by
//!   105's function when absent, refused when only revoked rows exist).
//! * WHO READS IT, on every edge read surface the database layer serves, each
//!   on an `epigraph_app` connection stamped from the reader's resolved
//!   `Viewer`: `EdgeRepository::list_filtered` (REST `GET /api/v1/edges`),
//!   `EdgeRepository::get_by_source` / `endpoint_types` (MCP
//!   `get_neighborhood` / `traverse`) and `GraphViewRepository::subgraph_edges`
//!   (graph query / `graph_full`).
//!   An outsider and the guest see none; the holder and a member of the bound
//!   team see it (CALIBRATION in every test).
//! * The declaration: a grant-inserted and a backfilled edge carry the same
//!   `(visibility, owner, declared owner)`, so no later re-meet of the two
//!   public endpoints widens it.
//! * The migration's precondition (OCC01) and post-condition (OCC02).
//! * Migration 295: only a GENUINE projection is re-owned (the marker the audit
//!   trigger writes, joined to its `role_assignments` row by assignment id,
//!   holder and role). A forged edge of the projection's shape, written by any
//!   edge writer, is never re-owned by a bind / unbind or by the reconcile
//!   pass, and never makes a binding change fail.
//! * Migration 296: a projection edge (any row carrying the marker) is
//!   written only by a maintenance session or a maintenance-owned definer
//!   frame. A writer of the owning team cannot widen, strip, re-time or
//!   delete one, nor write the marker onto a row of its own (OCC05); the
//!   maintenance verbs (grant, end, bind, unbind) still re-project through
//!   the guard.
//!
//! Two surfaces cannot reach an agent-to-agent edge at all, so they have no
//! row here: PROV export is claim-rooted (`epigraph-engine/src/export/prov.rs`
//! walks claim lineage), and the ego view's edges are those of a centre CLAIM
//! (`EgoRepository::edges`: `e.source_type = 'claim'` / `e.target_type =
//! 'claim'`). Measured: with the holder as the centre, the ego read returns
//! no projection edge even to the holder. All names are invented.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::pool::{ScopedPool, SessionGucMode};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;

// ─── harness ─────────────────────────────────────────────────────────────

async fn app_pool(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool")
}

async fn viewer(pool: &PgPool, who: Option<Uuid>) -> Viewer {
    match who {
        Some(w) => Viewer::resolve(pool, w).await.expect("resolve viewer"),
        None => fixture::public_viewer(pool).await,
    }
}

const REL: &str = "OCCUPIES";

/// How many projection edges of `holder` each read surface returns to `who`
/// (None = the guest), in the order
/// `[list_filtered, get_by_source, subgraph_edges, endpoint_types>0]`.
async fn seen(pool: &PgPool, scoped: &ScopedPool, who: Option<Uuid>, holder: Uuid) -> [usize; 4] {
    let v = viewer(pool, who).await;
    let mut read = scoped.read_as(&v).await.expect("read_as");
    let is_rel = |r: &str| r.eq_ignore_ascii_case(REL);
    let listed = epigraph_db::EdgeRepository::list_filtered(
        &mut *read,
        &v,
        Some(holder),
        None,
        Some(REL),
        None,
        None,
        100,
    )
    .await
    .expect("list_filtered")
    .iter()
    .filter(|e| is_rel(&e.relationship))
    .count();
    let by_source = epigraph_db::EdgeRepository::get_by_source(&mut *read, &v, holder, "agent")
        .await
        .expect("get_by_source")
        .iter()
        .filter(|e| is_rel(&e.relationship))
        .count();
    let nodes: Vec<Uuid> = sqlx::query_scalar(
        "SELECT target_id FROM edges WHERE source_id = $1 AND relationship = 'OCCUPIES'",
    )
    .bind(holder)
    .fetch_all(pool)
    .await
    .expect("role nodes (superuser)");
    let mut ids = vec![holder];
    ids.extend(nodes);
    let sub = epigraph_db::GraphViewRepository::subgraph_edges(&mut *read, &v, &ids)
        .await
        .expect("subgraph_edges")
        .iter()
        .filter(|e| is_rel(&e.relationship))
        .count();
    let types = epigraph_db::EdgeRepository::endpoint_types(&mut *read, &v, holder)
        .await
        .expect("endpoint_types")
        .len();
    [listed, by_source, sub, usize::from(types > 0)]
}

/// The ROSTER read from the role node's side: how many projection edges
/// INTO `node` `who` reads through `get_by_target` (MCP `get_neighborhood` on
/// the role node) and `list_filtered(target_id)` (REST
/// `GET /api/v1/edges?target_id=`). These answer "every holder of role X".
async fn roster_seen(
    pool: &PgPool,
    scoped: &ScopedPool,
    who: Option<Uuid>,
    node: Uuid,
) -> [usize; 2] {
    let v = viewer(pool, who).await;
    let mut read = scoped.read_as(&v).await.expect("read_as");
    let is_rel = |r: &str| r.eq_ignore_ascii_case(REL);
    let by_target = epigraph_db::EdgeRepository::get_by_target(&mut *read, &v, node, "agent")
        .await
        .expect("get_by_target")
        .iter()
        .filter(|e| is_rel(&e.relationship))
        .count();
    let listed = epigraph_db::EdgeRepository::list_filtered(
        &mut *read,
        &v,
        None,
        Some(node),
        Some(REL),
        None,
        None,
        100,
    )
    .await
    .expect("list_filtered by target")
    .iter()
    .filter(|e| is_rel(&e.relationship))
    .count();
    [by_target, listed]
}

const NONE: [usize; 4] = [0, 0, 0, 0];
const ONE: [usize; 4] = [1, 1, 1, 1];

/// `(visibility, owner, declared owner)` of each projection edge of `holder`,
/// read on the superuser pool.
async fn tenancy(pool: &PgPool, holder: Uuid) -> Vec<(String, Uuid, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT visibility::text, owner_group_id, declared_owner_group_id FROM edges \
          WHERE source_id = $1 AND relationship = 'OCCUPIES' ORDER BY created_at",
    )
    .bind(holder)
    .fetch_all(pool)
    .await
    .expect("tenancy")
}

// ─── fixtures ────────────────────────────────────────────────────────────

/// A registered human operator with a personal group.
async fn person(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    let (a, g) = fixture::seed_agent_with_group(pool, label).await;
    fixture::make_human_operator(pool, a).await;
    (a, g)
}

async fn group_of(pool: &PgPool, kind: &str, members: &[Uuid]) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = if kind == "team" {
        id.as_bytes().iter().copied().cycle().take(32).collect()
    } else {
        Vec::new()
    };
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(format!("role-edge {kind} {id}"))
    .bind(format!("did:key:role-edge-{id}"))
    .bind(&key)
    .bind(kind)
    .bind(members[0])
    .execute(pool)
    .await
    .expect("group");
    for m in members {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(id)
        .bind(m)
        .execute(pool)
        .await
        .expect("membership");
    }
    id
}

async fn seed_role(pool: &PgPool, key: &str) -> Uuid {
    let node = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type, role, labels) \
         VALUES ($1, uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()), $2, 'role', \
                 'custom', ARRAY['role'])",
    )
    .bind(node)
    .bind(key)
    .execute(pool)
    .await
    .expect("role node");
    sqlx::query(
        "INSERT INTO platform_roles (key, elevates, reads_audit, role_node_id, description) \
         VALUES ($1, false, false, $2, 'role edge test role')",
    )
    .bind(key)
    .bind(node)
    .execute(pool)
    .await
    .expect("platform role");
    node
}

async fn try_grant(pool: &PgPool, role: &str, holder: Uuid) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT public.epigraph_grant_role($1, $2, now() - interval '5 seconds', NULL, NULL, \
                'role edge test grant')",
    )
    .bind(role)
    .bind(holder)
    .fetch_one(pool)
    .await
}

async fn grant(pool: &PgPool, role: &str, holder: Uuid) -> Uuid {
    try_grant(pool, role, holder).await.expect("grant role")
}

async fn end(pool: &PgPool, assignment: Uuid) {
    sqlx::query(
        "UPDATE role_assignments SET revoked_at = now(), revoked_by = session_user, \
                revoked_reason = 'role edge test end' WHERE id = $1",
    )
    .bind(assignment)
    .execute(pool)
    .await
    .expect("end assignment");
}

async fn bind(pool: &PgPool, group: Uuid, role: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO group_role_bindings (group_id, role, member_role, include_agents, reason) \
         VALUES ($1, $2, 'reader', false, 'role edge test binding') RETURNING id",
    )
    .bind(group)
    .bind(role)
    .fetch_one(pool)
    .await
    .expect("binding")
}

async fn unbind(pool: &PgPool, binding: Uuid) {
    sqlx::query(
        "UPDATE group_role_bindings SET revoked_at = now(), revoked_by = session_user, \
                revoked_reason = 'role edge test unbind' WHERE id = $1",
    )
    .bind(binding)
    .execute(pool)
    .await
    .expect("unbind");
}

// ─── the owner rule, read on every surface ───────────────────────────────

/// A role bound to exactly one team: the projection edge is owned by that
/// team. An outsider and the guest read no projection edge on any surface; a
/// direct teammate and the holder read it (CALIBRATION); the edge is never
/// public, and its declaration is recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bound_roles_edge_is_read_by_the_team_and_the_holder_only(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _) = person(&pool, "holder").await;
    let (mate, _) = fixture::seed_agent_with_group(&pool, "mate").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "outsider").await;
    let node = seed_role(&pool, "role:edge-test-a").await;
    let team = group_of(&pool, "team", &[mate]).await;
    bind(&pool, team, "role:edge-test-a").await;
    grant(&pool, "role:edge-test-a", h).await;

    assert_eq!(
        tenancy(&pool, h).await,
        vec![("group".to_string(), team, Some(team))],
        "owned and declared by the bound team"
    );
    assert_eq!(
        seen(&pool, &scoped, Some(outsider), h).await,
        NONE,
        "outsider"
    );
    assert_eq!(seen(&pool, &scoped, None, h).await, NONE, "guest");
    assert_eq!(seen(&pool, &scoped, Some(mate), h).await, ONE, "teammate");
    assert_eq!(seen(&pool, &scoped, Some(h), h).await, ONE, "holder");
    // The roster, read from the role node's side.
    assert_eq!(
        roster_seen(&pool, &scoped, Some(outsider), node).await,
        [0, 0],
        "outsider roster"
    );
    assert_eq!(
        roster_seen(&pool, &scoped, None, node).await,
        [0, 0],
        "guest roster"
    );
    assert_eq!(
        roster_seen(&pool, &scoped, Some(mate), node).await,
        [1, 1],
        "teammate roster"
    );
}

/// A role bound to no group, or to two: the holder's personal group owns the
/// edge. Only the holder (and a privileged session) reads it; a member of
/// either bound team does not.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unbound_or_twice_bound_roles_edge_is_the_holders_own(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h0, h0_personal) = person(&pool, "holder zero").await;
    let (h2, h2_personal) = person(&pool, "holder two").await;
    let (mate, _) = fixture::seed_agent_with_group(&pool, "mate").await;
    seed_role(&pool, "role:edge-test-none").await;
    seed_role(&pool, "role:edge-test-two").await;
    let t1 = group_of(&pool, "team", &[mate]).await;
    let t2 = group_of(&pool, "community", &[mate]).await;
    bind(&pool, t1, "role:edge-test-two").await;
    bind(&pool, t2, "role:edge-test-two").await;
    grant(&pool, "role:edge-test-none", h0).await;
    grant(&pool, "role:edge-test-two", h2).await;

    for (h, personal, who) in [(h0, h0_personal, "no binding"), (h2, h2_personal, "two")] {
        assert_eq!(
            tenancy(&pool, h).await,
            vec![("group".to_string(), personal, Some(personal))],
            "{who}: the holder's personal group"
        );
        assert_eq!(
            seen(&pool, &scoped, Some(mate), h).await,
            NONE,
            "{who}: mate"
        );
        assert_eq!(seen(&pool, &scoped, None, h).await, NONE, "{who}: guest");
        assert_eq!(seen(&pool, &scoped, Some(h), h).await, ONE, "{who}: holder");
    }
    let maint: i64 = fixture::as_role(&pool, "epigraph_maintenance", |mut c| async move {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE relationship = 'OCCUPIES' \
              AND source_id = ANY($1)",
        )
        .bind(vec![h0, h2])
        .fetch_one(&mut *c)
        .await
        .expect("maintenance read");
        (c, n)
    })
    .await;
    assert_eq!(maint, 2, "a maintenance session reads both");
}

/// Binding the role after the grant moves the edge into the team; unbinding
/// moves it back to the holder's personal group, so the ex-team keeps
/// nothing. An end and a re-grant keep the team-only owner.
#[sqlx::test(migrations = "../../migrations")]
async fn binding_changes_and_re_grants_keep_the_edge_team_only(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, personal) = person(&pool, "holder").await;
    let (mate, _) = fixture::seed_agent_with_group(&pool, "mate").await;
    seed_role(&pool, "role:edge-test-move").await;
    let team = group_of(&pool, "team", &[mate]).await;
    let a1 = grant(&pool, "role:edge-test-move", h).await;
    assert_eq!(
        tenancy(&pool, h).await,
        vec![("group".to_string(), personal, Some(personal))],
        "CALIBRATION: unbound, personal"
    );
    assert_eq!(
        seen(&pool, &scoped, Some(mate), h).await,
        NONE,
        "CALIBRATION"
    );

    let b = bind(&pool, team, "role:edge-test-move").await;
    assert_eq!(
        tenancy(&pool, h).await,
        vec![("group".to_string(), team, Some(team))],
        "binding moves the edge into the team"
    );
    assert_eq!(
        seen(&pool, &scoped, Some(mate), h).await,
        ONE,
        "teammate after bind"
    );

    end(&pool, a1).await;
    let a2 = grant(&pool, "role:edge-test-move", h).await;
    assert_ne!(a1, a2);
    assert_eq!(
        tenancy(&pool, h).await,
        vec![
            ("group".to_string(), team, Some(team)),
            ("group".to_string(), team, Some(team)),
        ],
        "the end keeps the owner, the re-grant lands in the team"
    );

    unbind(&pool, b).await;
    assert_eq!(
        tenancy(&pool, h).await,
        vec![
            ("group".to_string(), personal, Some(personal)),
            ("group".to_string(), personal, Some(personal)),
        ],
        "unbinding moves every edge of the role back to the holder"
    );
    assert_eq!(
        seen(&pool, &scoped, Some(mate), h).await,
        NONE,
        "the ex-team keeps nothing"
    );
    assert_ne!(
        seen(&pool, &scoped, Some(h), h).await,
        NONE,
        "the holder keeps its edges"
    );
}

/// A holder with no personal group gets one minted (by 105's function, under
/// its `did:epigraph:personal:` key) and it owns the edge: never the world
/// group. A holder whose personal membership is only revoked is refused
/// (RVK01) and no edge is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_missing_personal_group_is_minted_and_a_revoked_one_refuses(pool: PgPool) {
    seed_role(&pool, "role:edge-test-mint").await;
    let bare = Uuid::new_v4();
    let pk: Vec<u8> = bare.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(bare)
        .bind(&pk)
        .execute(&pool)
        .await
        .expect("bare agent");
    fixture::make_human_operator(&pool, bare).await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM groups WHERE did_key = $1")
        .bind(format!("did:epigraph:personal:{bare}"))
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(before, 0, "PREMISE: no personal group");
    grant(&pool, "role:edge-test-mint", bare).await;
    let minted: Uuid = sqlx::query_scalar(
        "SELECT id FROM groups WHERE did_key = $1 AND kind = 'personal' \
            AND created_by_agent_id = $2",
    )
    .bind(format!("did:epigraph:personal:{bare}"))
    .bind(bare)
    .fetch_one(&pool)
    .await
    .expect("minted personal group");
    assert_eq!(
        tenancy(&pool, bare).await,
        vec![("group".to_string(), minted, Some(minted))]
    );

    let (revoked, personal) = person(&pool, "revoked").await;
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(personal)
    .bind(revoked)
    .execute(&pool)
    .await
    .expect("revoke the personal row");
    let err = try_grant(&pool, "role:edge-test-mint", revoked)
        .await
        .expect_err("a holder with only a revoked personal row is refused");
    assert!(err.to_string().contains("REVOKED"), "{err}");
    assert!(tenancy(&pool, revoked).await.is_empty(), "no edge written");
    let world: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE relationship = 'OCCUPIES' AND visibility = 'public'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(world, 0, "no projection edge is ever public");
}

// ─── migration 292 ───────────────────────────────────────────────────────

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

fn below(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < version)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) -> Result<(), String> {
    let mut conn = pool.acquire().await.expect("acquire");
    let r = migrator.run(&mut *conn).await.map_err(|e| e.to_string());
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    r
}

/// Below 292: an unbound role's edge and a bound role's edge, both public
/// (130's body). After: each owned by the rule, its declaration recorded
/// exactly as a grant at head records it, and one summary audit row with the
/// count shape.
async fn seed_public_projections(pool: &PgPool) -> (Uuid, Uuid, Uuid, Uuid, Uuid) {
    let (h1, p1) = person(pool, "below one").await;
    let (h2, _) = person(pool, "below two").await;
    let (mate, _) = fixture::seed_agent_with_group(pool, "below mate").await;
    seed_role(pool, "role:edge-test-old").await;
    seed_role(pool, "role:edge-test-old-bound").await;
    let team = group_of(pool, "team", &[mate]).await;
    bind(pool, team, "role:edge-test-old-bound").await;
    grant(pool, "role:edge-test-old", h1).await;
    grant(pool, "role:edge-test-old-bound", h2).await;
    for h in [h1, h2] {
        let t = tenancy(pool, h).await;
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].0, "public", "PREMISE: 130 projects public");
    }
    (h1, p1, h2, team, mate)
}

#[sqlx::test(migrations = false)]
async fn migration_292_backfills_every_projection_and_audits_the_counts(pool: PgPool) {
    migrate(&pool, &below(292)).await.expect("migrate to 291");
    let (h1, p1, h2, team, mate) = seed_public_projections(&pool).await;
    migrate(&pool, &MIGRATOR).await.expect("migrate to head");
    assert_eq!(
        tenancy(&pool, h1).await,
        vec![("group".to_string(), p1, Some(p1))],
        "unbound: the holder's personal group, declared"
    );
    assert_eq!(
        tenancy(&pool, h2).await,
        vec![("group".to_string(), team, Some(team))],
        "bound: the team, declared"
    );
    let scoped = app_pool(&pool).await;
    assert_eq!(
        seen(&pool, &scoped, None, h2).await,
        NONE,
        "guest after backfill"
    );
    assert_eq!(
        seen(&pool, &scoped, Some(mate), h2).await,
        ONE,
        "teammate after backfill"
    );

    // A grant at head records the same shape as the backfill did.
    let (h3, p3) = person(&pool, "head").await;
    grant(&pool, "role:edge-test-old", h3).await;
    assert_eq!(
        tenancy(&pool, h3).await,
        vec![("group".to_string(), p3, Some(p3))]
    );

    let audits: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = 'edges.role_edges_team_only'",
    )
    .fetch_all(&pool)
    .await
    .expect("audit");
    assert_eq!(audits.len(), 1, "one summary row");
    let d = &audits[0];
    assert_eq!(d["migration"], 292);
    assert_eq!(d["before"], 2, "{d}");
    assert_eq!(d["rows"], 2, "{d}");
    assert_eq!(d["after"], 0, "{d}");
}

/// The post-condition: a backfill that moves nothing (a runner row security
/// filters) refuses the migration instead of leaving the edges public.
/// Reproduced by a trigger that silently skips the backfill's rows.
#[sqlx::test(migrations = false)]
async fn migration_292_refuses_when_the_backfill_moves_nothing(pool: PgPool) {
    migrate(&pool, &below(292)).await.expect("migrate to 291");
    let (h1, ..) = seed_public_projections(&pool).await;
    for stmt in [
        "CREATE FUNCTION public.test_skip_edge_reown() RETURNS trigger \
         LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$ \
         BEGIN IF NEW.visibility IS DISTINCT FROM OLD.visibility THEN \
         RETURN NULL; END IF; RETURN NEW; END $$",
        "CREATE TRIGGER test_skip_edge_reown BEFORE UPDATE ON public.edges \
         FOR EACH ROW EXECUTE FUNCTION public.test_skip_edge_reown()",
    ] {
        sqlx::query(stmt).execute(&pool).await.expect(stmt);
    }
    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("a backfill that moved nothing must refuse");
    assert!(err.contains("OCC02"), "post-condition refusal: {err}");
    assert_eq!(tenancy(&pool, h1).await[0].0, "public", "rolled back whole");
}

/// The precondition: an audit trigger whose body is not 130's is never
/// overwritten blind.
#[sqlx::test(migrations = false)]
async fn migration_292_refuses_over_another_audit_body(pool: PgPool) {
    migrate(&pool, &below(292)).await.expect("migrate to 291");
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.epigraph_role_assignments_audit() \
         RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER \
         SET search_path = public, pg_temp AS $$ BEGIN RETURN NULL; END $$",
    )
    .execute(&pool)
    .await
    .expect("another body");
    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("292 must refuse over another body");
    assert!(err.contains("OCC01"), "precondition refusal: {err}");
}

/// 292's and 295's functions: owned by the maintenance role, on 172's path,
/// EXECUTE revoked from PUBLIC and not granted to the application role (an
/// application-callable owner rule would be a binding oracle; an
/// application-callable re-own would drive personal-group mints).
#[sqlx::test(migrations = "../../migrations")]
async fn migration_292_functions_are_pinned_owned_and_not_app_callable(pool: PgPool) {
    for sig in [
        "public.epigraph_role_edge_owner(text, uuid)",
        "public.epigraph_group_role_bindings_reown_role_edges()",
        "public.epigraph_reown_role_projection_edges(text)",
    ] {
        let row: (String, bool, Vec<String>, bool) = sqlx::query_as(
            "SELECT pg_get_userbyid(p.proowner)::text, p.prosecdef, \
                    COALESCE(p.proconfig, ARRAY[]::text[]), \
                    has_function_privilege('epigraph_app', p.oid, 'EXECUTE') \
               FROM pg_proc p WHERE p.oid = to_regprocedure($1)",
        )
        .bind(sig)
        .fetch_one(&pool)
        .await
        .expect(sig);
        assert_eq!(row.0, "epigraph_maintenance", "{sig}");
        assert!(row.1, "{sig} is SECURITY DEFINER");
        assert_eq!(
            row.2,
            vec!["search_path=pg_catalog, pg_temp".to_string()],
            "{sig}"
        );
        assert!(!row.3, "{sig} must not be executable by epigraph_app");
    }
}

// ─── migration 295: only a genuine projection is re-owned ────────────────

/// An edge of the projection's shape written by an ordinary edge writer (the
/// superuser stands in for any writer: what is under test is the row's shape,
/// not who may write it). Both endpoints are agents, so it lands
/// `('public', world)` unless `owner` declares a group.
async fn forge(
    pool: &PgPool,
    source: Uuid,
    node: Uuid,
    props: serde_json::Value,
    owner: Option<Uuid>,
) -> Uuid {
    let (vis, g) = match owner {
        Some(g) => ("group", g),
        None => ("public", Uuid::nil()),
    };
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties, visibility, owner_group_id) \
         VALUES ($1, 'agent', $2, 'agent', 'OCCUPIES', $3, $4, $5) RETURNING id",
    )
    .bind(source)
    .bind(node)
    .bind(props)
    .bind(vis)
    .bind(g)
    .fetch_one(pool)
    .await
    .expect("forged edge")
}

/// `(visibility, owner, declared owner)` of one edge, read on the superuser pool.
async fn edge_tenancy(pool: &PgPool, id: Uuid) -> (String, Uuid, Option<Uuid>) {
    sqlx::query_as(
        "SELECT visibility::text, owner_group_id, declared_owner_group_id FROM edges WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("edge tenancy")
}

async fn personal_groups_of(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM groups WHERE did_key = $1")
        .bind(format!("did:epigraph:personal:{agent}"))
        .fetch_one(pool)
        .await
        .expect("count personal groups")
}

/// The forged rows one test plants against role `role` (node `node`) and the
/// genuine assignment `real` of holder `h`:
/// * the holder's own `{role}` edge with no marker;
/// * a `{role}` edge from an agent whose only personal row is REVOKED (105's
///   RVK01 refuses a mint for it: 292's re-own called the owner rule for it and
///   failed the whole binding change);
/// * the full marker with an assignment id no `role_assignments` row has, from
///   an agent with NO personal group (292 minted one for it);
/// * the full marker naming the REAL assignment from another agent.
struct Forged {
    ids: Vec<Uuid>,
    no_group: Uuid,
}

async fn plant_forgeries(pool: &PgPool, role: &str, node: Uuid, h: Uuid, real: Uuid) -> Forged {
    let (revoked, revoked_personal) = fixture::seed_agent_with_group(pool, "forger revoked").await;
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(revoked_personal)
    .bind(revoked)
    .execute(pool)
    .await
    .expect("revoke the forger's personal row");
    let no_group = Uuid::new_v4();
    let pk: Vec<u8> = no_group
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(no_group)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("agent with no personal group");
    let (other, _) = fixture::seed_agent_with_group(pool, "forger other").await;
    let marker = |assignment: String| {
        serde_json::json!({"assignment_id": assignment, "role": role,
                           "source": "role_assignments", "projection": true})
    };
    let ids = vec![
        forge(pool, h, node, serde_json::json!({"role": role}), None).await,
        forge(pool, revoked, node, serde_json::json!({"role": role}), None).await,
        forge(
            pool,
            no_group,
            node,
            marker(Uuid::new_v4().to_string()),
            None,
        )
        .await,
        forge(pool, other, node, marker(real.to_string()), None).await,
    ];
    Forged { ids, no_group }
}

/// A bind and an unbind re-own the genuine projection only. Every forged row
/// keeps exactly the tenancy its writer gave it, no personal group is minted
/// for a forger, and a forger whose personal group is revoked does not make
/// the binding change fail.
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_role_edge_is_never_reowned_and_never_blocks_a_binding_change(pool: PgPool) {
    let (h, personal) = person(&pool, "holder").await;
    let (mate, _) = fixture::seed_agent_with_group(&pool, "mate").await;
    let node = seed_role(&pool, "role:edge-test-forged").await;
    let team = group_of(&pool, "team", &[mate]).await;
    let real = grant(&pool, "role:edge-test-forged", h).await;
    let genuine: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE properties @> jsonb_build_object('assignment_id', $1::text)",
    )
    .bind(real)
    .fetch_one(&pool)
    .await
    .expect("the genuine projection");
    let forged = plant_forgeries(&pool, "role:edge-test-forged", node, h, real).await;
    let mut before = Vec::new();
    for id in &forged.ids {
        before.push(edge_tenancy(&pool, *id).await);
    }
    assert!(
        before.iter().all(|t| t.0 == "public"),
        "PREMISE: forged public"
    );

    let b = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO group_role_bindings (group_id, role, member_role, include_agents, reason) \
         VALUES ($1, 'role:edge-test-forged', 'reader', false, 'forged edge test') RETURNING id",
    )
    .bind(team)
    .fetch_one(&pool)
    .await
    .expect("a bind succeeds whatever forged rows exist");
    assert_eq!(
        edge_tenancy(&pool, genuine).await,
        ("group".to_string(), team, Some(team)),
        "CALIBRATION: the genuine projection moves into the team"
    );
    for (id, was) in forged.ids.iter().zip(&before) {
        assert_eq!(
            &edge_tenancy(&pool, *id).await,
            was,
            "bind re-owned forged {id}"
        );
    }

    sqlx::query(
        "UPDATE group_role_bindings SET revoked_at = now(), revoked_by = session_user, \
                revoked_reason = 'forged edge test unbind' WHERE id = $1",
    )
    .bind(b)
    .execute(&pool)
    .await
    .expect("an unbind succeeds whatever forged rows exist");
    assert_eq!(
        edge_tenancy(&pool, genuine).await,
        ("group".to_string(), personal, Some(personal)),
        "CALIBRATION: the genuine projection moves back to the holder"
    );
    for (id, was) in forged.ids.iter().zip(&before) {
        assert_eq!(
            &edge_tenancy(&pool, *id).await,
            was,
            "unbind re-owned forged {id}"
        );
    }
    assert_eq!(
        personal_groups_of(&pool, forged.no_group).await,
        0,
        "no personal group is minted for a forger"
    );
}

/// 295's reconcile pass, from 294: a genuine projection left public is
/// re-owned by the rule; forged rows are neither moved nor counted, and a
/// forged public row does not trip the post-condition. One summary row with
/// the count shape.
#[sqlx::test(migrations = false)]
async fn migration_295_reconciles_genuine_projections_only(pool: PgPool) {
    migrate(&pool, &below(295)).await.expect("migrate to 294");
    let (h, _) = person(&pool, "below holder").await;
    let (mate, _) = fixture::seed_agent_with_group(&pool, "below mate").await;
    let node = seed_role(&pool, "role:edge-test-reconcile").await;
    let team = group_of(&pool, "team", &[mate]).await;
    bind(&pool, team, "role:edge-test-reconcile").await;
    let real = grant(&pool, "role:edge-test-reconcile", h).await;
    // A genuine projection left public (a row written before 292, or widened
    // since): the reconcile pass must catch it.
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, \
                declared_owner_group_id = NULL \
          WHERE properties @> jsonb_build_object('assignment_id', $1::text)",
    )
    .bind(real)
    .bind(Uuid::nil())
    .execute(&pool)
    .await
    .expect("widen the genuine projection below 295");
    assert_eq!(tenancy(&pool, h).await[0].0, "public", "PREMISE");
    let forged = plant_forgeries(&pool, "role:edge-test-reconcile", node, h, real).await;
    let mut before = Vec::new();
    for id in &forged.ids {
        before.push(edge_tenancy(&pool, *id).await);
    }

    migrate(&pool, &MIGRATOR).await.expect("migrate to head");

    let genuine: (String, Uuid, Option<Uuid>) = sqlx::query_as(
        "SELECT visibility::text, owner_group_id, declared_owner_group_id FROM edges \
          WHERE properties @> jsonb_build_object('assignment_id', $1::text) \
            AND source_id = $2",
    )
    .bind(real)
    .bind(h)
    .fetch_one(&pool)
    .await
    .expect("genuine");
    assert_eq!(genuine, ("group".to_string(), team, Some(team)));
    for (id, was) in forged.ids.iter().zip(&before) {
        assert_eq!(
            &edge_tenancy(&pool, *id).await,
            was,
            "reconcile moved forged {id}"
        );
    }
    assert_eq!(personal_groups_of(&pool, forged.no_group).await, 0);
    let audits: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT details FROM security_events \
          WHERE event_type = 'edges.role_projection_edges_reconciled'",
    )
    .fetch_all(&pool)
    .await
    .expect("audit");
    assert_eq!(audits.len(), 1, "one summary row");
    let d = &audits[0];
    assert_eq!(d["migration"], 295);
    assert_eq!(d["before"], 1, "only the genuine public projection: {d}");
    assert_eq!(d["rows"], 1, "{d}");
    assert_eq!(d["after"], 0, "{d}");
}

// ─── migration 296: a projection edge is maintenance-only ────────────────

/// The SQLSTATE and message of a refused write, or None when it succeeded.
async fn try_write(scoped: &ScopedPool, v: &Viewer, sql: &str, id: Uuid) -> Option<String> {
    let mut tx = scoped.begin_as(v).await.expect("stamped tx");
    let r = sqlx::query(sql).bind(id).execute(&mut *tx).await;
    match r {
        Ok(done) => {
            assert_eq!(
                done.rows_affected(),
                1,
                "{sql}: the write must reach the row"
            );
            tx.commit().await.expect("commit");
            None
        }
        Err(e) => {
            let code = e
                .as_database_error()
                .and_then(|d| d.code().map(|c| c.to_string()))
                .unwrap_or_default();
            Some(format!("{code} {e}"))
        }
    }
}

/// A writer of the team that owns a projection edge cannot widen it, re-own
/// it, strip or rewrite its marker, re-time it or delete it: each is refused
/// by the guard (OCC05, 42501) and the row is unchanged. CALIBRATION: the
/// same session updates and deletes an unmarked edge of the same relationship
/// owned by the same team, so the refusal is the guard's, not row security's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_team_writer_cannot_widen_reown_or_delete_a_projection_edge(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (h, _) = person(&pool, "holder").await;
    let (mate, _) = fixture::seed_agent_with_group(&pool, "mate").await;
    let node = seed_role(&pool, "role:edge-test-guard").await;
    let team = group_of(&pool, "team", &[mate]).await;
    bind(&pool, team, "role:edge-test-guard").await;
    let real = grant(&pool, "role:edge-test-guard", h).await;
    let proj: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE properties @> jsonb_build_object('assignment_id', $1::text)",
    )
    .bind(real)
    .fetch_one(&pool)
    .await
    .expect("projection");
    let snapshot = |pool: PgPool| async move {
        sqlx::query_as::<
            _,
            (
                String,
                Uuid,
                Option<Uuid>,
                serde_json::Value,
                Option<String>,
            ),
        >(
            "SELECT visibility::text, owner_group_id, declared_owner_group_id, properties, \
                    valid_to::text FROM edges WHERE id = $1",
        )
        .bind(proj)
        .fetch_one(&pool)
        .await
        .expect("snapshot")
    };
    let before = snapshot(pool.clone()).await;
    assert_eq!((before.0.as_str(), before.1), ("group", team), "PREMISE");
    let v = viewer(&pool, Some(mate)).await;

    for (what, sql) in [
        (
            "widen",
            "UPDATE edges SET visibility = 'public' WHERE id = $1",
        ),
        (
            "strip the marker",
            "UPDATE edges SET properties = properties - 'projection' WHERE id = $1",
        ),
        (
            "rewrite the role",
            "UPDATE edges SET properties = properties || '{\"role\": \"role:other\"}' \
              WHERE id = $1",
        ),
        ("re-time", "UPDATE edges SET valid_to = now() WHERE id = $1"),
        ("delete", "DELETE FROM edges WHERE id = $1"),
    ] {
        let err = try_write(&scoped, &v, sql, proj).await;
        let err = err.unwrap_or_else(|| panic!("{what}: a team writer changed a projection edge"));
        assert!(
            err.contains("OCC05") && err.starts_with("42501"),
            "{what}: {err}"
        );
    }
    // Re-owning was already refused by 260's owner guard, which fires first;
    // pinned here as a regression check, not as this guard's work.
    let err = try_write(
        &scoped,
        &v,
        "UPDATE edges SET owner_group_id = '00000000-0000-0000-0000-000000000000' \
          WHERE id = $1",
        proj,
    )
    .await;
    assert!(
        err.is_some(),
        "re-own: a team writer re-owned a projection edge"
    );
    assert_eq!(
        snapshot(pool.clone()).await,
        before,
        "the projection is unchanged"
    );

    // CALIBRATION: the same writer changes and deletes an UNMARKED edge of the
    // same relationship that the same team owns.
    let plain = forge(
        &pool,
        mate,
        node,
        serde_json::json!({"role": "role:edge-test-guard"}),
        Some(team),
    )
    .await;
    assert_eq!(
        try_write(
            &scoped,
            &v,
            "UPDATE edges SET properties = properties || '{\"note\": 1}' WHERE id = $1",
            plain
        )
        .await,
        None,
        "CALIBRATION: update"
    );
    assert_eq!(
        try_write(&scoped, &v, "DELETE FROM edges WHERE id = $1", plain).await,
        None,
        "CALIBRATION: delete"
    );
}

/// A writer of a team cannot write the marker at all: not by INSERTing an
/// edge that carries it, and not by ADDING it to an edge the team owns (an
/// UPDATE whose NEW row carries it). So only the audit trigger's definer frame
/// (or maintenance) ever writes a row that reads as a projection.
/// CALIBRATION: the same INSERT without the marker succeeds on the same
/// session, so the refusal is the guard's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_team_writer_cannot_write_the_projection_marker(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (mate, _) = fixture::seed_agent_with_group(&pool, "mate").await;
    let node = seed_role(&pool, "role:edge-test-mark").await;
    let team = group_of(&pool, "team", &[mate]).await;
    let v = viewer(&pool, Some(mate)).await;
    let insert = |props: &'static str| {
        format!(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                                properties, visibility, owner_group_id) \
             SELECT $1, 'agent', '{node}', 'agent', 'OCCUPIES', '{props}'::jsonb, 'group', '{team}'"
        )
    };
    let marked = insert(
        r#"{"role": "role:edge-test-mark", "source": "role_assignments", "projection": true}"#,
    );
    let err = try_write(&scoped, &v, &marked, mate)
        .await
        .expect("inserting the marker is refused");
    assert!(
        err.contains("OCC05") && err.starts_with("42501"),
        "insert: {err}"
    );
    let plain_sql = insert(r#"{"role": "role:edge-test-mark"}"#);
    assert_eq!(
        try_write(&scoped, &v, &plain_sql, mate).await,
        None,
        "CALIBRATION: the unmarked insert"
    );

    let plain = forge(&pool, mate, node, serde_json::json!({}), Some(team)).await;
    let err = try_write(
        &scoped,
        &v,
        "UPDATE edges SET properties = properties || \
                '{\"source\": \"role_assignments\", \"projection\": true}' WHERE id = $1",
        plain,
    )
    .await
    .expect("adding the marker is refused");
    assert!(
        err.contains("OCC05") && err.starts_with("42501"),
        "update: {err}"
    );
}

/// The legitimate writers pass the guard: on a real maintenance session
/// (`session_user` = the maintenance role, not the superuser harness) a grant
/// projects into the bound team, a bind and an unbind re-own, an end closes
/// the edge (owner kept), and a maintenance narrowing of `valid_to` lands.
#[sqlx::test(migrations = "../../migrations")]
async fn the_maintenance_verbs_still_re_project_through_the_guard(pool: PgPool) {
    let (h, personal) = person(&pool, "holder").await;
    let (mate, _) = fixture::seed_agent_with_group(&pool, "mate").await;
    seed_role(&pool, "role:edge-test-maint").await;
    let team = group_of(&pool, "team", &[mate]).await;
    let (b, a) = fixture::as_role(&pool, "epigraph_maintenance", |mut c| async move {
        let b: Uuid = sqlx::query_scalar(
            "INSERT INTO group_role_bindings (group_id, role, member_role, include_agents, \
                                              reason) \
             VALUES ($1, 'role:edge-test-maint', 'reader', false, 'maint bind') RETURNING id",
        )
        .bind(team)
        .fetch_one(&mut *c)
        .await
        .expect("maintenance bind");
        let a: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_grant_role('role:edge-test-maint', $1, \
                    now() - interval '5 seconds', NULL, NULL, 'maint grant')",
        )
        .bind(h)
        .fetch_one(&mut *c)
        .await
        .expect("maintenance grant");
        (c, (b, a))
    })
    .await;
    assert_eq!(
        tenancy(&pool, h).await,
        vec![("group".to_string(), team, Some(team))],
        "grant"
    );

    fixture::as_role(&pool, "epigraph_maintenance", |mut c| async move {
        sqlx::query(
            "UPDATE group_role_bindings SET revoked_at = now(), revoked_by = session_user, \
                    revoked_reason = 'maint unbind' WHERE id = $1",
        )
        .bind(b)
        .execute(&mut *c)
        .await
        .expect("maintenance unbind");
        (c, ())
    })
    .await;
    assert_eq!(
        tenancy(&pool, h).await,
        vec![("group".to_string(), personal, Some(personal))],
        "unbind"
    );

    let narrowed = fixture::as_role(&pool, "epigraph_maintenance", |mut c| async move {
        sqlx::query(
            "UPDATE role_assignments SET revoked_at = now(), revoked_by = session_user, \
                    revoked_reason = 'maint end' WHERE id = $1",
        )
        .bind(a)
        .execute(&mut *c)
        .await
        .expect("maintenance end");
        let n = sqlx::query(
            "UPDATE edges SET valid_to = valid_to - interval '1 microsecond' \
              WHERE properties @> jsonb_build_object('assignment_id', $1::text)",
        )
        .bind(a)
        .execute(&mut *c)
        .await
        .expect("maintenance narrowing")
        .rows_affected();
        (c, n)
    })
    .await;
    assert_eq!(
        narrowed, 1,
        "the maintenance narrowing reaches the projection"
    );
    let (closed, owner): (bool, Uuid) = sqlx::query_as(
        "SELECT e.valid_to IS NOT NULL AND e.properties ? 'ended_at', e.owner_group_id \
           FROM edges e WHERE e.properties @> jsonb_build_object('assignment_id', $1::text)",
    )
    .bind(a)
    .fetch_one(&pool)
    .await
    .expect("ended projection");
    assert!(closed, "the end closes the projection");
    assert_eq!(owner, personal, "the end keeps the owner");
}

/// 295's precondition: a binding trigger whose body is not 292's is never
/// overwritten blind.
#[sqlx::test(migrations = false)]
async fn migration_295_refuses_over_another_binding_trigger_body(pool: PgPool) {
    migrate(&pool, &below(295)).await.expect("migrate to 294");
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.epigraph_group_role_bindings_reown_role_edges() \
         RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER \
         SET search_path = pg_catalog, pg_temp AS $$ BEGIN RETURN NULL; END $$",
    )
    .execute(&pool)
    .await
    .expect("another body");
    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("295 must refuse over another body");
    assert!(err.contains("OCC03"), "precondition refusal: {err}");
}
