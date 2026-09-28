//! Migration 120 (operator decision D8): an edge between two public claims is
//! owned by its WRITER's group and stays public.
//!
//! Every tuple assertion below compares `(owner_group_id, visibility,
//! co_owner_group_id, writer_group_id)`.
//!
//! # Why every arm that asserts an admission or a refusal runs as `epigraph_app`
//!
//! `#[sqlx::test]` connects as the superuser `epigraph`, which bypasses every
//! policy, so "the delete removed nothing" and "the delete removed the row" are
//! indistinguishable on the harness connection. Those arms switch to the
//! non-bypassing `epigraph_app` (`SET SESSION AUTHORIZATION`) and stamp the
//! session GUCs exactly as `ScopedPool::begin_as` does. The arms that are ABOUT
//! a privileged session (the maintenance login, a privileged stamped session,
//! the administrative re-point) say so.
//!
//! # Re-points
//!
//! No application path re-points an edge's endpoints: `patch_edge` updates
//! `valid_to` and `properties` only, and every `SET source_id` / `SET
//! target_id` in `crates/*/src` is in the administrative repair
//! (`claim.rs`) or the tenancy backfill. So the re-point arms drive raw SQL:
//! on the application role for the owner and the bystander (what 117's policy
//! admits), and on a privileged principal-less session for the statement the
//! administrative cascade issues.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::AgentRepository;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

const WORLD: Uuid = Uuid::nil();

type Tuple = (Uuid, String, Option<Uuid>, Option<Uuid>);

async fn assert_app_role_does_not_bypass(pool: &PgPool) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app's rolbypassrls");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS, so every arm in this file is vacuous"
    );
}

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Stamp `conn` for `agent` exactly as `ScopedPool::begin_as` would.
async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
    assert!(
        !writable.is_empty(),
        "a writer with no writable group makes the arm vacuous"
    );
    set_gucs(conn, &groups, &writable, &agent.to_string()).await;
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

/// The unstamped steady state of a session.
async fn unstamp(conn: &mut PgConnection) {
    set_gucs(conn, "", "", "").await;
}

/// An agent with NO group at all.
async fn seed_groupless_agent(pool: &PgPool) -> Uuid {
    let agent = Uuid::new_v4();
    let pk: Vec<u8> = agent.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed a groupless agent");
    agent
}

/// Make `agent` a member of `group` with `role` (`writer` or `reader`).
async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

async fn add_writer(pool: &PgPool, group: Uuid, agent: Uuid) {
    add_member(pool, group, agent, "writer").await;
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the agent to its operator on the harness connection");
}

async fn seed_paper(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi) VALUES ($1) RETURNING id")
        .bind(format!("10.0000/w12b.{}", Uuid::new_v4()))
        .fetch_one(pool)
        .await
        .expect("seed paper")
}

/// The SQLSTATE of an error, or its text.
fn code(e: &sqlx::Error) -> String {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.to_string())
        .unwrap_or_else(|| e.to_string())
}

/// INSERT an edge on `conn` with the default declaration (the column defaults).
async fn insert_edge(
    conn: &mut PgConnection,
    source: (Uuid, &str),
    target: (Uuid, &str),
) -> Result<Uuid, String> {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, 'supports') RETURNING id",
    )
    .bind(source.0)
    .bind(source.1)
    .bind(target.0)
    .bind(target.1)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| code(&e))
}

/// INSERT a claim -> claim edge declaring every tenancy column, the author
/// record included.
async fn insert_declared_edge(
    conn: &mut PgConnection,
    source: Uuid,
    target: Uuid,
    visibility: &str,
    owner: Uuid,
    co_owner: Option<Uuid>,
    writer: Option<Uuid>,
) -> Result<Uuid, String> {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id, co_owner_group_id, writer_group_id) \
         VALUES ($1, 'claim', $2, 'claim', 'supports', $3, $4, $5, $6) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(visibility)
    .bind(owner)
    .bind(co_owner)
    .bind(writer)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| code(&e))
}

async fn tuple(pool: &PgPool, edge: Uuid) -> Tuple {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, co_owner_group_id, writer_group_id \
           FROM edges WHERE id = $1",
    )
    .bind(edge)
    .fetch_one(pool)
    .await
    .expect("edge tuple")
}

fn t(owner: Uuid, vis: &str, co: Option<Uuid>, writer: Option<Uuid>) -> Tuple {
    (owner, vis.to_string(), co, writer)
}

/// Rows changed by `sql` (binding `$1 = id`), or the SQLSTATE it raised.
async fn exec(conn: &mut PgConnection, sql: &str, id: Uuid) -> Result<u64, String> {
    sqlx::query(sql)
        .bind(id)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| code(&e))
}

/// Rows changed by `sql` (binding `$1 = id`, `$2 = arg`), or the SQLSTATE.
async fn exec2(conn: &mut PgConnection, sql: &str, id: Uuid, arg: Uuid) -> Result<u64, String> {
    sqlx::query(sql)
        .bind(id)
        .bind(arg)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| code(&e))
}

async fn exists(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM edges WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("edge exists")
}

const PATCH: &str =
    "UPDATE edges SET properties = properties || '{\"w12b\": 1}'::jsonb WHERE id = $1";
const RETRACT: &str = "UPDATE edges SET valid_to = now() WHERE id = $1 AND valid_to IS NULL";
const DELETE: &str = "DELETE FROM edges WHERE id = $1";

// ===========================================================================
// 1. The writer owns its edge between two public claims.
// ===========================================================================

/// W links two WORLD-owned public claims another agent wrote. The edge lands
/// `(W_g, public, NULL, W_g)` although W bound a different group as its
/// author record and declared the world as the owner: the author record comes
/// from the SESSION. A stranger Z reads it. Z's patch, retract and delete each
/// change 0 rows; W's change exactly 1 each.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stamped_writers_edge_between_two_public_claims_is_its_own(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (z, z_g) = fixture::seed_agent_with_group(&pool, "stranger-z").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (edge, z_reads, z_ops, w_ops) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let edge = insert_declared_edge(&mut conn, a, b, "public", WORLD, None, Some(z_g))
                .await
                .expect("W links two public claims");
            stamp(&mut conn, &p, z).await;
            let z_reads: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE id = $1")
                .bind(edge)
                .fetch_one(&mut *conn)
                .await
                .expect("Z reads");
            let z_ops = (
                exec(&mut conn, PATCH, edge).await,
                exec(&mut conn, RETRACT, edge).await,
                exec(&mut conn, DELETE, edge).await,
            );
            stamp(&mut conn, &p, w).await;
            let w_ops = (
                exec(&mut conn, PATCH, edge).await,
                exec(&mut conn, RETRACT, edge).await,
                exec(&mut conn, DELETE, edge).await,
            );
            (conn, (edge, z_reads, z_ops, w_ops))
        })
        .await;

    assert_eq!(z_reads, 1, "a stranger reads a public edge");
    assert_eq!(
        z_ops,
        (Ok(0), Ok(0), Ok(0)),
        "a bystander patches, retracts and deletes nothing of W's edge"
    );
    assert_eq!(
        w_ops,
        (Ok(1), Ok(1), Ok(1)),
        "the writer patches, retracts and deletes its own edge"
    );
    assert!(!exists(&pool, edge).await, "W's delete removed the row");
    assert_ne!(w_g, z_g);
}

/// The tuple, read before any mutation, in its own test so that a mutant that
/// only changes the owner cannot hide behind the operation arms above.
#[sqlx::test(migrations = "../../migrations")]
async fn the_writer_record_comes_from_the_session_not_the_caller(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (_z, z_g) = fixture::seed_agent_with_group(&pool, "other-z").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;

    let p = pool.clone();
    let app_edge = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let e = insert_declared_edge(&mut conn, a, b, "public", WORLD, None, Some(z_g))
            .await
            .expect("W links");
        (conn, e)
    })
    .await;
    assert_eq!(
        tuple(&pool, app_edge).await,
        t(w_g, "public", None, Some(w_g)),
        "the writer's group owns it, and the caller-bound author record is replaced"
    );

    // A privileged session with NO principal binds an author record too: it is
    // replaced by NULL, and the edge is the world's.
    let mut conn = pool.acquire().await.expect("acquire");
    unstamp(&mut conn).await;
    let priv_edge = insert_declared_edge(&mut conn, a, b, "public", WORLD, None, Some(z_g))
        .await
        .expect("a privileged principal-less insert");
    drop(conn);
    assert_eq!(
        tuple(&pool, priv_edge).await,
        t(WORLD, "public", None, None),
        "no principal: no author record, world-owned, whatever the caller bound"
    );
}

// ===========================================================================
// 2. The D8 scope: claims (and evidence), and a synthesis source.
// ===========================================================================

/// An agent -> claim edge (the AUTHORED shape) and a paper -> claim edge by W
/// stay `(world, public)`: outside D8's "between two public claims". The
/// author record is still written. W's delete of either changes 0 rows. A
/// claim -> evidence edge IS in scope.
#[sqlx::test(migrations = "../../migrations")]
async fn a_structural_edge_stays_administrative_with_its_author_recorded(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let claim = fixture::seed_public_claim(&pool, author, "public claim").await;
    let paper = seed_paper(&pool).await;
    let ev = fixture::seed_evidence(&pool, claim, "observation").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (authored, from_paper, to_evidence, deletes) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let authored = insert_edge(&mut conn, (w, "agent"), (claim, "claim"))
                .await
                .expect("W writes an AUTHORED-shaped edge");
            let from_paper = insert_edge(&mut conn, (paper, "paper"), (claim, "claim"))
                .await
                .expect("W writes a paper -> claim edge");
            let to_evidence = insert_edge(&mut conn, (claim, "claim"), (ev, "evidence"))
                .await
                .expect("W writes a claim -> evidence edge");
            let deletes = (
                exec(&mut conn, DELETE, authored).await,
                exec(&mut conn, DELETE, from_paper).await,
            );
            (conn, (authored, from_paper, to_evidence, deletes))
        })
        .await;

    assert_eq!(
        tuple(&pool, authored).await,
        t(WORLD, "public", None, Some(w_g))
    );
    assert_eq!(
        tuple(&pool, from_paper).await,
        t(WORLD, "public", None, Some(w_g))
    );
    assert_eq!(
        tuple(&pool, to_evidence).await,
        t(w_g, "public", None, Some(w_g)),
        "a claim -> evidence edge is between two tenancy-bearing epistemic nodes"
    );
    assert_eq!(
        deletes,
        (Ok(0), Ok(0)),
        "a structural edge is administrative: its writer cannot delete it"
    );
}

/// KC-1: a registered non-claim SOURCE whose owner writes provenance edges
/// in-process on its own stamped transaction (`synthesis`) is in scope: its
/// edge onto a public claim is the writer's. As a TARGET it is not.
///
/// `syntheses` is created by a downstream product's migrations, not the
/// kernel's; `validate_edge_reference` resolves the type through the
/// `entity_types` registry and returns false when the backing table is absent,
/// so the test creates a stand-in with the registered id column.
#[sqlx::test(migrations = "../../migrations")]
async fn a_synthesis_sourced_edge_onto_a_public_claim_is_the_writers(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "synthesis-owner").await;
    let claim = fixture::seed_public_claim(&pool, author, "public claim").await;
    let registered: (String, String) = sqlx::query_as(
        "SELECT table_name, id_column FROM entity_types WHERE type_name = 'synthesis'",
    )
    .fetch_one(&pool)
    .await
    .expect("synthesis is a registered entity type");
    assert_eq!(registered, ("syntheses".to_string(), "id".to_string()));
    for stmt in [
        "CREATE TABLE IF NOT EXISTS public.syntheses (id uuid PRIMARY KEY)",
        "GRANT SELECT ON public.syntheses TO epigraph_app",
    ] {
        sqlx::query(stmt).execute(&pool).await.expect(stmt);
    }
    let synthesis = Uuid::new_v4();
    sqlx::query("INSERT INTO public.syntheses (id) VALUES ($1)")
        .bind(synthesis)
        .execute(&pool)
        .await
        .expect("seed a synthesis");

    let p = pool.clone();
    let (sourced, targeted, own_delete) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let sourced = insert_edge(&mut conn, (synthesis, "synthesis"), (claim, "claim"))
                .await
                .expect("a synthesis-sourced edge is admitted");
            let targeted = insert_edge(&mut conn, (claim, "claim"), (synthesis, "synthesis"))
                .await
                .expect("a synthesis-targeted edge is admitted");
            let own_delete = exec(&mut conn, DELETE, sourced).await;
            (conn, (sourced, targeted, own_delete))
        })
        .await;
    assert_eq!(
        own_delete,
        Ok(1),
        "the synthesis owner deletes its own edge"
    );
    assert!(!exists(&pool, sourced).await);
    assert_eq!(
        tuple(&pool, targeted).await,
        t(WORLD, "public", None, Some(w_g)),
        "synthesis is in scope as a SOURCE only"
    );

    // Re-insert to read the tuple of a live synthesis-sourced edge.
    let p = pool.clone();
    let again = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let e = insert_edge(&mut conn, (synthesis, "synthesis"), (claim, "claim"))
            .await
            .expect("re-insert");
        (conn, e)
    })
    .await;
    assert_eq!(tuple(&pool, again).await, t(w_g, "public", None, Some(w_g)));
}

// ===========================================================================
// 3. Two agents of one operator share their edges; an unlinked one does not.
// ===========================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn an_operators_agents_share_their_edges_and_nobody_else_does(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (operator, operator_g) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (agent_a, agent_a_g) = fixture::seed_agent_with_group(&pool, "operated-a").await;
    let (agent_b, _) = fixture::seed_agent_with_group(&pool, "operated-b").await;
    let (unlinked, _) = fixture::seed_agent_with_group(&pool, "unlinked").await;
    link(&pool, agent_a, operator).await;
    link(&pool, agent_b, operator).await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (edge, by_unlinked, by_b) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, agent_a).await;
            let edge = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
                .await
                .expect("A links");
            stamp(&mut conn, &p, unlinked).await;
            let by_unlinked = exec(&mut conn, DELETE, edge).await;
            stamp(&mut conn, &p, agent_b).await;
            let by_b = exec(&mut conn, DELETE, edge).await;
            (conn, (edge, by_unlinked, by_b))
        })
        .await;
    assert_eq!(by_unlinked, Ok(0), "an unlinked agent is refused");
    assert_eq!(
        by_b,
        Ok(1),
        "a sibling agent of the same operator is admitted"
    );
    assert!(!exists(&pool, edge).await);
    assert_ne!(agent_a_g, operator_g);
}

/// The owner is the OPERATOR's group, not the operated agent's own (#503's
/// rule, reused through `epigraph_writer_group()`).
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agents_edge_is_owned_by_its_operators_group(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (operator, operator_g) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "operated").await;
    link(&pool, agent, operator).await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;

    let p = pool.clone();
    let edge = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, agent).await;
        let e = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
            .await
            .expect("link");
        (conn, e)
    })
    .await;
    assert_eq!(
        tuple(&pool, edge).await,
        t(operator_g, "public", None, Some(operator_g))
    );
}

// ===========================================================================
// 4. No principal, no writable group, a privileged stamped session.
// ===========================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn only_a_principal_with_a_writable_group_owns_an_edge(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let groupless = seed_groupless_agent(&pool).await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    assert_app_role_does_not_bypass(&pool).await;

    // The application role, unstamped, and with a principal but no groups.
    let (unstamped, no_group) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        unstamp(&mut conn).await;
        let unstamped = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
            .await
            .expect("an unstamped insert still lands as world (077's world arm)");
        set_gucs(&mut conn, "", "", &groupless.to_string()).await;
        let no_group = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
            .await
            .expect("a principal with no writable group lands as world");
        (conn, (unstamped, no_group))
    })
    .await;
    assert_eq!(
        tuple(&pool, unstamped).await,
        t(WORLD, "public", None, None)
    );
    assert_eq!(tuple(&pool, no_group).await, t(WORLD, "public", None, None));

    // The maintenance role with no principal: world.
    let maint = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        unstamp(&mut conn).await;
        let e = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
            .await
            .expect("a maintenance insert");
        (conn, e)
    })
    .await;
    assert_eq!(tuple(&pool, maint).await, t(WORLD, "public", None, None));

    // A privileged session that carries W's stamp: W's group (arm (i) applies
    // to privileged sessions with a principal; 114 section 2(b) does not).
    let mut conn = pool.acquire().await.expect("acquire");
    stamp(&mut conn, &pool, w).await;
    let privileged = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
        .await
        .expect("a privileged stamped insert");
    unstamp(&mut conn).await;
    drop(conn);
    assert_eq!(
        tuple(&pool, privileged).await,
        t(w_g, "public", None, Some(w_g))
    );
}

// ===========================================================================
// 5. Declarations and mixed endpoints keep 072's rules.
// ===========================================================================

/// An explicit `('group', G)` declaration between two public claims is kept
/// (072's no-widening arm runs first, unchanged), with the author recorded.
/// A declared co-owned edge survives its INSERT and a propagation fire.
#[sqlx::test(migrations = "../../migrations")]
async fn a_declared_private_edge_between_public_claims_is_kept_with_its_co_owner(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (_h, h_g) = fixture::seed_agent_with_group(&pool, "co-owner-h").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;

    let p = pool.clone();
    let declared = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let e = insert_declared_edge(&mut conn, a, b, "group", w_g, None, None)
            .await
            .expect("W declares its edge private to its own group");
        (conn, e)
    })
    .await;
    assert_eq!(
        tuple(&pool, declared).await,
        t(w_g, "group", None, Some(w_g))
    );

    // A co-owned declaration (privileged: a writer in both groups does not
    // exist for personal groups).
    let mut conn = pool.acquire().await.expect("acquire");
    unstamp(&mut conn).await;
    let co_owned = insert_declared_edge(&mut conn, a, b, "group", w_g, Some(h_g), None)
        .await
        .expect("a co-owned declaration");
    drop(conn);
    assert_eq!(
        tuple(&pool, co_owned).await,
        t(w_g, "group", Some(h_g), None),
        "INSERT kept the co-owner"
    );

    // Fire propagation: a public-to-public owner change of an endpoint.
    sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(a)
        .bind(w_g)
        .execute(&pool)
        .await
        .expect("re-own endpoint A, staying public");
    assert_eq!(
        tuple(&pool, co_owned).await,
        t(w_g, "group", Some(h_g), None),
        "a propagation fire kept the co-owner"
    );
    assert_eq!(
        tuple(&pool, declared).await,
        t(w_g, "group", None, Some(w_g))
    );
}

/// A public claim linked to a claim private to G: the meet, `('group', G)`. A
/// writer that can READ G's claim but not write G is refused (42501, the write
/// rule; a writer that cannot even see the endpoint is refused earlier, by the
/// edge-reference check); a writer in G is admitted, the edge is G's (not the
/// writer's), and the author record names the writer.
#[sqlx::test(migrations = "../../migrations")]
async fn a_mixed_edge_takes_the_meet_and_records_its_author(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (owner, g) = fixture::seed_agent_with_group(&pool, "group-owner").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-in-g").await;
    let (z, _) = fixture::seed_agent_with_group(&pool, "reader-of-g").await;
    add_writer(&pool, g, w).await;
    add_member(&pool, g, z, "reader").await;
    let public = fixture::seed_public_claim(&pool, author, "public claim").await;
    let private = fixture::seed_group_claim(&pool, owner, g, "G's private claim").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (by_z, by_w) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, z).await;
        let by_z = insert_edge(&mut conn, (public, "claim"), (private, "claim")).await;
        stamp(&mut conn, &p, w).await;
        let by_w = insert_edge(&mut conn, (public, "claim"), (private, "claim")).await;
        (conn, (by_z, by_w))
    })
    .await;
    assert_eq!(
        by_z,
        Err("42501".to_string()),
        "a writer not in G is refused"
    );
    let by_w = by_w.expect("a writer in G is admitted");
    assert_eq!(tuple(&pool, by_w).await, t(g, "group", None, Some(w_g)));
}

// ===========================================================================
// 6. Propagation: public-to-public owner changes never touch a public edge.
// ===========================================================================

/// A maintenance-style public-to-public owner change of an endpoint (the
/// operator re-own) leaves W's edge AND a world edge exactly as they were: the
/// `edges` update counter in the changing transaction does not move. Then
/// privatizing the endpoint narrows W's edge to the meet.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_owner_change_leaves_public_edges_and_a_narrowing_takes_the_meet(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (_o, o_g) = fixture::seed_agent_with_group(&pool, "new-owner").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let world_edge = fixture::seed_edge(&pool, a, b).await;

    let p = pool.clone();
    let w_edge = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let e = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
            .await
            .expect("W links");
        (conn, e)
    })
    .await;
    assert_eq!(
        tuple(&pool, w_edge).await,
        t(w_g, "public", None, Some(w_g))
    );
    assert_eq!(
        tuple(&pool, world_edge).await,
        t(WORLD, "public", None, None)
    );

    let mut tx = pool.begin().await.expect("begin");
    let before: i64 = sqlx::query_scalar(
        "SELECT n_tup_upd FROM pg_stat_xact_user_tables \
          WHERE schemaname = 'public' AND relname = 'edges'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("edges xact counter");
    let moved = sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(a)
        .bind(o_g)
        .execute(&mut *tx)
        .await
        .expect("re-own A, staying public")
        .rows_affected();
    let after: i64 = sqlx::query_scalar(
        "SELECT n_tup_upd FROM pg_stat_xact_user_tables \
          WHERE schemaname = 'public' AND relname = 'edges'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("edges xact counter");
    tx.commit().await.expect("commit");
    assert_eq!(moved, 1, "calibration: the endpoint moved");
    assert_eq!(after - before, 0, "no edge row was written by propagation");
    assert_eq!(
        tuple(&pool, w_edge).await,
        t(w_g, "public", None, Some(w_g))
    );
    assert_eq!(
        tuple(&pool, world_edge).await,
        t(WORLD, "public", None, None)
    );

    // A narrowing takes the meet; the author record stays.
    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(a)
        .execute(&pool)
        .await
        .expect("privatize A into its owner's group");
    assert_eq!(tuple(&pool, w_edge).await, t(o_g, "group", None, Some(w_g)));
    assert_eq!(tuple(&pool, world_edge).await, t(o_g, "group", None, None));
}

// ===========================================================================
// 7. Privatization: apply then revert restores every tuple exactly.
// ===========================================================================

/// Apply (restrict endpoint A into group P, then the boundary re-meet) and
/// revert (restore A to public, then the re-meet) on a privileged connection,
/// as the privatization job runs them. Three edges touch A:
///   * W's claim -> claim edge: `(W_g, public)` -> the meet -> `(W_g, public)`
///     again, from the author record;
///   * a legacy (principal-less) edge: world -> the meet -> world;
///   * W's OUT-OF-SCOPE agent -> claim edge, which carries W's author record
///     but was stamped world: world -> the meet -> world, never W's.
/// Every author record is untouched throughout.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_then_revert_restores_every_edge_tuple_exactly(pool: PgPool) {
    use epigraph_db::repos::privatization::PrivatizationRepository;

    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (_p, p_g) = fixture::seed_agent_with_group(&pool, "privatizing-group").await;
    let a = fixture::seed_public_claim(&pool, author, "public A, to privatize").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let legacy = fixture::seed_edge(&pool, a, b).await;

    let p = pool.clone();
    let (w_edge, structural) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let w_edge = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
            .await
            .expect("W's claim -> claim edge");
        let structural = insert_edge(&mut conn, (w, "agent"), (a, "claim"))
            .await
            .expect("W's agent -> claim edge");
        (conn, (w_edge, structural))
    })
    .await;
    let before = [
        tuple(&pool, w_edge).await,
        tuple(&pool, legacy).await,
        tuple(&pool, structural).await,
    ];
    assert_eq!(
        before,
        [
            t(w_g, "public", None, Some(w_g)),
            t(WORLD, "public", None, None),
            t(WORLD, "public", None, Some(w_g)),
        ],
        "fixture shape"
    );

    // Apply.
    let mut tx = pool.begin().await.expect("begin");
    let moved = PrivatizationRepository::restrict_claims_conn(&mut tx, &[a], p_g)
        .await
        .expect("restrict A");
    assert_eq!(moved, vec![a]);
    PrivatizationRepository::recompute_boundary_meet_conn(&mut tx, &[a])
        .await
        .expect("re-meet (apply)");
    tx.commit().await.expect("commit apply");
    for e in [w_edge, legacy, structural] {
        let (o, v, co, _) = tuple(&pool, e).await;
        assert_eq!(
            (o, v.as_str(), co),
            (p_g, "group", None),
            "applied: the meet"
        );
    }

    // Revert.
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL epigraph.allow_declassify = 'yes'")
        .execute(&mut *tx)
        .await
        .expect("allow declassify");
    sqlx::query("UPDATE claims SET visibility = 'public', owner_group_id = $2 WHERE id = $1")
        .bind(a)
        .bind(WORLD)
        .execute(&mut *tx)
        .await
        .expect("restore A");
    PrivatizationRepository::recompute_boundary_meet_conn(&mut tx, &[a])
        .await
        .expect("re-meet (revert)");
    tx.commit().await.expect("commit revert");

    let after = [
        tuple(&pool, w_edge).await,
        tuple(&pool, legacy).await,
        tuple(&pool, structural).await,
    ];
    assert_eq!(
        after, before,
        "apply then revert restores the writer's edge, the legacy edge and the \
         out-of-scope edge byte for byte"
    );
}

// ===========================================================================
// 8. Re-points (raw SQL; see the module doc).
// ===========================================================================

/// The owner re-points its public edge onto another public claim (application
/// role): 1 row, owner kept, signature cleared (117's unsign). A bystander's
/// re-point changes 0 rows. The administrative re-point (a privileged session
/// with no principal, as the cascade runs) keeps W's owner too.
#[sqlx::test(migrations = "../../migrations")]
async fn a_repoint_keeps_the_writers_owner_for_the_owner_and_the_cascade(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (z, _) = fixture::seed_agent_with_group(&pool, "bystander-z").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let c = fixture::seed_public_claim(&pool, author, "public C").await;
    let d = fixture::seed_public_claim(&pool, author, "public D").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let edge = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let e = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
            .await
            .expect("W links");
        (conn, e)
    })
    .await;
    sqlx::query(
        "UPDATE edges SET signature = decode(repeat('ab', 64), 'hex'), signer_id = $2, \
                          content_hash = decode(repeat('cd', 32), 'hex') WHERE id = $1",
    )
    .bind(edge)
    .bind(w)
    .execute(&pool)
    .await
    .expect("sign the edge (privileged)");

    let p = pool.clone();
    let (by_z, by_w) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, z).await;
        let by_z = exec2(
            &mut conn,
            "UPDATE edges SET target_id = $2 WHERE id = $1",
            edge,
            d,
        )
        .await;
        stamp(&mut conn, &p, w).await;
        let by_w = exec2(
            &mut conn,
            "UPDATE edges SET source_id = $2 WHERE id = $1",
            edge,
            c,
        )
        .await;
        (conn, (by_z, by_w))
    })
    .await;
    assert_eq!(by_z, Ok(0), "a bystander re-points nothing");
    assert_eq!(by_w, Ok(1), "the owner re-points its own edge");
    let (source, signer): (Uuid, Option<Uuid>) =
        sqlx::query_as("SELECT source_id, signer_id FROM edges WHERE id = $1")
            .bind(edge)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!((source, signer), (c, None), "moved, and unsigned");
    assert_eq!(tuple(&pool, edge).await, t(w_g, "public", None, Some(w_g)));

    // The administrative re-point: a privileged session with no principal.
    let mut conn = pool.acquire().await.expect("acquire");
    unstamp(&mut conn).await;
    let n = exec2(
        &mut conn,
        "UPDATE edges SET target_id = $2 WHERE id = $1",
        edge,
        d,
    )
    .await;
    drop(conn);
    assert_eq!(n, Ok(1));
    assert_eq!(
        tuple(&pool, edge).await,
        t(w_g, "public", None, Some(w_g)),
        "the cascade's re-point keeps the writer's owner (arm (u))"
    );
}

/// Arm (u) keeps the owner a public edge HAS, not the one its author record
/// would give: an edge a privileged session re-owned (an operator's
/// administrative re-own, so its owner differs from its author record) keeps
/// that owner when the cascade re-points it on a principal-less session, and so
/// does a re-point onto a structural endpoint. Without (u) the re-point would
/// recompute the owner from the author record (or the scope) and silently undo
/// the re-own.
#[sqlx::test(migrations = "../../migrations")]
async fn a_repoint_keeps_the_owner_the_edge_has_not_the_author_record(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (_o, o_g) = fixture::seed_agent_with_group(&pool, "operator-o").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let c = fixture::seed_public_claim(&pool, author, "public C").await;

    let p = pool.clone();
    let edge = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let e = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
            .await
            .expect("W links");
        (conn, e)
    })
    .await;
    sqlx::query("UPDATE edges SET owner_group_id = $2 WHERE id = $1")
        .bind(edge)
        .bind(o_g)
        .execute(&pool)
        .await
        .expect("an administrative re-own (privileged)");
    assert_eq!(tuple(&pool, edge).await, t(o_g, "public", None, Some(w_g)));

    let mut conn = pool.acquire().await.expect("acquire");
    unstamp(&mut conn).await;
    let n = exec2(
        &mut conn,
        "UPDATE edges SET target_id = $2 WHERE id = $1",
        edge,
        c,
    )
    .await;
    assert_eq!(n, Ok(1));
    assert_eq!(
        tuple(&pool, edge).await,
        t(o_g, "public", None, Some(w_g)),
        "the cascade's re-point keeps the owner the edge has"
    );
    let n = sqlx::query("UPDATE edges SET target_id = $2, target_type = 'agent' WHERE id = $1")
        .bind(edge)
        .bind(author)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected());
    drop(conn);
    assert_eq!(n.expect("re-point onto a structural endpoint"), 1);
    assert_eq!(
        tuple(&pool, edge).await,
        t(o_g, "public", None, Some(w_g)),
        "so does a re-point onto a structural endpoint"
    );
}

/// Re-points never widen: onto a group claim the edge takes the meet; a group
/// edge re-pointed onto public endpoints stays group with its co-owner; a
/// mixed private edge re-pointed onto a PUBLIC canonical (the statement the
/// supersede / dedup cascade issues, on a privileged session) stays group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_repoint_never_widens(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (owner, g) = fixture::seed_agent_with_group(&pool, "group-owner").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (_h, h_g) = fixture::seed_agent_with_group(&pool, "co-owner-h").await;
    add_writer(&pool, g, w).await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let canonical = fixture::seed_public_claim(&pool, author, "public canonical").await;
    let private = fixture::seed_group_claim(&pool, owner, g, "G's private claim").await;

    let p = pool.clone();
    let (w_edge, onto_group, mixed) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let w_edge = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
                .await
                .expect("W links");
            let onto_group = exec2(
                &mut conn,
                "UPDATE edges SET target_id = $2 WHERE id = $1",
                w_edge,
                private,
            )
            .await;
            let mixed = insert_edge(&mut conn, (a, "claim"), (private, "claim"))
                .await
                .expect("a mixed edge");
            (conn, (w_edge, onto_group, mixed))
        })
        .await;
    assert_eq!(onto_group, Ok(1));
    assert_eq!(
        tuple(&pool, w_edge).await,
        t(g, "group", None, Some(w_g)),
        "onto a group claim: the meet"
    );

    // A co-owned group edge between public endpoints, re-pointed (privileged).
    let mut conn = pool.acquire().await.expect("acquire");
    unstamp(&mut conn).await;
    let co_owned = insert_declared_edge(&mut conn, a, b, "group", g, Some(h_g), None)
        .await
        .expect("declared co-owned");
    let n = exec2(
        &mut conn,
        "UPDATE edges SET target_id = $2 WHERE id = $1",
        co_owned,
        canonical,
    )
    .await;
    assert_eq!(n, Ok(1));
    // The mixed private edge, re-pointed onto the public canonical by the
    // cascade's statement.
    let n = exec2(
        &mut conn,
        "UPDATE edges SET target_id = $2 WHERE id = $1",
        mixed,
        canonical,
    )
    .await;
    assert_eq!(n, Ok(1));
    drop(conn);
    assert_eq!(
        tuple(&pool, co_owned).await,
        t(g, "group", Some(h_g), None),
        "a group edge re-pointed onto public endpoints stays group, co-owner unchanged"
    );
    assert_eq!(
        tuple(&pool, mixed).await,
        t(g, "group", None, Some(w_g)),
        "a mixed private edge re-pointed onto a public canonical stays group"
    );
}

// ===========================================================================
// 9. The author record is immutable to the application.
// ===========================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_privileged_session_cannot_rewrite_the_author_record(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (_z, z_g) = fixture::seed_agent_with_group(&pool, "other-z").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;

    let p = pool.clone();
    let (edge, rewrite) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let edge = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
            .await
            .expect("W links");
        let rewrite = exec2(
            &mut conn,
            "UPDATE edges SET writer_group_id = $2 WHERE id = $1",
            edge,
            z_g,
        )
        .await;
        (conn, (edge, rewrite))
    })
    .await;
    assert_eq!(rewrite, Err("42501".to_string()));
    assert_eq!(tuple(&pool, edge).await, t(w_g, "public", None, Some(w_g)));
}

// ===========================================================================
// 11. The legacy re-own to the recorded signer.
// ===========================================================================

async fn sign_as(pool: &PgPool, edge: Uuid, signer: Uuid) {
    sqlx::query(
        "UPDATE edges SET signature = decode(repeat('ab', 64), 'hex'), signer_id = $2 \
          WHERE id = $1",
    )
    .bind(edge)
    .bind(signer)
    .execute(pool)
    .await
    .expect("sign (privileged)");
}

async fn reown(
    pool: &PgPool,
    limit: Option<i32>,
    exclude: Option<Vec<Uuid>>,
) -> Result<i64, String> {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        unstamp(&mut conn).await;
        let r: Result<i64, String> =
            sqlx::query_scalar("SELECT public.epigraph_reown_legacy_edges_to_signer($1, $2)")
                .bind(limit)
                .bind(exclude)
                .fetch_one(&mut *conn)
                .await
                .map_err(|e| code(&e));
        (conn, r)
    })
    .await
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_legacy_reown_follows_an_attributable_signer_only(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (operator, operator_g) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (linked, _) = fixture::seed_agent_with_group(&pool, "linked-signer").await;
    let (personal, personal_g) = fixture::seed_agent_with_group(&pool, "personal-signer").await;
    let (excluded, _) = fixture::seed_agent_with_group(&pool, "excluded-signer").await;
    let groupless = seed_groupless_agent(&pool).await;
    link(&pool, linked, operator).await;
    let (owner, g) = fixture::seed_agent_with_group(&pool, "group-owner").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    let private = fixture::seed_group_claim(&pool, owner, g, "private").await;

    let by_linked = fixture::seed_edge(&pool, a, b).await;
    let by_personal = fixture::seed_edge(&pool, b, a).await;
    let by_excluded = fixture::seed_edge(&pool, a, b).await;
    let by_groupless = fixture::seed_edge(&pool, a, b).await;
    let unsigned = fixture::seed_edge(&pool, a, b).await;
    let out_of_scope: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'agent', $2, 'claim', 'AUTHORED') RETURNING id",
    )
    .bind(linked)
    .bind(a)
    .fetch_one(&pool)
    .await
    .expect("an AUTHORED edge");
    // A stale world stamp on an edge whose meet is private: never widened.
    let not_public_meet = fixture::seed_edge_owned_by(&pool, a, private, "public", WORLD).await;
    for (edge, signer) in [
        (by_linked, linked),
        (by_personal, personal),
        (by_excluded, excluded),
        (by_groupless, groupless),
        (out_of_scope, linked),
        (not_public_meet, linked),
    ] {
        sign_as(&pool, edge, signer).await;
    }

    assert_eq!(
        reown(&pool, Some(100), None).await,
        Err("22004".to_string()),
        "the exclusion list is mandatory"
    );
    assert_eq!(reown(&pool, Some(100), Some(vec![excluded])).await, Ok(2));
    assert_eq!(
        reown(&pool, Some(100), Some(vec![excluded])).await,
        Ok(0),
        "idempotent"
    );

    assert_eq!(
        tuple(&pool, by_linked).await,
        t(operator_g, "public", None, Some(operator_g)),
        "an operator-linked signer: the operator's group, owner AND author record"
    );
    assert_eq!(
        tuple(&pool, by_personal).await,
        t(personal_g, "public", None, Some(personal_g))
    );
    for (edge, why) in [
        (by_excluded, "an excluded signer"),
        (by_groupless, "a signer with neither group"),
        (unsigned, "an unsigned edge"),
        (out_of_scope, "an out-of-scope edge"),
        (not_public_meet, "a non-public meet"),
    ] {
        let (o, v, _, wr) = tuple(&pool, edge).await;
        assert_eq!(
            (o, v.as_str(), wr),
            (WORLD, "public", None),
            "{why} is skipped"
        );
    }
    let events: Vec<(Option<Uuid>, i64)> = sqlx::query_as(
        "SELECT agent_id, (details->>'rows')::bigint FROM security_events \
          WHERE event_type = 'edges.legacy_signer_reown'",
    )
    .fetch_all(&pool)
    .await
    .expect("events");
    assert_eq!(
        events,
        vec![(None, 2)],
        "exactly one event, for the call that changed rows"
    );

    // The application role may not call it.
    let refused = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r: Result<i64, String> = sqlx::query_scalar(
            "SELECT public.epigraph_reown_legacy_edges_to_signer(10, ARRAY[]::uuid[])",
        )
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| code(&e));
        (conn, r)
    })
    .await;
    assert_eq!(refused, Err("42501".to_string()));
}

// ===========================================================================
// 13. Retract, then link the same triple again.
// ===========================================================================

/// W links A -> B through `create_if_not_exists_conn` (the link tools' and the
/// HTTP create route's path), retracts it, and links the same triple again:
/// a NEW in-force edge is created (`was_created = true`, a different id), not
/// a silent `was_created = false` onto the retracted row. Z re-asserting the
/// same triple gets W's in-force edge back and is told it does not own it.
/// The explicit re-run variant still counts the retracted row as present.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_link_asserted_again_is_a_new_edge(pool: PgPool) {
    use epigraph_db::EdgeRepository;

    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (z, _) = fixture::seed_agent_with_group(&pool, "other-z").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;
    assert_app_role_does_not_bypass(&pool).await;

    async fn link_ab(
        conn: &mut PgConnection,
        a: Uuid,
        b: Uuid,
    ) -> Result<(epigraph_db::EdgeRow, bool), epigraph_db::DbError> {
        EdgeRepository::create_if_not_exists_conn(
            conn, a, "claim", b, "claim", "supports", None, None, None,
        )
        .await
    }

    let p = pool.clone();
    let out = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let (first, first_created) = link_ab(&mut conn, a, b).await.expect("W links");
        let first_owned = EdgeRepository::owned_by_session(&mut *conn, first.id)
            .await
            .expect("owned");
        let retracted = EdgeRepository::retract_by_id(&mut *conn, first.id)
            .await
            .expect("W retracts its own edge");
        let (again, again_created) = link_ab(&mut conn, a, b).await.expect("W links again");
        let (rerun, rerun_created) = EdgeRepository::create_if_absent_including_retracted_conn(
            &mut conn, b, "claim", a, "claim", "refutes", None, None, None,
        )
        .await
        .expect("a re-run writer's first link");
        let rerun_retracted = EdgeRepository::retract_by_id(&mut *conn, rerun.id)
            .await
            .expect("retract it");
        let (rerun_again, rerun_again_created) =
            EdgeRepository::create_if_absent_including_retracted_conn(
                &mut conn, b, "claim", a, "claim", "refutes", None, None, None,
            )
            .await
            .expect("the re-run");
        stamp(&mut conn, &p, z).await;
        let (by_z, by_z_created) = link_ab(&mut conn, a, b).await.expect("Z re-asserts");
        let z_owned = EdgeRepository::owned_by_session(&mut *conn, by_z.id)
            .await
            .expect("owned");
        (
            conn,
            (
                (first.id, first_created, first_owned, retracted),
                (again.id, again_created, again.valid_to.is_none()),
                (rerun.id, rerun_created, rerun_retracted),
                (rerun_again.id, rerun_again_created),
                (by_z.id, by_z_created, z_owned),
            ),
        )
    })
    .await;
    let (first, again, rerun, rerun_again, by_z) = out;
    assert_eq!((first.1, first.2, first.3), (true, true, true));
    assert!(
        again.1,
        "the re-assertion inserts, it does not report the retracted row"
    );
    assert_ne!(again.0, first.0, "a new edge, not the retracted one");
    assert!(again.2, "and it is in force");
    assert_eq!(
        tuple(&pool, again.0).await,
        t(w_g, "public", None, Some(w_g))
    );
    assert!(rerun.1 && rerun.2);
    assert_eq!(
        (rerun_again.0, rerun_again.1),
        (rerun.0, false),
        "the explicit re-run variant never resurrects a retracted edge"
    );
    assert_eq!(
        (by_z.0, by_z.1, by_z.2),
        (again.0, false, false),
        "Z gets W's in-force edge back, and is told it is not Z's"
    );
}

// ===========================================================================
// 14. The `edge_retract` deferral is the edge owner's, for a withdrawn edge factor.
// ===========================================================================

/// 120's `epigraph_record_cascade_deferral` records `edge_retract` only for an
/// edge the session owns or co-owns, that carries an edge-factor perspective
/// (`perspective_type = 'edge'`), and that is not retracted into the future.
/// Everything else is CX03 (42501), with nothing recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn the_edge_retract_deferral_is_the_owners_and_only_for_a_withdrawn_edge_factor(
    pool: PgPool,
) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, _) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (z, _) = fixture::seed_agent_with_group(&pool, "bystander-z").await;
    let a = fixture::seed_public_claim(&pool, author, "public A").await;
    let b = fixture::seed_public_claim(&pool, author, "public B").await;

    let p = pool.clone();
    let [retracted, future, unkeyed, genuine] =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let mut ids = [Uuid::nil(); 4];
            for slot in &mut ids {
                *slot = insert_edge(&mut conn, (a, "claim"), (b, "claim"))
                    .await
                    .expect("W links");
            }
            (conn, ids)
        })
        .await;
    for (id, kind) in [
        (retracted, "edge"),
        (future, "edge"),
        (genuine, "analytical"),
    ] {
        sqlx::query("INSERT INTO perspectives (id, name, perspective_type) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(format!("w12b {kind} {id}"))
            .bind(kind)
            .execute(&pool)
            .await
            .expect("perspective");
    }
    sqlx::query(
        "UPDATE edges SET valid_to = CASE WHEN id = $2 THEN now() + interval '1 day' \
                                          ELSE now() END \
          WHERE id = ANY($1)",
    )
    .bind(vec![retracted, future, unkeyed, genuine])
    .bind(future)
    .execute(&pool)
    .await
    .expect("retract (privileged)");

    let record = |agent: Uuid, edge: Uuid| {
        let p = pool.clone();
        async move {
            fixture::as_role(&p.clone(), "epigraph_app", |mut conn| async move {
                stamp(&mut conn, &p, agent).await;
                let r: Result<Uuid, String> = sqlx::query_scalar(
                    "SELECT public.epigraph_record_cascade_deferral(\
                         'edge_retract', $1, $2, NULL, NULL, NULL, 'w12b')",
                )
                .bind(agent)
                .bind(edge)
                .fetch_one(&mut *conn)
                .await
                .map_err(|e| code(&e));
                (conn, r)
            })
            .await
        }
    };
    assert_eq!(
        record(z, retracted).await,
        Err("42501".to_string()),
        "a bystander cannot defer a cascade over another writer's edge"
    );
    for (edge, why) in [
        (future, "a future-dated retraction"),
        (unkeyed, "an edge with no edge-factor perspective"),
        (genuine, "a genuine (non-edge) perspective"),
    ] {
        assert_eq!(
            record(w, edge).await,
            Err("42501".to_string()),
            "{why} records nothing"
        );
    }
    record(w, retracted)
        .await
        .expect("the owner records its withdrawn edge factor");
    let rows: Vec<(Option<Uuid>, String)> = sqlx::query_as(
        "SELECT agent_id, details->'trigger'->>'subject_id' FROM security_events \
          WHERE event_type = 'cascade.deferred' AND details->>'cause' = 'edge_retract'",
    )
    .fetch_all(&pool)
    .await
    .expect("deferrals");
    assert_eq!(rows, vec![(Some(w), retracted.to_string())]);
}

// ===========================================================================
// 17. Catalog ratchets.
// ===========================================================================

async fn prosrc(pool: &PgPool, name: &str) -> String {
    sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc WHERE proname = $1 AND pronamespace = 'public'::regnamespace",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{name} must exist: {e}"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_trigger_and_the_reown_carry_the_writer_rule_and_the_one_scope(pool: PgPool) {
    let trigger = prosrc(&pool, "epigraph_edges_tenancy").await;
    for needle in [
        "public.epigraph_writer_group()",
        "OLD.owner_group_id",
        "public.epigraph_edge_writer_scope(NEW.source_type, NEW.target_type)",
        "NEW.writer_group_id := CASE WHEN public.epigraph_principal_id() IS NOT NULL",
    ] {
        assert!(
            trigger.contains(needle),
            "the trigger lost `{needle}`:\n{trigger}"
        );
    }
    let reown = prosrc(&pool, "epigraph_reown_legacy_edges_to_signer").await;
    for needle in [
        "public.epigraph_edge_writer_scope(e.source_type, e.target_type)",
        "<> ALL (p_exclude_signers)",
        "writer_group_id = cand.w",
    ] {
        assert!(
            reown.contains(needle),
            "the legacy re-own lost `{needle}`:\n{reown}"
        );
    }
    // Exactly these catalog bodies reference the scope (the revert is Rust).
    let referencing: Vec<String> = sqlx::query_scalar(
        "SELECT proname::text FROM pg_proc \
          WHERE pronamespace = 'public'::regnamespace \
            AND prosrc LIKE '%epigraph_edge_writer_scope%' ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("catalog");
    assert_eq!(
        referencing,
        vec![
            "epigraph_edges_tenancy".to_string(),
            "epigraph_reown_legacy_edges_to_signer".to_string()
        ]
    );
}

/// The privatization revert is Rust, so its half of "one scope, read in every
/// recompute site" is a source ratchet: the body of
/// `recompute_boundary_meet_conn` must consult the scope predicate AND the
/// author record for the both-public owner.
#[test]
fn the_privatization_revert_reads_the_scope_and_the_author_record() {
    let src = include_str!("../src/repos/privatization.rs");
    let start = src
        .find("pub async fn recompute_boundary_meet_conn(")
        .expect("recompute_boundary_meet_conn exists");
    let end = start
        + src[start..]
            .find("\n    }\n")
            .expect("the function body ends");
    let body = &src[start..end];
    for needle in [
        "public.epigraph_edge_writer_scope(e.source_type, e.target_type)",
        "wg.id = e.writer_group_id",
        "THEN e.writer_group_id END AS wg",
        "THEN COALESCE(ep.wg,",
    ] {
        assert!(body.contains(needle), "the revert lost `{needle}`:\n{body}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_scope_is_two_epistemic_endpoints_or_a_synthesis_source(pool: PgPool) {
    let cases = [
        ("claim", "claim", true),
        ("claim", "evidence", true),
        ("evidence", "claim", true),
        ("evidence", "evidence", true),
        ("synthesis", "claim", true),
        ("synthesis", "evidence", true),
        ("claim", "synthesis", false),
        ("agent", "claim", false),
        ("claim", "agent", false),
        ("paper", "claim", false),
        ("workflow", "claim", false),
        ("trace", "claim", false),
        ("claim", "trace", false),
        ("analysis", "claim", false),
        ("frame", "claim", false),
    ];
    for (s, tt, want) in cases {
        let got: bool = sqlx::query_scalar("SELECT public.epigraph_edge_writer_scope($1, $2)")
            .bind(s)
            .bind(tt)
            .fetch_one(&pool)
            .await
            .expect("scope");
        assert_eq!(got, want, "scope({s}, {tt})");
    }
    let null: bool = sqlx::query_scalar("SELECT public.epigraph_edge_writer_scope(NULL, 'claim')")
        .fetch_one(&pool)
        .await
        .expect("scope of NULL");
    assert!(!null, "a NULL type is never in scope");
}

/// D1's consequence and D8: no DELETE or UPDATE policy on `edges` licenses a
/// session by the endpoint it writes.
#[sqlx::test(migrations = "../../migrations")]
async fn no_edges_write_policy_licenses_the_source_writer(pool: PgPool) {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT polname::text, \
                coalesce(pg_get_expr(polqual, polrelid), '') || ' ' || \
                coalesce(pg_get_expr(polwithcheck, polrelid), '') \
           FROM pg_policy WHERE polrelid = 'public.edges'::regclass \
            AND polcmd IN ('d', 'w', '*') ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("catalog");
    assert!(rows.iter().any(|(n, _)| n == "edges_delete_owner"));
    for (name, expr) in &rows {
        assert!(
            !expr.contains("epigraph_session_writes_node"),
            "{name} still licenses the source writer: {expr}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_guard_watches_the_author_record(pool: PgPool) {
    let def: String = sqlx::query_scalar(
        "SELECT pg_get_triggerdef(t.oid) FROM pg_trigger t \
          WHERE t.tgrelid = 'public.edges'::regclass AND t.tgname = 'edges_owner_immutable'",
    )
    .fetch_one(&pool)
    .await
    .expect("edges_owner_immutable");
    assert!(
        def.contains("UPDATE OF owner_group_id, co_owner_group_id, writer_group_id"),
        "{def}"
    );
    assert!(
        def.contains("(old.writer_group_id IS DISTINCT FROM new.writer_group_id)"),
        "{def}"
    );
    let grants: (bool, bool) = sqlx::query_as(
        "SELECT has_function_privilege('epigraph_app', \
                  'public.epigraph_reown_legacy_edges_to_signer(integer, uuid[])', 'EXECUTE'), \
                has_function_privilege('epigraph_maintenance', \
                  'public.epigraph_reown_legacy_edges_to_signer(integer, uuid[])', 'EXECUTE')",
    )
    .fetch_one(&pool)
    .await
    .expect("grants");
    assert_eq!(
        grants,
        (false, true),
        "the legacy re-own is the maintenance role's alone"
    );
}
