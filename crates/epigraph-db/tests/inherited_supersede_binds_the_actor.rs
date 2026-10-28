//! Backlog 1a54283d, operator ruling R-85 (a): once the operator binding is
//! armed, the claims trigger checks the ACTOR of a supersession, not the author
//! the successor inherits.
//!
//! The supersede act (`ClaimRepository::supersede_act_conn`) restates the
//! retired claim under its author (ruling R-23 keeps that contract) and
//! records the acting agent as the successor's `AUTHORED` act edge. The
//! trigger already bound the writer (the stamped principal: bound, and a
//! writer of the owner group), but it also ran the attribution check on the
//! inherited author: an inherited author that belongs to no human was refused
//! `OPL01`, and one of another human `OPL02`, although the actor is bound and
//! writes the group. Under R-85 the inherited author of the act's INSERT is no
//! longer attributed to the writer; the writer is what is checked.
//!
//! The three refusals the inherited author caused, one test each: an author
//! bound to no human (`OPL01`), another human's live agent (`OPL02`), and
//! another human's RETIRED identity (`OPL02`).
//!
//! What stays: the writer's own checks (unbound actor `OPL01`, an actor whose
//! human does not write the group `OPL02`), the attribution of a FRESH claim
//! naming another human's agent (`OPL02`), and the attribution of a RE-OPEN of
//! an inherited successor (it is not the act and writes no act edge).
//!
//! Every write is on the APPLICATION ROLE with real stamps; the stamps list
//! the owner group as writable, so row security admits the rows and the
//! trigger alone decides.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::AgentRepository;
use sqlx::PgPool;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

/// A `('public', group)` claim by `agent`, on whatever connection `exec` is.
async fn insert_claim<'e, E>(exec: E, agent: Uuid, group: Uuid) -> Result<Uuid, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let id = Uuid::new_v4();
    let hash = id.as_bytes().repeat(2);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("inherited supersede probe {id}"))
    .bind(hash)
    .bind(agent)
    .bind(group)
    .execute(exec)
    .await?;
    Ok(id)
}

async fn arm(pool: &PgPool) {
    let armed: bool = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let armed_now: bool =
            sqlx::query_scalar("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
                .fetch_one(&mut *conn)
                .await
                .expect("the maintenance role arms");
        (conn, armed_now)
    })
    .await;
    assert!(armed, "the database arms");
}

async fn link_live(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("live link");
}

async fn add_writer(pool: &PgPool, group: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("writer membership");
}

/// Run `f` on an `epigraph_app` connection stamped as `principal`, with
/// `groups` readable AND writable, then unstamp.
async fn as_app_stamped<F, Fut, T>(pool: &PgPool, principal: Uuid, groups: &[Uuid], f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    let set = groups
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $2, false)",
        )
        .bind(principal.to_string())
        .bind(&set)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let (mut conn, out) = f(conn).await;
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, out)
    })
    .await
}

/// `actor` supersedes `old` through the real act, on an application session
/// stamped as `actor` with `groups`; committed on success. The act records
/// `actor` as the successor's act edge.
async fn supersede_as(
    pool: &PgPool,
    actor: Uuid,
    groups: &[Uuid],
    old: Uuid,
) -> Result<Uuid, epigraph_db::DbError> {
    as_app_stamped(pool, actor, groups, |mut conn| async move {
        let r = {
            let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
            let r = epigraph_db::ClaimRepository::supersede_act_conn(
                &mut tx,
                epigraph_core::ClaimId::from_uuid(old),
                &format!("a restatement of {old} by {actor}"),
                epigraph_core::TruthValue::new(0.6).expect("truth"),
                "R-85 probe",
                epigraph_db::SupersedeActor::new(actor, epigraph_db::SupersedeTool::SupersedeClaim),
            )
            .await;
            if r.is_ok() {
                tx.commit().await.expect("commit");
            }
            r.map(|(new, _)| new)
        };
        (conn, r)
    })
    .await
}

async fn author_of(pool: &PgPool, claim: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("the claim")
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("the claim")
}

/// The sources of the act edges (`properties ? 'supersede_act'`) into `claim`.
async fn act_edge_sources(pool: &PgPool, claim: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT source_id FROM edges \
          WHERE relationship = 'AUTHORED' AND source_type = 'agent' \
            AND target_id = $1 AND target_type = 'claim' AND properties ? 'supersede_act' \
          ORDER BY source_id",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("act edges")
}

/// Human A's live agent X, human B's live agent Y (a writer of A's group, as
/// B is), an unlinked legacy identity L, and two claims in A's group: L's and
/// X's. Armed. Returns `(a_group, x, y, legacy, legacy_claim, x_claim)`.
async fn two_humans_sharing_a_group(pool: &PgPool) -> (Uuid, Uuid, Uuid, Uuid, Uuid, Uuid) {
    let (a, a_group) = fixture::seed_human_operator(pool, "human-a").await;
    let (b, _) = fixture::seed_human_operator(pool, "human-b").await;
    let (x, _) = fixture::seed_agent_with_group(pool, "a-agent-x").await;
    let (y, _) = fixture::seed_agent_with_group(pool, "b-agent-y").await;
    let (legacy, _) = fixture::seed_agent_with_group(pool, "unlinked-legacy").await;
    link_live(pool, x, a).await;
    link_live(pool, y, b).await;
    // B writes A's group, and so may its agent Y.
    add_writer(pool, a_group, b).await;
    add_writer(pool, a_group, y).await;
    let legacy_claim = insert_claim(pool, legacy, a_group)
        .await
        .expect("the legacy claim");
    let x_claim = insert_claim(pool, x, a_group).await.expect("X's claim");
    arm(pool).await;
    (a_group, x, y, legacy, legacy_claim, x_claim)
}

/// `actor` supersedes `old` (authored by `author`) in `group`: the act lands,
/// the successor keeps the inherited author, the act edge names the actor and
/// the predecessor is retired.
async fn assert_actor_supersedes(
    pool: &PgPool,
    actor: Uuid,
    group: Uuid,
    old: Uuid,
    author: Uuid,
    what: &str,
) {
    let new = supersede_as(pool, actor, &[group], old)
        .await
        .unwrap_or_else(|e| panic!("{what}: the actor is bound and writes the group: {e:?}"));
    assert_eq!(
        author_of(pool, new).await,
        author,
        "{what}: the successor inherits the predecessor's author"
    );
    assert_eq!(
        act_edge_sources(pool, new).await,
        vec![actor],
        "{what}: the act edge names the actor"
    );
    assert!(
        !is_current(pool, old).await,
        "{what}: the predecessor is retired"
    );
}

/// THE RULING, first refusal the inherited author caused: human A's live
/// agent X, bound and a writer of A's group, restates a claim there by L, a
/// legacy identity bound to no human. It lands, the successor keeps L as its
/// author, and the act edge names X.
///
/// Red at the pre-R-85 trigger (153's body): `OperatorLinkRequired` (OPL01),
/// because the inherited author L is unbound.
#[sqlx::test(migrations = "../../migrations")]
async fn an_inherited_supersede_of_an_unbound_legacy_author_is_bound_on_the_actor(pool: PgPool) {
    let (a_group, x, _, legacy, legacy_claim, _) = two_humans_sharing_a_group(&pool).await;
    assert_actor_supersedes(
        &pool,
        x,
        a_group,
        legacy_claim,
        legacy,
        "X restates the unbound legacy author's claim",
    )
    .await;
}

/// THE RULING, second refusal: human B's live agent Y, a writer of A's group
/// whose human B writes it too, restates a claim there by A's agent X. It
/// lands, the successor keeps X as its author, and the act edge names Y.
///
/// Red at the pre-R-85 trigger (153's body): `OperatorScopeRefused` (OPL02),
/// because the inherited author X belongs to A, not to Y's human.
#[sqlx::test(migrations = "../../migrations")]
async fn an_inherited_supersede_of_another_humans_agent_is_bound_on_the_actor(pool: PgPool) {
    let (a_group, x, y, _, _, x_claim) = two_humans_sharing_a_group(&pool).await;
    assert_actor_supersedes(
        &pool,
        y,
        a_group,
        x_claim,
        x,
        "B's agent Y restates A's agent X's claim in a group both humans write",
    )
    .await;
}

/// THE RULING, third refusal: the inherited author R is a RETIRED identity of
/// human A (its operator link is retired, so it can never write again, but it
/// still belongs to A). Human B's live agent Y, a writer of A's group whose
/// human B writes it too, restates R's claim there. It lands, the successor
/// keeps R as its author, and the act edge names Y.
///
/// Red at the pre-R-85 trigger (153's body): `OperatorScopeRefused` (OPL02),
/// because 166's attribution reads a retired identity's human for an
/// inherited author, and R belongs to A, not to Y's human.
#[sqlx::test(migrations = "../../migrations")]
async fn an_inherited_supersede_of_another_humans_retired_identity_is_bound_on_the_actor(
    pool: PgPool,
) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "human-b").await;
    let (r, _) = fixture::seed_agent_with_group(&pool, "a-retired-r").await;
    let (y, _) = fixture::seed_agent_with_group(&pool, "b-agent-y").await;
    link_live(&pool, y, b).await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_retired_agent(&mut conn, r, a)
            .await
            .expect("R's retired tie to A");
    }
    add_writer(&pool, a_group, b).await;
    add_writer(&pool, a_group, y).await;
    let r_claim = insert_claim(&pool, r, a_group).await.expect("R's claim");
    arm(&pool).await;
    let retired: bool = sqlx::query_scalar("SELECT public.epigraph_agent_is_retired($1)")
        .bind(r)
        .fetch_one(&pool)
        .await
        .expect("probe");
    assert!(retired, "CALIBRATION: R is a retired identity of A");

    assert_actor_supersedes(
        &pool,
        y,
        a_group,
        r_claim,
        r,
        "B's agent Y restates A's retired identity R's claim in a group both humans write",
    )
    .await;
}

/// The ACTOR is still checked on the act, and a fresh claim is still
/// attributed. After R-85, as before it:
/// * an UNBOUND actor U, stamped as a writer of A's group, may not supersede
///   there (`OPL01`, the writer's binding);
/// * human C's live agent Z, whose human does not write A's group, may not
///   supersede there (`OPL02`, the writer's scope);
/// * B's agent Y, a writer of A's group, may not write a FRESH claim there
///   naming A's agent X (`OPL02`, attribution: only the act's inherited author
///   is relieved of it).
///
/// Each refused write leaves the predecessor current.
#[sqlx::test(migrations = "../../migrations")]
async fn the_actor_is_still_bound_and_scoped_and_a_fresh_claim_still_attributed(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "human-b").await;
    let (c, _) = fixture::seed_human_operator(&pool, "human-c").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "a-agent-x").await;
    let (y, _) = fixture::seed_agent_with_group(&pool, "b-agent-y").await;
    let (z, _) = fixture::seed_agent_with_group(&pool, "c-agent-z").await;
    let (u, _) = fixture::seed_agent_with_group(&pool, "unbound-u").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "unlinked-legacy").await;
    link_live(&pool, x, a).await;
    link_live(&pool, y, b).await;
    link_live(&pool, z, c).await;
    add_writer(&pool, a_group, b).await;
    add_writer(&pool, a_group, y).await;
    let for_u = insert_claim(&pool, legacy, a_group).await.expect("claim");
    let for_z = insert_claim(&pool, legacy, a_group).await.expect("claim");
    arm(&pool).await;

    let r = supersede_as(&pool, u, &[a_group], for_u).await;
    assert!(
        matches!(r, Err(epigraph_db::DbError::OperatorLinkRequired { .. })),
        "an unbound actor: {r:?}"
    );
    assert!(is_current(&pool, for_u).await, "nothing retired");

    let r = supersede_as(&pool, z, &[a_group], for_z).await;
    assert!(
        matches!(r, Err(epigraph_db::DbError::OperatorScopeRefused { .. })),
        "an actor whose human does not write the group: {r:?}"
    );
    assert!(is_current(&pool, for_z).await, "nothing retired");

    let fresh = as_app_stamped(&pool, y, &[a_group], |mut conn| async move {
        let r = insert_claim(&mut *conn, x, a_group).await;
        (conn, r)
    })
    .await;
    assert_eq!(
        fresh.as_ref().err().and_then(sqlstate).as_deref(),
        Some("OPL02"),
        "a fresh claim naming another human's agent: {fresh:?}"
    );
}

/// A RE-OPEN is not the act: it writes no act edge, so the inherited author of
/// a re-opened successor is still attributed to the writer. Human A's agent X
/// authored P; a privileged (maintenance) session restates it as S (S inherits
/// X). B's agent Y, a writer of A's group, may retire S, but re-opening S is
/// refused `OPL02`: X belongs to A, not to Y's human. CONTROL: X re-opens S
/// itself.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reopen_of_an_inherited_successor_is_still_attributed_to_its_writer(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "human-b").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "a-agent-x").await;
    let (y, _) = fixture::seed_agent_with_group(&pool, "b-agent-y").await;
    link_live(&pool, x, a).await;
    link_live(&pool, y, b).await;
    add_writer(&pool, a_group, b).await;
    add_writer(&pool, a_group, y).await;
    let p = insert_claim(&pool, x, a_group).await.expect("X's claim");
    arm(&pool).await;

    let s = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
        let (s, _) = epigraph_db::ClaimRepository::supersede_act_conn(
            &mut tx,
            epigraph_core::ClaimId::from_uuid(p),
            "a custodial restatement",
            epigraph_core::TruthValue::new(0.6).expect("truth"),
            "R-85 re-open probe",
            epigraph_db::SupersedeActor::new(a, epigraph_db::SupersedeTool::CustodialSupersede),
        )
        .await
        .expect("a privileged session restates X's claim");
        tx.commit().await.expect("commit");
        (conn, s)
    })
    .await;
    assert_eq!(author_of(&pool, s).await, x, "S inherits X");

    let set_current = |who: Uuid, current: bool| {
        let pool = pool.clone();
        async move {
            as_app_stamped(&pool, who, &[a_group], |mut conn| async move {
                let r = sqlx::query("UPDATE claims SET is_current = $2 WHERE id = $1")
                    .bind(s)
                    .bind(current)
                    .execute(&mut *conn)
                    .await
                    .map(|r| r.rows_affected());
                (conn, r)
            })
            .await
        }
    };
    assert_eq!(
        set_current(y, false).await.expect("Y retires S"),
        1,
        "Y retires S"
    );
    let reopen = set_current(y, true).await;
    assert_eq!(
        reopen.as_ref().err().and_then(sqlstate).as_deref(),
        Some("OPL02"),
        "B's agent re-opens a successor inherited by A's agent: {reopen:?}"
    );
    assert!(
        !is_current(&pool, s).await,
        "the refused re-open left S retired"
    );
    assert_eq!(
        set_current(x, true).await.expect("CONTROL: X re-opens S"),
        1,
        "CONTROL: X re-opens its own inherited successor"
    );
}

// =====================================================================
// Migration 185's precondition and its rollback.
// =====================================================================

fn up_to_below(version: i64) -> sqlx::migrate::Migrator {
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

/// The definition, owner and ACL of the function 185 re-bodies.
async fn trigger_function(pool: &PgPool) -> (String, String, Option<String>) {
    sqlx::query_as(
        "SELECT pg_get_functiondef(p.oid), p.proowner::regrole::text, p.proacl::text \
           FROM pg_proc p \
          WHERE p.oid = 'public.epigraph_claims_require_operator_binding()'::regprocedure",
    )
    .fetch_one(pool)
    .await
    .expect("the claims binding trigger function")
}

/// `docs/runbooks/185-undo.sql`, applied twice to a database that went
/// pre-185 -> 185 (not to head), restores the pre-185 (153) definition of the
/// claims binding trigger function byte for byte, with its owner and ACL; at
/// 185 the function is owned by the maintenance role and carries the 185
/// delta.
#[sqlx::test(migrations = false)]
async fn the_185_rollback_restores_the_pre_185_trigger_body(pool: PgPool) {
    migrate(&pool, &up_to_below(185))
        .await
        .expect("migrate to 184");
    let before = trigger_function(&pool).await;
    migrate(&pool, &up_to_below(186))
        .await
        .expect("migrate to 185");
    let at_185 = trigger_function(&pool).await;
    assert_ne!(
        at_185.0, before.0,
        "CALIBRATION: 185 re-bodied the function"
    );
    assert!(
        at_185.0.contains("185 (ruling R-85"),
        "the body at 185 is 185's"
    );
    assert_eq!(
        at_185.1, "epigraph_maintenance",
        "185 keeps the function maintenance-owned"
    );
    assert_eq!(at_185.2, before.2, "185 keeps the function's ACL");

    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/185-undo.sql"),
    )
    .expect("185-undo.sql");
    for run in 1..=2 {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the undo script applies (run {run}): {e}"));
    }
    assert_eq!(
        trigger_function(&pool).await,
        before,
        "the function is not its pre-185 self after the undo"
    );
}

/// 185 re-states 153's body whole, so it refuses to apply over any other body
/// (another migration's re-body would otherwise be silently dropped), and
/// changes nothing: the function and `_sqlx_migrations` stay as they were.
/// POSITIVE CONTROL: restored to 153's exact body, 185 applies.
#[sqlx::test(migrations = false)]
async fn migration_185_refuses_to_apply_over_another_body(pool: PgPool) {
    migrate(&pool, &up_to_below(185))
        .await
        .expect("migrate to 184");
    let original: String = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc \
          WHERE oid = 'public.epigraph_claims_require_operator_binding()'::regprocedure",
    )
    .fetch_one(&pool)
    .await
    .expect("153's body");
    let set_body = |src: String| {
        let pool = pool.clone();
        async move {
            sqlx::raw_sql(&format!(
                "CREATE OR REPLACE FUNCTION public.epigraph_claims_require_operator_binding() \
                 RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER \
                 SET search_path = public, pg_temp AS $body${src}$body$"
            ))
            .execute(&pool)
            .await
            .expect("re-body");
        }
    };
    set_body(format!("{original}-- a later migration's delta\n")).await;
    let err = migrate(&pool, &up_to_below(186))
        .await
        .expect_err("185 over another body");
    assert!(
        err.contains("is not the body 185 re-states"),
        "the refusal names the reason: {err}"
    );
    let applied: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 185)")
            .fetch_one(&pool)
            .await
            .expect("probe");
    assert!(!applied, "a refused 185 is not recorded");

    set_body(original).await;
    migrate(&pool, &up_to_below(186))
        .await
        .expect("POSITIVE CONTROL: over 153's body, 185 applies");
}
