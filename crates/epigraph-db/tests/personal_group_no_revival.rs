//! Migration 105: `epigraph_ensure_personal_group` never revives a revoked
//! membership and never promotes a role.
//!
//! # Why every arm calls it as `epigraph_app`
//!
//! `#[sqlx::test]` connects as `epigraph` — superuser, BYPASSRLS, owner of
//! every table — so an arm shaped "the call succeeds" proves nothing about the
//! deployed role. Every call under test here runs on a connection that is
//! `SET SESSION AUTHORIZATION epigraph_app` (`fixture::downgraded_pool`), the
//! non-bypassing role the MCP server and the API connect as, and the function is
//! reached through the same `EXECUTE` grant production uses. The STATE is read
//! back on the superuser pool, which sees every row whatever its visibility, so
//! a "still revoked" reading cannot be an RLS artefact.
//!
//! # The contract under test (for the personal group, across every epoch)
//!
//! * live row        -> the group, no write, role kept;
//! * only revoked    -> `DbError::MembershipRevoked` (SQLSTATE `RVK01`), state
//!                      unchanged;
//! * no row at all   -> first-time provisioning (group + live epoch-0 admin).
//!
//! # Verified to fail
//!
//! With `migrations/105_personal_group_no_revival.sql` removed (so the test
//! databases carry 077's `ON CONFLICT … DO UPDATE SET revoked_at = NULL, role =
//! 'admin'`), the revoked, reader, other-epoch and raw-SQL arms FAIL; the
//! provisioning and concurrency arms pass on both, as they must. The recorded
//! output is in the commit message.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{AgentRepository, DbError};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent = Uuid::new_v4();
    let pk: Vec<u8> = agent.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    agent
}

/// `(role, live)` for every row of `agent` in its personal group, read on the
/// superuser pool, ordered by epoch.
async fn rows(pool: &PgPool, agent: Uuid) -> Vec<(i32, String, bool)> {
    sqlx::query_as(
        "SELECT m.epoch, m.role::text, m.revoked_at IS NULL \
           FROM group_memberships m JOIN groups g ON g.id = m.group_id \
          WHERE m.agent_id = $1 AND g.did_key = 'did:epigraph:personal:' || $1::text \
          ORDER BY m.epoch",
    )
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("read membership rows")
}

async fn ensure_as_app(app: &PgPool, agent: Uuid) -> Result<Uuid, DbError> {
    let mut conn = app.acquire().await.expect("acquire app connection");
    AgentRepository::ensure_personal_group(&mut conn, agent).await
}

/// CALIBRATION: the connection really is the non-bypassing role, so every arm
/// below is measured where production runs.
async fn app_pool(pool: &PgPool) -> PgPool {
    let app = fixture::downgraded_pool(pool, "epigraph_app").await;
    let (user, bypass): (String, bool) = sqlx::query_as(
        "SELECT current_user::text, rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&app)
    .await
    .expect("whoami");
    assert_eq!(user, "epigraph_app");
    assert!(
        !bypass,
        "epigraph_app must not bypass RLS, or these arms are vacuous"
    );
    app
}

/// No row of any state: first-time provisioning still works, and a second call
/// is idempotent (same group, still one row).
#[sqlx::test(migrations = "../../migrations")]
async fn a_fresh_agent_is_provisioned_once(pool: PgPool) {
    let app = app_pool(&pool).await;
    let agent = seed_agent(&pool).await;

    let g1 = ensure_as_app(&app, agent)
        .await
        .expect("first provisioning");
    assert_eq!(rows(&pool, agent).await, vec![(0, "admin".into(), true)]);
    let g2 = ensure_as_app(&app, agent).await.expect("idempotent");
    assert_eq!(g1, g2);
    assert_eq!(rows(&pool, agent).await, vec![(0, "admin".into(), true)]);
}

/// THE ROOT ARM. Revoke, call, and the row is still revoked with its role
/// unchanged; the call returns the named refusal, not a success.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_membership_is_refused_and_stays_revoked(pool: PgPool) {
    let app = app_pool(&pool).await;
    let agent = seed_agent(&pool).await;
    ensure_as_app(&app, agent).await.expect("provision");
    sqlx::query("UPDATE group_memberships SET revoked_at = now() WHERE agent_id = $1")
        .bind(agent)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(rows(&pool, agent).await, vec![(0, "admin".into(), false)]);

    let res = ensure_as_app(&app, agent).await;
    assert_eq!(
        rows(&pool, agent).await,
        vec![(0, "admin".into(), false)],
        "the revoked membership must not be revived"
    );
    match res {
        Err(DbError::MembershipRevoked { message }) => assert!(
            message.contains(&agent.to_string()),
            "the refusal names the agent, got: {message}"
        ),
        other => panic!("expected DbError::MembershipRevoked, got {other:?}"),
    }
}

/// A live `reader` stays a reader: the call returns the group and writes
/// nothing, where 077's body silently promoted it to admin.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_stays_a_reader(pool: PgPool) {
    let app = app_pool(&pool).await;
    let agent = seed_agent(&pool).await;
    let g = ensure_as_app(&app, agent).await.expect("provision");
    sqlx::query("UPDATE group_memberships SET role = 'reader' WHERE agent_id = $1")
        .bind(agent)
        .execute(&pool)
        .await
        .unwrap();

    let again = ensure_as_app(&app, agent)
        .await
        .expect("a live row resolves");
    assert_eq!(again, g);
    assert_eq!(
        rows(&pool, agent).await,
        vec![(0, "reader".into(), true)],
        "a live reader must not be promoted"
    );
}

/// A revoked row at a DIFFERENT epoch is the same operator decision: no
/// epoch-0 row may be inserted beside it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_row_at_another_epoch_is_refused(pool: PgPool) {
    let app = app_pool(&pool).await;
    let agent = seed_agent(&pool).await;
    ensure_as_app(&app, agent).await.expect("provision");
    sqlx::query("UPDATE group_memberships SET epoch = 1, revoked_at = now() WHERE agent_id = $1")
        .bind(agent)
        .execute(&pool)
        .await
        .unwrap();

    let res = ensure_as_app(&app, agent).await;
    assert!(
        matches!(res, Err(DbError::MembershipRevoked { .. })),
        "expected the refusal, got {res:?}"
    );
    assert_eq!(
        rows(&pool, agent).await,
        vec![(1, "admin".into(), false)],
        "no epoch-0 row may be inserted beside a revoked one"
    );
}

/// A raw-SQL caller (the e2e fixtures call the function directly) sees the
/// refusal as SQLSTATE `RVK01`, not as a NULL it could bind as a group id.
#[sqlx::test(migrations = "../../migrations")]
async fn a_raw_sql_caller_sees_the_sqlstate(pool: PgPool) {
    let app = app_pool(&pool).await;
    let agent = seed_agent(&pool).await;
    ensure_as_app(&app, agent).await.expect("provision");
    sqlx::query("UPDATE group_memberships SET revoked_at = now() WHERE agent_id = $1")
        .bind(agent)
        .execute(&pool)
        .await
        .unwrap();

    let err =
        sqlx::query_scalar::<_, Option<Uuid>>("SELECT public.epigraph_ensure_personal_group($1)")
            .bind(agent)
            .fetch_one(&app)
            .await
            .expect_err("the refusal must be an error, not a row");
    let code = err
        .as_database_error()
        .and_then(|d| d.code().map(|c| c.to_string()));
    assert_eq!(
        code.as_deref(),
        Some(epigraph_db::PERSONAL_MEMBERSHIP_REVOKED)
    );
}

/// Two first-time provisioning calls racing: both succeed with the same group,
/// and exactly one live row results.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_first_provisioning_yields_one_row(pool: PgPool) {
    let app = app_pool(&pool).await;
    let agent = seed_agent(&pool).await;

    let (a, b) = tokio::join!(ensure_as_app(&app, agent), ensure_as_app(&app, agent));
    let (a, b) = (a.expect("first caller"), b.expect("second caller"));
    assert_eq!(a, b, "one personal group");
    assert_eq!(rows(&pool, agent).await, vec![(0, "admin".into(), true)]);
}

/// `ClaimRepository::default_decl_for_author` (the wrapper every write path's
/// owner group goes through) gives the SAME answer on every connection role.
///
/// It used to read the group on the caller's connection first and mint only on
/// a miss. As `epigraph_app` unstamped that read was blind (always minted); on
/// a BYPASSRLS connection it was not, and returned the personal group of an
/// agent whose membership was REVOKED — so a claim by a revoked author was
/// owned by the group it had been revoked from. It now asks the definer
/// function directly.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_group_wrapper_refuses_a_revoked_author_on_every_role(pool: PgPool) {
    use epigraph_db::ClaimRepository;
    let app = app_pool(&pool).await;

    // A live author resolves on both roles, to the same group.
    let live = seed_agent(&pool).await;
    let g = ensure_as_app(&app, live).await.expect("provision");
    let mut su = pool.acquire().await.unwrap();
    let mut ap = app.acquire().await.unwrap();
    let d_su = ClaimRepository::default_decl_for_author(&mut su, live)
        .await
        .expect("live author, superuser");
    let d_app = ClaimRepository::default_decl_for_author(&mut ap, live)
        .await
        .expect("live author, epigraph_app");
    assert_eq!(d_su.owner_group_bind(), Some(g));
    assert_eq!(d_app.owner_group_bind(), Some(g));

    // A revoked author is refused on both roles, and stays revoked.
    let revoked = seed_agent(&pool).await;
    ensure_as_app(&app, revoked).await.expect("provision");
    sqlx::query("UPDATE group_memberships SET revoked_at = now() WHERE agent_id = $1")
        .bind(revoked)
        .execute(&pool)
        .await
        .unwrap();
    let r_su = ClaimRepository::default_decl_for_author(&mut su, revoked).await;
    assert!(
        matches!(r_su, Err(DbError::MembershipRevoked { .. })),
        "BYPASSRLS: a revoked author must be refused, not owned by the group it was \
         revoked from; got {r_su:?}"
    );
    let r_app = ClaimRepository::default_decl_for_author(&mut ap, revoked).await;
    assert!(
        matches!(r_app, Err(DbError::MembershipRevoked { .. })),
        "epigraph_app: a revoked author must be refused, got {r_app:?}"
    );
    assert_eq!(rows(&pool, revoked).await, vec![(0, "admin".into(), false)]);
}
