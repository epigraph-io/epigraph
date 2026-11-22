//! Migration 236: `epigraph_live_memberships(agent)` answers only for the
//! session principal (or a maintenance session); the unbound body moves to the
//! maintenance-only `epigraph_live_memberships_unbound(agent)` (backlog
//! fad5a6c4).
//!
//! Before 236 any application-role session could list ANY agent's live group
//! memberships, direct and role-derived, by passing its id. The `#[sqlx::test]`
//! harness is a superuser (always admitted), so every negative answer here is
//! read on a connection whose `session_user` is `epigraph_app`, and calibrated
//! against the superuser's answer for the same agent.
//!
//! The positive controls are the callers that must keep working:
//! `Viewer::resolve` on an unstamped application pool (which now stamps the
//! principal for its one statement and must leave nothing on the connection),
//! the definer callers that ask about another agent (`epigraph_writable_teams`,
//! `epigraph_readable_teams`, re-pointed at the unbound twin), and a
//! maintenance session.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::GroupMembershipRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// An agent with its personal group (admin) and a writer row in a fresh TEAM
/// group, so it holds two live memberships, one of them in a team.
async fn agent_with_team(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    let (agent, _personal) = fixture::seed_agent_with_group(pool, label).await;
    let team: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, 'did:probe:' || $1, $2, 'team', $3) RETURNING id",
    )
    .bind(format!("{label}-team-{agent}"))
    .bind(vec![7u8; 32])
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(team)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed team membership");
    (agent, team)
}

/// How many rows `epigraph_live_memberships(agent)` answers on a connection
/// whose session user is `role`, with `principal` stamped ("" = unstamped).
async fn count_as(pool: &PgPool, role: &str, principal: &str, agent: Uuid) -> i64 {
    let principal = principal.to_string();
    fixture::as_role(pool, role, |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(&principal)
            .execute(&mut *conn)
            .await
            .expect("stamp the principal");
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.epigraph_live_memberships($1)")
                .bind(agent)
                .fetch_one(&mut *conn)
                .await
                .expect("the bound read answers");
        sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
            .execute(&mut *conn)
            .await
            .expect("clear the principal");
        (conn, n)
    })
    .await
}

/// The red test of fad5a6c4: an UNSTAMPED application-role session (the
/// ambient case: no principal at all) asking for another agent's memberships
/// gets nothing, where the superuser reads both of that agent's rows.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unstamped_app_session_reads_no_agents_memberships(pool: PgPool) {
    let (b, _) = agent_with_team(&pool, "unstamped-b").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let all: i64 = sqlx::query_scalar("SELECT count(*) FROM public.epigraph_live_memberships($1)")
        .bind(b)
        .fetch_one(&pool)
        .await
        .expect("superuser read");
    assert_eq!(all, 2, "CALIBRATION: the superuser reads B's two rows");
    assert_eq!(
        count_as(&pool, "epigraph_app", "", b).await,
        0,
        "an unstamped application session must not list B's memberships"
    );
}

/// The red test, stamped: an application session stamped as A asking for B
/// gets nothing, and asking for A (its own principal) gets A's rows.
#[sqlx::test(migrations = "../../migrations")]
async fn an_app_session_stamped_as_a_reads_its_own_memberships_not_bs(pool: PgPool) {
    let (a, _) = agent_with_team(&pool, "stamped-a").await;
    let (b, _) = agent_with_team(&pool, "stamped-b").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    assert_eq!(
        count_as(&pool, "epigraph_app", &a.to_string(), b).await,
        0,
        "a session stamped as A must not list B's memberships"
    );
    assert_eq!(
        count_as(&pool, "epigraph_app", &a.to_string(), a).await,
        2,
        "POSITIVE CONTROL: a session stamped as A lists A's own two rows"
    );
}

/// A maintenance session (the CLI's DSN, `epigraph_bypass()`) still answers
/// for any agent, stamped or not.
#[sqlx::test(migrations = "../../migrations")]
async fn a_maintenance_session_answers_for_any_agent(pool: PgPool) {
    let (b, _) = agent_with_team(&pool, "maint-b").await;
    assert_eq!(count_as(&pool, "epigraph_maintenance", "", b).await, 2);
}

/// `Viewer::resolve` on an UNSTAMPED application pool still resolves the
/// principal's full set (it stamps its own principal for the one statement),
/// and the stamp does not outlive that statement: the next statement on the
/// SAME connection (a one-connection pool) sees no principal.
#[sqlx::test(migrations = "../../migrations")]
async fn viewer_resolve_stamps_its_principal_for_one_statement_only(pool: PgPool) {
    use sqlx::Executor;
    let (a, team) = agent_with_team(&pool, "resolve-a").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let url = fixture::database_url_for(&pool).await;
    let app = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("SET SESSION AUTHORIZATION epigraph_app")
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("one-connection application pool");

    let viewer = Viewer::resolve(&app, a)
        .await
        .expect("resolve on the app role");
    let groups = viewer.group_bind().expect("scoped viewer").to_vec();
    assert_eq!(
        groups.len(),
        2,
        "the personal group and the team: {groups:?}"
    );
    assert!(groups.contains(&team));
    assert!(viewer.writable_groups().contains(&team));

    let rows = GroupMembershipRepository::list_live_for_agent(&app, a)
        .await
        .expect("list on the app role");
    assert_eq!(rows.len(), 2);

    let left: String =
        sqlx::query_scalar("SELECT COALESCE(current_setting('epigraph.principal_id', true), '')")
            .fetch_one(&app)
            .await
            .expect("read the principal back");
    assert_eq!(
        left, "",
        "the resolve's principal stamp must not outlive its own statement"
    );
}

/// The definers that ask about an agent other than the session principal go
/// through the unbound twin, so they answer exactly as before on an unstamped
/// application session: `epigraph_writable_teams(B)` and
/// `epigraph_readable_teams(B)` both still name B's team (`own`).
#[sqlx::test(migrations = "../../migrations")]
async fn the_team_definers_still_answer_on_an_unstamped_app_session(pool: PgPool) {
    let (b, team) = agent_with_team(&pool, "teams-b").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let (writable, readable) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let w: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT group_id, via FROM public.epigraph_writable_teams($1)")
                .bind(b)
                .fetch_all(&mut *conn)
                .await
                .expect("writable teams");
        let r: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT group_id, via FROM public.epigraph_readable_teams($1)")
                .bind(b)
                .fetch_all(&mut *conn)
                .await
                .expect("readable teams");
        (conn, (w, r))
    })
    .await;
    assert_eq!(writable, vec![(team, "own".to_string())]);
    assert_eq!(readable, vec![(team, "own".to_string())]);
}

/// The catalog half. The unbound twin is a maintenance-owned SECURITY DEFINER
/// that neither PUBLIC nor the application role may execute; the bound read
/// keeps its signature, owner and application grant; and EVERY function body
/// that calls either is listed here, so a new definer caller has to choose:
/// the bound read (it asks about the session principal) or the twin (it asks
/// about another agent, and is then an answer for any agent on whatever role
/// may execute it).
#[sqlx::test(migrations = "../../migrations")]
async fn the_unbound_twin_is_maintenance_only_and_every_caller_is_listed(pool: PgPool) {
    let twin = "public.epigraph_live_memberships_unbound(uuid)";
    let (definer, owner, app, maint, public_acl): (bool, String, bool, bool, bool) =
        sqlx::query_as(
            "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, \
                    has_function_privilege('epigraph_app', p.oid, 'EXECUTE'), \
                    has_function_privilege('epigraph_maintenance', p.oid, 'EXECUTE'), \
                    p.proacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) x \
                                                 WHERE x.grantee = 0) \
               FROM pg_proc p WHERE p.oid = to_regprocedure($1)",
        )
        .bind(twin)
        .fetch_optional(&pool)
        .await
        .expect("catalog read")
        .unwrap_or_else(|| panic!("{twin} must exist"));
    assert!(definer, "{twin} is SECURITY DEFINER");
    assert_eq!(owner, "epigraph_maintenance");
    assert!(!app, "the application role must not execute {twin}");
    assert!(maint);
    assert!(!public_acl, "{twin} carries an explicit ACL without PUBLIC");

    let (owner, app): (String, bool) = sqlx::query_as(
        "SELECT pg_get_userbyid(p.proowner)::text, \
                has_function_privilege('epigraph_app', p.oid, 'EXECUTE') \
           FROM pg_proc p WHERE p.oid = to_regprocedure('public.epigraph_live_memberships(uuid)')",
    )
    .fetch_one(&pool)
    .await
    .expect("bound read catalog row");
    assert_eq!(owner, "epigraph_maintenance");
    assert!(
        app,
        "Viewer::resolve calls the bound read on the application role"
    );

    let callers = |pattern: &'static str| {
        let pool = pool.clone();
        async move {
            let names: Vec<String> = sqlx::query_scalar(
                "SELECT p.oid::regprocedure::text FROM pg_proc p \
                  WHERE p.prosrc LIKE $1 ORDER BY 1",
            )
            .bind(pattern)
            .fetch_all(&pool)
            .await
            .expect("callers");
            names
        }
    };
    assert_eq!(
        callers("%epigraph\\_live\\_memberships(%").await,
        vec![
            "epigraph_publicize_claims(uuid[],text)".to_string(),
            "epigraph_share_claims_with_team(uuid[],uuid,text)".to_string(),
        ],
        "the bound read's definer callers ask about the session principal only"
    );
    assert_eq!(
        callers("%epigraph\\_live\\_memberships\\_unbound(%").await,
        vec![
            "epigraph_live_memberships(uuid)".to_string(),
            "epigraph_readable_teams(uuid)".to_string(),
            "epigraph_writable_teams(uuid)".to_string(),
        ],
        "the twin's callers"
    );
}

/// `docs/runbooks/236-undo.sql` restores the three predecessor bodies by md5
/// (as 236's precondition reads them) and drops the twin, after which an
/// unstamped application session reads another agent's rows again (235's
/// behaviour, which is what an undo means).
#[sqlx::test(migrations = "../../migrations")]
async fn the_236_undo_restores_the_predecessor_bodies(pool: PgPool) {
    let undo = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/runbooks/236-undo.sql"
    ))
    .expect("read the undo");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("apply the undo");
    for (signature, md5) in [
        (
            "public.epigraph_live_memberships(uuid)",
            "7648baee271b2163a52c28db1b4a74b6",
        ),
        (
            "public.epigraph_writable_teams(uuid)",
            "fe6592171c20613810ef6b1ddf39c36e",
        ),
        (
            "public.epigraph_readable_teams(uuid)",
            "7da080030db7dbaeae7f60074d59b660",
        ),
    ] {
        let found: (String, String) = sqlx::query_as(
            "SELECT md5(p.prosrc), pg_get_userbyid(p.proowner)::text FROM pg_proc p \
              WHERE p.oid = to_regprocedure($1)",
        )
        .bind(signature)
        .fetch_one(&pool)
        .await
        .expect("pg_proc");
        assert_eq!(
            found,
            (md5.to_string(), "epigraph_maintenance".to_string()),
            "{signature}"
        );
    }
    let twin: Option<String> = sqlx::query_scalar(
        "SELECT to_regprocedure('public.epigraph_live_memberships_unbound(uuid)')::text",
    )
    .fetch_one(&pool)
    .await
    .expect("twin lookup");
    assert_eq!(twin, None, "the undo drops the twin");
    let (b, _) = agent_with_team(&pool, "undo-b").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    assert_eq!(count_as(&pool, "epigraph_app", "", b).await, 2);
}
