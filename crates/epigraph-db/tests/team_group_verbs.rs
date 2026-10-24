//! Migration 164: maintenance-only, audited verbs for KEYLESS team groups.
//!
//! Four `SECURITY DEFINER` functions, owned by `epigraph_maintenance` and
//! executable by that role alone:
//!
//! * `epigraph_create_team_group(name, admin, reason)`: a `kind = 'team'`
//!   group with no key material (empty `public_key`, no `group_key_epochs`
//!   row), `did_key = 'did:epigraph:group:<id>'`, created by and with a live
//!   `admin` membership for a REGISTERED HUMAN OPERATOR;
//! * `epigraph_team_group_add_member(group, agent, role, reason)`;
//! * `epigraph_team_group_remove_member(group, agent, reason)`: a REVOKE
//!   (`revoked_at` set), never a delete;
//! * `epigraph_team_group_set_member_role(group, agent, role, reason)`.
//!
//! What is pinned, each refusal next to the positive control that shows the
//! same call shape succeeds when the refused condition is absent:
//!
//! * the application role cannot EXECUTE any verb, whatever session settings
//!   it forges (principal, group sets, the enforcement valve); the identical
//!   call on a maintenance session succeeds;
//! * create, add, set-role and remove each write exactly one `security_events`
//!   row, whose `group.` event family the application role cannot forge;
//! * the last live admin can be neither removed nor demoted;
//! * an operated agent is a member (any role) only of a group its own operator
//!   WRITES, armed or not, and never an admin; an unbound or retired-linked
//!   agent is never a member; an operator cannot be removed or demoted below
//!   writer while its operated agents are live members;
//! * a removal keeps the row (`revoked_at` set), `Viewer::resolve` stops
//!   returning the group, the member's stamped application session stops
//!   reading the group's claims, and a re-add writes a NEW row;
//! * migration 092's group-creation arm ends with the creator's membership.
//!
//! Every verb runs on a session whose `session_user` IS `epigraph_maintenance`
//! (`SET SESSION AUTHORIZATION`), not on the harness superuser, so the grants
//! are what is measured.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{AgentRepository, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

const INSUFFICIENT_PRIVILEGE: &str = "42501";
const NOT_A_HUMAN_ADMIN: &str = "GRP01";
const LAST_ADMIN: &str = "GRP02";
const OPERATOR_SCOPE: &str = "GRP03";
const NOT_BOUND: &str = "GRP04";
const DUPLICATE_NAME: &str = "GRP06";

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref().err().and_then(sqlstate)
}

/// What `add` / `remove` / `set-role` answer: the live membership row they
/// touched (none for a remove of a non-member), whether they wrote, and the
/// role the row held before (remove and set-role).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Act {
    membership: Option<Uuid>,
    applied: bool,
    prior_role: Option<String>,
}

/// A connection whose `session_user` is `epigraph_maintenance` (the operator
/// CLI's role). Hand it back to [`reset`].
async fn maint(pool: &PgPool) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_maintenance")
        .await
        .expect("downgrade to the maintenance role");
    conn
}

async fn create(pool: &PgPool, name: &str, admin: Uuid) -> Result<Uuid, sqlx::Error> {
    let mut c = maint(pool).await;
    let r = sqlx::query_scalar("SELECT public.epigraph_create_team_group($1, $2, $3)")
        .bind(name)
        .bind(admin)
        .bind("team group verb test")
        .fetch_one(&mut *c)
        .await;
    reset(c).await;
    r
}

async fn add(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) -> Result<Act, sqlx::Error> {
    let mut c = maint(pool).await;
    let r: Result<(Option<Uuid>, bool), _> = sqlx::query_as(
        "SELECT out_membership_id, out_applied \
           FROM public.epigraph_team_group_add_member($1, $2, $3, $4)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .bind("team group verb test")
    .fetch_one(&mut *c)
    .await;
    reset(c).await;
    r.map(|(membership, applied)| Act {
        membership,
        applied,
        prior_role: None,
    })
}

async fn remove(pool: &PgPool, group: Uuid, agent: Uuid) -> Result<Act, sqlx::Error> {
    let mut c = maint(pool).await;
    let r: Result<(Option<Uuid>, bool, Option<String>), _> = sqlx::query_as(
        "SELECT out_membership_id, out_applied, out_prior_role \
           FROM public.epigraph_team_group_remove_member($1, $2, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind("team group verb test")
    .fetch_one(&mut *c)
    .await;
    reset(c).await;
    r.map(|(membership, applied, prior_role)| Act {
        membership,
        applied,
        prior_role,
    })
}

async fn set_role(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) -> Result<Act, sqlx::Error> {
    let mut c = maint(pool).await;
    let r: Result<(Option<Uuid>, bool, Option<String>), _> = sqlx::query_as(
        "SELECT out_membership_id, out_applied, out_prior_role \
           FROM public.epigraph_team_group_set_member_role($1, $2, $3, $4)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .bind("team group verb test")
    .fetch_one(&mut *c)
    .await;
    reset(c).await;
    r.map(|(membership, applied, prior_role)| Act {
        membership,
        applied,
        prior_role,
    })
}

/// A registered human operator with its personal group.
async fn human(pool: &PgPool, label: &str) -> Uuid {
    fixture::seed_human_operator(pool, label).await.0
}

/// An agent LIVE-linked to `operator` through migration 107's real link.
async fn operated(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let out = AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the agent");
    assert!(out.link_live, "PREMISE: a live link: {out:?}");
    agent
}

/// An agent with a RETIRED link to `operator` (107's retired link: no
/// membership, zero write authority).
async fn retired(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_retired_agent(&mut conn, agent, operator)
        .await
        .expect("retire-link the agent");
    agent
}

async fn arm(pool: &PgPool) {
    let mut c = maint(pool).await;
    sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
        .fetch_one(&mut *c)
        .await
        .expect("the maintenance role arms");
    reset(c).await;
}

/// Every membership row of `(group, agent)`: `(epoch, role, revoked)`, oldest
/// epoch first.
async fn rows(pool: &PgPool, group: Uuid, agent: Uuid) -> Vec<(i32, String, bool)> {
    sqlx::query_as(
        "SELECT epoch, role::text, revoked_at IS NOT NULL FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 ORDER BY epoch",
    )
    .bind(group)
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("membership rows")
}

async fn live_role(pool: &PgPool, group: Uuid, agent: Uuid) -> Option<String> {
    sqlx::query_scalar(
        "SELECT role::text FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(agent)
    .fetch_optional(pool)
    .await
    .expect("live role")
}

/// The `group.*` audit rows naming `group`, oldest first:
/// `(event_type, agent_id, details)`.
async fn audit(pool: &PgPool, group: Uuid) -> Vec<(String, Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT event_type::text, agent_id, details FROM security_events \
          WHERE event_type LIKE 'group.%' AND details->>'group_id' = $1::text \
          ORDER BY created_at, id",
    )
    .bind(group)
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

async fn group_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM groups")
        .fetch_one(pool)
        .await
        .expect("group count")
}

async fn group_audit_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM security_events WHERE event_type LIKE 'group.%'")
        .fetch_one(pool)
        .await
        .expect("audit count")
}

/// An application-role connection that FORGES every session setting a
/// privileged caller might be expected to carry: the principal is the group's
/// own admin, the group sets name the group, and the enforcement valve is off.
async fn forged_app_conn(
    pool: &PgPool,
    principal: Uuid,
    group: Uuid,
) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade to the application role");
    sqlx::query(
        "SELECT set_config('epigraph.principal_id', $1, false), \
                set_config('epigraph.group_ids', $2, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.operator_link_enforcement', 'off', false)",
    )
    .bind(principal.to_string())
    .bind(group.to_string())
    .execute(&mut *conn)
    .await
    .expect("forge the session settings");
    conn
}

async fn reset(mut conn: sqlx::pool::PoolConnection<sqlx::Postgres>) {
    use sqlx::Executor;
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset session authorization");
}

/// `(prosecdef, owner, proacl, proconfig)` of one function.
type CatalogRow = (bool, String, Option<String>, Option<Vec<String>>);

/// The four verbs are `SECURITY DEFINER`, owned by `epigraph_maintenance`,
/// with an explicit ACL naming the maintenance role and neither PUBLIC nor the
/// application role. Pinned in the catalog because the harness migrates as a
/// superuser: a silently no-opped `OWNER TO` would pass every behavioural test.
#[sqlx::test(migrations = "../../migrations")]
async fn the_verbs_are_maintenance_owned_definers_only_maintenance_executes(pool: PgPool) {
    for signature in [
        "public.epigraph_create_team_group(text, uuid, text)",
        "public.epigraph_team_group_add_member(uuid, uuid, text, text)",
        "public.epigraph_team_group_remove_member(uuid, uuid, text)",
        "public.epigraph_team_group_set_member_role(uuid, uuid, text, text)",
    ] {
        let row: Option<CatalogRow> = sqlx::query_as(
            "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, p.proacl::text, \
                    p.proconfig \
               FROM pg_proc p WHERE p.oid = to_regprocedure($1)",
        )
        .bind(signature)
        .fetch_optional(&pool)
        .await
        .expect("catalog read");
        let Some((secdef, owner, acl, config)) = row else {
            panic!("{signature} does not exist");
        };
        assert!(secdef, "{signature} must be SECURITY DEFINER");
        assert_eq!(owner, "epigraph_maintenance", "{signature} owner");
        let acl = acl.unwrap_or_default();
        assert!(
            acl.contains("epigraph_maintenance=X"),
            "{signature}: the maintenance role must hold EXECUTE: {acl}"
        );
        assert!(
            !acl.contains("epigraph_app="),
            "{signature}: the application role must not hold EXECUTE: {acl}"
        );
        assert!(
            !acl.contains("{=X") && !acl.contains(",=X"),
            "{signature}: PUBLIC must not hold EXECUTE: {acl}"
        );
        assert!(
            config
                .unwrap_or_default()
                .iter()
                .any(|c| c.starts_with("search_path=")),
            "{signature} must pin its search_path"
        );
        for (role, expected) in [("epigraph_app", false), ("epigraph_maintenance", true)] {
            let can: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
                .bind(role)
                .bind(signature)
                .fetch_one(&pool)
                .await
                .expect("function privilege");
            assert_eq!(can, expected, "{role} EXECUTE on {signature}");
        }
    }
}

/// The application role cannot call any verb, even stamped as the group's own
/// live admin with the group in both of its group sets and the enforcement
/// valve off; nothing is written and no audit row appears. The positive
/// control is the identical call on a maintenance session, which succeeds.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_execute_the_verbs_even_with_forged_session_settings(pool: PgPool) {
    let admin = human(&pool, "forge-admin").await;
    let other = human(&pool, "forge-other").await;
    let group = create(&pool, "forge probe team", admin)
        .await
        .expect("POSITIVE CONTROL: a maintenance session creates the group");
    let groups_before = group_count(&pool).await;
    let audit_before = group_audit_count(&pool).await;

    let mut conn = forged_app_conn(&pool, admin, group).await;
    let calls: [(&str, sqlx::query::Query<'_, sqlx::Postgres, _>); 4] = [
        (
            "create",
            sqlx::query("SELECT public.epigraph_create_team_group($1, $2, $3)")
                .bind("forged team")
                .bind(admin)
                .bind("forged"),
        ),
        (
            "add",
            sqlx::query("SELECT * FROM public.epigraph_team_group_add_member($1, $2, $3, $4)")
                .bind(group)
                .bind(other)
                .bind("writer")
                .bind("forged"),
        ),
        (
            "set-role",
            sqlx::query("SELECT * FROM public.epigraph_team_group_set_member_role($1, $2, $3, $4)")
                .bind(group)
                .bind(admin)
                .bind("reader")
                .bind("forged"),
        ),
        (
            "remove",
            sqlx::query("SELECT * FROM public.epigraph_team_group_remove_member($1, $2, $3)")
                .bind(group)
                .bind(admin)
                .bind("forged"),
        ),
    ];
    for (what, q) in calls {
        let r = q.execute(&mut *conn).await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{what} on a forged application session must be refused 42501: {r:?}"
        );
    }
    reset(conn).await;

    assert_eq!(
        group_count(&pool).await,
        groups_before,
        "no group was created"
    );
    assert_eq!(
        group_audit_count(&pool).await,
        audit_before,
        "no audit row was written"
    );
    assert_eq!(
        live_role(&pool, group, admin).await.as_deref(),
        Some("admin")
    );
    assert_eq!(live_role(&pool, group, other).await, None);

    // POSITIVE CONTROL: the same add on a maintenance session.
    let ok = add(&pool, group, other, "writer")
        .await
        .expect("the maintenance session adds the member");
    assert!(ok.applied, "{ok:?}");
    assert_eq!(
        live_role(&pool, group, other).await.as_deref(),
        Some("writer")
    );
}

/// The `group.` audit family is reserved: the application role cannot insert
/// a row that looks like a roster act, while it still writes an ordinary
/// security event.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_forge_a_group_audit_row(pool: PgPool) {
    let admin = human(&pool, "audit-forge").await;
    let mut conn = forged_app_conn(&pool, admin, Uuid::new_v4()).await;
    let forged = sqlx::query(
        "INSERT INTO security_events (event_type, agent_id, success, details) \
         VALUES ('group.member_added', $1, true, '{}'::jsonb)",
    )
    .bind(admin)
    .execute(&mut *conn)
    .await;
    assert_eq!(
        code_of(&forged).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "a forged group.* audit row must be refused: {forged:?}"
    );
    let ordinary = sqlx::query(
        "INSERT INTO security_events (event_type, agent_id, success, details) \
         VALUES ('probe.ordinary_event', $1, true, '{}'::jsonb)",
    )
    .bind(admin)
    .execute(&mut *conn)
    .await;
    reset(conn).await;
    ordinary.expect("POSITIVE CONTROL: an unreserved event type is still app-writable");
}

/// Create, add, set-role and remove on a maintenance session: each does what
/// it says, the group is keyless, and each writes exactly one audit row naming
/// the group, the member, the roles and the reason.
#[sqlx::test(migrations = "../../migrations")]
async fn create_add_set_role_and_remove_work_on_maintenance_and_each_is_audited(pool: PgPool) {
    let admin = human(&pool, "lifecycle-admin").await;
    let member = human(&pool, "lifecycle-member").await;

    let group = create(&pool, "Synthetic Research Team", admin)
        .await
        .expect("create");
    let (kind, did_key, key_len, creator, status): (String, String, i32, Option<Uuid>, String) =
        sqlx::query_as(
            "SELECT kind::text, did_key, octet_length(public_key), created_by_agent_id, \
                    status::text FROM groups WHERE id = $1",
        )
        .bind(group)
        .fetch_one(&pool)
        .await
        .expect("the group row");
    assert_eq!(kind, "team");
    assert_eq!(did_key, format!("did:epigraph:group:{group}"));
    assert_eq!(key_len, 0, "a keyless team group carries no key material");
    assert_eq!(creator, Some(admin), "the admin Person is the creator");
    assert_eq!(status, "active");
    let epochs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM group_key_epochs WHERE group_id = $1")
            .bind(group)
            .fetch_one(&pool)
            .await
            .expect("epochs");
    assert_eq!(epochs, 0, "no key epoch is written for a keyless group");
    let (share, epoch): (Vec<u8>, i32) = sqlx::query_as(
        "SELECT wrapped_key_share, epoch FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(admin)
    .fetch_one(&pool)
    .await
    .expect("the admin row");
    assert!(share.is_empty(), "the admin's share is empty");
    assert_eq!(epoch, 0);
    assert_eq!(
        live_role(&pool, group, admin).await.as_deref(),
        Some("admin")
    );

    let added = add(&pool, group, member, "writer").await.expect("add");
    assert!(added.applied && added.membership.is_some(), "{added:?}");
    assert_eq!(
        live_role(&pool, group, member).await.as_deref(),
        Some("writer")
    );

    // Idempotent: the same add again writes nothing and no audit row.
    let again = add(&pool, group, member, "writer").await.expect("re-add");
    assert!(!again.applied, "{again:?}");
    assert_eq!(again.membership, added.membership);

    let set = set_role(&pool, group, member, "reader")
        .await
        .expect("set-role");
    assert!(set.applied, "{set:?}");
    assert_eq!(set.prior_role.as_deref(), Some("writer"));
    assert_eq!(
        set.membership, added.membership,
        "set-role changes the live row"
    );
    assert_eq!(
        live_role(&pool, group, member).await.as_deref(),
        Some("reader")
    );

    let removed = remove(&pool, group, member).await.expect("remove");
    assert!(removed.applied, "{removed:?}");
    assert_eq!(removed.prior_role.as_deref(), Some("reader"));
    assert_eq!(live_role(&pool, group, member).await, None);

    let events = audit(&pool, group).await;
    let kinds: Vec<&str> = events.iter().map(|(k, _, _)| k.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "group.team_created",
            "group.member_added",
            "group.member_role_set",
            "group.member_removed"
        ],
        "one audit row per act, none for the no-op re-add: {events:?}"
    );
    let (_, created_agent, created) = &events[0];
    assert_eq!(*created_agent, Some(admin));
    assert_eq!(created["admin"], admin.to_string());
    assert_eq!(created["display_name"], "Synthetic Research Team");
    assert_eq!(created["reason"], "team group verb test");
    for (kind, agent, d) in &events[1..] {
        assert_eq!(*agent, Some(member), "{kind} names the member");
        assert_eq!(d["member"], member.to_string(), "{kind}: {d}");
        assert_eq!(d["reason"], "team group verb test", "{kind}: {d}");
        assert!(d["session_user"].is_string(), "{kind}: {d}");
    }
    assert_eq!(events[1].2["role"], "writer");
    assert_eq!(events[2].2["prior_role"], "writer");
    assert_eq!(events[2].2["role"], "reader");
    assert_eq!(events[3].2["prior_role"], "reader");
}

/// The admin must be a REGISTERED human operator: an agent with no registry
/// row, and a human whose recorded human client was suspended, are refused and
/// nothing is written. A team name already in use by an active team group is
/// refused too, so a re-run cannot mint a second group.
#[sqlx::test(migrations = "../../migrations")]
async fn create_requires_a_registered_human_admin_and_a_free_name(pool: PgPool) {
    let (plain, _) = fixture::seed_agent_with_group(&pool, "not-a-human").await;
    let suspended = human(&pool, "suspended-human").await;
    sqlx::query("UPDATE oauth_clients SET status = 'suspended' WHERE agent_id = $1")
        .bind(suspended)
        .execute(&pool)
        .await
        .expect("suspend the human client");
    let groups_before = group_count(&pool).await;
    for (who, what) in [
        (plain, "an unregistered agent"),
        (suspended, "a suspended human"),
    ] {
        let r = create(&pool, "Synthetic Refused Team", who).await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(NOT_A_HUMAN_ADMIN),
            "{what} as admin: {r:?}"
        );
    }
    assert_eq!(
        group_count(&pool).await,
        groups_before,
        "nothing was created"
    );
    assert_eq!(group_audit_count(&pool).await, 0, "no audit row");

    // POSITIVE CONTROL: a registered human creates the group.
    let ok = human(&pool, "registered-human").await;
    create(&pool, "Synthetic Refused Team", ok)
        .await
        .expect("a registered human admin is admitted");

    // The same name again (case and padding aside) is refused.
    let dup = create(&pool, "  synthetic refused TEAM ", ok).await;
    assert_eq!(code_of(&dup).as_deref(), Some(DUPLICATE_NAME), "{dup:?}");
    let named: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM groups \
          WHERE kind = 'team' AND lower(btrim(display_name)) = 'synthetic refused team'",
    )
    .fetch_one(&pool)
    .await
    .expect("named team groups");
    assert_eq!(named, 1, "the duplicate created nothing");
}

/// The last live admin can be neither removed nor demoted. With a second live
/// admin, the first is removable, and then the second is the last.
#[sqlx::test(migrations = "../../migrations")]
async fn the_last_live_admin_can_be_neither_removed_nor_demoted(pool: PgPool) {
    let first = human(&pool, "last-admin-first").await;
    let second = human(&pool, "last-admin-second").await;
    let group = create(&pool, "Synthetic Admin Team", first)
        .await
        .expect("create");

    let r = remove(&pool, group, first).await;
    assert_eq!(code_of(&r).as_deref(), Some(LAST_ADMIN), "remove: {r:?}");
    for role in ["writer", "reader"] {
        let r = set_role(&pool, group, first, role).await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(LAST_ADMIN),
            "demote to {role}: {r:?}"
        );
    }
    assert_eq!(
        live_role(&pool, group, first).await.as_deref(),
        Some("admin")
    );
    assert_eq!(
        audit(&pool, group).await.len(),
        1,
        "only the creation is audited"
    );

    // POSITIVE CONTROL: a second live admin makes the first removable.
    add(&pool, group, second, "admin")
        .await
        .expect("second admin");
    let ok = remove(&pool, group, first)
        .await
        .expect("remove the first admin");
    assert!(
        ok.applied && ok.prior_role.as_deref() == Some("admin"),
        "{ok:?}"
    );

    // Now the second is the last.
    let r = remove(&pool, group, second).await;
    assert_eq!(code_of(&r).as_deref(), Some(LAST_ADMIN), "{r:?}");
    let r = set_role(&pool, group, second, "writer").await;
    assert_eq!(code_of(&r).as_deref(), Some(LAST_ADMIN), "{r:?}");
    assert_eq!(
        live_role(&pool, group, second).await.as_deref(),
        Some("admin")
    );
}

/// The scope rule, checked on two groups: one before the database is armed and
/// one after, because the verb holds it in both states (a maintenance session
/// is exempt from 122's membership trigger, so the verb is the only control).
///
/// * an operated agent is refused at ANY role while its operator does not
///   write the group (not a member, or only a reader), and admitted as reader
///   or writer once the operator writes it;
/// * an operated agent is never an admin (admins are humans);
/// * an unbound agent and a retired-linked agent are never members;
/// * the operator cannot be removed, nor demoted to reader, while its agent is
///   a live member; it can once the agent is removed.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_is_a_member_only_where_its_operator_writes(pool: PgPool) {
    let owner = human(&pool, "scope-owner").await;
    let operator = human(&pool, "scope-operator").await;
    let agent = operated(&pool, operator, "scope-agent").await;
    let gone = retired(&pool, operator, "scope-retired").await;
    let (unbound, _) = fixture::seed_agent_with_group(&pool, "scope-unbound").await;

    for (phase, armed) in [("unarmed", false), ("armed", true)] {
        if armed {
            arm(&pool).await;
        }
        let group = create(&pool, &format!("Synthetic Scope Team {phase}"), owner)
            .await
            .expect("create");

        // The operator is not a member: the agent is refused at every role.
        for role in ["reader", "writer"] {
            let r = add(&pool, group, agent, role).await;
            assert_eq!(
                code_of(&r).as_deref(),
                Some(OPERATOR_SCOPE),
                "{phase}: agent as {role} with a non-member operator: {r:?}"
            );
        }
        // The operator only READS the group: still refused.
        add(&pool, group, operator, "reader")
            .await
            .expect("operator reader");
        let r = add(&pool, group, agent, "reader").await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(OPERATOR_SCOPE),
            "{phase}: agent with a reader operator: {r:?}"
        );
        // Unbound and retired-linked agents are never members.
        for (who, what) in [(unbound, "unbound"), (gone, "retired-linked")] {
            let r = add(&pool, group, who, "reader").await;
            assert_eq!(
                code_of(&r).as_deref(),
                Some(NOT_BOUND),
                "{phase}: {what}: {r:?}"
            );
        }
        assert_eq!(live_role(&pool, group, agent).await, None);

        // POSITIVE CONTROL: once the operator writes the group, the agent is
        // admitted as writer (and as reader via set-role).
        set_role(&pool, group, operator, "writer")
            .await
            .expect("operator writer");
        add(&pool, group, agent, "writer")
            .await
            .expect("the agent is admitted where its operator writes");
        set_role(&pool, group, agent, "reader")
            .await
            .expect("the agent may be demoted to reader");
        // Never an admin, by add or by set-role.
        let r = set_role(&pool, group, agent, "admin").await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(NOT_A_HUMAN_ADMIN),
            "{phase}: {r:?}"
        );

        // The operator cannot leave its agent stranded.
        let r = remove(&pool, group, operator).await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(OPERATOR_SCOPE),
            "{phase}: {r:?}"
        );
        let r = set_role(&pool, group, operator, "reader").await;
        assert_eq!(
            code_of(&r).as_deref(),
            Some(OPERATOR_SCOPE),
            "{phase}: {r:?}"
        );
        assert_eq!(
            live_role(&pool, group, operator).await.as_deref(),
            Some("writer")
        );

        // POSITIVE CONTROL: with the agent removed, the operator can go.
        remove(&pool, group, agent).await.expect("remove the agent");
        remove(&pool, group, operator)
            .await
            .expect("the operator is removable once its agent is gone");
    }
}

/// A removal is a REVOKE: the row stays with `revoked_at` set. The member's
/// `Viewer::resolve` stops returning the group, and its stamped application
/// session stops reading the group's claim (row security, not the in-query
/// predicate). A re-add writes a NEW row at the next epoch, leaving the
/// revoked one in place.
#[sqlx::test(migrations = "../../migrations")]
async fn removal_is_a_revoke_and_the_viewer_stops_seeing_the_group(pool: PgPool) {
    let admin = human(&pool, "revoke-admin").await;
    let member = human(&pool, "revoke-member").await;
    let group = create(&pool, "Synthetic Revoke Team", admin)
        .await
        .expect("create");
    add(&pool, group, member, "writer").await.expect("add");
    let claim = fixture::seed_group_claim(&pool, admin, group, "revoke probe claim").await;

    let sees = |pool: PgPool| async move {
        let viewer = Viewer::resolve(&pool, member).await.expect("resolve");
        let in_set = viewer.group_bind().is_some_and(|g| g.contains(&group));
        let groups: Vec<String> = viewer
            .group_bind()
            .unwrap_or_default()
            .iter()
            .map(Uuid::to_string)
            .collect();
        let writable: Vec<String> = viewer
            .writable_groups()
            .iter()
            .map(Uuid::to_string)
            .collect();
        use sqlx::Executor;
        let mut conn = pool.acquire().await.expect("acquire");
        conn.execute("SET SESSION AUTHORIZATION epigraph_app")
            .await
            .expect("downgrade");
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $3, false)",
        )
        .bind(member.to_string())
        .bind(groups.join(","))
        .bind(writable.join(","))
        .execute(&mut *conn)
        .await
        .expect("stamp as the viewer");
        let reads: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&mut *conn)
            .await
            .expect("stamped read");
        conn.execute("RESET SESSION AUTHORIZATION")
            .await
            .expect("reset");
        (in_set, reads)
    };

    assert_eq!(
        sees(pool.clone()).await,
        (true, 1),
        "POSITIVE CONTROL: a live member resolves the group and reads its claim"
    );

    let removed = remove(&pool, group, member).await.expect("remove");
    assert!(removed.applied, "{removed:?}");
    assert_eq!(
        rows(&pool, group, member).await,
        [(0, "writer".to_string(), true)],
        "the row is kept, revoked"
    );
    assert_eq!(
        sees(pool.clone()).await,
        (false, 0),
        "a removed member neither resolves the group nor reads its claim"
    );

    // Removing again is a no-op, not a second revoke.
    let again = remove(&pool, group, member).await.expect("remove again");
    assert!(!again.applied && again.membership.is_none(), "{again:?}");

    // A re-add is a new row; the revoked one stays.
    let readd = add(&pool, group, member, "reader").await.expect("re-add");
    assert!(readd.applied, "{readd:?}");
    assert_ne!(
        readd.membership, removed.membership,
        "a new row, not a revival"
    );
    assert_eq!(
        rows(&pool, group, member).await,
        [
            (0, "writer".to_string(), true),
            (1, "reader".to_string(), false)
        ],
        "the ledger keeps the revoked row and adds a live one"
    );
    assert_eq!(sees(pool.clone()).await, (true, 1));
}

/// Migration 092's group-creation arm on a verb-created group: the creator's
/// stamped application session reads the roster while it is a live member, and
/// loses it once removed (another admin remains), so the arm keyed on
/// `created_by_agent_id` does not outlive the membership.
#[sqlx::test(migrations = "../../migrations")]
async fn the_creator_arm_ends_with_the_creators_membership(pool: PgPool) {
    let creator = human(&pool, "arm-creator").await;
    let successor = human(&pool, "arm-successor").await;
    let group = create(&pool, "Synthetic Arm Team", creator)
        .await
        .expect("create");

    // The creator's stamped session with NO group set: only the 092 arm (or
    // its own-row arm) can admit it.
    let probe_live = human(&pool, "arm-probe-live").await;
    let probe_gone = human(&pool, "arm-probe-gone").await;
    let roster_seen = |pool: PgPool, probe: Uuid| async move {
        use sqlx::Executor;
        let mut conn = pool.acquire().await.expect("acquire");
        conn.execute("SET SESSION AUTHORIZATION epigraph_app")
            .await
            .expect("downgrade");
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(creator.to_string())
            .execute(&mut *conn)
            .await
            .expect("stamp");
        let group_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM groups WHERE id = $1")
            .bind(group)
            .fetch_one(&mut *conn)
            .await
            .expect("groups read");
        let insert = sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 7, 'reader')",
        )
        .bind(group)
        .bind(probe)
        .execute(&mut *conn)
        .await;
        conn.execute("RESET SESSION AUTHORIZATION")
            .await
            .expect("reset");
        (group_rows, insert.is_ok())
    };

    let (seen, inserted) = roster_seen(pool.clone(), probe_live).await;
    assert_eq!(seen, 1, "POSITIVE CONTROL: the live creator sees its group");
    assert!(
        inserted,
        "POSITIVE CONTROL: the live creator enrols through the arm"
    );

    add(&pool, group, successor, "admin")
        .await
        .expect("successor admin");
    remove(&pool, group, creator)
        .await
        .expect("remove the creator");

    let (seen, inserted) = roster_seen(pool.clone(), probe_gone).await;
    assert_eq!(
        seen, 0,
        "a removed creator no longer sees the group through 092's arm"
    );
    assert!(!inserted, "a removed creator can no longer enrol members");
    assert_eq!(
        live_role(&pool, group, successor).await.as_deref(),
        Some("admin")
    );
}

/// The verbs act on keyless TEAM groups only: a personal group, the world
/// group, and a keyed team group are refused (their rosters have their own
/// paths), and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn the_member_verbs_refuse_groups_that_are_not_keyless_team_groups(pool: PgPool) {
    let admin = human(&pool, "kind-admin").await;
    let member = human(&pool, "kind-member").await;
    let personal: Uuid = sqlx::query_scalar(
        "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
    )
    .bind(admin)
    .fetch_one(&pool)
    .await
    .expect("personal group");
    let world = fixture::world_group(&pool).await;
    let keyed: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ('keyed probe', 'did:key:probe-' || gen_random_uuid()::text, \
                 decode(repeat('ab', 32), 'hex'), 'team', $1) RETURNING id",
    )
    .bind(admin)
    .fetch_one(&pool)
    .await
    .expect("keyed team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(keyed)
    .bind(admin)
    .execute(&pool)
    .await
    .expect("keyed group admin row");

    for (g, what) in [
        (personal, "personal"),
        (world, "world"),
        (keyed, "keyed team"),
    ] {
        let r = add(&pool, g, member, "reader").await;
        assert_eq!(code_of(&r).as_deref(), Some("GRP05"), "{what}: {r:?}");
        assert_eq!(live_role(&pool, g, member).await, None, "{what}");
    }
    // POSITIVE CONTROL: a verb-created group admits the same member.
    let group = create(&pool, "Synthetic Kind Team", admin)
        .await
        .expect("create");
    add(&pool, group, member, "reader").await.expect("add");
}
