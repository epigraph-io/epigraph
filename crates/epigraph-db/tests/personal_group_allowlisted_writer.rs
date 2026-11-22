//! Migration 235 (SR-3 GAP-4, backlog e694b36e): `group-member add --role
//! writer` reaches ONE kind of personal-group member, the client-allowlisted
//! agent of the group's own owner, and that row lapses with the allowance.
//!
//! `epigraph_team_group_add_member` admits an active personal group only when
//! ALL of these hold, and refuses GRP05 otherwise:
//!
//! * (a) the agent's author binding is `client_allowlist` (migration 149);
//! * (b) the agent's live human is the group's owner;
//! * (c) the caller is a maintenance session (164's gate, unchanged);
//! * (d) the role is `writer`.
//!
//! Each refusal below is paired with the positive control that the same call
//! shape lands when the refused condition is absent, and each was
//! mutation-tested against the migration (the PR records the results).
//!
//! Every verb runs on a session whose `session_user` IS `epigraph_maintenance`
//! (`SET SESSION AUTHORIZATION`), not on the harness superuser.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "support/delegation_fixture.rs"]
mod delegation;

use epigraph_db::{AgentRepository, DelegationLive, RunTokens, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

const NOT_MANAGED: &str = "GRP05";
const INSUFFICIENT_PRIVILEGE: &str = "42501";

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref()
        .err()
        .and_then(|e| e.as_database_error())
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

async fn maint(pool: &PgPool) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_maintenance")
        .await
        .expect("downgrade to the maintenance role");
    conn
}

async fn reset(mut conn: sqlx::pool::PoolConnection<sqlx::Postgres>) {
    use sqlx::Executor;
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset session authorization");
}

/// `group-member add` as the operator CLI calls it: `(membership, applied)`.
async fn add(
    pool: &PgPool,
    group: Uuid,
    agent: Uuid,
    role: &str,
) -> Result<(Option<Uuid>, bool), sqlx::Error> {
    let mut c = maint(pool).await;
    let r = sqlx::query_as(
        "SELECT out_membership_id, out_applied \
           FROM public.epigraph_team_group_add_member($1, $2, $3, $4)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .bind("SR-3 GAP-4 test")
    .fetch_one(&mut *c)
    .await;
    reset(c).await;
    r
}

/// `group-member remove`: `(membership, applied, prior_role)`.
async fn remove(
    pool: &PgPool,
    group: Uuid,
    agent: Uuid,
) -> Result<(Option<Uuid>, bool, Option<String>), sqlx::Error> {
    let mut c = maint(pool).await;
    let r = sqlx::query_as(
        "SELECT out_membership_id, out_applied, out_prior_role \
           FROM public.epigraph_team_group_remove_member($1, $2, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind("SR-3 GAP-4 test")
    .fetch_one(&mut *c)
    .await;
    reset(c).await;
    r
}

async fn set_role(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) -> Option<String> {
    let mut c = maint(pool).await;
    let r: Result<(Option<Uuid>, bool, Option<String>), _> = sqlx::query_as(
        "SELECT out_membership_id, out_applied, out_prior_role \
           FROM public.epigraph_team_group_set_member_role($1, $2, $3, $4)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .bind("SR-3 GAP-4 test")
    .fetch_one(&mut *c)
    .await;
    reset(c).await;
    code_of(&r)
}

/// Every membership row of `(group, agent)`: `(epoch, role, revoked)`.
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

/// The `group.*` audit rows naming `group`: `(event_type, member, details)`.
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

/// `(readable, writable)`: whether `agent`'s resolved viewer carries `group`.
async fn resolves(pool: &PgPool, agent: Uuid, group: Uuid) -> (bool, bool) {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    (
        viewer.group_bind().is_some_and(|g| g.contains(&group)),
        viewer.writable_groups().contains(&group),
    )
}

/// An allowlisted service agent of `operator`, holding NO membership of the
/// operator's group yet: `(client row id, agent id)`.
async fn allowlisted(pool: &PgPool, operator: Uuid, operator_group: Uuid) -> (Uuid, Uuid) {
    delegation::delegator(pool, operator, operator_group, None, true).await
}

async fn arm(pool: &PgPool) {
    let mut c = maint(pool).await;
    sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
        .fetch_one(&mut *c)
        .await
        .expect("the maintenance role arms");
    reset(c).await;
}

/// Insert a `('group', owner_group)` claim authored by `agent` on an
/// `epigraph_app` connection stamped from `agent`'s RESOLVED viewer (the three
/// GUCs `ScopedPool` stamps), so the row policy decides from the viewer the
/// membership produced, not from a set the test hands it.
async fn write_as_resolved(
    pool: &PgPool,
    agent: Uuid,
    owner_group: Uuid,
) -> Result<Uuid, sqlx::Error> {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    let join = |ids: &[Uuid]| {
        ids.iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let groups = join(viewer.group_bind().unwrap_or_default());
    let writable = join(viewer.writable_groups());
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $3, false)",
        )
        .bind(agent.to_string())
        .bind(&groups)
        .bind(&writable)
        .execute(&mut *conn)
        .await
        .expect("stamp from the viewer");
        let id = Uuid::new_v4();
        let r = sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id) \
             VALUES ($1, $2, $3, 0.5, $4, true, 'group', $5)",
        )
        .bind(id)
        .bind(format!("SR-3 GAP-4 host write probe {id}"))
        .bind(id.as_bytes().repeat(2))
        .bind(agent)
        .bind(owner_group)
        .execute(&mut *conn)
        .await
        .map(|_| id);
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, r)
    })
    .await
}

/// POSITIVE: the allowlisted agent of operator O is added as a WRITER of O's
/// personal group. One live row at epoch 0, one audit row naming the arm, and
/// the agent's resolved viewer reads and writes the group. A repeat is a
/// no-op, not a second row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_allowlisted_agent_of_the_owner_is_added_as_writer(pool: PgPool) {
    let (owner, group) = delegation::human_operator(&pool, "gap4-owner").await;
    let (_, agent) = allowlisted(&pool, owner, group).await;
    assert_eq!(
        resolves(&pool, agent, group).await,
        (false, false),
        "PREMISE"
    );

    let (membership, applied) = add(&pool, group, agent, "writer").await.expect("add");
    assert!(applied && membership.is_some());
    assert_eq!(
        rows(&pool, group, agent).await,
        [(0, "writer".to_string(), false)]
    );
    assert_eq!(resolves(&pool, agent, group).await, (true, true));

    let events = audit(&pool, group).await;
    assert_eq!(events.len(), 1, "{events:?}");
    let (kind, member, details) = &events[0];
    assert_eq!(kind, "group.member_added");
    assert_eq!(*member, Some(agent));
    assert_eq!(details["arm"], "personal_client_allowlist");
    assert_eq!(details["kind"], "personal");
    assert_eq!(details["role"], "writer");
    assert_eq!(details["operator"], owner.to_string());

    let again = add(&pool, group, agent, "writer").await.expect("repeat");
    assert_eq!(again, (membership, false), "a repeat is a no-op");
    assert_eq!(
        audit(&pool, group).await.len(),
        1,
        "a no-op writes no audit row"
    );
}

/// (b): an agent allowlisted for O is refused GRP05 in ANOTHER human's (P's)
/// personal group, with no row and no audit row; the positive control is the
/// same agent into O's own group.
#[sqlx::test(migrations = "../../migrations")]
async fn it_is_refused_in_another_humans_personal_group(pool: PgPool) {
    let (owner, group) = delegation::human_operator(&pool, "gap4-b-owner").await;
    let (_, other_group) = delegation::human_operator(&pool, "gap4-b-other").await;
    let (_, agent) = allowlisted(&pool, owner, group).await;

    let r = add(&pool, other_group, agent, "writer").await;
    assert_eq!(code_of(&r).as_deref(), Some(NOT_MANAGED), "{r:?}");
    assert!(rows(&pool, other_group, agent).await.is_empty());
    assert!(audit(&pool, other_group).await.is_empty());

    add(&pool, group, agent, "writer")
        .await
        .expect("POSITIVE CONTROL: its owner's group");
}

/// (d): the allowlisted agent of the owner is refused GRP05 as `admin` and as
/// `reader`; only `writer` lands.
#[sqlx::test(migrations = "../../migrations")]
async fn it_is_refused_as_admin_and_as_reader(pool: PgPool) {
    let (owner, group) = delegation::human_operator(&pool, "gap4-d-owner").await;
    let (_, agent) = allowlisted(&pool, owner, group).await;

    for role in ["admin", "reader"] {
        let r = add(&pool, group, agent, role).await;
        assert_eq!(code_of(&r).as_deref(), Some(NOT_MANAGED), "{role}: {r:?}");
        assert!(rows(&pool, group, agent).await.is_empty(), "{role}");
    }
    add(&pool, group, agent, "writer")
        .await
        .expect("POSITIVE CONTROL: writer");
}

/// (a): agents that are NOT client-allowlisted are refused GRP05 in O's
/// personal group, whatever else holds:
///
/// * a LIVE-LINKED agent of O whose acting row the operator revoked (its live
///   human IS the owner, so only (a) refuses: the verb must not revive a row
///   107's link path owns);
/// * an agent whose allowlisted client is SUSPENDED (binding lapses);
/// * an unbound agent;
/// * a registered human that is not the owner.
///
/// The positive control is an allowlisted agent of O.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_allowlisted_agent_is_still_refused(pool: PgPool) {
    let (owner, group) = delegation::human_operator(&pool, "gap4-a-owner").await;
    let linked = delegation::linked_principal(&pool, owner, "gap4-a-linked").await;
    delegation::revoke_membership(&pool, linked, group).await;
    let (suspended_client, suspended) = allowlisted(&pool, owner, group).await;
    delegation::set_client_status(&pool, suspended_client, "suspended").await;
    let (unbound, _) = delegation::agent_with_group(&pool, "gap4-a-unbound").await;
    let (person, _) = delegation::human_operator(&pool, "gap4-a-person").await;

    for (agent, what) in [
        (linked, "live-linked agent whose acting row was revoked"),
        (suspended, "agent of a suspended allowlisted client"),
        (unbound, "unbound agent"),
        (person, "registered human, not the owner"),
    ] {
        let before = rows(&pool, group, agent).await;
        let r = add(&pool, group, agent, "writer").await;
        assert_eq!(code_of(&r).as_deref(), Some(NOT_MANAGED), "{what}: {r:?}");
        assert_eq!(
            rows(&pool, group, agent).await,
            before,
            "{what}: no row written"
        );
    }
    assert!(audit(&pool, group).await.is_empty(), "no audit row");

    let (_, agent) = allowlisted(&pool, owner, group).await;
    add(&pool, group, agent, "writer")
        .await
        .expect("POSITIVE CONTROL: an allowlisted agent of the owner");
}

/// (c): the application role cannot reach the arm, whatever it forges; the
/// identical call on a maintenance session lands.
#[sqlx::test(migrations = "../../migrations")]
async fn the_application_role_cannot_use_the_arm(pool: PgPool) {
    let (owner, group) = delegation::human_operator(&pool, "gap4-c-owner").await;
    let (_, agent) = allowlisted(&pool, owner, group).await;
    let r = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $2, false)",
        )
        .bind(owner.to_string())
        .bind(group.to_string())
        .execute(&mut *conn)
        .await
        .expect("forge the owner's stamp");
        let r: Result<(Option<Uuid>, bool), _> = sqlx::query_as(
            "SELECT out_membership_id, out_applied \
               FROM public.epigraph_team_group_add_member($1, $2, 'writer', 'forged')",
        )
        .bind(group)
        .bind(agent)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "{r:?}"
    );
    assert!(rows(&pool, group, agent).await.is_empty());
    add(&pool, group, agent, "writer")
        .await
        .expect("POSITIVE CONTROL: maintenance");
}

/// After the allowance is REVOKED:
///
/// * the existing row is CUT OFF at the agent's next resolve (it no longer
///   reads or writes the owner's group), while the row itself stays live;
/// * a new add is refused GRP05 (with the row live, and again after it is
///   removed);
/// * `group-member remove` (the existing remove path) still revokes the row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_allowance_refuses_a_new_add_and_cuts_the_row_off(pool: PgPool) {
    let (owner, group) = delegation::human_operator(&pool, "gap4-rev-owner").await;
    let (client, agent) = allowlisted(&pool, owner, group).await;
    add(&pool, group, agent, "writer").await.expect("add");
    assert_eq!(resolves(&pool, agent, group).await, (true, true), "PREMISE");

    delegation::revoke_allowance(&pool, client).await;

    assert_eq!(
        resolves(&pool, agent, group).await,
        (false, false),
        "the row lapses with the allowance: the viewer neither reads nor writes the group"
    );
    assert_eq!(
        rows(&pool, group, agent).await,
        [(0, "writer".to_string(), false)],
        "the row itself is untouched (the lapse is read, not written)"
    );
    assert_eq!(
        resolves(&pool, owner, group).await,
        (true, true),
        "the owner is unaffected"
    );

    let r = add(&pool, group, agent, "writer").await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(NOT_MANAGED),
        "re-add, row live: {r:?}"
    );

    let (membership, applied, prior) = remove(&pool, group, agent)
        .await
        .expect("the existing remove path revokes the lapsed row");
    assert!(applied && membership.is_some());
    assert_eq!(prior.as_deref(), Some("writer"));
    assert_eq!(
        rows(&pool, group, agent).await,
        [(0, "writer".to_string(), true)]
    );

    let r = add(&pool, group, agent, "writer").await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(NOT_MANAGED),
        "re-add after remove: {r:?}"
    );
    assert_eq!(rows(&pool, group, agent).await.len(), 1, "no new row");
}

/// The added row is what lets the agent write into the owner's group under
/// row security, on an ARMED database, stamped from its resolved viewer: the
/// identical insert is refused before the add and lands after it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_added_row_lets_the_agent_write_a_claim_under_rls(pool: PgPool) {
    let (owner, group) = delegation::human_operator(&pool, "gap4-rls-owner").await;
    let (_, agent) = allowlisted(&pool, owner, group).await;
    arm(&pool).await;

    let before = write_as_resolved(&pool, agent, group).await;
    assert!(
        before.is_err(),
        "NEGATIVE CONTROL: no row, no write: {before:?}"
    );

    add(&pool, group, agent, "writer").await.expect("add");
    let claim = write_as_resolved(&pool, agent, group)
        .await
        .expect("the writer row admits the claim under row security, armed");
    let (author, owner_group): (Uuid, Uuid) =
        sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("the claim landed");
    assert_eq!((author, owner_group), (agent, group));
}

/// The run-token delegation (backlog e694b36e) becomes live through the verb:
/// a delegator allowlisted for O reads `None` until `group-member add` gives
/// it the writer row, `Some(O, O's group)` after, and `None` again once its
/// allowance is revoked (the row still live).
#[sqlx::test(migrations = "../../migrations")]
async fn the_verb_makes_a_run_token_delegation_live(pool: PgPool) {
    let (owner, group) = delegation::human_operator(&pool, "gap4-dlg-owner").await;
    let (client, delegator) = allowlisted(&pool, owner, group).await;
    let principal = delegation::linked_principal(&pool, owner, "gap4-dlg-principal").await;
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let check = move |p: PgPool| async move {
        AgentRepository::delegated_principal_pool(&p, RunTokens::On, delegator, principal)
            .await
            .expect("the check answers")
    };

    assert_eq!(
        check(app.clone()).await,
        None,
        "PREMISE: no row, no delegation"
    );
    add(&pool, group, delegator, "writer").await.expect("add");
    assert_eq!(
        check(app.clone()).await,
        Some(DelegationLive {
            operator_id: owner,
            operator_group_id: group,
        })
    );
    delegation::revoke_allowance(&pool, client).await;
    assert_eq!(check(app).await, None, "revoked: no delegation");
}

/// The remove arm reaches only rows of agents allowlisted (live or revoked)
/// for the owner: the owner's own row and a live-linked agent's row are still
/// GRP05, and set-role is GRP05 on a personal group for every member. The
/// positive control is the allowlisted agent's row.
#[sqlx::test(migrations = "../../migrations")]
async fn remove_and_set_role_stay_closed_to_every_other_personal_row(pool: PgPool) {
    let (owner, group) = delegation::human_operator(&pool, "gap4-rm-owner").await;
    let linked = delegation::linked_principal(&pool, owner, "gap4-rm-linked").await;
    let (other, other_group) = delegation::human_operator(&pool, "gap4-rm-other").await;
    let (_, foreign) = allowlisted(&pool, other, other_group).await;
    delegation::membership(&pool, group, foreign, "writer").await;
    let (_, agent) = allowlisted(&pool, owner, group).await;
    add(&pool, group, agent, "writer").await.expect("add");

    for (member, what) in [
        (owner, "the owner"),
        (linked, "a live-linked agent"),
        (foreign, "an agent allowlisted for another human"),
    ] {
        let r = remove(&pool, group, member).await;
        assert_eq!(code_of(&r).as_deref(), Some(NOT_MANAGED), "{what}: {r:?}");
        assert_eq!(
            rows(&pool, group, member).await.last().map(|r| r.2),
            Some(false),
            "{what}: still live"
        );
    }
    for member in [owner, linked, agent] {
        assert_eq!(
            set_role(&pool, group, member, "reader").await.as_deref(),
            Some(NOT_MANAGED)
        );
    }
    let (_, applied, _) = remove(&pool, group, agent)
        .await
        .expect("POSITIVE CONTROL: the allowlisted agent's row");
    assert!(applied);
}

/// The undo re-states the three predecessor bodies exactly (md5 of `prosrc`
/// as 235's precondition reads them), so applying it restores the pre-235
/// behaviour: a personal group is GRP05 again for the allowlisted agent.
#[sqlx::test(migrations = "../../migrations")]
async fn the_235_undo_restores_the_predecessor_bodies(pool: PgPool) {
    let undo = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/runbooks/235-undo.sql"
    ))
    .expect("read the undo");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("apply the undo");
    for (signature, md5) in [
        (
            "public.epigraph_team_group_add_member(uuid, uuid, text, text)",
            "cb17e2a66f951f5fb59b11e1e5d0ee2d",
        ),
        (
            "public.epigraph_team_group_remove_member(uuid, uuid, text)",
            "d4238f78519cc7c41e6a5aea9bb188bf",
        ),
        (
            "public.epigraph_live_memberships(uuid)",
            "1d22f82a109b5ccd55302670eec719f6",
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
    let (owner, group) = delegation::human_operator(&pool, "gap4-undo-owner").await;
    let (_, agent) = allowlisted(&pool, owner, group).await;
    let r = add(&pool, group, agent, "writer").await;
    assert_eq!(code_of(&r).as_deref(), Some(NOT_MANAGED), "{r:?}");
}
