//! Migration 309: the team lists answer only for the session principal (the
//! writable list also for the principal's operated agent), and group-admin
//! decisions follow LIVE membership. Backlogs 1c5edc26 and a91d957d.
//!
//! Every refusal is read on a connection whose `session_user` is
//! `epigraph_app` (the `#[sqlx::test]` harness is a superuser, which every
//! gate admits), and calibrated against the superuser's answer.
//!
//! The team lists (1c5edc26):
//! * the operator arm of `epigraph_writable_teams`: a live human operator
//!   with a live link reads its agent's list; a retired link, an unrelated
//!   human and a human whose registration is revoked (its link still live)
//!   read nothing; `epigraph_readable_teams` has no such arm;
//! * 209's `epigraph_set_agent_default_group` still lets an operator set its
//!   agent's team default on the application role (its VIS02 check asks the
//!   AGENT's list with the operator stamped);
//! * the Rust callers that run before any stamp exists keep answering on the
//!   application role: `Viewer::resolve` (the human's team of an operated
//!   agent) and `ClaimRepository::resolve_visibility_choice` (the author's
//!   team), and the latter leaves the connection's principal as it found it,
//!   outside and inside a transaction.
//!
//! The group-admin decision (a91d957d), on a verb-made team group (164) with
//! three live admins and one LAPSED admin (an unrevoked `admin` row whose
//! human's registration was revoked):
//! * `epigraph_is_group_admin` is false for the lapsed admin;
//! * 181's `epigraph_mark_group_reseal_required` refuses it at its admin
//!   gate (GRA01);
//! * `InstanceAdminRepository::privatization_authority` neither counts it
//!   among the other live admins nor calls it a target-group admin;
//! * `PrivatizationRepository::is_live_group_admin_conn` (the dispatch-time
//!   approver check) answers false for it.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::VisibilityChoice;
use epigraph_db::repos::instance_admin::InstanceAdminRepository;
use epigraph_db::repos::privatization::PrivatizationRepository;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ChoiceResolution, ClaimRepository};
use sqlx::PgPool;
use uuid::Uuid;

// ─── fixtures ────────────────────────────────────────────────────────────

/// A team group (not verb-made, so 164's lapse rule does not apply) with
/// `member` holding a `role` row in it.
async fn team_with(pool: &PgPool, member: Uuid, role: &str, label: &str) -> Uuid {
    let team: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, 'did:probe:' || $1, $2, 'team', $3) RETURNING id",
    )
    .bind(format!("{label}-team-{member}"))
    .bind(vec![7u8; 32])
    .bind(member)
    .fetch_one(pool)
    .await
    .expect("seed team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(team)
    .bind(member)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed team membership");
    team
}

async fn linked_agent(pool: &PgPool, human: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("live link");
    agent
}

async fn retired_agent(pool: &PgPool, human: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_retired_agent(&mut conn, agent, human)
        .await
        .expect("retired link");
    agent
}

/// `func(agent)` (one of the two team lists) on a connection whose session
/// user is `role`, with `principal` stamped (`None`: unstamped).
async fn teams_as(
    pool: &PgPool,
    role: &str,
    principal: Option<Uuid>,
    func: &'static str,
    agent: Uuid,
) -> Vec<(Uuid, String)> {
    let principal = principal.map(|p| p.to_string()).unwrap_or_default();
    fixture::as_role(pool, role, |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(&principal)
            .execute(&mut *conn)
            .await
            .expect("stamp the principal");
        let rows: Vec<(Uuid, String)> = sqlx::query_as(&format!(
            "SELECT group_id, via FROM public.{func}($1) ORDER BY group_id"
        ))
        .bind(agent)
        .fetch_all(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("{func} answers: {e}"));
        sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
            .execute(&mut *conn)
            .await
            .expect("clear the principal");
        (conn, rows)
    })
    .await
}

/// The superuser's answer (always admitted): the calibration every refusal is
/// read against.
async fn super_teams(pool: &PgPool, func: &'static str, agent: Uuid) -> Vec<(Uuid, String)> {
    sqlx::query_as(&format!(
        "SELECT group_id, via FROM public.{func}($1) ORDER BY group_id"
    ))
    .bind(agent)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| panic!("superuser {func}: {e}"))
}

const WRITABLE: &str = "epigraph_writable_teams";
const READABLE: &str = "epigraph_readable_teams";

/// A human operator `human` that WRITES a team (writer row), an agent `agent`
/// live-linked to it (so the agent writes that team only `via = 'operator'`),
/// and an agent `retired` whose link to the same human is retired and which
/// writes a team of its own.
struct Operated {
    human: Uuid,
    team: Uuid,
    agent: Uuid,
    retired: Uuid,
    retired_team: Uuid,
}

async fn operated(pool: &PgPool, label: &str) -> Operated {
    let (human, _) = fixture::seed_human_operator(pool, &format!("{label}-human")).await;
    let team = team_with(pool, human, "writer", &format!("{label}-human")).await;
    let agent = linked_agent(pool, human, &format!("{label}-agent")).await;
    let retired = retired_agent(pool, human, &format!("{label}-retired")).await;
    let retired_team = team_with(pool, retired, "writer", &format!("{label}-retired")).await;
    Operated {
        human,
        team,
        agent,
        retired,
        retired_team,
    }
}

// ─── the team lists (1c5edc26) ───────────────────────────────────────────

/// The operator arm. A live human operator stamped as itself reads the
/// writable list of the agent it holds a LIVE link to; it reads nothing for an
/// agent whose link is retired, and an unrelated human reads nothing for
/// either. The readable list has no operator arm. Each refusal is calibrated
/// against the superuser's non-empty answer for the same agent.
#[sqlx::test(migrations = "../../migrations")]
async fn the_writable_list_answers_the_live_operator_and_no_one_else(pool: PgPool) {
    let w = operated(&pool, "op-arm").await;
    let (stranger, _) = fixture::seed_human_operator(&pool, "op-arm-stranger").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let agent_writes = vec![(w.team, "operator".to_string())];
    let retired_writes = vec![(w.retired_team, "own".to_string())];
    assert_eq!(
        super_teams(&pool, WRITABLE, w.agent).await,
        agent_writes,
        "CALIBRATION: the agent writes its human's team, via operator"
    );
    assert_eq!(
        super_teams(&pool, WRITABLE, w.retired).await,
        retired_writes,
        "CALIBRATION: the retired agent writes its own team"
    );
    assert!(
        !super_teams(&pool, READABLE, w.agent).await.is_empty(),
        "CALIBRATION: the agent reads its human's team"
    );

    assert_eq!(
        teams_as(&pool, "epigraph_app", Some(w.human), WRITABLE, w.agent).await,
        agent_writes,
        "the live operator reads its agent's writable list"
    );
    assert_eq!(
        teams_as(&pool, "epigraph_app", Some(w.agent), WRITABLE, w.agent).await,
        agent_writes,
        "POSITIVE CONTROL: the agent itself reads its own list"
    );
    assert!(
        teams_as(&pool, "epigraph_app", Some(w.human), WRITABLE, w.retired)
            .await
            .is_empty(),
        "a retired link opens nothing"
    );
    assert!(
        teams_as(&pool, "epigraph_app", Some(stranger), WRITABLE, w.agent)
            .await
            .is_empty(),
        "an unrelated human reads nothing of the agent's list"
    );
    assert!(
        teams_as(&pool, "epigraph_app", Some(w.human), READABLE, w.agent)
            .await
            .is_empty(),
        "the readable list has no operator arm"
    );
    assert!(
        teams_as(&pool, "epigraph_app", None, WRITABLE, w.agent)
            .await
            .is_empty(),
        "an unstamped application session reads nothing"
    );

    // The arm needs a LIVE human registration as well as the live link: once
    // the human's registration is revoked (its link stays live, its team row
    // is not verb-made and stays live), it reads nothing of the agent's list,
    // not even the team the agent writes on its own. Mutation caught: the
    // `epigraph_is_human_operator(epigraph_principal_id())` conjunct replaced
    // with `true` (review finding 2).
    let own_team = team_with(&pool, w.agent, "writer", "op-arm-agent-own").await;
    let own_row = (own_team, "own".to_string());
    assert!(
        teams_as(&pool, "epigraph_app", Some(w.human), WRITABLE, w.agent)
            .await
            .contains(&own_row),
        "POSITIVE CONTROL: before the revoke the live operator reads the agent's own team"
    );
    fixture::revoke_human_operator(&pool, w.human).await;
    assert!(
        super_teams(&pool, WRITABLE, w.agent)
            .await
            .contains(&own_row),
        "CALIBRATION: the agent still writes its own team after its human's revoke"
    );
    assert!(
        teams_as(&pool, "epigraph_app", Some(w.human), WRITABLE, w.agent)
            .await
            .is_empty(),
        "a revoked human reads nothing of its agent's list, though the link is live"
    );
}

/// 209's operator path on the application role: the live operator sets its
/// agent's default to a team the agent writes only through it (209 checks the
/// team against the AGENT's writable list with the operator stamped, VIS02),
/// and the retired-link agent's default is refused as before (VIS05).
#[sqlx::test(migrations = "../../migrations")]
async fn an_operator_still_sets_its_agents_team_default_on_the_app_role(pool: PgPool) {
    let w = operated(&pool, "op-default").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let (human, agent, team, retired, retired_team) =
        (w.human, w.agent, w.team, w.retired, w.retired_team);
    let (set, refused) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(human.to_string())
            .execute(&mut *conn)
            .await
            .expect("stamp the operator");
        let set: Result<String, sqlx::Error> =
            sqlx::query_scalar("SELECT public.epigraph_set_agent_default_group($1, $2, false)")
                .bind(agent)
                .bind(team)
                .fetch_one(&mut *conn)
                .await;
        let refused: Result<String, sqlx::Error> =
            sqlx::query_scalar("SELECT public.epigraph_set_agent_default_group($1, $2, false)")
                .bind(retired)
                .bind(retired_team)
                .fetch_one(&mut *conn)
                .await;
        sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
            .execute(&mut *conn)
            .await
            .expect("clear the principal");
        (conn, (set, refused))
    })
    .await;
    assert_eq!(
        set.expect("the live operator sets its agent's team default"),
        "operator"
    );
    let stored: Option<Uuid> =
        sqlx::query_scalar("SELECT default_group_id FROM agents WHERE id = $1")
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("read the default back");
    assert_eq!(stored, Some(team));
    let err = refused.expect_err("a retired link sets nothing");
    let msg = err.to_string();
    assert!(msg.contains("VIS05"), "refused by 209's admission: {msg}");
}

/// `Viewer::resolve` on an UNSTAMPED application pool still adds an operated
/// agent's human's team to its read set: `list_operator_readable_teams`
/// stamps the agent it resolves for its one statement.
#[sqlx::test(migrations = "../../migrations")]
async fn viewer_resolve_on_the_app_role_keeps_the_humans_team(pool: PgPool) {
    let (owner, _) = fixture::seed_human_operator(&pool, "vr-owner").await;
    let team = team_with(&pool, owner, "admin", "vr").await;
    let (human, _) = fixture::seed_human_operator(&pool, "vr-human").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(team)
    .bind(human)
    .execute(&pool)
    .await
    .expect("the human reads the team");
    let agent = linked_agent(&pool, human, "vr-agent").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;

    let viewer = Viewer::resolve(&app, agent)
        .await
        .expect("resolve on the app role");
    let reads = viewer.group_bind().expect("a scoped viewer").to_vec();
    assert!(
        reads.contains(&team),
        "the human's team is in the operated agent's read set: {reads:?}"
    );
    assert!(!viewer.writable_groups().contains(&team));
}

/// `ClaimRepository::resolve_visibility_choice` on the application role
/// resolves the author's only team as the default, on an unstamped connection
/// (its pre-transaction call shape) and inside a transaction stamped as
/// someone else; and the connection's principal afterwards is what it was
/// before in both shapes (the author's stamp is scoped to the one read).
#[sqlx::test(migrations = "../../migrations")]
async fn resolve_visibility_choice_stamps_the_author_for_one_read_only(pool: PgPool) {
    use sqlx::Connection;
    let (author, _) = fixture::seed_agent_with_group(&pool, "rvc-author").await;
    let team = team_with(&pool, author, "writer", "rvc").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "rvc-other").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let principal = "SELECT COALESCE(current_setting('epigraph.principal_id', true), '')";

    let mut conn = app.acquire().await.expect("app connection");
    let resolved =
        ClaimRepository::resolve_visibility_choice(&mut conn, author, VisibilityChoice::Default)
            .await
            .expect("resolve on an unstamped app connection");
    assert!(
        matches!(resolved, ChoiceResolution::Team { group, grant: None } if group == team),
        "the author's only team is its default: {resolved:?}"
    );
    let left: String = sqlx::query_scalar(principal)
        .fetch_one(&mut *conn)
        .await
        .expect("read the principal back");
    assert_eq!(left, "", "no principal is left on the connection");

    let mut tx = conn.begin().await.expect("begin");
    sqlx::query("SELECT set_config('epigraph.principal_id', $1, true)")
        .bind(other.to_string())
        .execute(&mut *tx)
        .await
        .expect("stamp the transaction as another agent");
    let resolved =
        ClaimRepository::resolve_visibility_choice(&mut tx, author, VisibilityChoice::Default)
            .await
            .expect("resolve inside a stamped transaction");
    assert!(
        matches!(resolved, ChoiceResolution::Team { group, grant: None } if group == team),
        "the author's team, whoever the transaction is stamped as: {resolved:?}"
    );
    let kept: String = sqlx::query_scalar(principal)
        .fetch_one(&mut *tx)
        .await
        .expect("read the principal back");
    assert_eq!(
        kept,
        other.to_string(),
        "the transaction keeps its own principal after the call"
    );
    tx.rollback().await.expect("rollback");
}

// ─── the group-admin decision (a91d957d) ─────────────────────────────────

/// A verb-made team group (164) administered by `owner`, with two more live
/// admins and one LAPSED admin: an unrevoked `admin` row whose human's
/// registration has been revoked.
struct Admins {
    group: Uuid,
    owner: Uuid,
    live2: Uuid,
    lapsed: Uuid,
}

async fn admins(pool: &PgPool, label: &str) -> Admins {
    let (owner, _) = fixture::seed_human_operator(pool, &format!("{label}-owner")).await;
    let (live2, _) = fixture::seed_human_operator(pool, &format!("{label}-live2")).await;
    let (live3, _) = fixture::seed_human_operator(pool, &format!("{label}-live3")).await;
    let (lapsed, _) = fixture::seed_human_operator(pool, &format!("{label}-lapsed")).await;
    let group = fixture::verb_team_group(pool, &format!("Synthetic {label} Team"), owner).await;
    fixture::verb_team_group_add(pool, group, live2, "admin").await;
    fixture::verb_team_group_add(pool, group, live3, "admin").await;
    fixture::verb_team_group_add(pool, group, lapsed, "admin").await;
    fixture::revoke_human_operator(pool, lapsed).await;
    let lapsed_role: Option<String> = sqlx::query_scalar(
        "SELECT role::text FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(lapsed)
    .fetch_optional(pool)
    .await
    .expect("the lapsed row");
    assert_eq!(
        lapsed_role.as_deref(),
        Some("admin"),
        "PREMISE: the lapsed admin's row is still an unrevoked admin row"
    );
    Admins {
        group,
        owner,
        live2,
        lapsed,
    }
}

/// `epigraph_is_group_admin(group)` on the application role, stamped as
/// `principal`.
async fn is_admin_as(pool: &PgPool, principal: Uuid, group: Uuid) -> bool {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(principal.to_string())
            .execute(&mut *conn)
            .await
            .expect("stamp");
        let a: bool = sqlx::query_scalar("SELECT public.epigraph_is_group_admin($1)")
            .bind(group)
            .fetch_one(&mut *conn)
            .await
            .expect("is admin");
        sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
            .execute(&mut *conn)
            .await
            .expect("clear the principal");
        (conn, a)
    })
    .await
}

/// 181's `epigraph_mark_group_reseal_required(group)` on the application
/// role, stamped as `principal`.
async fn mark_as(pool: &PgPool, principal: Uuid, group: Uuid) -> Result<(), sqlx::Error> {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(principal.to_string())
            .execute(&mut *conn)
            .await
            .expect("stamp");
        let r = sqlx::query("SELECT public.epigraph_mark_group_reseal_required($1)")
            .bind(group)
            .execute(&mut *conn)
            .await
            .map(|_| ());
        sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
            .execute(&mut *conn)
            .await
            .expect("clear the principal");
        (conn, r)
    })
    .await
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_lapsed_admin_is_not_a_group_admin_on_the_app_role(pool: PgPool) {
    let a = admins(&pool, "isadm").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    assert!(
        is_admin_as(&pool, a.owner, a.group).await,
        "POSITIVE CONTROL: a live admin administers the group"
    );
    assert!(
        is_admin_as(&pool, a.live2, a.group).await,
        "POSITIVE CONTROL: an admin added by the verb administers the group"
    );
    assert!(
        !is_admin_as(&pool, a.lapsed, a.group).await,
        "a lapsed admin row decides nothing"
    );
}

/// 181's mark asks `epigraph_is_group_admin` first (GRA01). A verb-made team
/// group is keyless, so its row is changed only by the team-group verbs (164's
/// GRM06 guard on `groups`) and no mark on it ever lands; what this pins is
/// the ADMIN GATE, which runs before that guard: the lapsed admin is refused
/// there (GRA01), and the live owner passes it and is stopped only by the
/// later guard (GRM06). Before 309 the lapsed admin passed the gate too.
#[sqlx::test(migrations = "../../migrations")]
async fn a_lapsed_admin_cannot_mark_the_reseal_obligation(pool: PgPool) {
    let a = admins(&pool, "reseal").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let lapsed = mark_as(&pool, a.lapsed, a.group)
        .await
        .expect_err("a lapsed admin marks nothing")
        .to_string();
    assert!(lapsed.contains("GRA01"), "181's admin refusal: {lapsed}");

    let owner = mark_as(&pool, a.owner, a.group)
        .await
        .expect_err("CALIBRATION: no mark lands on a verb-made group")
        .to_string();
    assert!(
        !owner.contains("GRA01") && owner.contains("GRM06"),
        "POSITIVE CONTROL: the live owner passes the admin gate and is stopped only by the \
         team-group guard after it: {owner}"
    );
    let marked: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT reseal_required_at FROM groups WHERE id = $1")
            .bind(a.group)
            .fetch_one(&pool)
            .await
            .expect("read the mark");
    assert_eq!(marked, None);
}

/// A connection whose `session_user` is `epigraph_maintenance`: the
/// connection both privatization checks run on (`epigraph_bypass()`).
async fn maintenance_conn(pool: &PgPool) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    fixture::grant_app_privileges(pool, "epigraph_maintenance").await;
    fixture::downgraded_pool(pool, "epigraph_maintenance")
        .await
        .acquire()
        .await
        .expect("maintenance connection")
}

/// `privatization_authority` on a maintenance session: the lapsed admin is
/// not one of the target group's other live admins (condition 3b), and is not
/// a target-group admin itself (condition 4).
#[sqlx::test(migrations = "../../migrations")]
async fn the_privatization_authority_ignores_a_lapsed_admin(pool: PgPool) {
    let a = admins(&pool, "priv").await;
    let mut conn = maintenance_conn(&pool).await;

    let owner = InstanceAdminRepository::privatization_authority(&mut conn, a.owner, a.group)
        .await
        .expect("authority for the owner");
    assert!(owner.is_target_group_admin, "POSITIVE CONTROL");
    assert_eq!(
        owner.other_live_admins, 2,
        "two live admins besides the owner; the lapsed row is not one"
    );

    let lapsed = InstanceAdminRepository::privatization_authority(&mut conn, a.lapsed, a.group)
        .await
        .expect("authority for the lapsed admin");
    assert!(
        !lapsed.is_target_group_admin,
        "a lapsed admin is not an admin of the target group"
    );
    assert_eq!(lapsed.other_live_admins, 3, "owner, live2 and live3");
}

/// `is_live_group_admin_conn` (the dispatch-time approver check) on a
/// maintenance session: a lapsed admin's approval does not survive to
/// dispatch.
#[sqlx::test(migrations = "../../migrations")]
async fn the_dispatch_approver_check_refuses_a_lapsed_admin(pool: PgPool) {
    let a = admins(&pool, "approver").await;
    let mut conn = maintenance_conn(&pool).await;
    assert!(
        PrivatizationRepository::is_live_group_admin_conn(&mut conn, a.group, a.live2)
            .await
            .expect("approver check"),
        "POSITIVE CONTROL: a live admin approves"
    );
    assert!(
        !PrivatizationRepository::is_live_group_admin_conn(&mut conn, a.group, a.lapsed)
            .await
            .expect("approver check"),
        "a lapsed admin's approval does not survive to dispatch"
    );
}

// ─── the migration's precondition and its undo ───────────────────────────

const BODIES: [(&str, &str); 3] = [
    (
        "public.epigraph_writable_teams(uuid)",
        "d675bc199f78f07db83e1268ef9c5eaf",
    ),
    (
        "public.epigraph_readable_teams(uuid)",
        "d98f6b56fa1fb3b40d831501a0a44106",
    ),
    (
        "public.epigraph_is_group_admin(uuid)",
        "d7cd46f92f9d8b93d7562ace0d547205",
    ),
];

async fn body_md5_and_owner(pool: &PgPool, signature: &str) -> (String, String) {
    sqlx::query_as(
        "SELECT md5(p.prosrc), pg_get_userbyid(p.proowner)::text FROM pg_proc p \
          WHERE p.oid = to_regprocedure($1)",
    )
    .bind(signature)
    .fetch_one(pool)
    .await
    .expect("pg_proc")
}

fn read_repo_file(rel: &str) -> String {
    std::fs::read_to_string(format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// `docs/runbooks/309-undo.sql` restores the three predecessor bodies (the
/// md5s 309's precondition reads), owners kept; after it an unstamped
/// application session reads another agent's teams again and a lapsed admin
/// is an admin again (236's and 077's behaviour, which is what an undo
/// means). 309's own file then applies cleanly over the restored bodies, and
/// refuses (55000, nothing changed) over a body it was not written from.
#[sqlx::test(migrations = "../../migrations")]
async fn the_309_undo_restores_the_predecessors_and_309_reapplies_over_them(pool: PgPool) {
    sqlx::raw_sql(&read_repo_file("docs/runbooks/309-undo.sql"))
        .execute(&pool)
        .await
        .expect("apply the undo");
    for (signature, md5) in BODIES {
        assert_eq!(
            body_md5_and_owner(&pool, signature).await,
            (md5.to_string(), "epigraph_maintenance".to_string()),
            "{signature}"
        );
    }
    let w = operated(&pool, "undo").await;
    let a = admins(&pool, "undo").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    assert_eq!(
        teams_as(&pool, "epigraph_app", None, WRITABLE, w.agent).await,
        vec![(w.team, "operator".to_string())],
        "after the undo the unstamped read answers again"
    );
    assert!(
        is_admin_as(&pool, a.lapsed, a.group).await,
        "after the undo a lapsed admin row decides again"
    );

    let forward = read_repo_file("migrations/309_membership_definers_principal_bound.sql");
    sqlx::raw_sql(&forward)
        .execute(&pool)
        .await
        .expect("309 applies over the bodies the undo restores");
    assert!(teams_as(&pool, "epigraph_app", None, WRITABLE, w.agent)
        .await
        .is_empty());
    assert!(!is_admin_as(&pool, a.lapsed, a.group).await);

    // Over any other body: refused, nothing changed.
    sqlx::raw_sql(&read_repo_file("docs/runbooks/309-undo.sql"))
        .execute(&pool)
        .await
        .expect("undo again");
    sqlx::raw_sql(
        "CREATE OR REPLACE FUNCTION public.epigraph_is_group_admin(p_group uuid) \
         RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER \
         SET search_path = public, pg_temp AS $$ SELECT false $$",
    )
    .execute(&pool)
    .await
    .expect("a foreign body");
    let refused = sqlx::raw_sql(&forward)
        .execute(&pool)
        .await
        .expect_err("309 refuses a body it was not written from");
    let code = match &refused {
        sqlx::Error::Database(e) => e.code().map(|c| c.to_string()),
        _ => None,
    };
    assert_eq!(code.as_deref(), Some("55000"), "{refused}");
    assert_eq!(
        body_md5_and_owner(&pool, BODIES[0].0).await.0,
        BODIES[0].1,
        "nothing was changed: the writable list keeps 236's body"
    );
}
