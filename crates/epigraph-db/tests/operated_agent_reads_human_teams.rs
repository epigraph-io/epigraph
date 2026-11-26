//! Migration 234: an operated agent READS the teams its live human reads (the
//! read counterpart of owner decision D-V3; owner decision 2026-11-21).
//!
//! Measured on prod before the change (2026-11-21, kit 94057a3d): a stdio
//! `epigraph-mcp` signer live-linked to its human wrote a claim into the
//! human's team (D-V3) and then could not read it back: `get_claim` answered
//! "not found", because `Viewer::resolve` built the read set from the agent's
//! own memberships only.
//!
//! Pinned:
//! * `Viewer::resolve` of a live-linked agent carries every active team its
//!   human holds a live membership of, at any role (reader included), in the
//!   READ set, and none of them in the WRITABLE set;
//! * with that viewer, on an `epigraph_app` transaction stamped exactly as the
//!   request path stamps it, a group-private claim owned by the human's team is
//!   readable: the row policy (077 `claims_tenancy`) admits it;
//! * nothing is added for: an unlinked agent, a RETIRED link, a membership the
//!   human no longer holds (revoked), a human whose registration is revoked, a
//!   team that is not active, a group that is not a team or community;
//! * `epigraph_readable_teams` answers `own` for the agent's own teams and
//!   `operator` only for the human's, and is EXECUTE-able by `epigraph_app`
//!   (answering, since migration 309, only for the stamped principal).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;

// ─── fixtures (as bug_report_intake.rs builds them) ──────────────────────

async fn team_group(pool: &PgPool, admin: Uuid, label: &str, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, $2, 'did:test:team:' || $1::text, $3, $4, $5)",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .bind(kind)
    .bind(admin)
    .execute(pool)
    .await
    .expect("group");
    add_member(pool, id, admin, "admin").await;
    id
}

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
    .expect("membership");
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

async fn app(pool: &PgPool) -> ScopedPool {
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

fn reads(v: &Viewer) -> Vec<Uuid> {
    v.group_bind().expect("a scoped viewer").to_vec()
}

/// A human who is a READER (only) of a team someone else runs, and an agent
/// live-linked to that human.
struct World {
    human: Uuid,
    team: Uuid,
    agent: Uuid,
}

async fn world(pool: &PgPool) -> World {
    let (owner, _) = fixture::seed_human_operator(pool, "oart-owner").await;
    let team = team_group(pool, owner, "oart-team", "team").await;
    let (human, _) = fixture::seed_human_operator(pool, "oart-human").await;
    add_member(pool, team, human, "reader").await;
    let agent = linked_agent(pool, human, "oart-agent").await;
    World { human, team, agent }
}

// ─── the viewer ──────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_linked_agent_reads_its_humans_team_and_cannot_write_it(pool: PgPool) {
    let w = world(&pool).await;
    let v = Viewer::resolve(&pool, w.agent).await.expect("resolve");
    assert!(
        reads(&v).contains(&w.team),
        "the human's team is in the read set: {:?}",
        reads(&v)
    );
    assert!(
        !v.writable_groups().contains(&w.team),
        "a READ grant must never reach the writable set: {:?}",
        v.writable_groups()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_row_policy_admits_the_teams_claim_on_an_app_role_stamp(pool: PgPool) {
    let w = world(&pool).await;
    let (owner_of_claim, _) = fixture::seed_human_operator(&pool, "oart-author").await;
    add_member(&pool, w.team, owner_of_claim, "writer").await;
    let claim =
        fixture::seed_group_claim(&pool, owner_of_claim, w.team, "oart team-private claim").await;

    let v = Viewer::resolve(&pool, w.agent).await.expect("resolve");
    let scoped = app(&pool).await;
    let mut tx = scoped.begin_as(&v).await.expect("stamped transaction");
    let got = ClaimRepository::get_by_id(&mut *tx, &v, ClaimId::from_uuid(claim))
        .await
        .expect("read");
    tx.rollback().await.expect("rollback");
    assert!(
        got.is_some(),
        "the linked agent reads a claim owned by its human's team"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unlinked_agent_reads_nothing_of_the_team(pool: PgPool) {
    let w = world(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "oart-stranger").await;
    let v = Viewer::resolve(&pool, stranger).await.expect("resolve");
    assert!(!reads(&v).contains(&w.team));
    let _ = w.human;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_link_adds_nothing(pool: PgPool) {
    let w = world(&pool).await;
    let old = retired_agent(&pool, w.human, "oart-retired").await;
    let v = Viewer::resolve(&pool, old).await.expect("resolve");
    assert!(
        !reads(&v).contains(&w.team),
        "a retired link reads nothing through the human"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_membership_the_human_lost_adds_nothing(pool: PgPool) {
    let w = world(&pool).await;
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(w.team)
    .bind(w.human)
    .execute(&pool)
    .await
    .expect("revoke the human's membership");
    let v = Viewer::resolve(&pool, w.agent).await.expect("resolve");
    assert!(
        !reads(&v).contains(&w.team),
        "the agent follows its human's LIVE memberships only"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_human_whose_registration_is_revoked_adds_nothing(pool: PgPool) {
    let w = world(&pool).await;
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_now FROM public.epigraph_revoke_human_operator($1, $2)")
            .bind(w.human)
            .bind("234 test")
            .fetch_one(&pool)
            .await
            .expect("revoke the human's registration");
    assert!(revoked, "PREMISE: the registration was live");
    let v = Viewer::resolve(&pool, w.agent).await.expect("resolve");
    assert!(
        !reads(&v).contains(&w.team),
        "an agent stops reading through a human whose registration is revoked"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_inactive_team_adds_nothing(pool: PgPool) {
    let w = world(&pool).await;
    sqlx::query("UPDATE groups SET status = 'suspended' WHERE id = $1")
        .bind(w.team)
        .execute(&pool)
        .await
        .expect("suspend the team");
    let v = Viewer::resolve(&pool, w.agent).await.expect("resolve");
    assert!(!reads(&v).contains(&w.team));
}

// ─── the definer ─────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn readable_teams_says_own_or_operator_and_lists_teams_only(pool: PgPool) {
    let w = world(&pool).await;
    // The agent's own team, and a non-team group of the human (its own personal
    // group, which is never a team).
    let (owner, _) = fixture::seed_human_operator(&pool, "oart-own-owner").await;
    let own_team = team_group(&pool, owner, "oart-own-team", "team").await;
    add_member(&pool, own_team, w.agent, "reader").await;
    let rows: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT group_id, via FROM public.epigraph_readable_teams($1)")
            .bind(w.agent)
            .fetch_all(&pool)
            .await
            .expect("readable teams");
    let mut want = vec![
        (w.team, "operator".to_string()),
        (own_team, "own".to_string()),
    ];
    want.sort();
    let mut got = rows.clone();
    got.sort();
    assert_eq!(
        got, want,
        "exactly the human's team (operator) and the agent's own team (own)"
    );
}

/// `epigraph_app` may execute the definer, and since migration 309 it answers
/// only for the session principal: stamped as the agent it lists the agent's
/// one readable team, unstamped it lists nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_application_role_may_call_readable_teams(pool: PgPool) {
    let w = world(&pool).await;
    let app_pool = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let stamped: i64 = sqlx::query_scalar(
        "SELECT count(*) \
           FROM (SELECT set_config('epigraph.principal_id', $1::text, true)::uuid AS p) s \
          CROSS JOIN LATERAL public.epigraph_readable_teams(s.p)",
    )
    .bind(w.agent)
    .fetch_one(&app_pool)
    .await
    .expect("epigraph_app has EXECUTE on epigraph_readable_teams");
    assert_eq!(stamped, 1, "stamped as the agent: its human's team");
    let unstamped: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.epigraph_readable_teams($1)")
            .bind(w.agent)
            .fetch_one(&app_pool)
            .await
            .expect("epigraph_app has EXECUTE on epigraph_readable_teams");
    assert_eq!(
        unstamped, 0,
        "an unstamped app connection reads no one's teams"
    );
}
