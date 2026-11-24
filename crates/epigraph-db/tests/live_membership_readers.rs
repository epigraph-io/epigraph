//! The group membership READERS decide on LIVE membership (backlogs
//! 556c5416, 93ed2ec3, f712db53).
//!
//! Every reader is driven on the APPLICATION ROLE, on a connection stamped
//! from the caller's resolved viewer, as the request paths call them. The
//! harness superuser passes migration 236's principal gate (and 273's
//! roster gate) through its `rolsuper` arm, so a reader test on that pool
//! would pass whether or not the reader works for a real caller.
//!
//! One test pins that `revoke_member_unless_last_admin_conn` refuses an
//! autocommit connection, on which its roster lock would not be held.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{
    AgentRepository, ClaimRepository, ConsolidateMode, DbError, GroupMembershipRepository,
    GroupRepository, RevokeOutcome, ScopedPool, SessionGucMode, Viewer,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// A synthetic, non-elevating role key.
const ROLE: &str = "role:live-reader-test";

/// One verb-made team group (164) with four kinds of member:
///
/// * `owner`, its admin, a registered human (a plain direct member);
/// * `writer`, a registered human with a `writer` row;
/// * `derived`, a registered human with NO row, a member only through a
///   live assignment of [`ROLE`], which is bound to the group at `writer`;
/// * `lapsed`, a human with an unrevoked ADMIN row whose registration has
///   since been revoked, so the row no longer counts.
struct Team {
    group: Uuid,
    owner: Uuid,
    writer: Uuid,
    derived: Uuid,
    lapsed: Uuid,
}

async fn team(pool: &PgPool, name: &str) -> Team {
    let (owner, _) = fixture::seed_human_operator(pool, &format!("{name}-owner")).await;
    let (writer, _) = fixture::seed_human_operator(pool, &format!("{name}-writer")).await;
    let (derived, _) = fixture::seed_human_operator(pool, &format!("{name}-derived")).await;
    let (lapsed, _) = fixture::seed_human_operator(pool, &format!("{name}-lapsed")).await;
    let group = fixture::verb_team_group(pool, &format!("Synthetic {name} Team"), owner).await;
    fixture::verb_team_group_add(pool, group, writer, "writer").await;
    fixture::verb_team_group_add(pool, group, lapsed, "admin").await;
    fixture::bind_new_role_to_group(pool, ROLE, group, "writer", false).await;
    fixture::grant_role_now(pool, ROLE, derived).await;
    fixture::revoke_human_operator(pool, lapsed).await;
    assert!(
        fixture::has_unrevoked_row(pool, group, lapsed).await,
        "PREMISE: the lapsed admin's row is still unrevoked"
    );
    assert!(
        !fixture::has_unrevoked_row(pool, group, derived).await,
        "PREMISE: the derived member holds no row"
    );
    Team {
        group,
        owner,
        writer,
        derived,
        lapsed,
    }
}

async fn app_scoped(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool")
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

// =====================================================================
// is_member_conn / get_member_role_conn: the caller, on its own stamp
// =====================================================================

/// The caller-self readers behind `GET /api/v1/groups/:id`, the group-scoped
/// claim gates and `require_group_admin_conn` answer the caller's LIVE
/// membership on a connection stamped from its own viewer: the direct admin
/// and a role-derived member are members (the derived one at its derived
/// role, and a direct reader holding the writer role at the stronger one), a
/// lapsed ADMIN is not a member and has no role. On the old raw roster read
/// the derived member was refused and the lapsed admin kept `admin`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_caller_readers_answer_its_live_membership_on_its_own_stamp(pool: PgPool) {
    let t = team(&pool, "caller").await;
    let (both, _) = fixture::seed_human_operator(&pool, "caller-both").await;
    fixture::verb_team_group_add(&pool, t.group, both, "reader").await;
    fixture::grant_role_now(&pool, ROLE, both).await;
    let (stranger, _) = fixture::seed_human_operator(&pool, "caller-stranger").await;
    let scoped = app_scoped(&pool).await;

    for (who, agent, want) in [
        ("POSITIVE CONTROL: the direct admin", t.owner, Some("admin")),
        ("a direct writer", t.writer, Some("writer")),
        ("the role-derived member", t.derived, Some("writer")),
        (
            "a direct reader holding the writer role",
            both,
            Some("writer"),
        ),
        ("the lapsed ADMIN", t.lapsed, None),
        ("NEGATIVE CONTROL: a stranger", stranger, None),
    ] {
        let v = viewer(&pool, agent).await;
        let mut read = scoped.read_as(&v).await.expect("read_as");
        let member = GroupMembershipRepository::is_member_conn(&mut read, t.group, agent)
            .await
            .expect("is_member_conn");
        let role = GroupMembershipRepository::get_member_role_conn(&mut read, t.group, agent)
            .await
            .expect("get_member_role_conn");
        assert_eq!(member, want.is_some(), "is_member_conn: {who}");
        assert_eq!(role.as_deref(), want, "get_member_role_conn: {who}");
    }

    // Asked about ANOTHER agent the readers answer nothing (236's principal
    // gate, fail-closed): they are caller-self checks.
    let v = viewer(&pool, t.owner).await;
    let mut read = scoped.read_as(&v).await.expect("read_as");
    assert!(
        !GroupMembershipRepository::is_member_conn(&mut read, t.group, t.writer)
            .await
            .expect("is_member_conn"),
        "the owner's stamp does not answer for the writer"
    );
}

// =====================================================================
// get_members_conn: the group info roster
// =====================================================================

/// `GET /api/v1/groups/:id`'s roster on a member's stamp lists the live
/// explicit rows only: the owner and the writer, not the lapsed admin's
/// unrevoked row, and no derived member (it holds no row). Before migration
/// 273 the raw read on the same connection also listed the lapsed row. On the
/// lapsed member's own stamp it lists nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_group_roster_lists_the_live_explicit_rows_on_a_members_stamp(pool: PgPool) {
    let t = team(&pool, "roster").await;
    let scoped = app_scoped(&pool).await;
    let mut want = vec![t.owner, t.writer];
    want.sort();

    for (who, agent) in [("the owner", t.owner), ("the derived member", t.derived)] {
        let v = viewer(&pool, agent).await;
        let mut read = scoped.read_as(&v).await.expect("read_as");
        let mut got: Vec<Uuid> = GroupMembershipRepository::get_members_conn(&mut read, t.group)
            .await
            .expect("get_members_conn")
            .into_iter()
            .map(|m| m.agent_id)
            .collect();
        got.sort();
        assert_eq!(got, want, "{who}: the live explicit roster");
    }
    let v = viewer(&pool, t.lapsed).await;
    let mut read = scoped.read_as(&v).await.expect("read_as");
    let got = GroupMembershipRepository::get_members_conn(&mut read, t.group)
        .await
        .expect("get_members_conn");
    assert!(got.is_empty(), "the lapsed member reads no roster: {got:?}");
}

// =====================================================================
// The consolidate act
// =====================================================================

/// The consolidate act's "member of every private source's owner group" test,
/// on the acting agent's own stamped transaction as `consolidate_claims` runs
/// it: a role-derived WRITER of the group (no row) merges two of its claims
/// into the group's corpus. The old raw roster read refused it as a non-member
/// although the same transaction could read and write the sources.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_admits_a_role_derived_member_on_its_own_stamp(pool: PgPool) {
    let t = team(&pool, "consolidate").await;
    let a = fixture::seed_group_claim(&pool, t.owner, t.group, "derived source one").await;
    let b = fixture::seed_group_claim(&pool, t.owner, t.group, "derived source two").await;
    let scoped = app_scoped(&pool).await;
    let v = viewer(&pool, t.derived).await;
    assert!(
        v.group_bind().is_some_and(|g| g.contains(&t.group)),
        "PREMISE: the derived member's viewer reads the group"
    );
    let mut tx = scoped.begin_as(&v).await.expect("begin_as");
    let r = ClaimRepository::consolidate_act_conn(
        &mut tx,
        None,
        &[a, b],
        "a live derived member's merge",
        0.8,
        ConsolidateMode::Merge,
        "live membership reader test",
        t.derived,
    )
    .await;
    let merged = r.expect("a role-derived member consolidates its group's claims");
    tx.commit().await.expect("commit");
    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(merged.merged_id)
        .fetch_one(&pool)
        .await
        .expect("read the merged claim");
    assert_eq!(owner, t.group, "the merge lands in the group's corpus");
}

// =====================================================================
// The profile detail rule
// =====================================================================

/// A unique, `orcid_format`-valid ORCID derived from an agent id.
fn orcid_for(id: Uuid) -> String {
    let d = format!("{:016}", (id.as_u128() % 10_u128.pow(16)) as u64);
    format!("{}-{}-{}-{}", &d[0..4], &d[4..8], &d[8..12], &d[12..16])
}

/// Give `agent` a group-only profile with details to hide.
async fn group_only_profile(pool: &PgPool, agent: Uuid) -> String {
    let orcid = orcid_for(agent);
    sqlx::query(
        "UPDATE agents SET profile_visibility = 'group', orcid = $2, properties = $3 \
          WHERE id = $1",
    )
    .bind(agent)
    .bind(&orcid)
    .bind(json!({ "full_name": "Synthetic Person" }))
    .execute(pool)
    .await
    .expect("group-only profile");
    orcid
}

/// The profile detail rule (`get_public_profile`, `profile_details_visible`,
/// and the agent-lookup copies held to one text by `visibility_lint.rs`)
/// shows a group-only profile's details to a viewer that shares a group with
/// the agent only while the agent's row there still COUNTS: the direct writer
/// yes, the lapsed admin no (the raw roster read showed it). A role-derived
/// member holds no row and is not recognised as a groupmate (273 lists no
/// derived member), and a stranger is not one.
#[sqlx::test(migrations = "../../migrations")]
async fn a_profile_shows_details_to_a_live_explicit_groupmate_only(pool: PgPool) {
    let t = team(&pool, "profile").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "profile-stranger").await;
    let mut orcids = std::collections::HashMap::new();
    for a in [t.writer, t.lapsed, t.derived, stranger] {
        orcids.insert(a, group_only_profile(&pool, a).await);
    }
    let scoped = app_scoped(&pool).await;
    let v = viewer(&pool, t.owner).await;
    assert!(
        v.group_bind().is_some_and(|g| g.contains(&t.group)),
        "PREMISE: the viewer reads the group"
    );

    let cases = [
        ("POSITIVE CONTROL: a live direct groupmate", t.writer, true),
        ("a lapsed groupmate", t.lapsed, false),
        ("a role-derived member (no row)", t.derived, false),
        ("NEGATIVE CONTROL: a stranger", stranger, false),
    ];
    let mut read = scoped.read_as(&v).await.expect("read_as");
    for (who, agent, want) in cases {
        let profile = AgentRepository::get_public_profile(&mut *read, &v, agent)
            .await
            .expect("get_public_profile")
            .expect("the agent exists");
        assert_eq!(profile.properties.is_some(), want, "properties: {who}");
        assert_eq!(
            profile.orcid.as_deref(),
            want.then_some(orcids[&agent].as_str()),
            "orcid: {who}"
        );
    }
    let ids: Vec<Uuid> = cases.iter().map(|c| c.1).collect();
    let visible = AgentRepository::profile_details_visible(&mut *read, &v, &ids)
        .await
        .expect("profile_details_visible");
    for (who, agent, want) in cases {
        assert_eq!(
            visible.contains(&agent),
            want,
            "profile_details_visible: {who}"
        );
    }
}

// =====================================================================
// revoke_member_unless_last_admin_conn refuses an autocommit connection
// =====================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn the_guarded_revoke_refuses_an_autocommit_connection(pool: PgPool) {
    let (admin, _) = fixture::seed_agent_with_group(&pool, "revoke-tx-admin").await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "revoke-tx-member").await;
    let group = Uuid::new_v4();
    let key = blake3::hash(group.as_bytes());
    GroupRepository::create_with_admin(
        &pool,
        group,
        Some("revoke-tx"),
        &format!("did:key:revoke-tx-{group}"),
        key.as_bytes(),
        None,
        admin,
    )
    .await
    .expect("keyed group");
    GroupMembershipRepository::add_member(&pool, group, member, &[0u8; 60], 0, "writer")
        .await
        .expect("member");
    let reseal = || async {
        sqlx::query_scalar::<_, bool>(
            "SELECT reseal_required_at IS NOT NULL FROM groups WHERE id = $1",
        )
        .bind(group)
        .fetch_one(&pool)
        .await
        .expect("read the re-key mark")
    };

    // A bare pool connection: autocommit, every statement its own transaction.
    let mut bare = pool.acquire().await.expect("acquire");
    let r =
        GroupMembershipRepository::revoke_member_unless_last_admin_conn(&mut bare, group, member)
            .await;
    assert!(
        matches!(&r, Err(DbError::InvalidData { reason }) if reason.contains("transaction")),
        "an autocommit connection is refused before the guard runs: {r:?}"
    );
    assert!(
        fixture::has_unrevoked_row(&pool, group, member).await,
        "nothing was revoked"
    );
    assert!(!reseal().await, "nothing was marked");
    drop(bare);

    // POSITIVE CONTROL: the same call on a transaction revokes and marks.
    let mut tx = pool.begin().await.expect("begin");
    let r = GroupMembershipRepository::revoke_member_unless_last_admin_conn(&mut tx, group, member)
        .await
        .expect("revoke on a transaction");
    tx.commit().await.expect("commit");
    assert_eq!(r, RevokeOutcome::Revoked);
    assert!(!fixture::has_unrevoked_row(&pool, group, member).await);
    assert!(reseal().await, "the re-key obligation is marked");
}
