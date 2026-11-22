//! The membership READERS decide on LIVE membership (backlog f712db53,
//! 93ed2ec3, 556c5416).
//!
//! Migration 165 made a registered human holding a role bound to a group a
//! live member of it, COMPUTED by `epigraph_live_memberships` and never
//! written as a `group_memberships` row. Migrations 164 and 235 made some
//! direct rows LAPSE without being revoked: a row in a verb-made team group
//! (`did:epigraph:group:`) counts only while its human is a live human
//! operator, and a personal-group row of an allowlisted agent only while its
//! allowance names the group's owner. `Viewer::resolve` already reads that
//! definer, so claim reads and writes follow both rules.
//!
//! The readers pinned here read the raw roster instead (`revoked_at IS
//! NULL`), so each one refused a role-derived member and admitted a lapsed
//! one:
//!
//! * `GroupMembershipRepository::is_member` / `is_member_conn`, the gate of
//!   `GET /api/v1/groups/:id` and of the group-scoped claim routes;
//! * `get_member_role` / `get_member_role_conn`, behind
//!   `require_group_admin_conn` (every REST group admin route);
//! * `get_members_conn`, the roster `GET /api/v1/groups/:id` counts;
//! * the consolidate act's "member of every private source's owner group";
//! * the profile detail check ("shares a live group with it") of
//!   `AgentRepository::get_public_profile`.
//!
//! Each test sets up one role-derived member and one lapsed member and asks
//! the reader about both, beside a positive control on a plain direct member.
//! Fixtures go through the real maintenance verbs (`viewer_fixture.rs`).
//!
//! The last test pins that `revoke_member_unless_last_admin_conn` refuses an
//! autocommit connection, on which its roster lock would not be held.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{
    AgentRepository, ClaimRepository, ConsolidateMode, DbError, GroupMembershipRepository,
    GroupRepository, RevokeOutcome, Viewer,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// A synthetic, non-elevating role key.
const ROLE: &str = "role:live-reader-test";

/// One verb-made team group with three kinds of member:
///
/// * `owner`, its admin, a registered human (a plain direct member);
/// * `derived`, a registered human with NO row, a member only through a
///   live assignment of [`ROLE`], which is bound to the group at `writer`;
/// * `lapsed`, a human with an unrevoked `writer` row whose registration has
///   since been revoked, so the row no longer counts.
struct Team {
    group: Uuid,
    owner: Uuid,
    derived: Uuid,
    lapsed: Uuid,
}

async fn team(pool: &PgPool, name: &str) -> Team {
    let (owner, _) = fixture::seed_human_operator(pool, &format!("{name}-owner")).await;
    let (derived, _) = fixture::seed_human_operator(pool, &format!("{name}-derived")).await;
    let (lapsed, _) = fixture::seed_human_operator(pool, &format!("{name}-lapsed")).await;
    let group = fixture::verb_team_group(pool, &format!("Synthetic {name} Team"), owner).await;
    fixture::verb_team_group_add(pool, group, lapsed, "writer").await;
    fixture::bind_new_role_to_group(pool, ROLE, group, "writer", false).await;
    fixture::grant_role_now(pool, ROLE, derived).await;
    fixture::revoke_human_operator(pool, lapsed).await;

    // PREMISES, read straight off the definer and the raw roster, so a
    // failure below is the reader's and not the fixture's.
    let live = |agent: Uuid| async move {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM public.epigraph_live_memberships($1) WHERE group_id = $2",
        )
        .bind(agent)
        .bind(group)
        .fetch_one(pool)
        .await
        .expect("live memberships");
        n > 0
    };
    assert!(live(owner).await, "PREMISE: the owner is a live member");
    assert!(
        live(derived).await,
        "PREMISE: the role holder is a live member"
    );
    assert!(
        !live(lapsed).await,
        "PREMISE: the lapsed member is not live"
    );
    assert!(
        !fixture::has_unrevoked_row(pool, group, derived).await,
        "PREMISE: the derived member holds no row"
    );
    assert!(
        fixture::has_unrevoked_row(pool, group, lapsed).await,
        "PREMISE: the lapsed member's row is still unrevoked"
    );
    Team {
        group,
        owner,
        derived,
        lapsed,
    }
}

// =====================================================================
// is_member / get_member_role / get_members_conn
// =====================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn is_member_admits_a_derived_member_and_refuses_a_lapsed_one(pool: PgPool) {
    let t = team(&pool, "is-member").await;
    let mut conn = pool.acquire().await.expect("acquire");
    for (agent, want, who) in [
        (t.owner, true, "POSITIVE CONTROL: the direct admin"),
        (t.derived, true, "the role-derived member"),
        (t.lapsed, false, "the lapsed member"),
    ] {
        assert_eq!(
            GroupMembershipRepository::is_member(&pool, t.group, agent)
                .await
                .expect("is_member"),
            want,
            "is_member: {who}"
        );
        assert_eq!(
            GroupMembershipRepository::is_member_conn(&mut conn, t.group, agent)
                .await
                .expect("is_member_conn"),
            want,
            "is_member_conn: {who}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_member_role_answers_the_live_role(pool: PgPool) {
    let t = team(&pool, "member-role").await;
    // A human with a direct READER row who also holds the role bound at
    // WRITER: both arms answer, and the stronger one is the member's role.
    let (both, _) = fixture::seed_human_operator(&pool, "member-role-both").await;
    fixture::verb_team_group_add(&pool, t.group, both, "reader").await;
    fixture::grant_role_now(&pool, ROLE, both).await;

    // The lapsed member is made an ADMIN before its registration goes, so
    // the row that lapses is exactly the one `require_group_admin_conn` reads.
    let (lapsed_admin, _) = fixture::seed_human_operator(&pool, "member-role-ladmin").await;
    fixture::verb_team_group_add(&pool, t.group, lapsed_admin, "admin").await;
    fixture::revoke_human_operator(&pool, lapsed_admin).await;
    assert!(fixture::has_unrevoked_row(&pool, t.group, lapsed_admin).await);

    let mut conn = pool.acquire().await.expect("acquire");
    for (agent, want, who) in [
        (t.owner, Some("admin"), "POSITIVE CONTROL: the direct admin"),
        (t.derived, Some("writer"), "the role-derived member"),
        (
            both,
            Some("writer"),
            "a direct reader holding the writer role",
        ),
        (t.lapsed, None, "the lapsed writer"),
        (lapsed_admin, None, "the lapsed ADMIN"),
    ] {
        let pooled = GroupMembershipRepository::get_member_role(&pool, t.group, agent)
            .await
            .expect("get_member_role");
        let on_conn = GroupMembershipRepository::get_member_role_conn(&mut conn, t.group, agent)
            .await
            .expect("get_member_role_conn");
        assert_eq!(pooled.as_deref(), want, "get_member_role: {who}");
        assert_eq!(on_conn.as_deref(), want, "get_member_role_conn: {who}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_roster_omits_a_lapsed_row(pool: PgPool) {
    let t = team(&pool, "roster").await;
    let mut conn = pool.acquire().await.expect("acquire");
    let members: Vec<Uuid> = GroupMembershipRepository::get_members_conn(&mut conn, t.group)
        .await
        .expect("get_members_conn")
        .into_iter()
        .map(|m| m.agent_id)
        .collect();
    assert_eq!(
        members,
        vec![t.owner],
        "the explicit roster is the live direct rows: the owner (POSITIVE CONTROL), \
         not the lapsed row; a derived member holds no row to list"
    );
    let pooled: Vec<Uuid> = GroupMembershipRepository::get_members(&pool, t.group)
        .await
        .expect("get_members")
        .into_iter()
        .map(|m| m.agent_id)
        .collect();
    assert_eq!(pooled, members, "the pool form agrees");
}

// =====================================================================
// The consolidate act
// =====================================================================

async fn consolidate(pool: &PgPool, sources: &[Uuid], actor: Uuid) -> Result<Uuid, DbError> {
    ClaimRepository::consolidate(
        pool,
        sources,
        &format!("live-member merge by {actor}"),
        0.8,
        ConsolidateMode::Merge,
        "live membership reader test",
        actor,
    )
    .await
    .map(|r| r.merged_id)
}

fn is_not_a_member_refusal(r: &Result<Uuid, DbError>) -> bool {
    matches!(r, Err(DbError::Conflict { reason }) if reason.contains("not a member"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_admits_a_derived_member_and_refuses_a_lapsed_one(pool: PgPool) {
    let t = team(&pool, "consolidate").await;
    let d1 = fixture::seed_group_claim(&pool, t.owner, t.group, "derived source one").await;
    let d2 = fixture::seed_group_claim(&pool, t.owner, t.group, "derived source two").await;
    let l1 = fixture::seed_group_claim(&pool, t.owner, t.group, "lapsed source one").await;
    let l2 = fixture::seed_group_claim(&pool, t.owner, t.group, "lapsed source two").await;

    let lapsed = consolidate(&pool, &[l1, l2], t.lapsed).await;
    assert!(
        is_not_a_member_refusal(&lapsed),
        "a lapsed member is refused as a non-member: {lapsed:?}"
    );
    let current: Vec<bool> =
        sqlx::query_scalar("SELECT is_current FROM claims WHERE id = ANY($1) ORDER BY id")
            .bind(vec![l1, l2])
            .fetch_all(&pool)
            .await
            .expect("read the lapsed member's sources");
    assert_eq!(current, vec![true, true], "nothing was retired");

    let derived = consolidate(&pool, &[d1, d2], t.derived).await;
    assert!(
        derived.is_ok(),
        "a role-derived member consolidates its group's claims: {derived:?}"
    );
    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(derived.unwrap())
        .fetch_one(&pool)
        .await
        .expect("read the merged claim");
    assert_eq!(owner, t.group, "the merge lands in the group's corpus");
}

// =====================================================================
// The profile detail check
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

#[sqlx::test(migrations = "../../migrations")]
async fn a_profile_shows_details_to_a_live_groupmate_only(pool: PgPool) {
    let t = team(&pool, "profile").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "profile-stranger").await;
    let (direct, _) = fixture::seed_human_operator(&pool, "profile-direct").await;
    fixture::verb_team_group_add(&pool, t.group, direct, "reader").await;
    let mut orcids = std::collections::HashMap::new();
    for a in [t.derived, t.lapsed, direct, stranger] {
        orcids.insert(a, group_only_profile(&pool, a).await);
    }
    // The viewer is the group's admin; it shares the group with every member.
    let viewer = Viewer::resolve(&pool, t.owner).await.expect("resolve");
    assert!(
        viewer.group_bind().is_some_and(|g| g.contains(&t.group)),
        "PREMISE: the viewer reads the group"
    );

    for (agent, want, who) in [
        (direct, true, "POSITIVE CONTROL: a direct live member"),
        (t.derived, true, "a role-derived member"),
        (t.lapsed, false, "a lapsed member"),
        (stranger, false, "NEGATIVE CONTROL: a stranger"),
    ] {
        let profile = AgentRepository::get_public_profile(&pool, &viewer, agent)
            .await
            .expect("get_public_profile")
            .expect("the agent exists");
        assert_eq!(
            profile.properties.is_some(),
            want,
            "get_public_profile properties: {who}"
        );
        assert_eq!(
            profile.orcid.as_deref(),
            want.then_some(orcids[&agent].as_str()),
            "get_public_profile orcid: {who}"
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
