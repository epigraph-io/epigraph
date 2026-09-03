//! `CommunityRepository` must keep the R7 projection live, not just replay it.
//!
//! # Why this file exists rather than an assertion added to `tenancy_coverage.rs`
//!
//! `tenancy_coverage.rs::every_community_projects_onto_a_group_and_its_members_onto_memberships`
//! seeds rows, **replays migration 068**, then asserts. It therefore tests the
//! migration's output and is structurally incapable of noticing that
//! `CommunityRepository::create` / `add_member` / `remove_member` do not
//! project — its own doc comment says exactly that. A green run there is not
//! evidence that these functions maintain the invariant.
//!
//! Every test here goes **through the repository**, which is the only way to
//! observe the drift.

mod viewer_fixture;

use epigraph_db::{CommunityRepository, MembershipOutcome};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

async fn seed_perspective(pool: &PgPool, agent: Option<Uuid>, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(name)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed perspective")
}

async fn live_membership(pool: &PgPool, group: Uuid, agent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("count live membership")
}

/// `create` must project the community onto a group in the same transaction.
///
/// This is load-bearing rather than tidy, though NOT for the reason an earlier
/// revision of this comment gave. It said 071's shim "**RAISES** if it is
/// absent"; it does not — the shim INSERTs the group on demand and falls
/// through to the owner's personal group when no live membership results. The
/// real reason is that the projection is a standing invariant no other test can
/// observe: `tenancy_coverage.rs::every_community_projects_onto_a_group_and_its_members_onto_memberships`
/// REPLAYS migration 068 before asserting, so it measures the migration, not
/// these functions. Without this test, `create` could stop projecting and
/// nothing in the tree would notice — the shim would paper over it at
/// ownership-write time with `created_by_agent_id` NULL, i.e. migration 068's
/// documented zero-administrator dead end.
#[sqlx::test(migrations = "../../migrations")]
async fn create_projects_the_community_onto_a_group(pool: PgPool) {
    let row = CommunityRepository::create(&pool, "physics", None, None, None, None)
        .await
        .expect("create community");

    let (id, kind, did_key): (Uuid, String, String) =
        sqlx::query_as("SELECT id, kind, did_key FROM groups WHERE id = $1")
            .bind(row.id)
            .fetch_one(&pool)
            .await
            .expect("the projected group must exist — 068's projection is a one-time snapshot");

    assert_eq!(
        id, row.id,
        "the projection is ID-PRESERVING, as migration 068 is"
    );
    assert_eq!(kind, "community");
    assert_eq!(did_key, format!("did:epigraph:community:{}", row.id));

    let epochs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM group_key_epochs WHERE group_id = $1")
            .bind(row.id)
            .fetch_one(&pool)
            .await
            .expect("count epochs");
    assert_eq!(epochs, 1, "068 gives every projected group an epoch-0 row");
}

/// A creator, when known, becomes the projected group's admin.
///
/// Migration 068: *"no member is projected as 'admin' … A projected community
/// group therefore has ZERO administrators until PR-12 gives it one — `POST
/// /groups/:id/members` cannot be used on it, and PR-18's '≥2 other live
/// admins' precondition is unsatisfiable by construction."*
#[sqlx::test(migrations = "../../migrations")]
async fn a_known_creator_becomes_the_projected_groups_admin(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "founder").await;

    let row = CommunityRepository::create(&pool, "chem", None, None, None, Some(agent))
        .await
        .expect("create community");

    let created_by: Option<Uuid> =
        sqlx::query_scalar("SELECT created_by_agent_id FROM groups WHERE id = $1")
            .bind(row.id)
            .fetch_one(&pool)
            .await
            .expect("read group");
    assert_eq!(created_by, Some(agent));

    let role: String = sqlx::query_scalar(
        "SELECT role FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(row.id)
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("the creator must have a live membership");
    assert_eq!(
        role, "admin",
        "without an admin the group is unadministrable and PR-18's privatization \
         precondition is unsatisfiable by construction"
    );
}

/// `add_member` must project onto `group_memberships`, as `role='reader'`.
///
/// `'reader'` and not `'writer'` for migration 068's stated reason:
/// `community_members` records that a perspective may READ, while
/// `Viewer::resolve` puts `admin|writer` into the WRITABLE set. Projecting
/// `'writer'` would hand every historical community member write authority over
/// the whole group's corpus.
#[sqlx::test(migrations = "../../migrations")]
async fn add_member_projects_a_reader_membership(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "member").await;
    let row = CommunityRepository::create(&pool, "bio", None, None, None, None)
        .await
        .expect("create community");
    let perspective = seed_perspective(&pool, Some(agent), "p").await;

    CommunityRepository::add_member(&pool, Some(agent), row.id, perspective)
        .await
        .expect("add member");

    let role: String = sqlx::query_scalar(
        "SELECT role FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(row.id)
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("the projected membership must exist");
    assert_eq!(role, "reader");
}

/// A perspective with no owning agent projects nothing — there is no agent to
/// grant to. Migration 068 has the same `IS NOT NULL` filter for the same
/// reason, and `perspectives.owner_agent_id` really is nullable.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agentless_perspective_projects_no_membership(pool: PgPool) {
    let row = CommunityRepository::create(&pool, "geo", None, None, None, None)
        .await
        .expect("create community");
    let orphan = seed_perspective(&pool, None, "p-no-agent").await;

    CommunityRepository::add_member(&pool, None, row.id, orphan)
        .await
        .expect("add member must not fail on an agentless perspective");

    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM group_memberships WHERE group_id = $1")
        .bind(row.id)
        .fetch_one(&pool)
        .await
        .expect("count memberships");
    assert_eq!(n, 0);
}

/// **The grant-direction drift.** `remove_member` must revoke the projected
/// membership.
///
/// Before PR-12 it deleted the `community_members` row and left the projected
/// `group_memberships` row LIVE, so a removed member kept its projected group
/// membership and — once PR-17 arms the predicate — kept read access to that
/// group's private corpus. Neither the plan nor `progress.json` lists this half
/// of the drift; both name only `create` and `add_member`.
#[sqlx::test(migrations = "../../migrations")]
async fn remove_member_revokes_the_projected_membership(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "member").await;
    let row = CommunityRepository::create(&pool, "astro", None, None, None, None)
        .await
        .expect("create community");
    let perspective = seed_perspective(&pool, Some(agent), "p").await;

    CommunityRepository::add_member(&pool, Some(agent), row.id, perspective)
        .await
        .expect("add member");
    assert_eq!(
        live_membership(&pool, row.id, agent).await,
        1,
        "precondition: the member is projected"
    );

    let removed = CommunityRepository::remove_member(&pool, Some(agent), row.id, perspective)
        .await
        .expect("remove member");
    assert_eq!(removed, MembershipOutcome::Applied);

    assert_eq!(
        live_membership(&pool, row.id, agent).await,
        0,
        "a removal that leaves the projected membership live is a revocation that \
         does not revoke — the removed agent keeps reading the group's corpus at PR-17"
    );

    // Revoked, not deleted: `group_memberships` is an auditable ledger and
    // `Viewer::resolve` filters on `revoked_at IS NULL`.
    let still_there: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NOT NULL",
    )
    .bind(row.id)
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("count revoked");
    assert_eq!(
        still_there, 1,
        "revocation must stamp revoked_at, not DELETE the row"
    );
}

/// Removing ONE of an agent's two perspectives must NOT cut its access.
///
/// Two perspectives owned by one agent both project onto the single
/// `(group, agent, epoch)` membership row, so an unconditional revoke would
/// remove access the remaining perspective still justifies. This is the
/// over-revocation the guarded `NOT EXISTS` in `remove_member` prevents, and it
/// is the failure mode a naive fix for the previous test would introduce.
#[sqlx::test(migrations = "../../migrations")]
async fn removing_one_of_two_perspectives_keeps_the_membership(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "member").await;
    let row = CommunityRepository::create(&pool, "maths", None, None, None, None)
        .await
        .expect("create community");
    let p1 = seed_perspective(&pool, Some(agent), "p1").await;
    let p2 = seed_perspective(&pool, Some(agent), "p2").await;

    CommunityRepository::add_member(&pool, Some(agent), row.id, p1)
        .await
        .expect("add p1");
    CommunityRepository::add_member(&pool, Some(agent), row.id, p2)
        .await
        .expect("add p2");

    CommunityRepository::remove_member(&pool, Some(agent), row.id, p1)
        .await
        .expect("remove p1");

    assert_eq!(
        live_membership(&pool, row.id, agent).await,
        1,
        "the agent is still in the community through p2; revoking here would cut \
         access its remaining perspective still justifies"
    );

    CommunityRepository::remove_member(&pool, Some(agent), row.id, p2)
        .await
        .expect("remove p2");

    assert_eq!(
        live_membership(&pool, row.id, agent).await,
        0,
        "once the LAST justifying perspective is gone, the membership must be revoked"
    );
}

/// A community created through the repository can be used by migration 071's
/// shim — the end-to-end reason `create` projecting matters.
///
/// The community is created WITH a creator, so its projected group has a live
/// admin. That is load-bearing: the shim refuses to stamp a community group
/// with no live members (it would be a row nobody could read) and falls back to
/// the owner's personal group instead. A community created with `None` here
/// would therefore exercise the fallback, not the projection — see
/// `tenancy_triggers.rs::an_empty_community_falls_back_to_the_owner_rather_than_a_black_hole`
/// for that path.
#[sqlx::test(migrations = "../../migrations")]
async fn a_repository_created_community_can_be_transcribed_by_the_shim(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "owner").await;
    let row = CommunityRepository::create(&pool, "shimmable", None, None, None, Some(agent))
        .await
        .expect("create community");

    let claim = fixture::seed_public_claim(&pool, agent, "to be community-owned").await;

    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, community_id) \
         VALUES ($1, 'claim', 'community', $2, $3)",
    )
    .bind(claim)
    .bind(agent)
    .bind(row.id)
    .execute(&pool)
    .await
    .expect(
        "the shim must resolve the community's projected group; before PR-12's \
         create() fix this raised 23503 because no group row existed",
    );

    let (owner, vis): (Uuid, String) =
        sqlx::query_as("SELECT owner_group_id, visibility::text FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read claim");
    assert_eq!((owner, vis.as_str()), (row.id, "group"));
}

// =============================================================================
// Closed membership — the authorization PR-12 owes because PR-12 is what makes
// the projected membership load-bearing.
// =============================================================================

/// A stranger cannot let itself into a community that already has members.
///
/// # Why this is PR-12's problem and not PR-14's
///
/// `POST /api/v1/communities/:id/members` performs no authorization
/// (`F-PR11-community-membership-is-self-service`, deferred by PR-11 to "the PR
/// that owns community authorization"). Until PR-12 the consequence lived only
/// in `access_control.rs::check_content_access`'s community arm — a table PR-14
/// deletes. PR-12 moves it into the control plane that SURVIVES PR-14: the
/// membership becomes a live `group_memberships` row, and `Viewer::resolve`
/// pushes every live membership into `group_ids` regardless of role. So without
/// this gate, a stranger creates a perspective, POSTs it into any community,
/// and reads that community's private corpus once PR-17 arms the predicate.
///
/// Gating only the PROJECTION would not have worked: migration 071's shim
/// replays the projection out of `community_members` on every
/// community-partitioned ownership write, so the `community_members` row itself
/// is the grant.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_cannot_add_itself_to_a_community_that_has_members(pool: PgPool) {
    let (insider, _) = fixture::seed_agent_with_group(&pool, "insider").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let row = CommunityRepository::create(&pool, "closed", None, None, None, Some(insider))
        .await
        .expect("create community");

    let their_own = seed_perspective(&pool, Some(stranger), "mine").await;
    let outcome = CommunityRepository::add_member(&pool, Some(stranger), row.id, their_own)
        .await
        .expect("add_member must not error, it must DENY");

    assert_eq!(
        outcome,
        MembershipOutcome::DeniedNotAMember,
        "an agent with no live membership in the community's projected group must \
         not be able to grant itself one — that is read authority over the whole \
         group's corpus at PR-17"
    );
    assert_eq!(
        live_membership(&pool, row.id, stranger).await,
        0,
        "and nothing may be written: the community_members row IS the grant, \
         because 071's shim replays the projection from it"
    );
    let joined: i64 =
        sqlx::query_scalar("SELECT count(*) FROM community_members WHERE community_id = $1")
            .bind(row.id)
            .fetch_one(&pool)
            .await
            .expect("count community_members");
    assert_eq!(joined, 0);
}

/// An existing member CAN add another — the rule is "closed", not "frozen".
///
/// This is the half that makes the gate a rule rather than a wall, and it is
/// deliberately weaker than "only an admin may add members": migration 068
/// left every projected community group with **zero administrators** by
/// design, so requiring an admin would make community membership permanently
/// unmanageable for every pre-existing community.
#[sqlx::test(migrations = "../../migrations")]
async fn a_live_member_can_add_another(pool: PgPool) {
    let (insider, _) = fixture::seed_agent_with_group(&pool, "insider").await;
    let (newcomer, _) = fixture::seed_agent_with_group(&pool, "newcomer").await;
    let row = CommunityRepository::create(&pool, "open-ish", None, None, None, Some(insider))
        .await
        .expect("create community");

    let theirs = seed_perspective(&pool, Some(newcomer), "theirs").await;
    let outcome = CommunityRepository::add_member(&pool, Some(insider), row.id, theirs)
        .await
        .expect("add member");

    assert_eq!(outcome, MembershipOutcome::Applied);
    assert_eq!(live_membership(&pool, row.id, newcomer).await, 1);
}

/// A community whose projected group has no live members is OPEN — the
/// bootstrap case.
///
/// Migration 068 projected communities with `created_by_agent_id` NULL and no
/// admin membership. Refusing the first `add_member` on those would leave every
/// pre-existing community unmanageable forever, with no in-band way out. The
/// bootstrap branch is therefore deliberate, and it is exactly why
/// `create_community` now passes the authenticated creator: a community created
/// through the route is never in this state.
#[sqlx::test(migrations = "../../migrations")]
async fn a_memberless_community_group_is_open_for_bootstrap(pool: PgPool) {
    let (anyone, _) = fixture::seed_agent_with_group(&pool, "anyone").await;
    let row = CommunityRepository::create(&pool, "orphaned", None, None, None, None)
        .await
        .expect("create community with no creator, exactly as migration 068 left them");

    let theirs = seed_perspective(&pool, Some(anyone), "theirs").await;
    let outcome = CommunityRepository::add_member(&pool, Some(anyone), row.id, theirs)
        .await
        .expect("add member");

    assert_eq!(
        outcome,
        MembershipOutcome::Applied,
        "a group with no live members has nobody who could ever authorize the \
         first join; refusing would be a permanent dead end, not a control"
    );
}

/// A stranger cannot EVICT a member — the integrity twin of the grant.
///
/// `remove_member` now stamps `revoked_at`, so an unauthenticated eviction is a
/// denial of read against a legitimate member rather than the bookkeeping no-op
/// it used to be. The DELETE route previously extracted nothing at all.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_cannot_evict_a_member(pool: PgPool) {
    let (insider, _) = fixture::seed_agent_with_group(&pool, "insider").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let row = CommunityRepository::create(&pool, "besieged", None, None, None, Some(insider))
        .await
        .expect("create community");
    let theirs = seed_perspective(&pool, Some(insider), "theirs").await;
    CommunityRepository::add_member(&pool, Some(insider), row.id, theirs)
        .await
        .expect("add member");

    let outcome = CommunityRepository::remove_member(&pool, Some(stranger), row.id, theirs)
        .await
        .expect("remove_member must DENY, not error");
    assert_eq!(outcome, MembershipOutcome::DeniedNotAMember);
    assert_eq!(
        live_membership(&pool, row.id, insider).await,
        1,
        "the member must still be live: a self-service eviction is a denial of \
         read once the revocation is real"
    );
}

/// An agent may always remove its OWN perspective.
///
/// Without this carve-out an agent whose only membership is the one being
/// removed could be evicted by a peer but could not leave voluntarily, which is
/// the wrong asymmetry for a "closed membership" rule.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_may_always_remove_its_own_perspective(pool: PgPool) {
    let (founder, _) = fixture::seed_agent_with_group(&pool, "founder").await;
    let (leaver, _) = fixture::seed_agent_with_group(&pool, "leaver").await;
    let row = CommunityRepository::create(&pool, "revolving", None, None, None, Some(founder))
        .await
        .expect("create community");
    let mine = seed_perspective(&pool, Some(leaver), "mine").await;
    CommunityRepository::add_member(&pool, Some(founder), row.id, mine)
        .await
        .expect("add member");

    let outcome = CommunityRepository::remove_member(&pool, Some(leaver), row.id, mine)
        .await
        .expect("remove member");
    assert_eq!(outcome, MembershipOutcome::Applied);
    assert_eq!(live_membership(&pool, row.id, leaver).await, 0);
}
