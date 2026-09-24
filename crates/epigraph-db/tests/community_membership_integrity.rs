//! F4 (`afb1cfaf`, `7cdea6f1`): community membership integrity, measured as the
//! deployed role.
//!
//! Every membership change under test runs on a pool whose connections are
//! `SET SESSION AUTHORIZATION epigraph_app` (non-bypassing) and then stamped
//! with the ACTING agent's tenancy context — the same three `set_config` calls
//! `ScopedPool::begin_as` makes — so the call sees exactly what the API route's
//! viewer-stamped transaction sees. Fixtures (creating the community, seeding
//! other members) run on the superuser pool; state is read back there too.
//!
//! Each arm is written against `CommunityRepository::{add_member,
//! remove_member}` called with a `&PgPool`, a shape both the pre- and the
//! post-batch-F signatures accept, so the same file measures both.
//!
//! # Verified to fail
//!
//! With `community.rs` and migration 106 reverted to the pre-batch-F tree, every
//! arm below FAILS; the recorded output is in the commit message.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{CommunityRepository, MembershipOutcome, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

/// A pool that acts as `actor`: `epigraph_app`, stamped with `actor`'s viewer.
async fn as_actor(pool: &PgPool, actor: Uuid) -> PgPool {
    use sqlx::Executor;
    let v = Viewer::resolve(pool, actor).await.expect("resolve actor");
    let join = |ids: Option<&[Uuid]>| {
        ids.unwrap_or(&[])
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let groups = join(v.group_bind());
    let writable = join(v.writable_bind());
    let url = fixture::database_url_for(pool).await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _meta| {
            let (groups, writable) = (groups.clone(), writable.clone());
            Box::pin(async move {
                conn.execute("SET SESSION AUTHORIZATION epigraph_app")
                    .await?;
                sqlx::query(
                    "SELECT set_config('epigraph.group_ids', $1, false), \
                            set_config('epigraph.writable_group_ids', $2, false), \
                            set_config('epigraph.principal_id', $3, false)",
                )
                .bind(groups)
                .bind(writable)
                .bind(actor.to_string())
                .execute(&mut *conn)
                .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("actor pool")
}

async fn agent(pool: &PgPool, label: &str) -> Uuid {
    fixture::seed_agent_with_group(pool, label).await.0
}

async fn perspective(pool: &PgPool, owner: Uuid, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(name)
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("seed perspective")
}

/// `role(live|revoked)` of `agent` in `group`, or "none".
async fn state(pool: &PgPool, group: Uuid, agent: Uuid) -> String {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT string_agg(role || CASE WHEN revoked_at IS NULL THEN '(live)' ELSE '(revoked)' END, ',') \
           FROM group_memberships WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(group)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("membership state")
    .unwrap_or_else(|| "none".to_string())
}

async fn listed(pool: &PgPool, community: Uuid, perspective: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM community_members \
                         WHERE community_id = $1 AND perspective_id = $2)",
    )
    .bind(community)
    .bind(perspective)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// A community created by `admin` (live admin), with `admin`'s own perspective
/// listed. Returns `(community, admin_perspective)`.
async fn community_with_admin(pool: &PgPool, admin: Uuid, name: &str) -> (Uuid, Uuid) {
    let c = CommunityRepository::create(pool, name, None, None, None, Some(admin))
        .await
        .expect("create community")
        .id;
    let p = perspective(pool, admin, &format!("{name}-admin")).await;
    let out = CommunityRepository::add_member(pool, Some(admin), c, p)
        .await
        .expect("admin lists its own perspective");
    assert_eq!(out, MembershipOutcome::Applied);
    (c, p)
}

/// F4a: a READER holding the scope cannot evict the admin.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_cannot_evict_the_admin(pool: PgPool) {
    let admin = agent(&pool, "f4-admin").await;
    let reader = agent(&pool, "f4-reader").await;
    let (c, admin_p) = community_with_admin(&pool, admin, "f4-evict").await;
    let reader_p = perspective(&pool, reader, "f4-reader-p").await;
    CommunityRepository::add_member(&pool, Some(admin), c, reader_p)
        .await
        .expect("admin adds the reader");
    assert_eq!(state(&pool, c, reader).await, "reader(live)");

    let as_reader = as_actor(&pool, reader).await;
    let out = CommunityRepository::remove_member(&as_reader, Some(reader), c, admin_p)
        .await
        .expect("a refusal is an outcome, not an error");
    assert_eq!(out, MembershipOutcome::DeniedNotAMember);
    assert_eq!(
        state(&pool, c, admin).await,
        "admin(live)",
        "the admin must survive"
    );
    assert!(listed(&pool, c, admin_p).await, "and so must its listing");
}

/// F4a: the last live admin cannot be removed — not even by itself.
#[sqlx::test(migrations = "../../migrations")]
async fn the_last_admin_cannot_be_removed(pool: PgPool) {
    let admin = agent(&pool, "f4-last").await;
    let (c, admin_p) = community_with_admin(&pool, admin, "f4-last").await;

    let as_admin = as_actor(&pool, admin).await;
    let out = CommunityRepository::remove_member(&as_admin, Some(admin), c, admin_p)
        .await
        .expect("a refusal is an outcome, not an error");
    assert_eq!(out, MembershipOutcome::LastAdmin);
    assert_eq!(state(&pool, c, admin).await, "admin(live)");
    assert!(
        listed(&pool, c, admin_p).await,
        "nothing may be written on the refusal"
    );
}

/// F4a: a revoked ADMIN re-added through `add_member` comes back as a READER.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_admin_readded_stays_a_reader(pool: PgPool) {
    let admin = agent(&pool, "f4-keeper").await;
    let other = agent(&pool, "f4-other-admin").await;
    let (c, _) = community_with_admin(&pool, admin, "f4-readd").await;
    let other_p = perspective(&pool, other, "f4-other-p").await;
    CommunityRepository::add_member(&pool, Some(admin), c, other_p)
        .await
        .expect("add the second agent");
    sqlx::query(
        "UPDATE group_memberships SET role = 'admin' WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(c)
    .bind(other)
    .execute(&pool)
    .await
    .unwrap();
    // The keeper evicts the second admin (not the last, so allowed) ...
    let out = CommunityRepository::remove_member(&pool, Some(admin), c, other_p)
        .await
        .expect("evict");
    assert_eq!(out, MembershipOutcome::Applied);
    assert_eq!(state(&pool, c, other).await, "admin(revoked)");

    // ... and re-adds it, as the deployed role. `add_member` requests `reader`.
    let as_admin = as_actor(&pool, admin).await;
    let out = CommunityRepository::add_member(&as_admin, Some(admin), c, other_p)
        .await
        .expect("re-add");
    assert_eq!(out, MembershipOutcome::Applied);
    assert_eq!(
        state(&pool, c, other).await,
        "reader(live)",
        "a revoked admin must not come back as admin"
    );
}

/// F4b: a community whose members were all removed does NOT re-open to the
/// first stranger — only a group that has never had a membership row does.
#[sqlx::test(migrations = "../../migrations")]
async fn an_emptied_group_does_not_rebootstrap(pool: PgPool) {
    let first = agent(&pool, "f4-first").await;
    let stranger = agent(&pool, "f4-stranger").await;
    // No creator: memberless, exactly as migration 068 left projected groups.
    let c = CommunityRepository::create(&pool, "f4-emptied", None, None, None, None)
        .await
        .expect("create")
        .id;
    let first_p = perspective(&pool, first, "f4-first-p").await;
    let out =
        CommunityRepository::add_member(&as_actor(&pool, first).await, Some(first), c, first_p)
            .await
            .expect("bootstrap");
    assert_eq!(
        out,
        MembershipOutcome::Applied,
        "a never-populated group bootstraps"
    );
    let out = CommunityRepository::remove_member(&pool, Some(first), c, first_p)
        .await
        .expect("the only member leaves");
    assert_eq!(out, MembershipOutcome::Applied);
    assert_eq!(state(&pool, c, first).await, "reader(revoked)");

    let stranger_p = perspective(&pool, stranger, "f4-stranger-p").await;
    let out = CommunityRepository::add_member(
        &as_actor(&pool, stranger).await,
        Some(stranger),
        c,
        stranger_p,
    )
    .await
    .expect("a refusal is an outcome, not an error");
    assert_eq!(out, MembershipOutcome::DeniedNotAMember);
    assert_eq!(state(&pool, c, stranger).await, "none");
    assert!(!listed(&pool, c, stranger_p).await);
}

/// F4b: two concurrent FIRST joiners of a never-populated group — exactly one
/// bootstraps, the other is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_first_joiners_admit_exactly_one(pool: PgPool) {
    let a = agent(&pool, "f4-race-a").await;
    let b = agent(&pool, "f4-race-b").await;
    let c = CommunityRepository::create(&pool, "f4-race", None, None, None, None)
        .await
        .expect("create")
        .id;
    let pa = perspective(&pool, a, "f4-race-a-p").await;
    let pb = perspective(&pool, b, "f4-race-b-p").await;
    let (as_a, as_b) = (as_actor(&pool, a).await, as_actor(&pool, b).await);

    let (ra, rb) = tokio::join!(
        CommunityRepository::add_member(&as_a, Some(a), c, pa),
        CommunityRepository::add_member(&as_b, Some(b), c, pb),
    );
    let mut outcomes = vec![ra.expect("a"), rb.expect("b")];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(
        outcomes,
        vec![
            MembershipOutcome::Applied,
            MembershipOutcome::DeniedNotAMember
        ],
        "exactly one first joiner may bootstrap"
    );
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships WHERE group_id = $1 AND revoked_at IS NULL",
    )
    .bind(c)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(live, 1);
}

/// A member may still LEAVE (its own perspective), as the deployed role: the
/// carve-out the group-membership WITH CHECK alone could not express.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_may_leave(pool: PgPool) {
    let admin = agent(&pool, "f4-host").await;
    let reader = agent(&pool, "f4-leaver").await;
    let (c, _) = community_with_admin(&pool, admin, "f4-leave").await;
    let reader_p = perspective(&pool, reader, "f4-leaver-p").await;
    CommunityRepository::add_member(&pool, Some(admin), c, reader_p)
        .await
        .expect("add");

    let out = CommunityRepository::remove_member(
        &as_actor(&pool, reader).await,
        Some(reader),
        c,
        reader_p,
    )
    .await
    .expect("leave");
    assert_eq!(out, MembershipOutcome::Applied);
    assert_eq!(state(&pool, c, reader).await, "reader(revoked)");
    assert!(!listed(&pool, c, reader_p).await);
}

/// An app session cannot act as somebody else: `acting_agent` must be the
/// stamped principal, or the call is denied.
#[sqlx::test(migrations = "../../migrations")]
async fn an_app_session_cannot_name_another_actor(pool: PgPool) {
    let admin = agent(&pool, "f4-real-admin").await;
    let impostor = agent(&pool, "f4-impostor").await;
    let (c, admin_p) = community_with_admin(&pool, admin, "f4-impostor").await;

    let as_impostor = as_actor(&pool, impostor).await;
    let out = CommunityRepository::remove_member(&as_impostor, Some(admin), c, admin_p)
        .await
        .expect("a refusal is an outcome, not an error");
    assert_eq!(out, MembershipOutcome::DeniedNotAMember);
    assert_eq!(state(&pool, c, admin).await, "admin(live)");
}

/// A community with a live admin and a live reader. Returns
/// `(community, admin, admin_perspective, reader)`.
async fn community_with_reader(pool: &PgPool, name: &str) -> (Uuid, Uuid, Uuid, Uuid) {
    let admin = agent(pool, &format!("{name}-admin")).await;
    let reader = agent(pool, &format!("{name}-reader")).await;
    let (c, admin_p) = community_with_admin(pool, admin, name).await;
    let reader_p = perspective(pool, reader, &format!("{name}-reader-p")).await;
    CommunityRepository::add_member(pool, Some(admin), c, reader_p)
        .await
        .expect("admin adds the reader");
    assert_eq!(state(pool, c, reader).await, "reader(live)");
    (c, admin, admin_p, reader)
}

/// An admin's eviction lasts (review finding, MEDIUM). A live READER lists a
/// perspective whose `owner_agent_id` is the evictee. Both perspective-create
/// paths accept a caller-supplied owner, and `perspectives_tenancy` does not
/// constrain it. The restore must be refused, with nothing written, because
/// re-admitting a removed member is an admin decision.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_cannot_readmit_an_evicted_member(pool: PgPool) {
    let (c, admin, _, reader) = community_with_reader(&pool, "f4-readmit").await;
    let evictee = agent(&pool, "f4-evictee").await;
    let evictee_p = perspective(&pool, evictee, "f4-evictee-p").await;
    CommunityRepository::add_member(&pool, Some(admin), c, evictee_p)
        .await
        .expect("add the evictee");
    let out = CommunityRepository::remove_member(
        &as_actor(&pool, admin).await,
        Some(admin),
        c,
        evictee_p,
    )
    .await
    .expect("evict");
    assert_eq!(out, MembershipOutcome::Applied);
    assert_eq!(state(&pool, c, evictee).await, "reader(revoked)");

    // The reader, as the deployed role, forges a perspective owned by the
    // evictee (the registry policy admits it) and lists it.
    let as_reader = as_actor(&pool, reader).await;
    let forged: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id, visibility, owner_group_id) \
         VALUES ('f4-forged', $1, 'public', '00000000-0000-0000-0000-000000000000') \
         RETURNING id",
    )
    .bind(evictee)
    .fetch_one(&as_reader)
    .await
    .expect("the registry policy admits a perspective with any owner");
    let out = CommunityRepository::add_member(&as_reader, Some(reader), c, forged)
        .await
        .expect("a refusal is an outcome, not an error");
    assert_eq!(out, MembershipOutcome::DeniedReadmitNeedsAdmin);
    assert_eq!(
        state(&pool, c, evictee).await,
        "reader(revoked)",
        "the eviction must stand"
    );
    assert!(!listed(&pool, c, forged).await, "nothing may be written");

    // An ADMIN may re-admit, at reader.
    let out = CommunityRepository::add_member(
        &as_actor(&pool, admin).await,
        Some(admin),
        c,
        evictee_p,
    )
    .await
    .expect("re-admit");
    assert_eq!(out, MembershipOutcome::Applied);
    assert_eq!(state(&pool, c, evictee).await, "reader(live)");
}

/// The membership ledger is not deletable by the deployed role (review
/// finding, MEDIUM). Before migration 106 revoked DELETE from `epigraph_app`, a
/// READER stamped with the community in its group set could delete the
/// ADMIN's row, which bypassed "a reader cannot evict" and the last-admin
/// guard. The sole member could also delete every row, after which a stranger
/// bootstrapped the "emptied" group.
#[sqlx::test(migrations = "../../migrations")]
async fn the_deployed_role_cannot_delete_membership_rows(pool: PgPool) {
    let (c, admin, _, reader) = community_with_reader(&pool, "f4-ledger").await;

    let code = |r: Result<sqlx::postgres::PgQueryResult, sqlx::Error>| {
        r.err()
            .and_then(|e| e.as_database_error().and_then(|d| d.code().map(|c| c.to_string())))
    };

    // A reader deleting the admin's row.
    let del = sqlx::query("DELETE FROM group_memberships WHERE group_id = $1 AND role = 'admin'")
        .bind(c)
        .execute(&as_actor(&pool, reader).await)
        .await;
    assert_eq!(code(del).as_deref(), Some("42501"), "reader delete");
    assert_eq!(state(&pool, c, admin).await, "admin(live)");

    // The admin deleting every row of its own community (so a stranger could
    // then bootstrap it).
    let del = sqlx::query("DELETE FROM group_memberships WHERE group_id = $1")
        .bind(c)
        .execute(&as_actor(&pool, admin).await)
        .await;
    assert_eq!(code(del).as_deref(), Some("42501"), "admin delete");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM group_memberships WHERE group_id = $1")
        .bind(c)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 2, "the roster must be intact");

    let stranger = agent(&pool, "f4-ledger-stranger").await;
    let stranger_p = perspective(&pool, stranger, "f4-ledger-stranger-p").await;
    let out = CommunityRepository::add_member(
        &as_actor(&pool, stranger).await,
        Some(stranger),
        c,
        stranger_p,
    )
    .await
    .expect("a refusal is an outcome, not an error");
    assert_eq!(out, MembershipOutcome::DeniedNotAMember);
}
