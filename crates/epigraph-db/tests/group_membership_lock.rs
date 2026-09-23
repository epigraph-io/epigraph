//! Every writer of a group's roster or key epoch takes the group membership
//! lock first, so an `add_member` can no longer land behind a rotation.
//!
//! `D-PR20-A` (docs/tenancy/progress.json) recorded the race. The rotation
//! locks the live roster `FOR UPDATE`, but a row lock does not stop an
//! `INSERT`, and `POST /groups/:id/members` read the current epoch on the pool
//! and inserted in a second statement. A member added mid-rotation was
//! therefore stamped at the epoch being retired and was not re-wrapped, and
//! the rotation still reported every live member re-wrapped.
//! `GroupMembershipRepository::lock_group_membership_conn` is the fix, with
//! `add_member` refusing a share wrapped for any epoch other than the one it
//! reads under that lock. These tests measure the lock rather than infer it
//! from timing.

mod viewer_fixture;

use epigraph_db::{
    AddMemberOutcome, CommunityRepository, GroupKeyEpochRepository, GroupMembershipRepository,
    GroupRepository, MembershipOutcome, RevokeOutcome, RotateOutcome,
};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

/// A structurally valid 60-byte wrapped share. The repo layer never unwraps
/// it; the route checks the length, not the contents.
fn share(seed: &str) -> Vec<u8> {
    let h = blake3::hash(seed.as_bytes());
    let mut bytes = h.as_bytes().to_vec();
    bytes.extend_from_slice(&h.as_bytes()[..28]);
    bytes
}

/// A `team` group whose creator is its admin, made the way `POST /groups`
/// makes it, and made rotatable by naming an external escrow.
async fn rotatable_team_group(pool: &PgPool, creator: Uuid, seed: &str) -> Uuid {
    let id = Uuid::new_v4();
    GroupRepository::create_with_admin(
        pool,
        id,
        Some(seed),
        &format!("did:key:test-{seed}-{id}"),
        blake3::hash(seed.as_bytes()).as_bytes(),
        None,
        creator,
    )
    .await
    .expect("create group");
    make_recoverable(pool, id).await;
    id
}

/// Satisfy rotation's recoverability gate with a `kms_key_ref`.
async fn make_recoverable(pool: &PgPool, group_id: Uuid) {
    sqlx::query(
        "UPDATE groups SET properties = properties || jsonb_build_object('kms_key_ref', 'arn:test') \
          WHERE id = $1",
    )
    .bind(group_id)
    .execute(pool)
    .await
    .expect("seed kms_key_ref");
}

async fn live_roster(pool: &PgPool, group_id: Uuid) -> Vec<(Uuid, i32)> {
    sqlx::query_as(
        "SELECT agent_id, epoch FROM group_memberships \
          WHERE group_id = $1 AND revoked_at IS NULL ORDER BY agent_id",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await
    .expect("read live roster")
}

/// A rotation share for every live member.
async fn shares_for_roster(pool: &PgPool, group_id: Uuid, seed: &str) -> Vec<(Uuid, Vec<u8>)> {
    live_roster(pool, group_id)
        .await
        .into_iter()
        .map(|(agent, _)| (agent, share(&format!("{seed}-{agent}"))))
        .collect()
}

/// Wait until a backend in this test database is blocked on a lock, or until
/// `task` returns. `true` means the wait was observed. Measured rather than
/// timed, for the reason `epigraph-api/tests/group_lifecycle.rs` gives on its
/// copy: every session in a `#[sqlx::test]` database is this test's own, so a
/// `Lock` wait here is unambiguous. An advisory-lock wait reports
/// `wait_event_type = 'Lock'` like a row-lock wait does.
async fn a_backend_is_blocked_on_a_lock<T>(
    pool: &PgPool,
    task: &tokio::task::JoinHandle<T>,
) -> bool {
    for _ in 0..200 {
        if task.is_finished() {
            return false;
        }
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(pool)
        .await
        .expect("read pg_stat_activity");
        if waiting > 0 {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

/// A connection this test owns, outside the `#[sqlx::test]` pool, so a lock
/// held on it lives exactly as long as the test says.
async fn own_connection(pool: &PgPool) -> sqlx::PgConnection {
    let url = fixture::database_url_for(pool).await;
    <sqlx::PgConnection as sqlx::Connection>::connect(&url)
        .await
        .expect("open a connection outside the test pool")
}

/// Hold the group membership lock on a connection of our own, start `writer`,
/// and require that it WAITS for the lock; then release it and return what the
/// writer returned.
async fn waits_for_the_group_lock<T, F>(pool: &PgPool, group_id: Uuid, name: &str, writer: F) -> T
where
    T: Send + std::fmt::Debug + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    let mut own = own_connection(pool).await;
    let mut holder = sqlx::Connection::begin(&mut own).await.expect("holder tx");
    GroupMembershipRepository::lock_group_membership_conn(&mut holder, group_id)
        .await
        .expect("hold the group membership lock");

    let task = tokio::spawn(writer);
    if !a_backend_is_blocked_on_a_lock(pool, &task).await {
        let early = task.await.expect("writer task panicked");
        panic!(
            "{name} did not wait for the group membership lock; it returned {early:?}. A writer \
             of a group's roster or epoch that skips the lock can interleave with a rotation."
        );
    }

    holder.rollback().await.expect("release the lock");
    tokio::time::timeout(std::time::Duration::from_secs(10), task)
        .await
        .unwrap_or_else(|_| panic!("{name} never unblocked after the lock was released"))
        .expect("writer task panicked")
}

/// THE CONTRACT: every writer of a group's roster or key epoch takes the lock.
///
/// One missing writer reopens the race for its path, so all five are listed
/// here: the group route's add and removal, the rotation, and both community
/// membership writers (a community's projected group is a real group with its
/// own epochs). Before the lock existed none of them waited.
#[sqlx::test(migrations = "../../migrations")]
async fn every_roster_writer_waits_for_the_group_membership_lock(pool: PgPool) {
    let (creator, _) = fixture::seed_agent_with_group(&pool, "creator").await;
    let (reader, _) = fixture::seed_agent_with_group(&pool, "reader").await;
    let (joiner, _) = fixture::seed_agent_with_group(&pool, "joiner").await;
    let group_id = rotatable_team_group(&pool, creator, "writers").await;

    let outcome =
        waits_for_the_group_lock(&pool, group_id, "GroupMembershipRepository::add_member", {
            let pool = pool.clone();
            async move {
                GroupMembershipRepository::add_member(
                    &pool,
                    group_id,
                    reader,
                    &share("r"),
                    0,
                    "reader",
                )
                .await
                .expect("add member")
            }
        })
        .await;
    assert!(
        matches!(outcome, AddMemberOutcome::Added { epoch: 0, .. }),
        "{outcome:?}"
    );

    let shares = shares_for_roster(&pool, group_id, "rot").await;
    let outcome =
        waits_for_the_group_lock(&pool, group_id, "GroupKeyEpochRepository::rotate_conn", {
            let pool = pool.clone();
            async move {
                let mut tx = pool.begin().await.expect("rotation tx");
                let outcome = GroupKeyEpochRepository::rotate_conn(&mut tx, group_id, &shares)
                    .await
                    .expect("rotate");
                tx.commit().await.expect("commit rotation");
                outcome
            }
        })
        .await;
    assert!(
        matches!(outcome, RotateOutcome::Rotated { new_epoch: 1, .. }),
        "{outcome:?}"
    );

    let outcome = waits_for_the_group_lock(
        &pool,
        group_id,
        "GroupMembershipRepository::revoke_member_unless_last_admin",
        {
            let pool = pool.clone();
            async move {
                GroupMembershipRepository::revoke_member_unless_last_admin(&pool, group_id, reader)
                    .await
                    .expect("revoke")
            }
        },
    )
    .await;
    assert_eq!(outcome, RevokeOutcome::Revoked);

    // The community writers, on a community's projected group.
    let community = CommunityRepository::create(&pool, "lock", None, None, None, Some(creator))
        .await
        .expect("create community");
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ('joiner', $1) RETURNING id",
    )
    .bind(joiner)
    .fetch_one(&pool)
    .await
    .expect("seed perspective");

    let outcome =
        waits_for_the_group_lock(&pool, community.id, "CommunityRepository::add_member", {
            let pool = pool.clone();
            async move {
                CommunityRepository::add_member(&pool, Some(creator), community.id, perspective)
                    .await
                    .expect("community add")
            }
        })
        .await;
    assert_eq!(outcome, MembershipOutcome::Applied);

    let outcome =
        waits_for_the_group_lock(&pool, community.id, "CommunityRepository::remove_member", {
            let pool = pool.clone();
            async move {
                CommunityRepository::remove_member(&pool, Some(creator), community.id, perspective)
                    .await
                    .expect("community remove")
            }
        })
        .await;
    assert_eq!(outcome, MembershipOutcome::Applied);
}

/// THE RACE ITSELF. A member added while a rotation is open never lands on
/// the epoch being retired.
///
/// The admin wrapped the newcomer's share for epoch 0, the epoch the group
/// reported before the rotation. The rotation runs on a connection of our own
/// and is left open, holding the lock with epoch 1 created but not committed.
/// The add must wait. When the rotation commits, the add reads epoch 1, sees
/// that the share was wrapped for epoch 0, and writes nothing. Resubmitted with
/// a share for epoch 1, it lands there, and every live member ends on epoch 1.
///
/// Before the lock, the add read epoch 0 (the rotation was uncommitted),
/// inserted immediately, and was left on the retired epoch with no epoch-1
/// share once the rotation committed. With the lock and no epoch check, it
/// would have waited and then written the epoch-0 share at epoch 1, where the
/// member cannot open it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_added_during_a_rotation_never_lands_on_the_retired_epoch(pool: PgPool) {
    let (creator, _) = fixture::seed_agent_with_group(&pool, "creator").await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "member").await;
    let (newcomer, _) = fixture::seed_agent_with_group(&pool, "newcomer").await;
    let group_id = rotatable_team_group(&pool, creator, "race").await;
    let added =
        GroupMembershipRepository::add_member(&pool, group_id, member, &share("m"), 0, "writer")
            .await
            .expect("add member");
    assert!(
        matches!(added, AddMemberOutcome::Added { epoch: 0, .. }),
        "{added:?}"
    );

    let shares = shares_for_roster(&pool, group_id, "race").await;
    let mut own = own_connection(&pool).await;
    let mut rotation = sqlx::Connection::begin(&mut own)
        .await
        .expect("rotation tx");
    let rotated = GroupKeyEpochRepository::rotate_conn(&mut rotation, group_id, &shares)
        .await
        .expect("rotate");
    assert_eq!(
        rotated,
        RotateOutcome::Rotated {
            previous_epoch: 0,
            new_epoch: 1,
            members_rewrapped: 2,
        }
    );

    let add = tokio::spawn({
        let pool = pool.clone();
        async move {
            GroupMembershipRepository::add_member(
                &pool,
                group_id,
                newcomer,
                &share("n-epoch-0"),
                0,
                "reader",
            )
            .await
        }
    });
    if !a_backend_is_blocked_on_a_lock(&pool, &add).await {
        let early = add.await.expect("add task panicked");
        panic!(
            "add_member did not wait for the open rotation; it returned {early:?}, so it read \
             the epoch the rotation is retiring"
        );
    }

    rotation.commit().await.expect("commit the rotation");

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), add)
        .await
        .expect("add_member never unblocked after the rotation committed")
        .expect("add task panicked")
        .expect("add member");
    assert_eq!(
        outcome,
        AddMemberOutcome::EpochMismatch {
            share_epoch: 0,
            current_epoch: 1,
        },
        "a share wrapped for epoch 0 must not be written once epoch 1 is current"
    );
    let roster = live_roster(&pool, group_id).await;
    assert_eq!(roster.len(), 2, "the refused add wrote a row: {roster:?}");

    let retried = GroupMembershipRepository::add_member(
        &pool,
        group_id,
        newcomer,
        &share("n-epoch-1"),
        1,
        "reader",
    )
    .await
    .expect("add member at the new epoch");
    assert!(
        matches!(retried, AddMemberOutcome::Added { epoch: 1, .. }),
        "{retried:?}"
    );

    let roster = live_roster(&pool, group_id).await;
    assert_eq!(roster.len(), 3, "{roster:?}");
    assert!(
        roster.iter().all(|(_, epoch)| *epoch == 1),
        "every live member must be on the new epoch after the rotation: {roster:?}"
    );
}

/// THE BACKSTOP. A rotation refuses to commit while a live member is still on
/// the retired epoch, even when that member was written by something that
/// skipped the lock.
///
/// Every in-tree writer takes the lock, so this simulates one that does not: a
/// raw `INSERT`, as a backfill or a hand-run statement would do. It is made
/// deterministic by holding one roster row, so the rotation blocks INSIDE its
/// roster read with that statement's snapshot already taken. The raw insert
/// commits while it waits. When the row is released, the rotation's roster is
/// the two members it has shares for. The roster check passes, and the
/// re-wraps land. Without the backstop it returned `Rotated` and committed,
/// leaving the inserted member live on epoch 0 while epoch 1 was active. It
/// must refuse, and the rollback must leave epoch 0 current.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rotation_refuses_to_strand_a_member_written_behind_its_roster_snapshot(pool: PgPool) {
    let (creator, _) = fixture::seed_agent_with_group(&pool, "creator").await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "member").await;
    let (bypasser, _) = fixture::seed_agent_with_group(&pool, "bypasser").await;
    let group_id = rotatable_team_group(&pool, creator, "backstop").await;
    GroupMembershipRepository::add_member(&pool, group_id, member, &share("m"), 0, "writer")
        .await
        .expect("add member");
    let shares = shares_for_roster(&pool, group_id, "backstop").await;
    assert_eq!(shares.len(), 2);

    // Hold one roster row so the rotation stops inside its roster read.
    let mut own = own_connection(&pool).await;
    let mut holder = sqlx::Connection::begin(&mut own).await.expect("holder tx");
    sqlx::query(
        "SELECT 1 FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL FOR UPDATE",
    )
    .bind(group_id)
    .bind(member)
    .fetch_one(&mut *holder)
    .await
    .expect("hold the member's row");

    let rotation = tokio::spawn({
        let pool = pool.clone();
        async move {
            let mut tx = pool.begin().await.expect("rotation tx");
            let outcome = GroupKeyEpochRepository::rotate_conn(&mut tx, group_id, &shares).await;
            if matches!(outcome, Ok(RotateOutcome::Rotated { .. })) {
                tx.commit().await.expect("commit rotation");
            }
            outcome
        }
    });
    if !a_backend_is_blocked_on_a_lock(&pool, &rotation).await {
        let early = rotation.await.expect("rotation task panicked");
        panic!("the rotation did not block on the held roster row; it returned {early:?}");
    }

    // A writer that skips the lock commits a live member while the rotation's
    // roster read is waiting.
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, $3, 0, 'reader')",
    )
    .bind(group_id)
    .bind(bypasser)
    .bind(share("bypass"))
    .execute(&pool)
    .await
    .expect("insert behind the snapshot");

    holder.rollback().await.expect("release the roster row");

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), rotation)
        .await
        .expect("the rotation never unblocked")
        .expect("rotation task panicked");
    match outcome {
        Err(epigraph_db::DbError::InvalidData { reason }) => assert!(
            reason.contains("would leave 1 live membership"),
            "unexpected refusal: {reason}"
        ),
        other => panic!(
            "the rotation must refuse while a live member is on the retired epoch; got {other:?}"
        ),
    }

    let current: Vec<(i32, String)> = sqlx::query_as(
        "SELECT epoch, status FROM group_key_epochs WHERE group_id = $1 ORDER BY epoch",
    )
    .bind(group_id)
    .fetch_all(&pool)
    .await
    .expect("read epochs");
    assert_eq!(
        current,
        vec![(0, "active".to_string())],
        "the refused rotation must roll back whole"
    );
    let roster = live_roster(&pool, group_id).await;
    assert_eq!(roster.len(), 3, "{roster:?}");
    assert!(roster.iter().all(|(_, epoch)| *epoch == 0), "{roster:?}");
}
