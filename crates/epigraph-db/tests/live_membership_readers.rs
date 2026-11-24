//! The group membership READERS decide on LIVE membership (backlogs
//! 556c5416, 93ed2ec3, f712db53).
//!
//! Every reader is driven on the APPLICATION ROLE, on a connection stamped
//! from the caller's resolved viewer, as the request paths call them. The
//! harness superuser passes migration 236's principal gate (and 273's
//! roster gate) through its `rolsuper` arm, so a reader test on that pool
//! would pass whether or not the reader works for a real caller.
//!
//! The last test pins that `revoke_member_unless_last_admin_conn` refuses an
//! autocommit connection, on which its roster lock would not be held.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{DbError, GroupMembershipRepository, GroupRepository, RevokeOutcome};
use sqlx::PgPool;
use uuid::Uuid;

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
