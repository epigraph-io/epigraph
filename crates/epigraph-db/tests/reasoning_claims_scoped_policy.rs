//! The claim half of `F-FAH-A1`'s fix (deferred-commitment screen key
//! `f-fah-a1-reasoning-analyze`). `ClaimRepository::truth_values_for` is the
//! claim read `POST /api/v1/reasoning/analyze` runs. It returns the truth value
//! of each requested claim the caller's `Viewer` may read, and nothing for the
//! rest.
//!
//! The handler used to take its claims from `AppState::claim_store`, a
//! process-wide in-memory map with no tenancy. The edge half is
//! `reasoning_edges_scoped_policy.rs`.
//!
//! Split as that file and the other `_policy` files are split. The PREDICATE
//! half runs on the `#[sqlx::test]` superuser pool, where only the in-query
//! predicate filters, and pairs every stranger arm with an owner arm over the
//! same rows. The POLICY half runs on connections downgraded to `epigraph_app`,
//! where migration 077's policies filter, stamped and unstamped.

mod viewer_fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, SessionGucMode};
use sqlx::{Executor, PgPool};
use uuid::Uuid;
use viewer_fixture::{
    bypass, scoped_pool_with_mode, seed_agent_with_group, seed_group_claim, seed_public_claim,
};

async fn ids_read(pool: &PgPool, viewer: &Viewer, ids: &[Uuid]) -> Vec<Uuid> {
    ClaimRepository::truth_values_for(pool, viewer, ids)
        .await
        .expect("the claim read must not error; a filtered read returns fewer rows")
        .into_iter()
        .map(|(id, _)| id)
        .collect()
}

fn sorted(mut v: Vec<Uuid>) -> Vec<Uuid> {
    v.sort();
    v
}

/// A stranger reads the public claim only. The owner reads both of its own
/// claims, which is what makes the stranger's result a filter and not an empty
/// fixture. An id that names no claim is absent for everyone.
#[sqlx::test(migrations = "../../migrations")]
async fn the_read_returns_only_claims_the_viewer_may_read(pool: PgPool) {
    let (owner, group) = seed_agent_with_group(&pool, "reasoning-claims-owner").await;
    let (stranger, _) = seed_agent_with_group(&pool, "reasoning-claims-stranger").await;
    let tag = Uuid::new_v4();
    let p = seed_public_claim(&pool, owner, &format!("reasoning claims p {tag}")).await;
    let h = seed_group_claim(&pool, owner, group, &format!("reasoning claims h {tag}")).await;
    sqlx::query("UPDATE claims SET truth_value = 0.3 WHERE id = $1")
        .bind(h)
        .execute(&pool)
        .await
        .expect("set h's truth value");
    let missing = Uuid::new_v4();
    let asked = [p, h, missing];

    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");
    assert!(
        !stranger_v.group_bind().expect("scoped").is_empty(),
        "CALIBRATION: the stranger must hold a group of its own, so $2 is bound with \
         members in it"
    );

    let mine = ClaimRepository::truth_values_for(&pool, &owner_v, &asked)
        .await
        .expect("owner read");
    assert_eq!(
        mine.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        sorted(vec![p, h]),
        "CALIBRATION: the owner reads both of its claims, in id order, and not the \
         id that names no claim"
    );
    assert_eq!(
        mine.iter().find(|(id, _)| *id == h).map(|(_, t)| *t),
        Some(0.3),
        "the stored truth value must come back"
    );
    assert_eq!(
        ids_read(&pool, &stranger_v, &asked).await,
        vec![p],
        "a stranger must not read the owner's private claim"
    );

    // A `Bypass` viewer renders no predicate and binds nothing.
    let (_scoped, bypass_v) = bypass(&pool).await;
    assert_eq!(
        ids_read(&pool, &bypass_v, &asked).await,
        sorted(vec![p, h]),
        "a Bypass viewer's read must bind no group array and filter nothing"
    );
}

async fn bypass_held(conn: &mut sqlx::PgConnection) -> bool {
    sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_bypass()")
}

async fn ids_on(conn: &mut sqlx::PgConnection, viewer: &Viewer, ids: &[Uuid]) -> Vec<Uuid> {
    ClaimRepository::truth_values_for(&mut *conn, viewer, ids)
        .await
        .expect("the read must not error under the policy")
        .into_iter()
        .map(|(id, _)| id)
        .collect()
}

/// The owner's own group-private claim, read on a stamped and on an unstamped
/// connection.
async fn policy_differential(pool: PgPool, mode: SessionGucMode) {
    let (owner, group) = seed_agent_with_group(&pool, "reasoning-claims-policy-owner").await;
    let (stranger, _) = seed_agent_with_group(&pool, "reasoning-claims-policy-stranger").await;
    let x = seed_group_claim(
        &pool,
        owner,
        group,
        &format!("reasoning claims policy x {}", Uuid::new_v4()),
    )
    .await;

    // Resolve BEFORE downgrading anything, on the superuser pool.
    let owner_v = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");
    let arm = format!("{mode:?}");
    let scoped = scoped_pool_with_mode(&pool, mode).await;

    let mut read = scoped.read_as(&owner_v).await.expect("read_as owner");
    read.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    assert!(
        !bypass_held(&mut read).await,
        "CALIBRATION ({arm}): the stamped session must not hold bypass"
    );
    let stamped_owner = ids_on(&mut read, &owner_v, &[x]).await;
    read.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    read.commit().await.expect("commit");

    let mut read = scoped.read_as(&stranger_v).await.expect("read_as stranger");
    read.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    let stamped_stranger = ids_on(&mut read, &stranger_v, &[x]).await;
    read.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    read.commit().await.expect("commit");

    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    assert!(
        !bypass_held(&mut conn).await,
        "CALIBRATION ({arm}): the unstamped session must not hold bypass"
    );
    let unstamped_owner = ids_on(&mut conn, &owner_v, &[x]).await;
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");

    assert_eq!(
        stamped_owner,
        vec![x],
        "COHERENCE ({arm}): on the stamped connection the owner reads its own claim"
    );
    assert!(
        stamped_stranger.is_empty(),
        "({arm}): a stamped stranger must not read the owner's claim"
    );
    assert!(
        unstamped_owner.is_empty(),
        "THE DIFFERENTIAL ({arm}): on an unstamped connection the owner's own private \
         claim must vanish. Got {unstamped_owner:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_read_serves_the_owners_claim_and_an_unstamped_one_does_not_in_session_mode(
    pool: PgPool,
) {
    policy_differential(pool, SessionGucMode::Session).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_read_serves_the_owners_claim_and_an_unstamped_one_does_not_in_transaction_mode(
    pool: PgPool,
) {
    policy_differential(pool, SessionGucMode::Transaction).await;
}
