//! `ClaimRepository::store_embedding` must answer "nothing stored" for a claim
//! whose seal commits while the store is waiting for it, not raise.
//!
//! # The race
//!
//! The seal (`privatization.rs`, the claim step of the seal commit) runs, in
//! ONE transaction, `INSERT INTO claim_encryption …` and then
//! `UPDATE claims SET content = <sentinel>, embedding = NULL, …`. That UPDATE
//! holds the claim row's lock until the seal commits.
//!
//! A store written as one statement,
//! `UPDATE claims … WHERE id = $1 AND NOT EXISTS (claim_encryption …)`,
//! blocks on that row lock. When the seal commits, READ COMMITTED re-checks the
//! qual on the NEW row version but against the statement's ORIGINAL snapshot
//! for every other table, `claim_encryption` included, so the `NOT EXISTS`
//! still passes. Migration 212's row trigger then looks the seal up with a
//! fresh snapshot, sees it, and raises 42501. The store returns `Err` where it
//! documents `Ok(false)`, and every batch caller that treats an error as fatal
//! (or as a failed row: `embed_backfill` exits 2) stops on one concurrently
//! sealed claim. Backlog f9807254.
//!
//! `store_embedding_if_unsealed` and `EvidenceRepository::store_embedding_as`
//! close the same window by taking the row lock in a SEPARATE statement first;
//! the guarded UPDATE then takes a fresh snapshot that includes the seal.
//!
//! # How the interleaving is forced
//!
//! Connection A replays the seal's two claim statements in the seal's order and
//! stays open. The store runs on the pool. A spawned task waits until
//! `pg_stat_activity` shows a backend of THIS test database blocked on a lock
//! (bounded), then commits A. No sleep decides the order.
//!
//! # Verified to fail
//!
//! With the single-statement store, `store_embedding` returns
//! `Err(QueryFailed)` carrying SQLSTATE 42501 from the 212 trigger.

mod viewer_fixture;

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

fn vector_literal(dims: usize, value: f32) -> String {
    format!("[{}]", vec![value.to_string(); dims].join(","))
}

async fn has_vector(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the vector column")
}

/// Commit `a` once some other backend of this database is observed waiting on
/// a lock (bounded at ~10 s). Returns whether the wait was observed.
fn commit_once_a_backend_waits(
    pool: &PgPool,
    a: sqlx::Transaction<'static, sqlx::Postgres>,
) -> tokio::task::JoinHandle<bool> {
    let watcher = pool.clone();
    tokio::spawn(async move {
        let mut waited = false;
        for _ in 0..500 {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                                 WHERE datname = current_database() \
                                   AND pid <> pg_backend_pid() \
                                   AND wait_event_type = 'Lock')",
            )
            .fetch_one(&watcher)
            .await
            .expect("read pg_stat_activity");
            if blocked {
                waited = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        a.commit().await.expect("commit A (the seal)");
        waited
    })
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_seal_committing_while_store_embedding_waits_stores_nothing_and_does_not_raise(
    pool: PgPool,
) {
    let (agent, group) = viewer_fixture::seed_agent_with_group(&pool, "store-race").await;
    let control = viewer_fixture::seed_group_claim(&pool, agent, group, "an open claim").await;
    let target = viewer_fixture::seed_group_claim(&pool, agent, group, "a claim to seal").await;
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(group)
    .execute(&pool)
    .await
    .expect("seed the key epoch the encryption FK requires");
    let vector = vector_literal(1536, 0.25);

    // CALIBRATION: an unsealed claim takes a vector through the same writer, so
    // the `false` below is not a store that refuses everything.
    assert!(
        ClaimRepository::store_embedding(&pool, control, &vector)
            .await
            .expect("store on the unsealed control"),
        "the unsealed control claim must take a vector"
    );
    assert!(has_vector(&pool, control).await);

    // A: the seal's claim statements, in the seal's order, left open.
    let mut a = pool.begin().await.expect("begin A");
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', decode('0badc0de', 'hex'))",
    )
    .bind(target)
    .bind(group)
    .execute(&mut *a)
    .await
    .expect("A: the ciphertext row");
    sqlx::query(
        "UPDATE claims SET content = '[sealed:race]', embedding = NULL, \
                           embedding_3072 = NULL WHERE id = $1",
    )
    .bind(target)
    .execute(&mut *a)
    .await
    .expect("A: blank the claim row (takes its lock)");

    let committer = commit_once_a_backend_waits(&pool, a);

    // B: the store, which must wait for A and then write nothing, cleanly.
    let stored = ClaimRepository::store_embedding(&pool, target, &vector).await;
    let waited = committer.await.expect("the committer task");

    assert!(
        waited,
        "the store never waited on the claim row's lock, so the race was not exercised"
    );
    let wrote = stored.expect(
        "a claim sealed while the store waited must be answered `Ok(false)`, \
         not an error from migration 212's trigger",
    );
    assert!(
        !wrote,
        "the store reported a vector written onto a claim sealed while it waited"
    );
    assert!(
        !has_vector(&pool, target).await,
        "a sealed claim carries a plaintext-derived vector"
    );
}
