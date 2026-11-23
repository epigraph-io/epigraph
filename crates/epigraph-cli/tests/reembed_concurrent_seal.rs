//! A claim sealed while `reembed` is writing its batch must be skipped, and
//! the rest of the batch (including rows AFTER it) must still be written.
//!
//! # The race
//!
//! `reembed` fetches a batch of unsealed rows, embeds them in one provider
//! call, then writes each row's `embedding_3072`. The write re-checks the seal
//! predicate, but a predicate inside a single `UPDATE` does not see a seal that
//! COMMITS WHILE THE UPDATE WAITS on the row lock the seal's own blanking
//! `UPDATE claims SET … embedding = NULL` holds: READ COMMITTED re-checks the
//! qual on the new row version against the statement's original snapshot for
//! `claim_encryption`. Migration 212's row trigger then sees the seal with a
//! fresh snapshot and raises 42501, and `run` returned that error, ending the
//! whole corpus pass on one concurrently sealed row. Backlog f9807254.
//!
//! # How the interleaving is forced
//!
//! The provider wrapper, inside the batch window (after `fetch_batch`, before
//! the writes), opens connection A and replays the seal's two claim statements
//! in the seal's order on the MIDDLE row of the batch, leaving A open. A spawned
//! task commits A once `pg_stat_activity` shows a backend of this test database
//! blocked on a lock (bounded). The rows are written in id order, so the row
//! before the victim is written before the wait and the row after it only if
//! the run survives the victim.
//!
//! # Verified to fail
//!
//! With the single-statement write, `run` returns
//! `Err(Database(..))` carrying SQLSTATE 42501, and the row after the victim is
//! never written.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sqlx::PgPool;
use tokio::task::JoinHandle;
use uuid::Uuid;

use epigraph_cli::reembed::{run, ReembedConfig, ReembedTarget};
use epigraph_embeddings::{
    EmbeddingConfig, EmbeddingError, EmbeddingService, MockProvider, TokenUsage,
};

const EPOCH: i32 = 0;

async fn seed_owner(pool: &PgPool) -> (Uuid, Uuid) {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'reembed-race-seal', 'system', \
                 ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent");
    // A `personal` group carries an empty `public_key`; it and its epoch exist
    // because `claim_encryption` has foreign keys onto them.
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ('reembed race seal', 'did:epigraph:personal:' || $1::text, ''::bytea, \
                 'personal', $1) \
         RETURNING id",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed group");
    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, $2, 'active')")
        .bind(group)
        .bind(EPOCH)
        .execute(pool)
        .await
        .expect("seed active key epoch");
    (agent, group)
}

async fn seed_claim(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, \
                             visibility, owner_group_id, embedding_3072) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, 'group', $3, NULL) \
         RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn has_vector(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding_3072 IS NOT NULL FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read embedding_3072")
}

/// Wraps `MockProvider`; on its first `batch_generate` it opens the seal of
/// `victim` (both statements, in the seal's order) and hands the open
/// transaction to a task that commits it once a backend waits on a lock.
struct SealingProvider {
    inner: MockProvider,
    pool: PgPool,
    victim: Uuid,
    group: Uuid,
    fired: AtomicBool,
    committer: Mutex<Option<JoinHandle<bool>>>,
}

#[async_trait]
impl EmbeddingService for SealingProvider {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.inner.generate(text).await
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if !self.fired.swap(true, Ordering::SeqCst) {
            let mut a = self.pool.begin().await.expect("begin A");
            sqlx::query(
                "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                               encrypted_content) \
                 VALUES ($1, $2, $3, 'fully_private', ''::bytea)",
            )
            .bind(self.victim)
            .bind(self.group)
            .bind(EPOCH)
            .execute(&mut *a)
            .await
            .expect("A: the ciphertext row");
            sqlx::query(
                "UPDATE claims SET content = '[sealed:race]', embedding = NULL, \
                                   embedding_3072 = NULL WHERE id = $1",
            )
            .bind(self.victim)
            .execute(&mut *a)
            .await
            .expect("A: blank the claim row (takes its lock)");

            let watcher = self.pool.clone();
            let handle = tokio::spawn(async move {
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
            });
            *self.committer.lock().expect("committer lock") = Some(handle);
        }
        self.inner.batch_generate(texts).await
    }

    fn dimension(&self) -> usize {
        self.inner.dimension()
    }

    fn token_usage(&self) -> TokenUsage {
        self.inner.token_usage()
    }

    fn reset_token_usage(&self) {
        self.inner.reset_token_usage();
    }

    async fn health_check(&self) -> Result<(), EmbeddingError> {
        self.inner.health_check().await
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_sealed_while_its_write_waits_is_skipped_and_the_batch_continues(pool: PgPool) {
    let (agent, group) = seed_owner(&pool).await;
    let mut ids = Vec::new();
    for n in 0..3 {
        ids.push(seed_claim(&pool, agent, group, &format!("reembed race claim {n}")).await);
    }
    ids.sort();
    let (before, victim, after) = (ids[0], ids[1], ids[2]);

    let provider = Arc::new(SealingProvider {
        inner: MockProvider::new(EmbeddingConfig::openai(3072)),
        pool: pool.clone(),
        victim,
        group,
        fired: AtomicBool::new(false),
        committer: Mutex::new(None),
    });

    let outcome = run(
        &pool,
        ReembedConfig {
            target: ReembedTarget::Claims,
            batch_size: 10,
            embedding_provider: provider.clone(),
            checkpoint_path: None,
        },
    )
    .await;

    let handle = provider
        .committer
        .lock()
        .expect("committer lock")
        .take()
        .expect("calibration: the seal was opened inside the batch window");
    let waited = handle.await.expect("the committer task");
    assert!(
        waited,
        "no write waited on the victim's row lock, so the race was not exercised"
    );

    let summary =
        outcome.expect("a claim sealed while its write waited must not abort the reembed run");
    assert!(
        has_vector(&pool, before).await,
        "calibration: the row before the victim is written"
    );
    assert!(
        has_vector(&pool, after).await,
        "the row after the concurrently sealed one must still be written"
    );
    assert!(
        !has_vector(&pool, victim).await,
        "a claim sealed mid-batch must not carry a 3072 vector"
    );
    assert_eq!(
        summary.rows_written, 2,
        "rows_written counts the two unsealed rows, not the sealed one"
    );
}
