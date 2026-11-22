//! The step lineage lock across a lineage back-fill (review of backlog
//! bf2e9aa6).
//!
//! `evolve_step` back-fills a NEW lineage id onto a parent whose
//! `step_lineage_id` was NULL, so the parent's lock key
//! (`COALESCE(step_lineage_id, id)`) changes from its own id to that lineage
//! id when the first evolve commits. An `executes` writer that read the NULL
//! lineage queued on the claim id behind that evolve; when it is granted that
//! (now stale) key, the next evolve of the lineage keys on the new id. These
//! tests pin that the writer re-keys onto the new id, so the next evolve's
//! authority read waits for the writer's in-flight edge and then sees it, and
//! calibrate the blocking check with a writer that keys after the back-fill.

use epigraph_db::WorkflowRepository;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool, seed: &[u8]) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'lineage lock') RETURNING id",
    )
    .bind(blake3::hash(seed).as_bytes().as_slice())
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_step(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
         VALUES ($1, sha256($1::bytea), $2, 0.5) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed step claim")
}

async fn seed_workflow(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal) VALUES ($1, $2, 'lineage lock test')",
    )
    .bind(id)
    .bind(format!("lineage-lock-{id}"))
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

/// Sessions of this test's database queued on an advisory lock.
async fn advisory_waiters(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() \
         AND wait_event_type = 'Lock' AND wait_event = 'advisory'",
    )
    .fetch_one(pool)
    .await
    .expect("read pg_stat_activity")
}

async fn wait_for_advisory_waiter(pool: &PgPool) -> bool {
    for _ in 0..200 {
        if advisory_waiters(pool).await > 0 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_keyed_before_a_backfill_still_serializes_with_the_next_evolve(pool: PgPool) {
    let agent = seed_agent(&pool, b"lineage-lock-rekey").await;
    let parent = seed_step(&pool, agent, "lineage lock: parent step").await;
    let attached = seed_workflow(&pool).await;

    // Evolve 1 on the parent (NULL lineage, so key = parent id): back-fill a
    // fresh lineage id and insert the new head in it, as
    // `ClaimRepository::evolve_step_conn` does; not yet committed.
    let mut evolve1 = pool.begin().await.unwrap();
    assert!(
        WorkflowRepository::lock_step_lineage_for_evolve(&mut evolve1, parent)
            .await
            .unwrap(),
        "evolve 1 locks the parent"
    );
    let lineage = Uuid::new_v4();
    sqlx::query("UPDATE claims SET step_lineage_id = $1 WHERE id = $2")
        .bind(lineage)
        .bind(parent)
        .execute(&mut *evolve1)
        .await
        .unwrap();
    let head: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, step_lineage_id) \
         VALUES ('lineage lock: new head', sha256('lineage lock: new head'::bytea), $1, 0.5, $2) \
         RETURNING id",
    )
    .bind(agent)
    .bind(lineage)
    .fetch_one(&mut *evolve1)
    .await
    .unwrap();

    // An executes writer attaching another workflow to the parent reads the
    // committed NULL lineage, keys on the parent id and queues behind evolve 1.
    let wpool = pool.clone();
    let writer = tokio::spawn(async move {
        let mut w = wpool.begin().await.unwrap();
        WorkflowRepository::lock_step_lineage_shared(&mut w, parent)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'workflow', $2, 'claim', 'executes')",
        )
        .bind(attached)
        .bind(parent)
        .execute(&mut *w)
        .await
        .unwrap();
        w
    });
    assert!(
        wait_for_advisory_waiter(&pool).await,
        "the writer queues behind evolve 1"
    );
    evolve1.commit().await.unwrap();
    // The writer now holds its lock(s) and an uncommitted executes edge.
    let writer_tx = writer.await.unwrap();

    // Evolve 2 on the new head: its authority read must wait for the
    // in-flight edge into the lineage, then see it.
    let epool = pool.clone();
    let mut evolve2 = tokio::spawn(async move {
        let mut c = epool.begin().await.unwrap();
        assert!(WorkflowRepository::lock_step_lineage_for_evolve(&mut c, head)
            .await
            .unwrap());
        let set = WorkflowRepository::workflows_executing_step_lineage(&mut c, head)
            .await
            .unwrap();
        c.rollback().await.unwrap();
        set
    });
    let mut queued = false;
    for _ in 0..200 {
        assert!(
            !evolve2.is_finished(),
            "evolve 2 took the lineage lock and read its authority set while an executes \
             writer keyed before the back-fill was in flight"
        );
        if advisory_waiters(&pool).await > 0 {
            queued = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(queued, "evolve 2 queues on the lineage lock");
    writer_tx.commit().await.unwrap();
    let set = tokio::time::timeout(Duration::from_secs(10), &mut evolve2)
        .await
        .expect("evolve 2 proceeds once the writer commits")
        .unwrap();
    assert!(
        set.contains(&attached),
        "evolve 2's authority set includes the workflow the writer attached: {set:?}"
    );
}

/// Calibration: a writer that keys AFTER the back-fill (on the lineage id)
/// blocks the next evolve, so the blocking check above can see a wait.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_keyed_after_a_backfill_blocks_the_next_evolve(pool: PgPool) {
    let agent = seed_agent(&pool, b"lineage-lock-calibration").await;
    let parent = seed_step(&pool, agent, "lineage lock: calibration parent").await;

    let mut evolve1 = pool.begin().await.unwrap();
    assert!(
        WorkflowRepository::lock_step_lineage_for_evolve(&mut evolve1, parent)
            .await
            .unwrap()
    );
    sqlx::query("UPDATE claims SET step_lineage_id = $1 WHERE id = $2")
        .bind(Uuid::new_v4())
        .bind(parent)
        .execute(&mut *evolve1)
        .await
        .unwrap();
    evolve1.commit().await.unwrap();

    let mut w = pool.begin().await.unwrap();
    WorkflowRepository::lock_step_lineage_shared(&mut w, parent)
        .await
        .unwrap();
    let mut c = pool.begin().await.unwrap();
    let r = tokio::time::timeout(
        Duration::from_secs(3),
        WorkflowRepository::lock_step_lineage_for_evolve(&mut c, parent),
    )
    .await;
    assert!(r.is_err(), "evolve 2 waits for the writer");
    drop(w);
}
