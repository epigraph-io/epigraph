//! The replacement cascades re-point `executes` edges under the destination's
//! step lineage lock (backlog 449a2afb).
//!
//! `evolve_step` holds the caller to workflow authority over every workflow
//! that executes the parent's step lineage, read under the lineage's EXCLUSIVE
//! advisory lock (`WorkflowRepository::lock_step_lineage_for_evolve`). An
//! `executes` INSERT takes that key in share mode (bf2e9aa6), but the
//! supersede, dedup, merge and un-mark cascades do not insert their edges:
//! they re-point them (`UPDATE edges SET target_id`). Without the lock, a
//! cascade moved a workflow's `executes` edge onto a member of the lineage
//! while an evolve of that lineage was between its authority read and its
//! commit, so the evolve changed what that workflow runs without authority
//! over it.
//!
//! Each test puts the cascade's DESTINATION in a lineage and has the evolve
//! lock a DIFFERENT member of it, so the only thing the cascade can wait on is
//! the lineage's advisory key (not a row lock). The cascade must queue on that
//! key while the evolve is open, then move the edge once it commits. The last
//! test takes the other order: an evolve that starts while a cascade is in
//! flight waits for it, then counts the re-pointed workflow.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::{ClaimRepository, ConsolidateMode, WorkflowRepository};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

/// How long a cascade may take once nothing blocks it.
const CASCADE_DEADLINE: Duration = Duration::from_secs(30);

async fn seed_workflow(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal) VALUES ($1, $2, 'repoint lock test')",
    )
    .bind(id)
    .bind(format!("repoint-lock-{id}"))
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

/// A PUBLIC level-2 step (a non-public one keeps its `executes`, OD-32, so
/// nothing would move).
async fn seed_step(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, content).await;
    sqlx::query("UPDATE claims SET properties = '{\"level\": 2}'::jsonb WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("mark the step level 2");
    id
}

async fn seed_executes(pool: &PgPool, workflow: Uuid, step: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, 'workflow', $2, 'claim', 'executes', '{\"plan_index\": 0, \"level\": 2}'::jsonb) \
         RETURNING id",
    )
    .bind(workflow)
    .bind(step)
    .fetch_one(pool)
    .await
    .expect("seed executes")
}

async fn set_lineage(pool: &PgPool, claim: Uuid, lineage: Uuid) {
    sqlx::query("UPDATE claims SET step_lineage_id = $1 WHERE id = $2")
        .bind(lineage)
        .bind(claim)
        .execute(pool)
        .await
        .expect("set step_lineage_id");
}

/// A step lineage holding `member` and a second step, the one the evolve
/// locks. Returns that second step.
async fn lineage_with(pool: &PgPool, agent: Uuid, member: Uuid) -> Uuid {
    let lineage = Uuid::new_v4();
    let head = seed_step(pool, agent, &format!("lineage head {lineage}")).await;
    set_lineage(pool, head, lineage).await;
    set_lineage(pool, member, lineage).await;
    head
}

async fn target_of(pool: &PgPool, edge: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("edge")
}

async fn advisory_waiters(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() \
         AND wait_event_type = 'Lock' AND wait_event = 'advisory'",
    )
    .fetch_one(pool)
    .await
    .expect("read pg_stat_activity")
}

/// An evolve of the lineage `head` belongs to, holding its exclusive lock.
async fn open_evolve(pool: &PgPool, head: Uuid) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut evolve = pool.begin().await.unwrap();
    assert!(
        WorkflowRepository::lock_step_lineage_for_evolve(&mut evolve, head)
            .await
            .unwrap(),
        "the evolve locks its parent"
    );
    evolve
}

/// Run `cascade` while an evolve of the destination's lineage is open: it
/// must queue on the lineage's advisory key (and not finish) until the evolve
/// commits, then finish.
async fn assert_cascade_waits_for_evolve<F>(pool: &PgPool, head: Uuid, what: &str, cascade: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let evolve = open_evolve(pool, head).await;
    let task = tokio::spawn(cascade);
    let mut queued = false;
    for _ in 0..200 {
        assert!(
            !task.is_finished(),
            "the {what} cascade re-pointed onto the lineage while an evolve of it held the \
             lineage lock"
        );
        if advisory_waiters(pool).await > 0 {
            queued = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(queued, "the {what} cascade queues on the lineage lock");
    assert!(!task.is_finished(), "the {what} cascade is still waiting");
    evolve.commit().await.unwrap();
    tokio::time::timeout(CASCADE_DEADLINE, task)
        .await
        .unwrap_or_else(|_| panic!("the {what} cascade finishes once the evolve commits"))
        .unwrap();
}

/// On the maintenance role, the session the admin cascade and the deferred
/// replay use.
async fn on_maintenance<F, Fut>(pool: PgPool, f: F)
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, ())>,
{
    fixture::as_role(&pool, "epigraph_maintenance", f).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_supersede_cascade_waits_for_an_evolve_of_the_successors_lineage(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "repoint-supersede").await;
    let workflow = seed_workflow(&pool).await;
    let old = seed_step(&pool, agent, "supersede: the old step").await;
    let edge = seed_executes(&pool, workflow, old).await;

    // The act on its own transaction, as a request path runs it.
    let mut tx = pool.begin().await.unwrap();
    let (new, _) = ClaimRepository::supersede_act_conn(
        &mut tx,
        None,
        ClaimId::from_uuid(old),
        "supersede: the old step, restated",
        TruthValue::clamped(0.6),
        "restated",
        epigraph_db::SupersedeActor::new(agent, epigraph_db::SupersedeTool::SupersedeClaim),
    )
    .await
    .expect("supersede act");
    tx.commit().await.unwrap();
    // The successor joins a lineage before the cascade runs (an evolve of it
    // back-filled one, say).
    let head = lineage_with(&pool, agent, new).await;

    let p = pool.clone();
    assert_cascade_waits_for_evolve(&pool, head, "supersede", async move {
        on_maintenance(p, |mut conn| async move {
            ClaimRepository::migrate_superseded_edges_conn(&mut conn, old, new)
                .await
                .expect("supersede edge migration");
            (conn, ())
        })
        .await;
    })
    .await;
    assert_eq!(
        target_of(&pool, edge).await,
        new,
        "the executes edge moved onto the successor"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_dedup_repair_waits_for_an_evolve_of_the_canonicals_lineage(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "repoint-dedup").await;
    let workflow = seed_workflow(&pool).await;
    let dup = seed_step(&pool, agent, "dedup: the duplicate step").await;
    let canonical = seed_step(&pool, agent, "dedup: the canonical step").await;
    let edge = seed_executes(&pool, workflow, dup).await;
    let head = lineage_with(&pool, agent, canonical).await;

    let mut tx = pool.begin().await.unwrap();
    ClaimRepository::mark_duplicate_act_conn(
        &mut tx,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup act");
    tx.commit().await.unwrap();

    let p = pool.clone();
    assert_cascade_waits_for_evolve(&pool, head, "dedup", async move {
        on_maintenance(p, |mut conn| async move {
            ClaimRepository::repair_marked_duplicate_conn(
                &mut conn,
                ClaimId::from_uuid(dup),
                ClaimId::from_uuid(canonical),
            )
            .await
            .expect("dedup repair");
            (conn, ())
        })
        .await;
    })
    .await;
    assert_eq!(
        target_of(&pool, edge).await,
        canonical,
        "the executes edge moved onto the canonical"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_merge_cascade_waits_for_an_evolve_of_the_merged_claims_lineage(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "repoint-merge").await;
    let workflow = seed_workflow(&pool).await;
    let a = seed_step(&pool, agent, "merge: the first source").await;
    let b = seed_step(&pool, agent, "merge: the second source").await;
    let edge = seed_executes(&pool, workflow, a).await;

    let mut tx = pool.begin().await.unwrap();
    let merged = ClaimRepository::consolidate_act_conn(
        &mut tx,
        None,
        &[a, b],
        "merge: both sources, merged",
        0.6,
        ConsolidateMode::Merge,
        "merge",
        agent,
    )
    .await
    .expect("merge act")
    .merged_id;
    tx.commit().await.unwrap();
    let head = lineage_with(&pool, agent, merged).await;

    let p = pool.clone();
    assert_cascade_waits_for_evolve(&pool, head, "merge", async move {
        on_maintenance(p, |mut conn| async move {
            ClaimRepository::migrate_consolidated_edges_conn(&mut conn, merged, &[a, b])
                .await
                .expect("merge edge migration");
            (conn, ())
        })
        .await;
    })
    .await;
    assert_eq!(
        target_of(&pool, edge).await,
        merged,
        "the executes edge moved onto the merged claim"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_reversal_waits_for_an_evolve_of_the_duplicates_lineage(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "repoint-unmark").await;
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let workflow = seed_workflow(&pool).await;
    let dup = seed_step(&pool, agent, "unmark: the duplicate step").await;
    let canonical = seed_step(&pool, agent, "unmark: the canonical step").await;
    let edge = seed_executes(&pool, workflow, dup).await;
    let head = lineage_with(&pool, agent, dup).await;

    // Mark (the repair moves the executes edge onto the canonical), with the
    // combined privileged form.
    let mut conn = pool.acquire().await.unwrap();
    let repair = ClaimRepository::mark_duplicate_with_repair_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("mark");
    drop(conn);
    assert_eq!(
        target_of(&pool, edge).await,
        canonical,
        "fixture: the mark moved the executes edge onto the canonical"
    );

    // The un-mark's reversal re-targets it back onto the duplicate, a member
    // of the evolved lineage.
    let p = pool.clone();
    assert_cascade_waits_for_evolve(&pool, head, "un-mark", async move {
        let mut conn = p.acquire().await.unwrap();
        ClaimRepository::unmark_duplicate_with_reversal_conn(
            &mut conn,
            &bypass,
            ClaimId::from_uuid(dup),
            &repair.revert,
        )
        .await
        .expect("unmark");
    })
    .await;
    assert_eq!(
        target_of(&pool, edge).await,
        dup,
        "the executes edge moved back onto the duplicate"
    );
}

/// The other order: a dedup repair in flight (re-pointed, not committed)
/// holds the canonical's lineage key, so an evolve of that lineage waits for
/// it and then reads the re-pointed workflow into its authority set.
#[sqlx::test(migrations = "../../migrations")]
async fn an_evolve_waits_for_a_cascade_in_flight_then_counts_the_repointed_workflow(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "repoint-evolve-waits").await;
    let workflow = seed_workflow(&pool).await;
    let dup = seed_step(&pool, agent, "evolve-waits: the duplicate step").await;
    let canonical = seed_step(&pool, agent, "evolve-waits: the canonical step").await;
    let edge = seed_executes(&pool, workflow, dup).await;
    let head = lineage_with(&pool, agent, canonical).await;

    let mut tx = pool.begin().await.unwrap();
    ClaimRepository::mark_duplicate_act_conn(
        &mut tx,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup act");
    tx.commit().await.unwrap();

    // Before the cascade, the lineage runs no workflow.
    {
        let mut c = pool.begin().await.unwrap();
        assert!(
            WorkflowRepository::workflows_executing_step_lineage(&mut c, head)
                .await
                .unwrap()
                .is_empty(),
            "fixture: no workflow executes the lineage yet"
        );
        c.rollback().await.unwrap();
    }

    // The cascade, in an outer transaction kept open after the re-point.
    let mut cascade = pool.begin().await.unwrap();
    ClaimRepository::repair_marked_duplicate_conn(
        &mut cascade,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup repair");

    let epool = pool.clone();
    let mut evolve = tokio::spawn(async move {
        let mut c = epool.begin().await.unwrap();
        assert!(
            WorkflowRepository::lock_step_lineage_for_evolve(&mut c, head)
                .await
                .unwrap()
        );
        let set = WorkflowRepository::workflows_executing_step_lineage(&mut c, head)
            .await
            .unwrap();
        c.rollback().await.unwrap();
        set
    });
    let mut queued = false;
    for _ in 0..200 {
        assert!(
            !evolve.is_finished(),
            "the evolve took the lineage lock and read its authority set while a cascade \
             re-pointing an executes edge onto the lineage was in flight"
        );
        if advisory_waiters(&pool).await > 0 {
            queued = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(queued, "the evolve queues on the lineage lock");
    cascade.commit().await.unwrap();
    let set = tokio::time::timeout(CASCADE_DEADLINE, &mut evolve)
        .await
        .expect("the evolve proceeds once the cascade commits")
        .unwrap();
    assert_eq!(
        target_of(&pool, edge).await,
        canonical,
        "the cascade moved the executes edge onto the canonical"
    );
    assert_eq!(
        set,
        vec![workflow],
        "the evolve's authority set includes the re-pointed workflow"
    );
}
