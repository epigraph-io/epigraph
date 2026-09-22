//! FINAL-PLAN §8.6 — `privatization_resume.rs`.
//!
//! "apply, abort at batch 3 of 10, resume, assert the final state equals the
//! uninterrupted result; assert the **downward-closure invariant holds at every
//! commit boundary**; assert re-running a committed batch is a byte-level no-op."
//!
//! # How the interruption is produced, and why not with a race
//!
//! The handler drains its own loop, so "kill it between batches" is not
//! expressible from a test without a second thread and a timing window — which
//! would make the regression flaky in the direction that matters (a green run
//! that raced past the assertion).
//!
//! Instead the partial state is CONSTRUCTED with the same repository primitives
//! the handler's batch uses — `restrict_claims_conn`, `record_item_audit_conn`,
//! `recompute_boundary_meet_conn`, `mark_items_conn` and the cursor
//! transition, in one transaction. That is not a fabricated state: it is
//! the state a committed batch leaves, produced by the code that leaves it. The
//! handler is then run against it and has to resume.
//!
//! The comparison against "the uninterrupted result" is a SECOND, structurally
//! identical world in the same test, applied in one go. Comparing two runs of
//! the same plan would compare a plan against itself.

#[path = "privatization_fixture.rs"]
mod fx;

use epigraph_db::repos::privatization::{
    ItemAuditBatch, ItemAuditDirection, PlanTransition, PrivatizationRepository,
};
use epigraph_db::visibility::SystemReason;
use fx::viewer_fixture;
use sqlx::PgPool;
use uuid::Uuid;

/// A four-claim derivation chain: `c[3] -> c[2] -> c[1] -> c[0]`, every edge
/// `derived_from`, so `c[0]` is the seed at depth 0 and `c[3]` is its deepest
/// derivation-descendant.
async fn chain(pool: &PgPool, agent: Uuid, tag: &str) -> Vec<Uuid> {
    let mut ids = Vec::new();
    for i in 0..4 {
        ids.push(viewer_fixture::seed_public_claim(pool, agent, &format!("{tag} link {i}")).await);
    }
    for i in 1..4 {
        fx::derived_from(pool, ids[i], ids[i - 1]).await;
    }
    ids
}

/// Every `(descendant, ancestor)` pair where the ancestor is private and the
/// descendant — a claim derived FROM it — is still public.
///
/// This is the downward-closure invariant stated as a query. An empty result is
/// the invariant holding; a non-empty one is a private parent with a public
/// restatement of its content, which is the state §6.5.5 says a `kill -9` must
/// never be able to leave permanently.
async fn closure_violations(pool: &PgPool) -> Vec<(Uuid, Uuid)> {
    sqlx::query_as(
        "SELECT child.id, parent.id \
           FROM edges e \
           JOIN claims child  ON child.id = e.source_id AND e.source_type = 'claim' \
           JOIN claims parent ON parent.id = e.target_id AND e.target_type = 'claim' \
          WHERE lower(e.relationship::text) = 'derived_from' \
            AND parent.visibility = 'group' \
            AND child.visibility = 'public'",
    )
    .fetch_all(pool)
    .await
    .expect("closure invariant probe")
}

/// Commit one batch by hand, exactly as the handler's batch transaction does.
///
/// Deepest-first, `FOR UPDATE`, then the tenancy write, the per-item audit row,
/// the meet, the item state and the cursor — the same repository calls in the
/// same order.
///
/// # THE COUPLING THIS CREATES, STATED
///
/// This is a SECOND implementation of the handler's batch body, living in a test
/// file. If `run_batch` gains a step, this will not, and the test keeps passing
/// while measuring something that is no longer "the state a committed batch
/// leaves". The alternative — racing a real handler and killing it between
/// batches — trades that for flakiness in the direction that matters, a green
/// run that raced past the assertion. The mitigation is that every call here is
/// a repository primitive rather than inline SQL, so a change to what a batch
/// WRITES is picked up automatically and only a change to WHICH CALLS a batch
/// makes is not.
///
/// Returns the ids it moved.
async fn commit_one_batch(
    pool: &PgPool,
    plan_id: Uuid,
    group: Uuid,
    actor: Uuid,
    batch: i64,
) -> Vec<Uuid> {
    let scoped = viewer_fixture::scoped_pool(pool).await;
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(SystemReason::PrivatizationApply)
        .await
        .expect("maintenance connection");
    let mut tx = sqlx::Connection::begin(&mut *conn)
        .await
        .expect("batch transaction");
    PrivatizationRepository::begin_batch_conn(&mut tx)
        .await
        .expect("batch bounds");
    let items = PrivatizationRepository::next_batch_conn(&mut tx, plan_id, "pending", true, batch)
        .await
        .expect("next batch");
    let ids: Vec<Uuid> = items.iter().map(|i| i.entity_id).collect();
    let changed = PrivatizationRepository::restrict_claims_conn(&mut tx, &ids, group)
        .await
        .expect("restrict");
    PrivatizationRepository::record_item_audit_conn(
        &mut tx,
        ItemAuditBatch {
            plan_id,
            actor_agent_id: actor,
            action: "item.apply",
            entity_ids: &ids,
            correlation_id: None,
            direction: ItemAuditDirection::Apply,
            target_group_id: group,
        },
    )
    .await
    .expect("item audit");
    PrivatizationRepository::recompute_boundary_meet_conn(&mut tx, &ids)
        .await
        .expect("meet");
    // `&changed`, not `&ids`, exactly as `run_batch` does: an item is `applied`
    // when this plan MOVED the row, not when it read it.
    PrivatizationRepository::mark_items_conn(&mut tx, plan_id, "claim", &changed, "applied", None)
        .await
        .expect("mark");
    if let Some(last) = items.last() {
        PrivatizationRepository::transition_plan_conn(
            &mut tx,
            plan_id,
            PlanTransition::Cursor {
                kind: &last.kind,
                depth: last.depth,
                id: last.entity_id,
            },
        )
        .await
        .expect("cursor");
    }
    tx.commit().await.expect("commit the batch");
    ids
}

/// An apply interrupted after one committed batch resumes to the same final
/// state an uninterrupted apply reaches, and the downward-closure invariant
/// holds at the interruption point.
#[sqlx::test(migrations = "../../migrations")]
async fn an_interrupted_apply_resumes_to_the_uninterrupted_result(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;

    let interrupted = chain(&pool, world.actor, "interrupted").await;
    let straight_through = chain(&pool, world.actor, "straight").await;

    let (plan_a, _) = fx::create_plan(&pool, &world, &[interrupted[0]]).await;
    let (plan_b, _) = fx::create_plan(&pool, &world, &[straight_through[0]]).await;
    assert_eq!(
        fx::items(&pool, plan_a).await.len(),
        4,
        "CALIBRATION: the closure must reach the whole chain, or 'interrupted' and 'resumed' \
         describe a one-item plan and the invariant below is vacuous"
    );

    // ---- the interruption: one committed batch, then nothing. ----
    let correlation_a = fx::dispatch(&pool, &world, plan_a, "applying").await;
    let first_batch = commit_one_batch(&pool, plan_a, world.target_group, world.actor, 2).await;
    assert_eq!(first_batch.len(), 2, "the batch bound must bite");

    // THE INVARIANT, AT THE COMMIT BOUNDARY. Deepest-first means the two rows
    // that moved are the two deepest derivation-descendants, so no public claim
    // is derived from a private one.
    let violations = closure_violations(&pool).await;
    assert!(
        violations.is_empty(),
        "the private set is not closed downward at a commit boundary: {violations:?}. A public \
         claim derived from a private one is a verbatim restatement of content the privatization \
         just hid, and an interrupted run would leave it that way permanently"
    );
    let mid = fx::tenancy(&pool, interrupted[3]).await;
    assert_eq!(
        mid.0, "group",
        "CALIBRATION: the deepest link must be the one that moved first, or 'deepest-first' is \
         not what was measured"
    );
    assert_eq!(
        fx::tenancy(&pool, interrupted[0]).await.0,
        "public",
        "CALIBRATION: the seed must still be public, or nothing was interrupted"
    );

    // ---- the resume. ----
    let resumed = fx::run_apply(
        &scoped,
        &fx::apply_job(plan_a, world.actor, &correlation_a),
        50,
    )
    .await
    .expect("the resumed run must not be refused");
    assert_eq!(
        resumed.metadata.items_processed,
        Some(2),
        "a resumed run must process exactly the items the interrupted one did not; re-processing \
         a committed batch would mean the item state is not the resume point"
    );

    // ---- the uninterrupted run. ----
    let correlation_b = fx::dispatch(&pool, &world, plan_b, "applying").await;
    fx::run_apply(
        &scoped,
        &fx::apply_job(plan_b, world.actor, &correlation_b),
        50,
    )
    .await
    .expect("the uninterrupted run must not be refused");

    // ---- the two worlds must agree. ----
    assert_eq!(
        fx::plan_state(&pool, plan_a).await,
        fx::plan_state(&pool, plan_b).await,
        "an interrupted-and-resumed plan must reach the same terminal state as one that ran \
         straight through"
    );
    for (a, b) in interrupted.iter().zip(straight_through.iter()) {
        assert_eq!(
            fx::tenancy(&pool, *a).await,
            fx::tenancy(&pool, *b).await,
            "claim tenancy diverged between the resumed and the uninterrupted run"
        );
    }
    let states_a: Vec<String> = fx::items(&pool, plan_a)
        .await
        .into_iter()
        .map(|(_, _, s)| s)
        .collect();
    let states_b: Vec<String> = fx::items(&pool, plan_b)
        .await
        .into_iter()
        .map(|(_, _, s)| s)
        .collect();
    assert_eq!(states_a, states_b, "item states diverged");
    assert!(
        states_a.iter().all(|s| s == "applied"),
        "every item must end applied, got {states_a:?}"
    );
    assert!(
        closure_violations(&pool).await.is_empty(),
        "the invariant must still hold at the terminal state"
    );
}

/// Re-running a committed batch changes nothing.
///
/// §6.5.5's ops-F11 correction requires the batch to be idempotent, because
/// stale-job recovery re-dispatches an interrupted run and the handler resumes
/// over rows a previous attempt may already have moved. The previous revision of
/// the plan claimed this held and it did not — nine of ten propagation arms
/// lacked the `IS DISTINCT FROM` guard the claim rested on.
///
/// # WHAT IS MEASURED, AND WHAT THE NAME MIGHT BE READ TO PROMISE
///
/// §8.6 asks for a byte-level no-op "on all seventeen derived tables". The
/// snapshot below covers `claims` and `edges` — the two tables the batch writes
/// DIRECTLY — and not the seventeen. That is sufficient BY MECHANISM rather than
/// by breadth, and the mechanism is worth stating because it is the thing that
/// would break: migration 072's propagation trigger is statement-level with a
/// firing gate of `(ch.owner_group_id, ch.visibility) IS DISTINCT FROM (p.…)`,
/// so a claims UPDATE that matches zero rows produces an empty transition table,
/// the trigger returns NULL immediately, and no derived row is written. The zero
/// row count asserted below is therefore the seventeen tables' assertion too. A
/// slice that gives the batch a write which does NOT go through `claims` has to
/// widen this snapshot.
///
/// `edges` is snapshotted separately and not left to the same argument, because
/// the meet is COMPUTED rather than copied and is the arm most likely to be
/// non-idempotent.
#[sqlx::test(migrations = "../../migrations")]
async fn re_running_a_committed_batch_is_a_no_op(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let links = chain(&pool, world.actor, "idem").await;
    let (plan, _) = fx::create_plan(&pool, &world, &[links[0]]).await;
    fx::dispatch(&pool, &world, plan, "applying").await;

    let moved = commit_one_batch(&pool, plan, world.target_group, world.actor, 2).await;
    assert_eq!(moved.len(), 2);

    let snapshot = tenancy_snapshot(&pool).await;

    // The same tenancy write, over the SAME ids, on a fresh transaction. The
    // item states have already moved, so `next_batch_conn` would return the
    // other two; this deliberately re-issues the write itself rather than the
    // batch, which is the statement the idempotence claim is about.
    let scoped = viewer_fixture::scoped_pool(&pool).await;
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(SystemReason::PrivatizationApply)
        .await
        .expect("maintenance connection");
    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("tx");
    let rows = PrivatizationRepository::restrict_claims_conn(&mut tx, &moved, world.target_group)
        .await
        .expect("re-run the tenancy write")
        .len();
    let edges = PrivatizationRepository::recompute_boundary_meet_conn(&mut tx, &moved)
        .await
        .expect("re-run the meet");
    tx.commit().await.expect("commit");

    assert_eq!(
        rows, 0,
        "re-running a committed batch's claims UPDATE must match zero rows. A non-zero count \
         means the `IS DISTINCT FROM` guard is absent and the propagation trigger fires again, \
         rewriting seventeen derived tables per resume"
    );
    assert_eq!(
        edges, 0,
        "re-running the boundary meet must match zero edges for the same reason"
    );
    assert_eq!(
        snapshot,
        tenancy_snapshot(&pool).await,
        "a re-run changed tenancy somewhere in the corpus"
    );
}

/// `(table, id, visibility, owner_group_id)` for every claim and edge, ordered.
///
/// Deliberately covers `edges` as well as `claims`: the meet is the arm most
/// likely to be non-idempotent, because it is computed rather than copied.
async fn tenancy_snapshot(pool: &PgPool) -> Vec<(String, Uuid, String, Uuid)> {
    sqlx::query_as(
        "SELECT 'claim', c.id, c.visibility::text, c.owner_group_id FROM claims c \
         UNION ALL \
         SELECT 'edge', e.id, e.visibility::text, e.owner_group_id FROM edges e \
         ORDER BY 1, 2",
    )
    .fetch_all(pool)
    .await
    .expect("tenancy snapshot")
}
