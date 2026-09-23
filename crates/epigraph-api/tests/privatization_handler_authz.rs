//! **Acceptance clause 8, and the five other conditions beside it.**
//!
//! "a hand-enqueued `privatization_apply` job is refused by the handler (sec F5)."
//!
//! # Where §8.6 puts this file, and why it is not there
//!
//! §8.6 assigns this regression to `crates/epigraph-db/tests/privatization_authz.rs`.
//! The thing under test is `epigraph_jobs::privatization`, and `epigraph-jobs`
//! depends on `epigraph-db` — so putting it there would mean adding
//! `epigraph-jobs` as a dev-dependency of `epigraph-db`. Cargo permits that, so
//! it is not impossible; it is a new build-graph edge from the schema crate back
//! to a consumer of it, for a test. `epigraph-api` already depends on both.
//! Recorded in `docs/tenancy/progress.json`.
//!
//! # THE VACUITY TRAP THIS FILE IS BUILT AROUND
//!
//! Migration 077's `jobs_app` policy carries
//! `job_type NOT IN ('privatization_apply', …)` in its `WITH CHECK`, so an
//! `INSERT INTO jobs` issued by `epigraph_app` is refused at the INSERT. A
//! regression written on a downgraded pool therefore fails before the handler is
//! ever called and reports a green measurement of the POLICY.
//!
//! FINAL-PLAN §6.5.5 and §8.6 both say "refused by **the handler**". So every
//! test below calls `JobHandler::handle` DIRECTLY, with a `Job` value built in
//! Rust and never inserted anywhere. That is strictly stronger than enqueueing:
//! it models an adversary who has already got a job row past every enqueue-side
//! control, which is the premise §6.5.5 states — "anything that can insert a
//! `jobs` row could otherwise apply an unapproved, un-second-approved,
//! stale-digest plan with full RLS bypass".
//!
//! # Every test asserts the same three consequences
//!
//! A refusal is not just an `Err`. §6.5.5: "Every refusal writes
//! `privatization_audit(action='plan.abort')` and sets `state='failed'`." And
//! the point of the whole exercise is that NO ROW MOVED. All three are asserted
//! every time, because a handler that returned `Err` after privatizing the
//! corpus would satisfy the first alone.

#[path = "privatization_fixture.rs"]
mod fx;

use epigraph_db::repos::privatization::{PlanTransition, PrivatizationRepository};
use epigraph_db::visibility::SystemReason;
use epigraph_jobs::JobError;
use fx::viewer_fixture;
use sqlx::PgPool;
use uuid::Uuid;

/// Assert the three consequences of a refusal.
async fn assert_refused(
    pool: &PgPool,
    plan: Uuid,
    claim: Uuid,
    outcome: Result<impl Sized, JobError>,
) {
    let err = outcome
        .map(|_| ())
        .expect_err("the handler must refuse this job");
    assert!(
        matches!(err, JobError::PermanentFailure { .. }),
        "a refusal must be PERMANENT. A transient failure is re-dispatched by the reaper, so a \
         forged job would be retried against the plan every ninety minutes. Got {err:?}"
    );
    assert_eq!(
        fx::plan_state(pool, plan).await,
        "failed",
        "§6.5.5: every refusal sets state='failed'"
    );
    assert!(
        fx::audit_actions(pool, plan)
            .await
            .iter()
            .any(|a| a == "plan.abort"),
        "§6.5.5: every refusal writes privatization_audit(action='plan.abort')"
    );
    assert_eq!(
        fx::tenancy(pool, claim).await.0,
        "public",
        "NO ROW MAY MOVE. This is the assertion the whole file exists for: a handler that \
         returned an error after privatizing the corpus would satisfy every other assertion here"
    );
    let states: Vec<String> = fx::items(pool, plan)
        .await
        .into_iter()
        .map(|(_, _, s)| s)
        .collect();
    assert!(
        states.iter().all(|s| s == "pending"),
        "no item may leave `pending` on a refused run, got {states:?}"
    );
}

/// A job for a plan that was never dispatched is refused (condition 1).
///
/// This is the bare shape of clause 8: an attacker who can produce a `jobs` row
/// picks a plan id that exists, names themselves, and runs. The plan is still
/// `previewed` — nobody flipped it — and that alone is the refusal.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hand_enqueued_job_for_an_undispatched_plan_is_refused(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let claim = viewer_fixture::seed_public_claim(&pool, world.actor, "not yours").await;
    let (plan, _) = fx::create_plan(&pool, &world, &[claim]).await;
    assert_eq!(fx::plan_state(&pool, plan).await, "previewed");

    let job = fx::apply_job(plan, world.actor, "forged-correlation");
    let outcome = fx::run_apply(&scoped, &job, 50).await;
    assert_refused(&pool, plan, claim, outcome).await;
}

/// A job whose correlation id names no audited request is refused (condition 6).
///
/// The harder half of clause 8, and the one a plausible forgery reaches: the
/// plan really is `applying`, `dispatched_by` really is the agent in the
/// payload, and the only thing missing is the `security_events` row the HTTP
/// layer writes in the same transaction as the flip. Without this condition a
/// second job for a legitimately dispatched plan — a replay — would run.
#[sqlx::test(migrations = "../../migrations")]
async fn a_job_whose_correlation_id_names_no_audited_request_is_refused(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let claim = viewer_fixture::seed_public_claim(&pool, world.actor, "replayed").await;
    let (plan, _) = fx::create_plan(&pool, &world, &[claim]).await;

    let real = fx::dispatch(&pool, &world, plan, "applying").await;
    let forged = format!("{real}-but-not");
    let outcome = fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &forged), 50).await;
    assert_refused(&pool, plan, claim, outcome).await;
}

/// A job that names a DIFFERENT agent than the one the flip recorded is refused
/// (condition 6, first half).
///
/// The two halves of condition 6 are independent and both are needed. This one
/// catches a payload whose `dispatched_by` was rewritten after the fact; the
/// test above catches a payload whose correlation id was invented. A handler
/// that checked only the correlation id would accept a job that attributed a
/// legitimate dispatch to somebody else, and every `privatization_audit` row the
/// run wrote would carry that name.
#[sqlx::test(migrations = "../../migrations")]
async fn a_job_that_reattributes_a_real_dispatch_is_refused(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let claim = viewer_fixture::seed_public_claim(&pool, world.actor, "misattributed").await;
    let (plan, _) = fx::create_plan(&pool, &world, &[claim]).await;
    let impostor = fx::add_admin(&pool, world.target_group, "impostor").await;

    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    let outcome = fx::run_apply(&scoped, &fx::apply_job(plan, impostor, &correlation), 50).await;
    assert_refused(&pool, plan, claim, outcome).await;
}

/// A correlation id issued for ONE plan does not authorise a job naming another
/// (condition 6, the subject binding).
///
/// §6.5.5's wording is "the `security_events` row the HTTP layer wrote for THIS
/// `correlation_id`" for THIS dispatch. Asked without the subject, the question
/// degrades to "did this agent ever dispatch something under this correlation
/// id", and a legitimately issued id would carry over to any other plan the same
/// admin had dispatched. The dispatching route already writes the plan id into
/// `security_events.details`, so the binding is a comparison rather than a new
/// column.
#[sqlx::test(migrations = "../../migrations")]
async fn a_correlation_id_issued_for_another_plan_does_not_authorise_this_one(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let mine = viewer_fixture::seed_public_claim(&pool, world.actor, "subject a").await;
    let theirs = viewer_fixture::seed_public_claim(&pool, world.actor, "subject b").await;
    let (plan_a, _) = fx::create_plan(&pool, &world, &[mine]).await;
    let (plan_b, _) = fx::create_plan(&pool, &world, &[theirs]).await;

    // Both plans are dispatched by the same admin, so `dispatched_by` agrees for
    // either. Only the SUBJECT tells the two correlation ids apart.
    //
    // `privatization_one_active_per_group` is unique on `target_group_id` over
    // the running states, so plan A is retired before plan B is dispatched —
    // which is also the realistic shape: the correlation id outlives the run it
    // was issued for.
    let correlation_a = fx::dispatch(&pool, &world, plan_a, "applying").await;
    sqlx::query("UPDATE privatization_plans SET state = 'failed' WHERE id = $1")
        .bind(plan_a)
        .execute(&pool)
        .await
        .expect("retire the first plan");
    fx::dispatch(&pool, &world, plan_b, "applying").await;

    let outcome = fx::run_apply(
        &scoped,
        &fx::apply_job(plan_b, world.actor, &correlation_a),
        50,
    )
    .await;
    assert_refused(&pool, plan_b, theirs, outcome).await;
}

/// A refusal does NOT relabel a plan that already reached a terminal state.
///
/// # The arrival this covers
///
/// `postgres_queue.rs::recover_stale_jobs` resets any job still `running` past
/// its threshold back to `pending` — the recovery these handlers' one-attempt
/// budget leans on. A worker that committed the terminal write and then died
/// before marking the job complete therefore has its job re-delivered, and the
/// re-delivered job finds a plan in `applied`, which condition 1 refuses. The
/// refusal must stop there: relabelling `applied` as `failed` would tell the
/// operator that a privatization which fully succeeded had failed, and would
/// name its author as the aborter, while every item still says `applied`.
///
/// The other direction is asserted too, because a `from_states` list that
/// covered nothing would also pass the first assertion.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refusal_leaves_a_plan_that_already_finished_alone(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let claim = viewer_fixture::seed_public_claim(&pool, world.actor, "redelivered").await;
    let (plan, _) = fx::create_plan(&pool, &world, &[claim]).await;

    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    let job = fx::apply_job(plan, world.actor, &correlation);
    fx::run_apply(&scoped, &job, 50).await.expect("apply");
    assert_eq!(fx::plan_state(&pool, plan).await, "applied");

    // THE SAME JOB VALUE, DELIVERED AGAIN. The plan is terminal now, so
    // condition 1 refuses — and the refusal must not move it.
    let outcome = fx::run_apply(&scoped, &job, 50).await;
    assert!(
        matches!(
            outcome,
            Err(epigraph_jobs::JobError::PermanentFailure { .. })
        ),
        "a re-delivered job for a finished plan is still refused"
    );
    assert_eq!(
        fx::plan_state(&pool, plan).await,
        "applied",
        "a refusal must not relabel a plan that already reached a terminal state; the run \
         succeeded and every item says so"
    );
    assert_eq!(
        fx::tenancy(&pool, claim).await.0,
        "group",
        "and the applied rows stay applied"
    );

    // CALIBRATION for the other direction: the same refusal on a plan that is
    // still pre-terminal DOES fail it, so the state list is not simply inert.
    let other = viewer_fixture::seed_public_claim(&pool, world.actor, "undispatched").await;
    let (pending_plan, _) = fx::create_plan(&pool, &world, &[other]).await;
    let outcome = fx::run_apply(
        &scoped,
        &fx::apply_job(pending_plan, world.actor, "forged"),
        50,
    )
    .await;
    assert_refused(&pool, pending_plan, other, outcome).await;
}

/// A plan whose frozen set moved under it is refused on the RECOMPUTED digest
/// (condition 4).
///
/// The condition is worth its weight only because the digest is recomputed from
/// `privatization_plan_items` at dispatch time. Reading the stored digest twice
/// and comparing it with itself would pass this test if the comparison were
/// written that way and the items were not consulted at all, which is why the
/// mutation here is to the ITEMS and not to the stored digest.
#[sqlx::test(migrations = "../../migrations")]
async fn a_plan_whose_frozen_items_changed_is_refused_on_the_recomputed_digest(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let parent = viewer_fixture::seed_public_claim(&pool, world.actor, "digest parent").await;
    let child = viewer_fixture::seed_public_claim(&pool, world.actor, "digest child").await;
    fx::derived_from(&pool, child, parent).await;
    let (plan, _) = fx::create_plan(&pool, &world, &[parent]).await;
    assert_eq!(fx::items(&pool, plan).await.len(), 2);

    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;

    // Remove one frozen item. The stored `plan_digest` still describes the
    // two-item set; the items are now a one-item set.
    sqlx::query("DELETE FROM privatization_plan_items WHERE plan_id = $1 AND entity_id = $2")
        .bind(plan)
        .bind(child)
        .execute(&pool)
        .await
        .expect("mutate the frozen set");

    let outcome = fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50).await;
    assert_refused(&pool, plan, parent, outcome).await;
}

/// A plan over the dual-control threshold with no approver is refused
/// (condition 2).
#[sqlx::test(migrations = "../../migrations")]
async fn a_plan_that_needs_a_second_approver_and_has_none_is_refused(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let claim = viewer_fixture::seed_public_claim(&pool, world.actor, "unapproved").await;
    let (plan, _) = fx::create_plan(&pool, &world, &[claim]).await;

    // `authors_losing_count > 0` is the OTHER arm of §6.5.5's threshold — the
    // one that does not need a thousand claims to reach, and the one that
    // matters most, because it means a living author loses their own work.
    set_authors_losing(&pool, plan, 1).await;

    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    let outcome = fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50).await;
    assert_refused(&pool, plan, claim, outcome).await;
}

/// An approver whose target-group admin membership was revoked between approve
/// and dispatch is refused (condition 3).
///
/// §6.5.5 calls this out by name: migration 081's approver guard fires on the
/// approving UPDATE and cannot see what happens afterwards, so the handler
/// re-checks. Without the re-check, an approval survives the authority that gave
/// it — and the window is exactly the one an operator uses when they revoke
/// somebody's access in a hurry.
#[sqlx::test(migrations = "../../migrations")]
async fn an_approver_whose_membership_was_revoked_after_approving_is_refused(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let claim = viewer_fixture::seed_public_claim(&pool, world.actor, "stale approval").await;
    let (plan, _) = fx::create_plan(&pool, &world, &[claim]).await;
    set_authors_losing(&pool, plan, 1).await;

    let approver = fx::add_admin(&pool, world.target_group, "second-pair-of-eyes").await;
    approve(&pool, plan, approver).await;

    // CALIBRATION: with the approver still live the same plan is ACCEPTED. This
    // is what makes the refusal below a measurement of the revocation rather
    // than of an approval path that never worked.
    let ok_plan = {
        let other = viewer_fixture::seed_public_claim(&pool, world.actor, "live approval").await;
        let (p, _) = fx::create_plan(&pool, &world, &[other]).await;
        set_authors_losing(&pool, p, 1).await;
        approve(&pool, p, approver).await;
        let correlation = fx::dispatch(&pool, &world, p, "applying").await;
        fx::run_apply(&scoped, &fx::apply_job(p, world.actor, &correlation), 50)
            .await
            .expect("a live approver's plan must be accepted");
        p
    };
    assert_eq!(fx::plan_state(&pool, ok_plan).await, "applied");

    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() \
          WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(world.target_group)
    .bind(approver)
    .execute(&pool)
    .await
    .expect("revoke the approver");

    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    let outcome = fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50).await;
    assert_refused(&pool, plan, claim, outcome).await;
}

/// Set `authors_losing_count`, which is what puts a plan over §6.5.5's
/// dual-control threshold without seeding a thousand claims.
async fn set_authors_losing(pool: &PgPool, plan: Uuid, count: i32) {
    sqlx::query("UPDATE privatization_plans SET authors_losing_count = $2 WHERE id = $1")
        .bind(plan)
        .bind(count)
        .execute(pool)
        .await
        .expect("set authors_losing_count");
}

/// Approve `plan` as `approver`, through the production transition.
async fn approve(pool: &PgPool, plan: Uuid, approver: Uuid) {
    let scoped = viewer_fixture::scoped_pool(pool).await;
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(SystemReason::PrivatizationApply)
        .await
        .expect("maintenance connection");
    let moved = PrivatizationRepository::transition_plan_conn(
        &mut conn,
        plan,
        PlanTransition::Approve { approver },
    )
    .await
    .expect("approve");
    assert_eq!(moved, 1, "CALIBRATION: the approval must take");
}
