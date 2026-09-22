//! FINAL-PLAN §8.6 — `privatization_drift.rs`.
//!
//! "insert a `derived_from` child mid-apply; assert the edge guard refuses it,
//! and that a maintenance-pool insert is caught by the post-apply rescan and
//! produces a follow-up plan (sec F9)."
//!
//! # ONE OF THE TWO ARMS. The rescan ships; the write-path companion does not.
//!
//! §6.5.5's sec-F9 fix has two halves. Half (1), the post-apply rescan, is what
//! this binary measures and what this slice ships. Half (2) is a companion
//! trigger on `edges`, which is a tier-A write path shared by every fixture in
//! five crates; it is deferred with an owner rather than smuggled into a feature
//! PR, and the deferral is recorded in `docs/tenancy/progress.json` as
//! `D-PR18-drift-write-guard`.
//!
//! So the assertions below are exactly the rescan arm, and the file says so
//! rather than implying both arms are covered.

#[path = "privatization_fixture.rs"]
mod fx;

use fx::viewer_fixture;
use sqlx::PgPool;
use uuid::Uuid;

/// A restatement inserted between the freeze and the apply is reported by the
/// post-apply rescan and turned into a follow-up plan.
///
/// # What makes this a real measurement rather than a re-selection
///
/// The child is created AFTER `create_plan` has frozen the item set, so it is
/// not in `privatization_plan_items` and no amount of re-reading the plan would
/// find it. The only thing that can is a rescan of the corpus around the APPLIED
/// ids, which is the code under test. The calibration below asserts the frozen
/// set really is one item, because a fixture that created the child first would
/// have the closure pull it in and the test would pass with the rescan deleted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_restatement_inserted_after_the_freeze_is_caught_by_the_post_apply_rescan(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;

    let parent = viewer_fixture::seed_public_claim(&pool, world.actor, "drift parent").await;
    let (plan, _) = fx::create_plan(&pool, &world, &[parent]).await;
    let frozen = fx::items(&pool, plan).await;
    assert_eq!(
        frozen.len(),
        1,
        "CALIBRATION: the frozen set must be the parent alone. If the child existed at freeze \
         time the closure would carry it, the plan would privatize it, and this test would pass \
         with the rescan removed"
    );

    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;

    // MID-FLIGHT. A writer restates the parent's content while the plan is
    // dispatched and before the batch runs.
    let child = viewer_fixture::seed_public_claim(&pool, world.actor, "drift child").await;
    fx::derived_from(&pool, child, parent).await;

    fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50)
        .await
        .expect("apply");

    assert_eq!(
        fx::plan_state(&pool, plan).await,
        "applied_with_drift",
        "a plan whose rescan found a restatement must land in `applied_with_drift`, not in \
         `applied`. The difference is the whole signal: `applied` tells an operator the region is \
         private, and it is not"
    );

    let drift_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT unnest(drift_ids) FROM privatization_plans WHERE id = $1")
            .bind(plan)
            .fetch_all(&pool)
            .await
            .expect("read drift_ids");
    assert_eq!(
        drift_ids,
        vec![child],
        "drift_ids must name the restatement and nothing else. The applied parent must NOT be in \
         it — it is already private, and reporting it as drift would make every plan report drift"
    );

    let actions = fx::audit_actions(&pool, plan).await;
    assert_eq!(
        actions.iter().filter(|a| *a == "plan.drift").count(),
        1,
        "§6.5.5 requires one `plan.drift` audit row PER drifted id, got {actions:?}"
    );

    // The follow-up plan: `previewed`, same target group, carrying the drifted
    // id. `previewed` and not applied, because a handler that privatized rows
    // nobody selected would be the standing privatization rule §6.5.1 refuses to
    // ship — the operator reviews it through the ordinary four-eyes surface.
    let followups: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, state FROM privatization_plans \
          WHERE id <> $1 AND target_group_id = $2",
    )
    .bind(plan)
    .bind(world.target_group)
    .fetch_all(&pool)
    .await
    .expect("read follow-up plans");
    assert_eq!(
        followups.len(),
        1,
        "exactly one follow-up plan, got {followups:?}"
    );
    let (followup_id, followup_state) = &followups[0];
    assert_eq!(
        followup_state, "previewed",
        "the follow-up must arrive in `previewed` so it goes through approval like any other plan"
    );
    let followup_items: Vec<Uuid> = fx::items(&pool, *followup_id)
        .await
        .into_iter()
        .map(|(id, _, _)| id)
        .collect();
    assert_eq!(
        followup_items,
        vec![child],
        "the follow-up must be frozen over the drifted ids"
    );
}

/// The auto-created follow-up plan carries a COMPUTED `authors_losing_count`
/// and a selector that describes the drift set.
///
/// # Why the number is load-bearing rather than bookkeeping
///
/// Three independent gates key on `authors_losing_count > 0`: `apply_plan`'s
/// second-approver `428`, the handler's re-validation condition 2, and
/// condition 5's `acknowledge_author_loss` requirement. The follow-up inherits
/// `mode` from its source, so a plan written with a hardcoded zero would route a
/// privatization that costs authors access to their own claims through the
/// single-approver path — the one shape the four-eyes rule exists to refuse. The
/// selector matters for the same surface: the follow-up is reviewed by a second
/// admin, and an empty seed list tells that reviewer nothing about what they are
/// approving.
#[sqlx::test(migrations = "../../migrations")]
async fn the_follow_up_plan_computes_its_own_author_loss_count(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;

    let parent = viewer_fixture::seed_public_claim(&pool, world.actor, "loss parent").await;
    let (plan, _) = fx::create_plan(&pool, &world, &[parent]).await;
    assert_eq!(
        fx::plan_shape(&pool, plan).await.2,
        0,
        "CALIBRATION: the SOURCE plan must lose no author — its claim is the actor's and the \
         actor is in the target group — or a non-zero follow-up count could be an inheritance \
         rather than a computation"
    );

    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;

    // MID-FLIGHT, and written by an agent who is NOT a member of the target
    // group: privatizing this restatement costs its author read access to their
    // own claim.
    let (outsider, _) = viewer_fixture::seed_agent_with_group(&pool, "drift-outsider").await;
    let child = viewer_fixture::seed_public_claim(&pool, outsider, "loss child").await;
    fx::derived_from(&pool, child, parent).await;

    fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50)
        .await
        .expect("apply");
    assert_eq!(fx::plan_state(&pool, plan).await, "applied_with_drift");

    let (followup, selector): (Uuid, serde_json::Value) = sqlx::query_as(
        "SELECT id, selector FROM privatization_plans WHERE id <> $1 AND target_group_id = $2",
    )
    .bind(plan)
    .bind(world.target_group)
    .fetch_one(&pool)
    .await
    .expect("read the follow-up plan");

    let (state, mode, authors_losing, item_count) = fx::plan_shape(&pool, followup).await;
    assert_eq!(state, "previewed");
    assert_eq!(mode, "restrict", "the follow-up inherits its source's mode");
    assert_eq!(item_count, 1);
    assert_eq!(
        authors_losing, 1,
        "the follow-up must count the author it would cost access, not assert zero"
    );

    assert_eq!(
        selector["seeds"]["ids"]["claims"],
        serde_json::json!([child]),
        "the follow-up's selector must describe the drift set; the reviewer asked to approve it \
         sees this field and nothing else about its scope"
    );
    assert_eq!(
        selector["origin"]["drift_rescan_of"],
        serde_json::json!(plan),
        "and it must say which plan's rescan produced it"
    );
}

/// A plan with no drift lands in `applied` and creates no follow-up.
///
/// The negative direction, and it is not decorative: a rescan that reported
/// every claim within one hop — or that failed to exclude the applied set —
/// would satisfy the positive test above and turn every privatization into an
/// unbounded chain of follow-up plans against the same group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_plan_with_no_restatement_lands_applied_and_creates_no_follow_up(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;

    let parent = viewer_fixture::seed_public_claim(&pool, world.actor, "quiet parent").await;
    let child = viewer_fixture::seed_public_claim(&pool, world.actor, "quiet child").await;
    // An EPISTEMIC-tier edge. It is a real relationship between the two claims
    // and it is deliberately not a restatement, so the rescan must ignore it.
    viewer_fixture::seed_edge(&pool, child, parent).await;

    let (plan, _) = fx::create_plan(&pool, &world, &[parent]).await;
    assert_eq!(fx::items(&pool, plan).await.len(), 1);

    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50)
        .await
        .expect("apply");

    assert_eq!(
        fx::plan_state(&pool, plan).await,
        "applied",
        "a `supports` neighbour is the epistemic tier and is not a restatement of the private \
         claim's content; reporting it as drift would privatize every claim that disagrees with \
         a private one"
    );
    assert_eq!(fx::tenancy(&pool, child).await.0, "public");
    let plans: i64 = sqlx::query_scalar("SELECT count(*) FROM privatization_plans")
        .fetch_one(&pool)
        .await
        .expect("count plans");
    assert_eq!(
        plans, 1,
        "no follow-up plan may be created when there is no drift"
    );
    assert!(!fx::audit_actions(&pool, plan)
        .await
        .iter()
        .any(|a| a == "plan.drift"));
}
