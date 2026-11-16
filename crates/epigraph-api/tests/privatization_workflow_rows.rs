//! Ruling R-98 Q8(a), backlog 630af617 (4), as the review addendum scopes it:
//! a privatization moves a `workflows` row with its plan only when the plan is
//! privatized AS A UNIT, records the row's pre-image in the plan's audit trail,
//! and a revert puts the row back exactly.
//!
//! The rule, decided in the apply batch's own transaction (behind the global
//! privatization lock, on the claims' state after the batch's UPDATE):
//!
//! * a PUBLIC row executing, at levels 0..2, a claim the batch moved becomes
//!   `('group', target)` only when EVERY level 0..2 claim it executes is now
//!   `('group', target)`; a row with one still-public structural claim, or one
//!   in another group, stays where it is;
//! * the move writes one `privatization_audit` row (`kind = 'workflow'`,
//!   `item.apply`) carrying the row's before and after tenancy;
//! * the revert, once every claim is back, restores each row this plan moved
//!   (and that still carries the plan's stamp) to that recorded pre-image, and
//!   records `item.revert`.
//!
//! Every test runs the real apply and revert handlers. The fully privatized
//! round trip runs them on a maintenance pool DOWNGRADED to
//! `epigraph_maintenance` (the role the job connection is), so the grants,
//! policies and 183's visibility guard on `workflows` are exercised rather
//! than bypassed by the superuser.

#[path = "privatization_fixture.rs"]
mod fx;

use std::sync::Arc;

use fx::viewer_fixture;
use sqlx::PgPool;
use uuid::Uuid;

/// A public level-`level` claim authored by the world's actor.
async fn structural_claim(pool: &PgPool, world: &fx::World, content: &str, level: i32) -> Uuid {
    let id = viewer_fixture::seed_public_claim(pool, world.actor, content).await;
    set_level(pool, id, level).await;
    id
}

async fn set_level(pool: &PgPool, claim: Uuid, level: i32) {
    sqlx::query(
        "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) \
                || jsonb_build_object('level', $2::int) WHERE id = $1",
    )
    .bind(claim)
    .bind(level)
    .execute(pool)
    .await
    .expect("set the claim's level");
}

/// A `workflows` row with the given tenancy (harness, superuser).
async fn workflow_row(pool: &PgPool, name: &str, visibility: &str, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, generation, metadata, visibility, \
                                owner_group_id) \
         VALUES ($1, $2, $3, 0, '{}'::jsonb, $4, $5)",
    )
    .bind(id)
    .bind(name)
    .bind(format!("goal of {name}"))
    .bind(visibility)
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed the workflows row");
    id
}

/// An `executes` edge `workflow -> claim` at `level`.
async fn executes(pool: &PgPool, workflow: Uuid, claim: Uuid, level: i32) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, $2, 'workflow', $3, 'claim', 'executes', jsonb_build_object('level', $4::int))",
    )
    .bind(Uuid::new_v4())
    .bind(workflow)
    .bind(claim)
    .bind(level)
    .execute(pool)
    .await
    .expect("seed the executes edge");
}

async fn row(pool: &PgPool, workflow: Uuid) -> (String, Uuid) {
    sqlx::query_as("SELECT visibility::text, owner_group_id FROM workflows WHERE id = $1")
        .bind(workflow)
        .fetch_one(pool)
        .await
        .expect("read the workflows row")
}

/// Every `kind = 'workflow'` audit row of `plan` as
/// `(action, entity, before_visibility, before_owner, after_visibility, after_owner)`.
type WorkflowAudit = (
    String,
    Uuid,
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<Uuid>,
);

async fn workflow_audit(pool: &PgPool, plan: Uuid) -> Vec<WorkflowAudit> {
    sqlx::query_as(
        "SELECT action, entity_id, before_visibility, before_owner_group_id, \
                after_visibility, after_owner_group_id \
           FROM privatization_audit WHERE plan_id = $1 AND kind = 'workflow' ORDER BY id",
    )
    .bind(plan)
    .fetch_all(pool)
    .await
    .expect("read the workflow audit rows")
}

/// The frozen claim set of `plan`, sorted.
async fn frozen(pool: &PgPool, plan: Uuid) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = fx::items(pool, plan)
        .await
        .into_iter()
        .map(|i| i.0)
        .collect();
    ids.sort();
    ids
}

fn sorted(mut ids: Vec<Uuid>) -> Vec<Uuid> {
    ids.sort();
    ids
}

/// Create, dispatch and apply a plan seeded on `seeds`, asserting it froze
/// exactly `seeds` (CALIBRATION: the closure and hull add nothing, so the
/// "partial" in a test is the partial it says it is).
async fn apply(
    pool: &PgPool,
    world: &fx::World,
    scoped: &Arc<epigraph_db::ScopedPool>,
    seeds: &[Uuid],
) -> Uuid {
    let (plan, _) = fx::create_plan(pool, world, seeds).await;
    assert_eq!(
        frozen(pool, plan).await,
        sorted(seeds.to_vec()),
        "CALIBRATION: the plan froze exactly its seeds"
    );
    let correlation = fx::dispatch(pool, world, plan, "applying").await;
    fx::run_apply(scoped, &fx::apply_job(plan, world.actor, &correlation), 1)
        .await
        .expect("apply");
    assert_eq!(fx::plan_state(pool, plan).await, "applied");
    plan
}

/// (1) A plan only PART of whose structural claims are privatized keeps its
/// row public: the row executes one restricted level-2 claim and one level-2
/// claim the plan leaves public. Moving it would hide a public plan from every
/// reader outside the target group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_partially_privatized_plan_keeps_its_workflows_row_public(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let (_, owner) = viewer_fixture::seed_agent_with_group(&pool, "wf-row-owner").await;
    let a = structural_claim(&pool, &world, "partial plan step a", 2).await;
    let b = structural_claim(&pool, &world, "partial plan step b", 2).await;
    let wf = workflow_row(&pool, "partial-plan", "public", owner).await;
    executes(&pool, wf, a, 2).await;
    executes(&pool, wf, b, 2).await;

    let plan = apply(&pool, &world, &scoped, &[a]).await;

    assert_eq!(
        fx::tenancy(&pool, a).await,
        ("group".to_string(), world.target_group),
        "CALIBRATION: the plan's claim moved"
    );
    assert_eq!(fx::tenancy(&pool, b).await.0, "public", "CALIBRATION");
    assert_eq!(
        row(&pool, wf).await,
        ("public".to_string(), owner),
        "a row with a still-public structural claim is not privatized as a unit and stays public"
    );
    assert_eq!(
        workflow_audit(&pool, plan).await,
        vec![],
        "no row move recorded"
    );
}

/// (2) A plan ALL of whose structural claims are privatized moves its row into
/// the target group, records the pre-image, and a revert puts it back
/// exactly. A level-3 operation atom the row also executes stays public and
/// does not hold the row back (183's rule: atoms say nothing about the plan).
/// Run on the `epigraph_maintenance` role the job connection is.
#[sqlx::test(migrations = "../../migrations")]
async fn a_fully_privatized_plans_row_moves_and_a_revert_restores_it_exactly(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let maintenance = viewer_fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let probe: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&maintenance)
        .await
        .expect("probe");
    assert_eq!(probe, "epigraph_maintenance", "CALIBRATION: downgraded");
    let scoped = Arc::new(
        viewer_fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(maintenance),
    );
    let (_, owner) = viewer_fixture::seed_agent_with_group(&pool, "wf-row-owner").await;
    let thesis = structural_claim(&pool, &world, "full plan thesis", 0).await;
    let a = structural_claim(&pool, &world, "full plan step a", 2).await;
    let b = structural_claim(&pool, &world, "full plan step b", 2).await;
    let atom = structural_claim(&pool, &world, "full plan shared atom", 3).await;
    let wf = workflow_row(&pool, "full-plan", "public", owner).await;
    for (claim, level) in [(thesis, 0), (a, 2), (b, 2), (atom, 3)] {
        executes(&pool, wf, claim, level).await;
    }

    // Batch size 1: the row must move with the LAST structural claim, not
    // with the first.
    let plan = apply(&pool, &world, &scoped, &[thesis, a, b]).await;

    assert_eq!(fx::tenancy(&pool, atom).await.0, "public", "CALIBRATION");
    assert_eq!(
        row(&pool, wf).await,
        ("group".to_string(), world.target_group),
        "a plan privatized as a unit takes its row with it"
    );
    assert_eq!(
        workflow_audit(&pool, plan).await,
        vec![(
            "item.apply".to_string(),
            wf,
            Some("public".to_string()),
            Some(owner),
            Some("group".to_string()),
            Some(world.target_group),
        )],
        "the row's pre-image is in the plan's audit trail"
    );

    let correlation = fx::dispatch(&pool, &world, plan, "reverting").await;
    fx::run_revert(&scoped, &fx::revert_job(plan, world.actor, &correlation), 1)
        .await
        .expect("revert");
    assert_eq!(fx::plan_state(&pool, plan).await, "reverted");
    for claim in [thesis, a, b] {
        assert_eq!(fx::tenancy(&pool, claim).await.0, "public", "CALIBRATION");
    }
    assert_eq!(
        row(&pool, wf).await,
        ("public".to_string(), owner),
        "the revert restores the row's recorded pre-image exactly"
    );
    let audit = workflow_audit(&pool, plan).await;
    assert_eq!(audit.len(), 2, "{audit:?}");
    assert_eq!(
        audit[1],
        (
            "item.revert".to_string(),
            wf,
            Some("group".to_string()),
            Some(world.target_group),
            Some("public".to_string()),
            Some(owner),
        ),
        "the restore is audited"
    );
}

/// (3) A row that executes, besides the plan's claim, a structural claim
/// private to ANOTHER group is not moved into the target group: the plan is
/// not the row's whole body, and moving it would take it away from the other
/// group's members.
#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_executing_another_groups_claims_is_not_moved(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let (other_agent, other) = viewer_fixture::seed_agent_with_group(&pool, "wf-other").await;
    let (_, owner) = viewer_fixture::seed_agent_with_group(&pool, "wf-row-owner").await;
    let a = structural_claim(&pool, &world, "mixed plan step a", 2).await;
    let theirs =
        viewer_fixture::seed_group_claim(&pool, other_agent, other, "mixed plan their step").await;
    set_level(&pool, theirs, 2).await;
    let wf = workflow_row(&pool, "mixed-plan", "public", owner).await;
    executes(&pool, wf, a, 2).await;
    executes(&pool, wf, theirs, 2).await;

    let plan = apply(&pool, &world, &scoped, &[a]).await;

    assert_eq!(
        fx::tenancy(&pool, a).await,
        ("group".to_string(), world.target_group),
        "CALIBRATION: the plan's claim moved"
    );
    assert_eq!(
        fx::tenancy(&pool, theirs).await,
        ("group".to_string(), other),
        "CALIBRATION: the other group's claim is untouched"
    );
    assert_eq!(
        row(&pool, wf).await,
        ("public".to_string(), owner),
        "a row executing another group's claims is not moved into the target group"
    );
    assert_eq!(workflow_audit(&pool, plan).await, vec![]);
}

/// (4) The decision is made on the state at APPLY, not at plan time. Between
/// the plan and the apply, one row gains a still-public level-2 step and
/// another is re-tenanted into a different group by a maintenance session:
/// neither is moved, and neither move is recorded. CALIBRATION: a third row,
/// unchanged since the plan, moves.
#[sqlx::test(migrations = "../../migrations")]
async fn a_row_that_changed_between_plan_and_apply_is_not_moved(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let (_, owner) = viewer_fixture::seed_agent_with_group(&pool, "wf-row-owner").await;
    let (_, elsewhere) = viewer_fixture::seed_agent_with_group(&pool, "wf-elsewhere").await;
    let a = structural_claim(&pool, &world, "drifting plan step a", 2).await;
    let grown = workflow_row(&pool, "grown-plan", "public", owner).await;
    let moved_away = workflow_row(&pool, "moved-away-plan", "public", owner).await;
    let steady = workflow_row(&pool, "steady-plan", "public", owner).await;
    for wf in [grown, moved_away, steady] {
        executes(&pool, wf, a, 2).await;
    }

    let (plan, _) = fx::create_plan(&pool, &world, &[a]).await;
    assert_eq!(frozen(&pool, plan).await, vec![a], "CALIBRATION");
    let added = structural_claim(&pool, &world, "drifting plan new public step", 2).await;
    executes(&pool, grown, added, 2).await;
    sqlx::query("UPDATE workflows SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(moved_away)
        .bind(elsewhere)
        .execute(&pool)
        .await
        .expect("re-tenant the row between plan and apply");
    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50)
        .await
        .expect("apply");

    assert_eq!(
        row(&pool, grown).await,
        ("public".to_string(), owner),
        "a row that gained a public structural step after the plan stays public"
    );
    assert_eq!(
        row(&pool, moved_away).await,
        ("group".to_string(), elsewhere),
        "a row re-tenanted after the plan is left where it now is"
    );
    assert_eq!(
        row(&pool, steady).await,
        ("group".to_string(), world.target_group),
        "CALIBRATION: the unchanged row moves"
    );
    let audit = workflow_audit(&pool, plan).await;
    assert_eq!(
        audit.iter().map(|r| r.1).collect::<Vec<_>>(),
        vec![steady],
        "only the moved row is recorded: {audit:?}"
    );
}

/// Every edge touching `workflow`, as `(edge, visibility, owner, co-owner)`.
async fn workflow_edges(pool: &PgPool, workflow: Uuid) -> Vec<(Uuid, String, Uuid, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT id, visibility::text, owner_group_id, co_owner_group_id FROM edges \
          WHERE source_id = $1 OR target_id = $1 ORDER BY id",
    )
    .bind(workflow)
    .fetch_all(pool)
    .await
    .expect("read the workflow's edges")
}

/// (5) Backlog 630af617 (3), migration 219: the edges of a plan privatized as a
/// unit follow its row. A workflow endpoint now contributes its row's tenancy
/// to an edge's meet, so once the row is `('group', target)` EVERY edge on it
/// is the target's: the `executes` edges onto its moved claims, the one onto
/// the level-3 atom that stays public, and its `variant_of` link to a public
/// parent generation (before, the last two stayed public and named the now
/// private plan). The revert puts every one of them back on its pre-apply
/// tuple exactly; the row goes back last, so the revert re-meets the row's
/// edges once it is public again (before, the `executes` edges onto the
/// restored claims stayed in the target group, met with the still-private
/// row). Run on the `epigraph_maintenance` role the job connection is.
#[sqlx::test(migrations = "../../migrations")]
async fn a_privatized_plans_edges_follow_its_row_and_a_revert_restores_them(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let maintenance = viewer_fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let scoped = Arc::new(
        viewer_fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(maintenance),
    );
    let (_, owner) = viewer_fixture::seed_agent_with_group(&pool, "wf-edges-owner").await;
    let thesis = structural_claim(&pool, &world, "edges plan thesis", 0).await;
    let a = structural_claim(&pool, &world, "edges plan step a", 2).await;
    let atom = structural_claim(&pool, &world, "edges plan shared atom", 3).await;
    let parent = workflow_row(&pool, "edges-plan", "public", owner).await;
    let wf = workflow_row(&pool, "edges-plan-next", "public", owner).await;
    for (claim, level) in [(thesis, 0), (a, 2), (atom, 3)] {
        executes(&pool, wf, claim, level).await;
    }
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'workflow', $2, 'workflow', 'variant_of')",
    )
    .bind(wf)
    .bind(parent)
    .execute(&pool)
    .await
    .expect("seed the variant_of edge");
    let before = workflow_edges(&pool, wf).await;
    assert_eq!(before.len(), 4, "CALIBRATION: {before:?}");
    assert!(
        before
            .iter()
            .all(|e| (e.1.as_str(), e.2, e.3) == ("public", Uuid::nil(), None)),
        "CALIBRATION: a public plan's edges are structural, ('public', world): {before:?}"
    );

    let plan = apply(&pool, &world, &scoped, &[thesis, a]).await;
    assert_eq!(
        row(&pool, wf).await,
        ("group".to_string(), world.target_group),
        "CALIBRATION: the row moved with its plan"
    );
    assert_eq!(fx::tenancy(&pool, atom).await.0, "public", "CALIBRATION");
    let applied = workflow_edges(&pool, wf).await;
    assert!(
        applied
            .iter()
            .all(|e| (e.1.as_str(), e.2, e.3) == ("group", world.target_group, None)),
        "every edge on a privatized plan's row is the target group's, the atom's and the \
         parent link included: {applied:?}"
    );

    let correlation = fx::dispatch(&pool, &world, plan, "reverting").await;
    fx::run_revert(&scoped, &fx::revert_job(plan, world.actor, &correlation), 1)
        .await
        .expect("revert");
    assert_eq!(fx::plan_state(&pool, plan).await, "reverted");
    assert_eq!(
        row(&pool, wf).await,
        ("public".to_string(), owner),
        "CALIBRATION: the row is back"
    );
    assert_eq!(
        workflow_edges(&pool, wf).await,
        before,
        "the revert restores every edge on the row to its pre-apply tuple"
    );
}
