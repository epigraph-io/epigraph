//! A replacement of a NON-PUBLIC step never re-points its `executes` edge.
//!
//! A workflow generation names its steps through `executes` edges
//! (`workflow -executes-> step`, carrying `plan_index`). A pinned, group-private
//! generation is verified by recomputing a digest over exactly those edges:
//! `(plan_index, level, claim_id, content)` in plan order. Any of the three
//! replacement acts used to move the edge onto the replacement claim:
//!
//! * a plain supersede (`supersede_claim`): `migrate_superseded_edges` freezes
//!   `executes` only for a STEP-LINEAGE pair, and a plain supersede writes no
//!   `step_lineage_id`, so the freeze never applied;
//! * a dedup (`mark_duplicate`, the semantic-duplicate sweep):
//!   `repair_marked_duplicate` had no freeze at all;
//! * a merge (`consolidate_claims`): `migrate_consolidated_edges` had none
//!   either, and with two executed sources it RETRACTED one of the two edges
//!   as a "redundant copy".
//!
//! Each of those changes the frozen plan, so the generation no longer verifies
//! and the pinned run is refused. The rule under test: when the retired claim is
//! non-public, `executes` stays on it, in either direction. It is read from the
//! claim's row, so the deferred replay of each cascade (the act on the caller's
//! transaction, the edge half later on the maintenance connection) gives the
//! same result. A PUBLIC step keeps today's behaviour, which the controls at the
//! bottom pin.

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::{ClaimRepository, ConsolidateMode};
use sqlx::PgPool;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

/// One item of a workflow's frozen plan: exactly the inputs of the digest the
/// host recomputes, plus the edge id (so a re-created edge is not mistaken for
/// the original).
type PlanItem = (i32, Uuid, Uuid, String, Option<String>);

/// The live `executes` items of `workflow` in plan order:
/// `(plan_index, edge_id, claim_id, content, level)`.
async fn plan(pool: &PgPool, workflow: Uuid) -> Vec<PlanItem> {
    sqlx::query_as(
        "SELECT (e.properties->>'plan_index')::int, e.id, c.id, c.content, \
                c.properties->>'level' \
           FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.source_type = 'workflow' \
            AND e.relationship = 'executes' AND e.target_type = 'claim' \
            AND e.valid_to IS NULL \
          ORDER BY (e.properties->>'plan_index')::int",
    )
    .bind(workflow)
    .fetch_all(pool)
    .await
    .expect("read the plan")
}

async fn seed_workflow(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal) VALUES ($1, $2, 'workflow-plan test')",
    )
    .bind(id)
    .bind(format!("workflow-plan-{id}"))
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

/// A level-2 step claim: group-private in `group` when given, else public.
async fn seed_step(pool: &PgPool, agent: Uuid, group: Option<Uuid>, content: &str) -> Uuid {
    let id = match group {
        Some(g) => fixture::seed_group_claim(pool, agent, g, content).await,
        None => fixture::seed_public_claim(pool, agent, content).await,
    };
    sqlx::query("UPDATE claims SET properties = '{\"level\": 2}'::jsonb WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("mark the step level 2");
    id
}

async fn seed_executes(pool: &PgPool, workflow: Uuid, step: Uuid, plan_index: i32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, 'workflow', $2, 'claim', 'executes', \
                 jsonb_build_object('plan_index', $3::int, 'level', 2)) \
         RETURNING id",
    )
    .bind(workflow)
    .bind(step)
    .bind(plan_index)
    .fetch_one(pool)
    .await
    .expect("seed executes")
}

/// A `supports` edge `from -> to`: a strengthening relationship every
/// replacement act migrates, so it proves the migration actually ran.
async fn seed_supports(pool: &PgPool, from: Uuid, to: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(from)
    .bind(to)
    .fetch_one(pool)
    .await
    .expect("seed supports")
}

/// `(source_id, target_id, still live)` of edge `id`.
async fn ends(pool: &PgPool, id: Uuid) -> (Uuid, Uuid, bool) {
    sqlx::query_as("SELECT source_id, target_id, valid_to IS NULL FROM edges WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("edge")
}

/// Live `supports` edges `from -> to`.
async fn live_supports(pool: &PgPool, from: Uuid, to: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
           AND relationship = 'supports' AND valid_to IS NULL",
    )
    .bind(from)
    .bind(to)
    .fetch_one(pool)
    .await
    .expect("count supports")
}

async fn visibility(pool: &PgPool, claim: Uuid) -> String {
    sqlx::query_scalar("SELECT visibility::text FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim")
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim")
}

/// A four-step workflow, each step in `group` or public, and a third claim
/// supporting each step.
struct Plan {
    agent: Uuid,
    group: Uuid,
    workflow: Uuid,
    steps: [Uuid; 4],
    supporter: Uuid,
    support_edges: [Uuid; 4],
}

/// Every step group-private (`private`) or every step public.
async fn seed_plan(pool: &PgPool, private: bool) -> Plan {
    seed_mixed_plan(pool, [private; 4]).await
}

/// Step `i` is group-private when `private[i]`, else public. The supporter is
/// group-private when any step is.
async fn seed_mixed_plan(pool: &PgPool, private: [bool; 4]) -> Plan {
    let (agent, group) = fixture::seed_agent_with_group(pool, "plan-author").await;
    let workflow = seed_workflow(pool).await;
    let mut steps = [Uuid::nil(); 4];
    for (i, slot) in steps.iter_mut().enumerate() {
        let tenancy = private[i].then_some(group);
        let step = seed_step(pool, agent, tenancy, &format!("step {i}: do the thing")).await;
        seed_executes(pool, workflow, step, i as i32).await;
        *slot = step;
    }
    let supporter = if private.contains(&true) {
        fixture::seed_group_claim(pool, agent, group, "a supporting note").await
    } else {
        fixture::seed_public_claim(pool, agent, "a supporting note").await
    };
    let mut support_edges = [Uuid::nil(); 4];
    for (slot, step) in support_edges.iter_mut().zip(steps) {
        *slot = seed_supports(pool, supporter, step).await;
    }
    for (step, private) in steps.into_iter().zip(private) {
        let want = if private { "group" } else { "public" };
        assert_eq!(
            visibility(pool, step).await,
            want,
            "fixture tenancy of {step}"
        );
    }
    Plan {
        agent,
        group,
        workflow,
        steps,
        supporter,
        support_edges,
    }
}

/// The Supersede admin cascade's edge half, on the maintenance role (the
/// connection `epigraph_engine::admin_cascade` and the deferred replay use).
async fn replay_supersede(pool: &PgPool, old: Uuid, new: Uuid) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        ClaimRepository::migrate_superseded_edges_conn(&mut conn, old, new)
            .await
            .expect("supersede edge migration on the maintenance role");
        (conn, ())
    })
    .await;
}

async fn replay_dedup(pool: &PgPool, dup: Uuid, canonical: Uuid) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        ClaimRepository::repair_marked_duplicate_conn(
            &mut conn,
            ClaimId::from_uuid(dup),
            ClaimId::from_uuid(canonical),
        )
        .await
        .expect("dedup repair on the maintenance role");
        (conn, ())
    })
    .await;
}

async fn replay_consolidate(pool: &PgPool, merged: Uuid, sources: Vec<Uuid>) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        ClaimRepository::migrate_consolidated_edges_conn(&mut conn, merged, &sources)
            .await
            .expect("consolidation edge migration on the maintenance role");
        (conn, ())
    })
    .await;
}

// ── group-private steps: the plan is frozen ─────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn supersede_of_group_private_executed_step_keeps_the_executes_edge(pool: PgPool) {
    let p = seed_plan(&pool, true).await;
    let before = plan(&pool, p.workflow).await;
    assert_eq!(before.len(), 4);

    // The combined form (one privileged transaction: act + edge migration).
    let mut conn = pool.acquire().await.unwrap();
    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(p.steps[1])
            .fetch_one(&mut *conn)
            .await
            .expect("the superseded claim's author");
    let (new_id, _) = ClaimRepository::supersede_conn(
        &mut conn,
        ClaimId::from_uuid(p.steps[1]),
        "step 1: do the thing, restated",
        TruthValue::clamped(0.6),
        "restated",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
    )
    .await
    .expect("supersede of a group-private step");
    drop(conn);

    assert!(!is_current(&pool, p.steps[1]).await, "the step was retired");
    assert_eq!(
        visibility(&pool, new_id).await,
        "group",
        "the replacement inherits the group tenancy"
    );
    // The migration ran: a strengthening edge followed the replacement.
    assert_eq!(
        ends(&pool, p.support_edges[1]).await,
        (p.supporter, new_id, true),
        "supports follows the replacement"
    );
    // ...and the frozen plan did not move.
    assert_eq!(
        plan(&pool, p.workflow).await,
        before,
        "the group-private generation's plan is unchanged by a plain supersede"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn deferred_supersede_replay_of_group_private_step_keeps_the_executes_edge(pool: PgPool) {
    let p = seed_plan(&pool, true).await;
    let before = plan(&pool, p.workflow).await;

    // The request path's shape: the act on the caller's transaction, the edge
    // migration later on the maintenance connection (and a second time, as a
    // replay of an already-applied cascade would).
    let mut tx = pool.begin().await.unwrap();
    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(p.steps[2])
            .fetch_one(&mut *tx)
            .await
            .expect("the superseded claim's author");
    let (new_id, _) = ClaimRepository::supersede_act_conn(
        &mut tx,
        ClaimId::from_uuid(p.steps[2]),
        "step 2: do the thing, restated",
        TruthValue::clamped(0.6),
        "restated",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
    )
    .await
    .expect("supersede act");
    tx.commit().await.unwrap();
    replay_supersede(&pool, p.steps[2], new_id).await;
    replay_supersede(&pool, p.steps[2], new_id).await;

    assert_eq!(
        ends(&pool, p.support_edges[2]).await,
        (p.supporter, new_id, true),
        "supports follows the replacement"
    );
    assert_eq!(
        plan(&pool, p.workflow).await,
        before,
        "the deferred replay leaves the group-private plan unchanged"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_and_consolidate_of_a_group_private_step_keep_the_plan(pool: PgPool) {
    let p = seed_plan(&pool, true).await;
    let before = plan(&pool, p.workflow).await;
    let canonical =
        fixture::seed_group_claim(&pool, p.agent, p.group, "step 0, stated elsewhere").await;

    // Dedup, combined form (the semantic-duplicate sweep's call).
    let mut conn = pool.acquire().await.unwrap();
    ClaimRepository::mark_duplicate_with_repair_conn(
        &mut conn,
        ClaimId::from_uuid(p.steps[0]),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup of a group-private step");
    // Merge of two executed steps, combined form.
    let merged = ClaimRepository::consolidate_conn(
        &mut conn,
        &[p.steps[2], p.steps[3]],
        "steps 2 and 3, merged",
        0.6,
        ConsolidateMode::Merge,
        "merge",
        p.agent,
    )
    .await
    .expect("merge of two group-private steps")
    .merged_id;
    drop(conn);

    assert!(!is_current(&pool, p.steps[0]).await);
    assert!(!is_current(&pool, p.steps[2]).await);
    assert_eq!(
        ends(&pool, p.support_edges[0]).await,
        (p.supporter, canonical, true),
        "supports follows the canonical claim"
    );
    assert_eq!(
        live_supports(&pool, p.supporter, merged).await,
        1,
        "the two supports edges collapse onto the merge"
    );
    assert_eq!(
        plan(&pool, p.workflow).await,
        before,
        "neither the dedup nor the merge re-pointed (or retracted) a frozen executes edge"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn deferred_dedup_and_consolidate_replays_of_a_group_private_step_keep_the_plan(
    pool: PgPool,
) {
    let p = seed_plan(&pool, true).await;
    let before = plan(&pool, p.workflow).await;
    let canonical =
        fixture::seed_group_claim(&pool, p.agent, p.group, "step 1, stated elsewhere").await;

    let mut tx = pool.begin().await.unwrap();
    ClaimRepository::mark_duplicate_act_conn(
        &mut tx,
        ClaimId::from_uuid(p.steps[1]),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup act");
    let merged = ClaimRepository::consolidate_act_conn(
        &mut tx,
        &[p.steps[2], p.steps[3]],
        "steps 2 and 3, merged",
        0.6,
        ConsolidateMode::Merge,
        "merge",
        p.agent,
    )
    .await
    .expect("merge act")
    .merged_id;
    tx.commit().await.unwrap();
    for _ in 0..2 {
        replay_dedup(&pool, p.steps[1], canonical).await;
        replay_consolidate(&pool, merged, vec![p.steps[2], p.steps[3]]).await;
    }

    assert_eq!(
        ends(&pool, p.support_edges[1]).await,
        (p.supporter, canonical, true),
        "supports follows the canonical claim"
    );
    assert_eq!(
        live_supports(&pool, p.supporter, merged).await,
        1,
        "the two supports edges collapse onto the merge"
    );
    assert_eq!(
        plan(&pool, p.workflow).await,
        before,
        "the deferred replays leave the group-private plan unchanged"
    );
}

// ── public steps: today's behaviour, unchanged ──────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn public_step_supersede_still_moves_executes(pool: PgPool) {
    let p = seed_plan(&pool, false).await;
    let before = plan(&pool, p.workflow).await;

    let mut conn = pool.acquire().await.unwrap();
    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(p.steps[1])
            .fetch_one(&mut *conn)
            .await
            .expect("the superseded claim's author");
    let (new_id, _) = ClaimRepository::supersede_conn(
        &mut conn,
        ClaimId::from_uuid(p.steps[1]),
        "step 1: do the thing, restated",
        TruthValue::clamped(0.6),
        "restated",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
    )
    .await
    .expect("supersede of a public step");
    drop(conn);

    let after = plan(&pool, p.workflow).await;
    assert_eq!(after.len(), 4);
    assert_eq!(after[1].1, before[1].1, "the same executes edge");
    assert_eq!(
        after[1].2, new_id,
        "a public step's executes follows the replacement"
    );
    for i in [0, 2, 3] {
        assert_eq!(after[i], before[i], "untouched item {i}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn public_step_dedup_and_consolidate_still_move_executes(pool: PgPool) {
    let p = seed_plan(&pool, false).await;
    let before = plan(&pool, p.workflow).await;
    let canonical = fixture::seed_public_claim(&pool, p.agent, "step 0, stated elsewhere").await;
    let outside = fixture::seed_public_claim(&pool, p.agent, "a note outside the plan").await;

    let mut conn = pool.acquire().await.unwrap();
    ClaimRepository::mark_duplicate_with_repair_conn(
        &mut conn,
        ClaimId::from_uuid(p.steps[0]),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup of a public step");
    let merged = ClaimRepository::consolidate_conn(
        &mut conn,
        &[p.steps[2], outside],
        "step 2 and a note, merged",
        0.6,
        ConsolidateMode::Merge,
        "merge",
        p.agent,
    )
    .await
    .expect("merge of a public step")
    .merged_id;
    drop(conn);

    let after = plan(&pool, p.workflow).await;
    assert_eq!(after.len(), 4);
    assert_eq!(
        (after[0].1, after[0].2),
        (before[0].1, canonical),
        "a public step's executes follows the canonical claim"
    );
    assert_eq!(
        (after[2].1, after[2].2),
        (before[2].1, merged),
        "a public step's executes follows the merge"
    );
    for i in [1, 3] {
        assert_eq!(after[i], before[i], "untouched item {i}");
    }
}

/// The request path's shape for a PUBLIC plan: each act on the caller's
/// transaction, each edge half on the maintenance role. Fail-closed makes an
/// unreadable row count as non-public, so this is what proves the maintenance
/// connection reads a public claim's `visibility` in all three migrations
/// (an unreadable row would freeze, and these edges would not move).
#[sqlx::test(migrations = "../../migrations")]
async fn public_step_deferred_replays_still_move_executes(pool: PgPool) {
    let p = seed_plan(&pool, false).await;
    let before = plan(&pool, p.workflow).await;
    let canonical = fixture::seed_public_claim(&pool, p.agent, "step 0, stated elsewhere").await;
    let outside = fixture::seed_public_claim(&pool, p.agent, "a note outside the plan").await;

    let mut tx = pool.begin().await.unwrap();
    ClaimRepository::mark_duplicate_act_conn(
        &mut tx,
        ClaimId::from_uuid(p.steps[0]),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup act");
    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(p.steps[1])
            .fetch_one(&mut *tx)
            .await
            .expect("the superseded claim's author");
    let (new_id, _) = ClaimRepository::supersede_act_conn(
        &mut tx,
        ClaimId::from_uuid(p.steps[1]),
        "step 1: do the thing, restated",
        TruthValue::clamped(0.6),
        "restated",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
    )
    .await
    .expect("supersede act");
    let merged = ClaimRepository::consolidate_act_conn(
        &mut tx,
        &[p.steps[2], outside],
        "step 2 and a note, merged",
        0.6,
        ConsolidateMode::Merge,
        "merge",
        p.agent,
    )
    .await
    .expect("merge act")
    .merged_id;
    tx.commit().await.unwrap();
    replay_dedup(&pool, p.steps[0], canonical).await;
    replay_supersede(&pool, p.steps[1], new_id).await;
    replay_consolidate(&pool, merged, vec![p.steps[2], outside]).await;

    let after = plan(&pool, p.workflow).await;
    assert_eq!(after.len(), 4);
    for (i, want) in [(0, canonical), (1, new_id), (2, merged)] {
        assert_eq!(
            (after[i].1, after[i].2),
            (before[i].1, want),
            "a public step's executes follows its replacement on the replay (item {i})"
        );
    }
    assert_eq!(after[3], before[3], "untouched item 3");
}

// ── mixed tenancy: the rule is keyed on the RETIRED claim ───────────────────
//
// A dedup and a merge may join claims of different visibility: a non-owner may
// attach a duplicate to a PUBLIC canonical, and a merge accepts one group plus
// public sources. The freeze must follow the retired claim's own visibility,
// never the replacement's, and in a merge each source's own.

#[sqlx::test(migrations = "../../migrations")]
async fn group_step_deduped_onto_a_public_canonical_keeps_its_executes(pool: PgPool) {
    let p = seed_plan(&pool, true).await;
    let before = plan(&pool, p.workflow).await;
    let canon_0 = fixture::seed_public_claim(&pool, p.agent, "step 0, stated publicly").await;
    let canon_1 = fixture::seed_public_claim(&pool, p.agent, "step 1, stated publicly").await;

    // Step 0: the request path's shape (act, then the edge half replayed twice
    // on the maintenance role).
    let mut tx = pool.begin().await.unwrap();
    ClaimRepository::mark_duplicate_act_conn(
        &mut tx,
        ClaimId::from_uuid(p.steps[0]),
        ClaimId::from_uuid(canon_0),
    )
    .await
    .expect("dedup act onto a public canonical");
    tx.commit().await.unwrap();
    replay_dedup(&pool, p.steps[0], canon_0).await;
    replay_dedup(&pool, p.steps[0], canon_0).await;

    // Step 1: the combined form (the semantic-duplicate sweep's call).
    let mut conn = pool.acquire().await.unwrap();
    ClaimRepository::mark_duplicate_with_repair_conn(
        &mut conn,
        ClaimId::from_uuid(p.steps[1]),
        ClaimId::from_uuid(canon_1),
    )
    .await
    .expect("dedup of a group-private step onto a public canonical");
    drop(conn);

    assert_eq!(visibility(&pool, canon_0).await, "public");
    assert_eq!(
        ends(&pool, p.support_edges[0]).await,
        (p.supporter, canon_0, true),
        "supports follows the public canonical (replay)"
    );
    assert_eq!(
        ends(&pool, p.support_edges[1]).await,
        (p.supporter, canon_1, true),
        "supports follows the public canonical (combined)"
    );
    assert_eq!(
        plan(&pool, p.workflow).await,
        before,
        "a group-private step keeps its executes even when its canonical is public"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn public_step_deduped_onto_a_group_canonical_still_moves_executes(pool: PgPool) {
    let p = seed_plan(&pool, false).await;
    let before = plan(&pool, p.workflow).await;
    let canonical =
        fixture::seed_group_claim(&pool, p.agent, p.group, "step 0, stated in the group").await;

    let mut conn = pool.acquire().await.unwrap();
    ClaimRepository::mark_duplicate_with_repair_conn(
        &mut conn,
        ClaimId::from_uuid(p.steps[0]),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup of a public step onto a group canonical");
    drop(conn);

    assert_eq!(visibility(&pool, canonical).await, "group");
    let after = plan(&pool, p.workflow).await;
    assert_eq!(after.len(), 4);
    assert_eq!(
        (after[0].1, after[0].2),
        (before[0].1, canonical),
        "a public step's executes follows its canonical even when the canonical is group-private"
    );
    for i in 1..4 {
        assert_eq!(after[i], before[i], "untouched item {i}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn merge_of_a_public_and_a_group_step_freezes_only_the_group_steps_executes(pool: PgPool) {
    // Steps 0, 1 and 3 group-private; step 2 public.
    let p = seed_mixed_plan(&pool, [true, true, false, true]).await;
    let before = plan(&pool, p.workflow).await;

    let mut tx = pool.begin().await.unwrap();
    let merged = ClaimRepository::consolidate_act_conn(
        &mut tx,
        &[p.steps[2], p.steps[3]],
        "steps 2 and 3, merged",
        0.6,
        ConsolidateMode::Merge,
        "merge",
        p.agent,
    )
    .await
    .expect("merge act of one public and one group step")
    .merged_id;
    tx.commit().await.unwrap();
    replay_consolidate(&pool, merged, vec![p.steps[2], p.steps[3]]).await;
    replay_consolidate(&pool, merged, vec![p.steps[2], p.steps[3]]).await;

    assert_eq!(
        visibility(&pool, merged).await,
        "group",
        "the merge takes the one group's tenancy"
    );
    assert_eq!(
        live_supports(&pool, p.supporter, merged).await,
        1,
        "the two supports edges collapse onto the merge"
    );
    let after = plan(&pool, p.workflow).await;
    assert_eq!(after.len(), 4, "no executes edge was retracted");
    assert_eq!(
        (after[2].1, after[2].2),
        (before[2].1, merged),
        "the public source's executes follows the merge"
    );
    assert_eq!(
        after[3], before[3],
        "the group-private source keeps its executes"
    );
    for i in [0, 1] {
        assert_eq!(after[i], before[i], "untouched item {i}");
    }
}

// ── the outgoing direction ─────────────────────────────────────────────────
//
// Every shipped `executes` writer is workflow-sourced, so the retired step is
// the TARGET. The rule also holds when the retired non-public claim is the
// SOURCE of an `executes` edge.

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_public_claim_keeps_its_outgoing_executes_through_all_three_acts(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "plan-author").await;
    let target = fixture::seed_group_claim(&pool, agent, group, "the executed claim").await;
    let (mut sources, mut executes, mut supports) = (Vec::new(), Vec::new(), Vec::new());
    for i in 0..3_i32 {
        let source = fixture::seed_group_claim(&pool, agent, group, &format!("runner {i}")).await;
        let edge: Uuid = sqlx::query_scalar(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                                properties) \
             VALUES ($1, 'claim', $2, 'claim', 'executes', \
                     jsonb_build_object('plan_index', $3::int)) RETURNING id",
        )
        .bind(source)
        .bind(target)
        .bind(i)
        .fetch_one(&pool)
        .await
        .expect("seed a claim-sourced executes");
        supports.push(seed_supports(&pool, source, target).await);
        executes.push(edge);
        sources.push(source);
    }
    let canonical = fixture::seed_group_claim(&pool, agent, group, "runner 1, elsewhere").await;
    let partner = fixture::seed_group_claim(&pool, agent, group, "runner 2's partner").await;

    let mut conn = pool.acquire().await.unwrap();
    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(sources[0])
            .fetch_one(&mut *conn)
            .await
            .expect("the superseded claim's author");
    let (new_id, _) = ClaimRepository::supersede_conn(
        &mut conn,
        ClaimId::from_uuid(sources[0]),
        "runner 0, restated",
        TruthValue::clamped(0.6),
        "restated",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
    )
    .await
    .expect("supersede");
    ClaimRepository::mark_duplicate_with_repair_conn(
        &mut conn,
        ClaimId::from_uuid(sources[1]),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup");
    let merged = ClaimRepository::consolidate_conn(
        &mut conn,
        &[sources[2], partner],
        "runner 2, merged",
        0.6,
        ConsolidateMode::Merge,
        "merge",
        agent,
    )
    .await
    .expect("merge")
    .merged_id;
    drop(conn);

    for (i, replacement) in [new_id, canonical, merged].into_iter().enumerate() {
        assert_eq!(
            ends(&pool, supports[i]).await,
            (replacement, target, true),
            "an outgoing supports follows the replacement (act {i})"
        );
        assert_eq!(
            ends(&pool, executes[i]).await,
            (sources[i], target, true),
            "a non-public claim keeps its outgoing executes (act {i})"
        );
    }
}
