//! The privatization handlers keep a DECLARED edge's declaration (backlog
//! 969f01f6, migration 260), through the real apply and revert jobs.
//!
//! `epigraph-db/tests/privatization_declared_edges.rs` pins the re-meet's
//! rule on the application role. This file pins that the handlers reach it
//! on every path that re-tenants an edge's endpoint: the apply batch (claim
//! edges, and the edges of a plan's `workflows` row that moves with its
//! claims), the revert batch, and the revert's workflow drain; and that each
//! declared edge kept off its meet is recorded in the plan's audit trail.

#[path = "privatization_fixture.rs"]
mod fx;

use fx::viewer_fixture;
use sqlx::PgPool;
use uuid::Uuid;

const WORLD: Uuid = Uuid::nil();

/// `(owner_group_id, visibility, co_owner_group_id)`.
async fn edge_tuple(pool: &PgPool, edge: Uuid) -> (Uuid, String, Option<Uuid>) {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, co_owner_group_id FROM edges WHERE id = $1",
    )
    .bind(edge)
    .fetch_one(pool)
    .await
    .expect("read the edge tuple")
}

/// An edge `src -> tgt` declared `('group', group)` (the trigger records the
/// declaration: both endpoints are public).
async fn declared_edge(pool: &PgPool, src: (Uuid, &str), tgt: (Uuid, &str), group: Uuid) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id) \
         VALUES ($1, $2, $3, $4, 'supports', 'group', $5) RETURNING id",
    )
    .bind(src.0)
    .bind(src.1)
    .bind(tgt.0)
    .bind(tgt.1)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed a declared edge");
    let declared: Option<Uuid> =
        sqlx::query_scalar("SELECT declared_owner_group_id FROM edges WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read the declaration");
    assert_eq!(
        declared,
        Some(group),
        "CALIBRATION: the declaration is recorded"
    );
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_restrict_and_its_revert_keep_declared_claim_and_workflow_edges(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let g = world.target_group;
    let (_h_agent, h) = viewer_fixture::seed_agent_with_group(&pool, "declarer-h").await;

    let step = viewer_fixture::seed_public_claim(&pool, world.actor, "the plan's step").await;
    sqlx::query("UPDATE claims SET properties = jsonb_build_object('level', 0) WHERE id = $1")
        .bind(step)
        .execute(&pool)
        .await
        .expect("make the step structural");
    let outsider = viewer_fixture::seed_public_claim(&pool, world.actor, "outside the plan").await;
    let wf = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, generation, metadata, visibility, \
                                owner_group_id) \
         VALUES ($1, 'declared-edge-plan', 'a plan', 0, '{}'::jsonb, 'public', $2)",
    )
    .bind(wf)
    .bind(WORLD)
    .execute(&pool)
    .await
    .expect("seed the public workflow");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'workflow', $2, 'claim', 'executes')",
    )
    .bind(wf)
    .bind(step)
    .execute(&pool)
    .await
    .expect("the plan executes its step");
    let claim_edge = declared_edge(&pool, (step, "claim"), (outsider, "claim"), h).await;
    let wf_edge = declared_edge(&pool, (outsider, "claim"), (wf, "workflow"), h).await;

    let (plan, _) = fx::create_plan(&pool, &world, &[step]).await;
    assert_eq!(
        fx::items(&pool, plan).await.len(),
        1,
        "CALIBRATION: the plan holds the step alone (a `supports` edge is not traversed)"
    );

    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50)
        .await
        .expect("apply");
    assert_eq!(fx::plan_state(&pool, plan).await, "applied");
    let wf_vis: String = sqlx::query_scalar("SELECT visibility::text FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(&pool)
        .await
        .expect("read the workflow");
    assert_eq!(wf_vis, "group", "CALIBRATION: the plan moved with its step");
    for (name, e) in [("claim", claim_edge), ("workflow", wf_edge)] {
        assert_eq!(
            edge_tuple(&pool, e).await,
            (h, "group".to_string(), Some(g)),
            "apply must narrow the declared {name} edge to H and G, never re-own it to G"
        );
        assert_eq!(
            fx::audit_pairs(&pool, plan, e, "edge.hold").await,
            vec![(Some("group".to_string()), Some("group".to_string()))],
            "the apply records the declared {name} edge it kept off the meet"
        );
    }

    let revert_correlation = fx::dispatch(&pool, &world, plan, "reverting").await;
    fx::run_revert(
        &scoped,
        &fx::revert_job(plan, world.actor, &revert_correlation),
        50,
    )
    .await
    .expect("revert");
    assert_eq!(fx::plan_state(&pool, plan).await, "reverted");
    assert_eq!(fx::tenancy(&pool, step).await.0, "public");
    for (name, e) in [("claim", claim_edge), ("workflow", wf_edge)] {
        assert_eq!(
            edge_tuple(&pool, e).await,
            (h, "group".to_string(), None),
            "the revert must give back the declared {name} edge exactly, never widen it"
        );
        assert_eq!(
            fx::audit_pairs(&pool, plan, e, "edge.hold").await,
            vec![
                (Some("group".to_string()), Some("group".to_string())),
                (Some("public".to_string()), Some("group".to_string())),
            ],
            "the revert records the declared {name} edge it kept off the (public) meet"
        );
    }
}
