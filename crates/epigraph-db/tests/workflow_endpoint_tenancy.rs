//! Migration 219: a `workflow` endpoint contributes its OWN tenancy (the
//! `workflows` row's `owner_group_id`, `visibility`, migration 183) to an
//! edge's meet (backlog 630af617, item 3).
//!
//! Before 219, `epigraph_node_tenancy` (070) answered `('public', world)` for a
//! workflow endpoint, and 122's inlined propagation read only `claims` and
//! `evidence`. So a group plan's `variant_of` edge, and its `executes` edge
//! onto a PUBLIC claim, were public: a non-member listing the edges into a
//! public generation or a public step saw the private plan.
//!
//! What is pinned, each on the harness superuser (the application-role
//! readers are pinned by `epigraph-api/tests/workflow_ingest_group_tenancy.rs`):
//!
//! * the oracle answers a workflow's own tuple, and keeps 070's owner and ACL;
//! * the write-time stamp (`epigraph_edges_tenancy`, 120) meets a group plan's
//!   `executes` / `variant_of` edge with the plan, and an edge between two
//!   public endpoints stays `('public', world)` (calibration);
//! * the claim-side cascade (`epigraph_propagate_tenancy`, arm (d)) meets an
//!   `executes` edge with the plan's row when the claim narrows: co-owned when
//!   the claim moves into ANOTHER group, never handed to that group alone;
//! * the one-time re-meet (219 section 4) narrows an edge stamped before 219,
//!   leaves public plans' edges alone, and is idempotent.
//!
//! Verified to fail (mutations of 219, each applied alone):
//! * the `workflow` arm removed from `epigraph_node_tenancy` -> all four fail
//!   (`narrowing_a_claim_co_owns_its_edge_from_another_groups_plan` at its
//!   write-time calibration);
//! * the two `workflows` LEFT JOINs removed from `epigraph_propagate_tenancy`
//!   -> `narrowing_a_claim_co_owns_its_edge_from_another_groups_plan` fails
//!   (the edge goes to the claim's group alone).

mod viewer_fixture;

use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

const WORLD: Uuid = Uuid::nil();

/// The migration file itself, so the re-run below cannot drift from it.
const MIGRATION_219: &str = include_str!("../../../migrations/219_workflow_endpoint_tenancy.sql");

/// A `workflows` row with the given tenancy (harness superuser).
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

/// An UNDECLARED edge (062's defaults): the trigger derives its tenancy.
async fn edge(
    pool: &PgPool,
    source: (Uuid, &str),
    target: (Uuid, &str),
    relationship: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(source.0)
    .bind(source.1)
    .bind(target.0)
    .bind(target.1)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("insert {relationship} edge: {e}"))
}

async fn edge_tenancy(pool: &PgPool, id: Uuid) -> (String, Uuid, Option<Uuid>) {
    sqlx::query_as(
        "SELECT visibility::text, owner_group_id, co_owner_group_id FROM edges WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read edge tenancy")
}

fn group(g: Uuid) -> (String, Uuid, Option<Uuid>) {
    ("group".to_string(), g, None)
}

fn public_world() -> (String, Uuid, Option<Uuid>) {
    ("public".to_string(), WORLD, None)
}

/// The text of 219 from its section 4 on (the bypass guard, the re-meet and
/// any later section, all idempotent), to re-run on a database that already
/// carries 219.
fn section_4() -> &'static str {
    let at = MIGRATION_219
        .find("-- 4. THE ONE-TIME RE-MEET")
        .expect("219 has its section 4");
    let start = MIGRATION_219[..at]
        .rfind("-- ====")
        .expect("section 4's rule line");
    &MIGRATION_219[start..]
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_oracle_answers_a_workflows_own_tuple(pool: PgPool) {
    let (_, g) = fixture::seed_agent_with_group(&pool, "wf-oracle").await;
    let private = workflow_row(&pool, "oracle-private", "group", g).await;
    let public = workflow_row(&pool, "oracle-public", "public", g).await;

    let answer = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (Uuid, String)>(
                "SELECT g, v::text FROM public.epigraph_node_tenancy($1, 'workflow')",
            )
            .bind(id)
            .fetch_all(&pool)
            .await
            .expect("call the oracle")
        }
    };
    assert_eq!(answer(private).await, vec![(g, "group".to_string())]);
    assert_eq!(answer(public).await, vec![(g, "public".to_string())]);
    assert_eq!(
        answer(Uuid::new_v4()).await,
        vec![(WORLD, "public".to_string())],
        "an unknown workflow id keeps 070's ('public', world) fallback"
    );

    // CREATE OR REPLACE kept 070's frame: maintenance-owned, not executable by
    // the application role.
    let (owner, app_exec): (String, bool) = sqlx::query_as(
        "SELECT pg_get_userbyid(p.proowner)::text, \
                has_function_privilege('epigraph_app', p.oid, 'EXECUTE') \
           FROM pg_proc p WHERE p.oid = 'public.epigraph_node_tenancy(uuid, text)'::regprocedure",
    )
    .fetch_one(&pool)
    .await
    .expect("read the oracle's catalog row");
    assert_eq!(owner, "epigraph_maintenance");
    assert!(
        !app_exec,
        "the oracle stays revoked from the application role"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_group_plans_new_edges_are_stamped_with_the_plans_group(pool: PgPool) {
    let (agent, g) = fixture::seed_agent_with_group(&pool, "wf-stamp").await;
    let step =
        fixture::seed_public_claim(&pool, agent, "a public step a private plan reuses").await;
    let parent = workflow_row(&pool, "stamp-lineage", "public", g).await;
    let child = workflow_row(&pool, "stamp-lineage-private", "group", g).await;
    let public_plan = workflow_row(&pool, "stamp-public", "public", g).await;

    let executes = edge(&pool, (child, "workflow"), (step, "claim"), "executes").await;
    let variant_of = edge(
        &pool,
        (child, "workflow"),
        (parent, "workflow"),
        "variant_of",
    )
    .await;
    let authored = edge(&pool, (agent, "agent"), (child, "workflow"), "AUTHORED").await;
    let public_executes = edge(
        &pool,
        (public_plan, "workflow"),
        (step, "claim"),
        "executes",
    )
    .await;

    assert_eq!(
        edge_tenancy(&pool, executes).await,
        group(g),
        "a group plan's executes edge onto a PUBLIC step is the plan's group's"
    );
    assert_eq!(
        edge_tenancy(&pool, variant_of).await,
        group(g),
        "a group generation's parent link is the generation's group's"
    );
    assert_eq!(
        edge_tenancy(&pool, authored).await,
        group(g),
        "a group plan's author edge is the plan's group's"
    );
    assert_eq!(
        edge_tenancy(&pool, public_executes).await,
        public_world(),
        "CALIBRATION: a public plan's edge onto a public step stays structural, ('public', world)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn narrowing_a_claim_co_owns_its_edge_from_another_groups_plan(pool: PgPool) {
    let (agent, plan_group) = fixture::seed_agent_with_group(&pool, "wf-plan-group").await;
    let (_, other) = fixture::seed_agent_with_group(&pool, "wf-claim-group").await;
    let atom = fixture::seed_public_claim(&pool, agent, "a shared public atom").await;
    let plan = workflow_row(&pool, "cascade-plan", "group", plan_group).await;
    let public_plan = workflow_row(&pool, "cascade-public-plan", "public", plan_group).await;
    let private_edge = edge(&pool, (plan, "workflow"), (atom, "claim"), "executes").await;
    let public_edge = edge(
        &pool,
        (public_plan, "workflow"),
        (atom, "claim"),
        "executes",
    )
    .await;
    assert_eq!(
        edge_tenancy(&pool, private_edge).await,
        group(plan_group),
        "CALIBRATION: the write-time stamp"
    );

    // The atom narrows into ANOTHER group (a privatization or restrict act).
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(atom)
        .bind(other)
        .execute(&pool)
        .await
        .expect("narrow the atom");

    assert_eq!(
        edge_tenancy(&pool, private_edge).await,
        ("group".to_string(), plan_group, Some(other)),
        "the cascade meets the edge with the PLAN's row as well as the claim: co-owned, so \
         the claim's group alone never reads an edge naming a plan it cannot read"
    );
    assert_eq!(
        edge_tenancy(&pool, public_edge).await,
        group(other),
        "CALIBRATION: a public plan's edge takes the claim's group alone"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_one_time_re_meet_narrows_a_group_plans_stale_edges(pool: PgPool) {
    let (agent, g) = fixture::seed_agent_with_group(&pool, "wf-backfill").await;
    let (other_agent, other) = fixture::seed_agent_with_group(&pool, "wf-backfill-other").await;
    let step = fixture::seed_public_claim(&pool, agent, "a public step").await;
    let theirs = fixture::seed_group_claim(&pool, other_agent, other, "their private step").await;
    let parent = workflow_row(&pool, "backfill-lineage", "public", g).await;
    let child = workflow_row(&pool, "backfill-lineage-private", "group", g).await;
    let public_plan = workflow_row(&pool, "backfill-public", "public", g).await;

    let executes = edge(&pool, (child, "workflow"), (step, "claim"), "executes").await;
    let variant_of = edge(
        &pool,
        (child, "workflow"),
        (parent, "workflow"),
        "variant_of",
    )
    .await;
    let cross = edge(&pool, (child, "workflow"), (theirs, "claim"), "executes").await;
    let public_executes = edge(
        &pool,
        (public_plan, "workflow"),
        (step, "claim"),
        "executes",
    )
    .await;

    // The rows as a pre-219 database stamped them: the plan counted as public.
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $3, co_owner_group_id = NULL \
          WHERE id = ANY($1) OR id = $2",
    )
    .bind(vec![executes, variant_of])
    .bind(public_executes)
    .bind(WORLD)
    .execute(&pool)
    .await
    .expect("restore the pre-219 public edges");
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(cross)
    .bind(other)
    .execute(&pool)
    .await
    .expect("restore the pre-219 claim-only meet");

    sqlx::raw_sql(section_4())
        .execute(&pool)
        .await
        .expect("re-run 219's section 4");

    assert_eq!(edge_tenancy(&pool, executes).await, group(g));
    assert_eq!(edge_tenancy(&pool, variant_of).await, group(g));
    assert_eq!(
        edge_tenancy(&pool, cross).await,
        ("group".to_string(), g, Some(other)),
        "an edge from a group plan onto another group's claim becomes co-owned"
    );
    assert_eq!(
        edge_tenancy(&pool, public_executes).await,
        public_world(),
        "a public plan's edge is not touched"
    );

    let before: Vec<(Uuid, String, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, visibility::text, owner_group_id, co_owner_group_id FROM edges ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("snapshot");
    sqlx::raw_sql(section_4())
        .execute(&pool)
        .await
        .expect("re-run 219's section 4 again");
    let after: Vec<(Uuid, String, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, visibility::text, owner_group_id, co_owner_group_id FROM edges ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("snapshot");
    assert_eq!(before, after, "the re-meet is idempotent");
}
