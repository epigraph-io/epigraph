//! `WorkflowRepository::find_descendants` must terminate on a cyclic lineage.
//!
//! It is the cascade walk behind `DELETE /api/v1/workflows/:id?cascade=true`.
//! Its recursive CTE used `UNION ALL`. With a `variant_of`/`supersedes` cycle
//! among the claims it walks, the working table never empties, so the
//! statement ran until something external stopped it. That statement sits
//! inside the route's `ScopedPool::begin_as` transaction, and the lane DB (like
//! a default Postgres) sets no `statement_timeout`. `UNION` discards a row that
//! is already in the result, so the walk stops.
//!
//! Found while making the MCP twin atomic (deferred-commitment screen key
//! deprecate-workflow-atomic). The MCP walk,
//! `WorkflowRepository::find_workflow_descendants`, uses `UNION` for the same
//! reason, and `epigraph-mcp/tests/deprecate_cascade_atomic_test.rs` pins it.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::WorkflowRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// `source --relationship--> target` between two claims. No tenancy columns
/// are named, so migration 070's trigger derives them from the endpoints.
/// Both endpoints are public here, so the edge is public too.
async fn lineage_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed lineage edge");
}

/// Edges (source -> target): a -> root, b -> a, a -> b, root -> b. Walking down
/// from root: root's child is a, a's child is b, and b's children are a and
/// root. So there are two cycles, one of them back through the root.
///
/// The read runs on a connection with a `statement_timeout`, so a walk that
/// does not terminate fails as an error. Without the timeout the test would
/// hang, and the backend would keep running after the test gave up.
#[sqlx::test(migrations = "../../migrations")]
async fn find_descendants_terminates_on_a_cyclic_lineage(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "cyclic-lineage").await;
    let root = fixture::seed_public_claim(&pool, agent, "root").await;
    let a = fixture::seed_public_claim(&pool, agent, "variant a").await;
    let b = fixture::seed_public_claim(&pool, agent, "variant b").await;
    lineage_edge(&pool, a, root, "variant_of").await;
    lineage_edge(&pool, b, a, "variant_of").await;
    lineage_edge(&pool, a, b, "supersedes").await;
    lineage_edge(&pool, root, b, "variant_of").await;

    let viewer = fixture::public_viewer(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SET statement_timeout = '10s'")
        .execute(&mut *conn)
        .await
        .expect("bound the statement");

    let got = WorkflowRepository::find_descendants(&mut *conn, &viewer, root)
        .await
        .expect("find_descendants must terminate on a cyclic lineage");

    let unique: std::collections::HashSet<Uuid> = got.iter().copied().collect();
    assert_eq!(got.len(), unique.len(), "no id twice: {got:?}");
    assert_eq!(
        unique,
        [a, b, root].into_iter().collect(),
        "every node reachable down the lineage, each once. The root is \
         included because the cycle reaches it; the route skips ids it already \
         holds"
    );
}
