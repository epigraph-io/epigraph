//! The MCP `deprecate_workflow` cascade is ONE read and ONE write.
//!
//! Deferred-commitment screen key deprecate-workflow-atomic
//! (`docs/superpowers/plans/2026-05-08-pr100-followups.md`, "Migrating to a
//! single transaction in `deprecate_workflow` cascade"). The tool used to
//! deprecate the root, then walk the lineage node by node. Every write was its
//! own autocommit statement: one `UPDATE claims` and one `UPDATE workflows` per
//! node. The edge read per node was `.unwrap_or_default()`. So:
//!
//! * a failure part-way through left the lineage half deprecated;
//! * a failure between a node's `claims` row and its `workflows` row left the
//!   two disagreeing;
//! * a failed edge read looked like "no children". The cascade stopped early
//!   and the tool still reported success.
//!
//! The first three tests inject each failure and assert that NOTHING was
//! written. Each one fails on the per-node loop. The last three pin the walk's
//! shape, which moved from a Rust loop into one recursive statement: a cycle
//! terminates, and a non-workflow or unreadable claim stops the walk, as the
//! loop's per-child probe did.
//!
//! Every assertion reads the ROW. An `Err` that still wrote would pass a
//! status-only test.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use uuid::Uuid;
mod common;
use common::*;

async fn plant_stub_embedding(pool: &PgPool, id: Uuid) {
    let stub = {
        let mut v = vec!["0.0"; 1536];
        v[0] = "0.1";
        format!("[{}]", v.join(","))
    };
    sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2")
        .bind(stub.as_str())
        .bind(id)
        .execute(pool)
        .await
        .expect("plant stub embedding");
}

/// The hierarchical `workflows` row that shares `id` with a flat workflow
/// claim. `truth_value` takes the column default, 1.0.
async fn seed_hierarchical_row(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal) \
         VALUES ($1, $2, 0, 'atomic cascade fixture')",
    )
    .bind(id)
    .bind(format!("atomic-cascade-{id}"))
    .execute(pool)
    .await
    .expect("seed hierarchical workflows row");
}

/// A flat workflow claim (truth 0.5, current) with an embedding and a
/// hierarchical row of the same id (truth 1.0).
async fn seed_full_workflow(pool: &PgPool, goal: &str) -> Uuid {
    let id = seed_workflow_claim(pool, goal, &["s1"]).await;
    plant_stub_embedding(pool, id).await;
    seed_hierarchical_row(pool, id).await;
    id
}

/// `(truth_value, is_current, embedding IS NOT NULL)` of the claim.
async fn claim_state(pool: &PgPool, id: Uuid) -> (f64, bool, bool) {
    sqlx::query_as(
        "SELECT truth_value, is_current, embedding IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read claim back")
}

async fn hierarchical_truth(pool: &PgPool, id: Uuid) -> f64 {
    sqlx::query_scalar("SELECT truth_value FROM workflows WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read workflows row back")
}

async fn assert_claim_untouched(pool: &PgPool, id: Uuid, what: &str) {
    let (truth, is_current, embedded) = claim_state(pool, id).await;
    assert!(
        (truth - 0.5).abs() < 1e-9 && is_current && embedded,
        "{what} ({id}) must be untouched (truth 0.5, is_current, embedded), \
         got truth={truth} is_current={is_current} embedded={embedded}"
    );
}

async fn assert_claim_deprecated(pool: &PgPool, id: Uuid, what: &str) {
    let (truth, is_current, embedded) = claim_state(pool, id).await;
    assert!(
        (truth - 0.05).abs() < 1e-9 && !is_current && !embedded,
        "{what} ({id}) must be deprecated (truth 0.05, not current, embedding NULL), \
         got truth={truth} is_current={is_current} embedded={embedded}"
    );
}

/// Make every `UPDATE` of `table`'s row `id` raise. Keyed on one id, so the
/// statement fails part-way through its rows, after others were written.
/// `id` is a `Uuid`, so formatting it into DDL cannot inject anything.
async fn fail_updates_of(pool: &PgPool, table: &str, id: Uuid) {
    sqlx::query(
        "CREATE OR REPLACE FUNCTION atomic_cascade_injected_failure() RETURNS trigger \
         LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'injected failure updating %', NEW.id; END $$",
    )
    .execute(pool)
    .await
    .expect("create failure-injection function");
    sqlx::query(&format!(
        "CREATE TRIGGER atomic_cascade_injected_failure_{table} \
         BEFORE UPDATE ON {table} FOR EACH ROW WHEN (NEW.id = '{id}'::uuid) \
         EXECUTE FUNCTION atomic_cascade_injected_failure()"
    ))
    .execute(pool)
    .await
    .expect("install failure-injection trigger");
}

async fn stop_failing_updates_of(pool: &PgPool, table: &str) {
    sqlx::query(&format!(
        "DROP TRIGGER atomic_cascade_injected_failure_{table} ON {table}"
    ))
    .execute(pool)
    .await
    .expect("drop failure-injection trigger");
}

async fn deprecate(
    pool: &PgPool,
    root: Uuid,
    cascade: bool,
) -> Result<rmcp::model::CallToolResult, epigraph_mcp::errors::McpError> {
    let viewer = fixture::public_viewer(pool).await;
    let server = build_test_server(pool.clone());
    epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        &viewer,
        epigraph_mcp::types::DeprecateWorkflowParams {
            workflow_id: root.to_string(),
            reason: "atomic cascade test".into(),
            cascade: Some(cascade),
        },
    )
    .await
}

fn deprecated_ids(result: &rmcp::model::CallToolResult) -> Vec<Uuid> {
    first_text(result)["deprecated_ids"]
        .as_array()
        .expect("deprecated_ids must be an array")
        .iter()
        .map(|v| v.as_str().expect("id string").parse().expect("uuid"))
        .collect()
}

/// root <- a <- b, and the write of b fails. Pre-fix, root and a had already
/// been committed by then: the call returned an error over a lineage it had
/// half deprecated.
///
/// Then the failure is removed and the same call is re-run. That proves the
/// refusal came from the injected failure and not from the fixture, and it pins
/// the success shape: every claim deprecated, every `workflows` row mirrored.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failure_part_way_through_the_cascade_deprecates_nothing(pool: PgPool) {
    let root = seed_full_workflow(&pool, "root").await;
    let a = seed_full_workflow(&pool, "variant a").await;
    let b = seed_full_workflow(&pool, "variant b").await;
    insert_claim_edge(&pool, a, root, "variant_of").await;
    insert_claim_edge(&pool, b, a, "variant_of").await;

    fail_updates_of(&pool, "claims", b).await;
    let result = deprecate(&pool, root, true).await;
    assert!(
        result.is_err(),
        "the injected failure on {b} must surface as an error"
    );
    for (id, what) in [(root, "the root"), (a, "variant a"), (b, "variant b")] {
        assert_claim_untouched(&pool, id, what).await;
        assert!(
            (hierarchical_truth(&pool, id).await - 1.0).abs() < 1e-9,
            "{what}'s workflows row must be untouched after a failed cascade"
        );
    }

    stop_failing_updates_of(&pool, "claims").await;
    let result = deprecate(&pool, root, true)
        .await
        .expect("with the failure removed, the same cascade succeeds");
    let mut got = deprecated_ids(&result);
    got.sort();
    let mut want = vec![root, a, b];
    want.sort();
    assert_eq!(got, want, "the retried cascade reports the whole lineage");
    for (id, what) in [(root, "the root"), (a, "variant a"), (b, "variant b")] {
        assert_claim_deprecated(&pool, id, what).await;
        assert!(
            (hierarchical_truth(&pool, id).await - 0.05).abs() < 1e-9,
            "{what}'s workflows row must be mirrored to 0.05"
        );
    }
}

/// The `workflows` mirror fails. Pre-fix, the claim write had already
/// committed in its own statement, so the flat row said "deprecated" and the
/// hierarchical row still said 1.0.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_hierarchical_mirror_rolls_back_the_claim_write(pool: PgPool) {
    let root = seed_full_workflow(&pool, "root").await;

    fail_updates_of(&pool, "workflows", root).await;
    let result = deprecate(&pool, root, false).await;
    assert!(
        result.is_err(),
        "the injected failure on the workflows row must surface as an error"
    );
    assert_claim_untouched(&pool, root, "the root claim").await;
    assert!(
        (hierarchical_truth(&pool, root).await - 1.0).abs() < 1e-9,
        "the root's workflows row must be untouched"
    );
}

/// The walk's edge read fails. Pre-fix it was `.unwrap_or_default()`: the loop
/// saw "no children", deprecated the root alone and reported success. Now the
/// walk is an error, and it runs before the write, so nothing is deprecated.
///
/// The failure is injected by renaming a column the walk reads. A trigger
/// cannot fire on a `SELECT`. The claims `UPDATE`'s own triggers do not read
/// that column, so the write would succeed if it ran.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_lineage_read_fails_the_call_before_anything_is_written(pool: PgPool) {
    let root = seed_full_workflow(&pool, "root").await;
    let a = seed_full_workflow(&pool, "variant a").await;
    insert_claim_edge(&pool, a, root, "variant_of").await;

    sqlx::query("ALTER TABLE edges RENAME COLUMN relationship TO relationship_hidden_by_test")
        .execute(&pool)
        .await
        .expect("break the lineage read");
    let result = deprecate(&pool, root, true).await;
    assert!(
        result.is_err(),
        "a failed lineage read must be an error, not an empty lineage; got {:?}",
        result.map(|r| first_text(&r))
    );
    assert_claim_untouched(&pool, root, "the root").await;
    assert_claim_untouched(&pool, a, "variant a").await;
}

/// A pool onto the same test database whose sessions carry a
/// `statement_timeout`, so a statement that never terminates fails with an
/// error instead of leaving a backend running after the test gives up.
async fn pool_with_statement_timeout(pool: &PgPool) -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("SET statement_timeout = '20s'")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect_with((*pool.connect_options()).clone())
        .await
        .expect("connect a statement-timeout pool to the test database")
}

/// Edges (source -> target): a -> root, b -> a, a -> b, root -> b. Walking
/// from root: root's child is a, a's child is b, and b's children are a and
/// root, so there are two cycles. The walk is one recursive statement now, so
/// termination comes from `UNION`, not from a visited set in Rust. A
/// statement timeout bounds it, so a regression to `UNION ALL` fails with an
/// error instead of hanging.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cycle_in_the_lineage_terminates_and_deprecates_each_node_once(pool: PgPool) {
    let root = seed_full_workflow(&pool, "root").await;
    let a = seed_full_workflow(&pool, "variant a").await;
    let b = seed_full_workflow(&pool, "variant b").await;
    insert_claim_edge(&pool, a, root, "variant_of").await;
    insert_claim_edge(&pool, b, a, "variant_of").await;
    insert_claim_edge(&pool, a, b, "supersedes").await;
    insert_claim_edge(&pool, root, b, "variant_of").await;

    let bounded = pool_with_statement_timeout(&pool).await;
    let result = deprecate(&bounded, root, true)
        .await
        .expect("the cascade over a cyclic lineage terminates and succeeds");
    bounded.close().await;

    let got = deprecated_ids(&result);
    let unique: std::collections::HashSet<Uuid> = got.iter().copied().collect();
    assert_eq!(got.len(), unique.len(), "no id twice: {got:?}");
    assert_eq!(
        unique,
        [root, a, b].into_iter().collect(),
        "exactly the three nodes of the cycle"
    );
    assert_eq!(got[0], root, "the root is reported first");
    for (id, what) in [(root, "the root"), (a, "variant a"), (b, "variant b")] {
        assert_claim_deprecated(&pool, id, what).await;
    }
}

/// root <- n <- w, where n is NOT a workflow. The per-node loop never walked
/// through a non-workflow claim, so w stayed live. A recursive statement that
/// collected every descendant and filtered by label only at the end would
/// deprecate w. That is the regression this pins.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_workflow_claim_stops_the_cascade(pool: PgPool) {
    let root = seed_full_workflow(&pool, "root").await;
    let n = seed_claim(&pool, "an ordinary claim revision", 0.5).await;
    plant_stub_embedding(&pool, n).await;
    let w = seed_full_workflow(&pool, "workflow beyond an ordinary claim").await;
    insert_claim_edge(&pool, n, root, "supersedes").await;
    insert_claim_edge(&pool, w, n, "variant_of").await;

    let result = deprecate(&pool, root, true)
        .await
        .expect("cascade succeeds");
    assert_eq!(deprecated_ids(&result), vec![root]);
    assert_claim_deprecated(&pool, root, "the root").await;
    assert_claim_untouched(&pool, n, "the non-workflow claim").await;
    assert_claim_untouched(&pool, w, "the workflow reached only through it").await;
    assert!(
        (hierarchical_truth(&pool, w).await - 1.0).abs() < 1e-9,
        "the unreached workflow's workflows row must be untouched"
    );
}

/// root <- p <- w, where p is a workflow private to a group the viewer is not
/// in. Both edges are forced PUBLIC, so the only thing that can stop the walk
/// at p is the claims predicate in the recursive term. The loop skipped p and
/// did not walk through it; so does the statement. Whether an unreadable child
/// should instead refuse the call is D-PR16-per-id-claim-oracles-write-half,
/// and this test does not decide it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_workflow_stops_the_cascade(pool: PgPool) {
    let root = seed_full_workflow(&pool, "root").await;
    let p = seed_full_workflow(&pool, "private variant").await;
    let stranger = seed_agent(&pool).await;
    seed_private_tenancy(&pool, p, stranger).await;
    let w = seed_full_workflow(&pool, "public variant of the private one").await;
    insert_claim_edge(&pool, p, root, "variant_of").await;
    insert_claim_edge(&pool, w, p, "variant_of").await;
    sqlx::query(
        "UPDATE edges SET visibility = 'public', co_owner_group_id = NULL \
         WHERE source_id = ANY($1)",
    )
    .bind(vec![p, w])
    .execute(&pool)
    .await
    .expect("force both lineage edges public");

    let result = deprecate(&pool, root, true)
        .await
        .expect("cascade succeeds");
    assert_eq!(deprecated_ids(&result), vec![root]);
    assert_claim_deprecated(&pool, root, "the root").await;
    assert_claim_untouched(&pool, p, "the private workflow").await;
    assert_claim_untouched(&pool, w, "the workflow reached only through it").await;
}
