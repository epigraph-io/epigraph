//! Tier-1 unit tests for create_claim_idempotent.
//! Patterns after crates/epigraph-db/tests/claim_repo_helpers.rs — which is
//! also where the `#[sqlx::test]` shape below comes from: that file has run on
//! a per-test database since it was written, with its own
//! `drop_unique_constraint` / `add_unique_constraint`.
//!
//! # Why every arm takes an injected `pool`
//!
//! These arms mutate the SCHEMA, not just rows. Five of the six run
//! `common::drop_unique_constraint`, which is
//! `ALTER TABLE claims DROP CONSTRAINT IF EXISTS uq_claims_content_hash_agent`
//! and is never restored by the arm that ran it; `helper_post_107_idempotent`
//! re-adds it after a table-wide dedup `DELETE FROM claims`; and
//! `helper_authored_failure_does_not_propagate` adds a `CHECK` on `edges` that
//! rejects every `AUTHORED` write while it is installed. On a shared database
//! each of those is visible to every other test in the process and to any other
//! process pointed at the same database.
//!
//! `#[sqlx::test]` gives each arm its own database, so the schema change is
//! scoped to the arm that made it and the assertions are unchanged. The
//! `test_pool_or_skip!` construction is dropped with the shared pool: it built a
//! pool from the ambient `DATABASE_URL` and silently RETURNED — a green,
//! vacuous pass — when that variable was unset.
//!
//! # What this does NOT license
//!
//! `ci.yml` runs `cargo test -p epigraph-mcp -- --test-threads=1` and names
//! this file's `CHECK` constraint as the reason. That flag is deliberately left
//! alone, and the comment's premise is now incomplete rather than merely stale:
//! `common::drop_unique_constraint` has FIVE callers in this crate —
//! `novelty_gate_test.rs`, `event_log_wiring_tests.rs`, `tool_resubmit_tests.rs`
//! and `memorize_persists_labels.rs` besides this file — and all four of those
//! still run on the shared pool. Converting this binary does not make the crate
//! safe to parallelise; the other four are reported as a measurement, not swept
//! in here on borrowed evidence.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::*;
use epigraph_crypto::ContentHasher;
use epigraph_mcp::claim_helper::create_claim_idempotent;
use sqlx::PgPool;
use tracing_test::traced_test;
use uuid::Uuid;

// ────────────────────────────────────────────────────────────────────────────
// helper_creates_when_absent — first call inserts and emits AUTHORED
// ────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn helper_creates_when_absent(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(&format!("absent {}", Uuid::new_v4()), agent_id);

    // `create_claim_idempotent` takes `&mut PgConnection` rather than a pool
    // now — the whole point of the change is that a submission's claim, trace,
    // evidence and AUTHORED edge share ONE stamped connection. A bare checkout
    // is the minimum shape that satisfies that here; `tx_is_not_poisoned_...`
    // below is the arm that drives the transactional one.
    let mut conn = pool.acquire().await.expect("checkout");
    let (returned, was_created) =
        create_claim_idempotent(&mut conn, &viewer, &claim, None, "test_tool")
            .await
            .expect("helper call");
    drop(conn);
    assert!(was_created, "first call should be was_created=true");

    let claim_uuid: Uuid = returned.id.into();
    let claim_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM claims WHERE id = $1")
        .bind(claim_uuid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(claim_count.0, 1, "exactly one claim row");

    let edge_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'AUTHORED'
           AND properties->>'tool' = 'test_tool'
           AND properties->>'was_created' = 'true'",
    )
    .bind(agent_id)
    .bind(claim_uuid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(edge_count.0, 1, "one AUTHORED edge with was_created=true");
}

// ────────────────────────────────────────────────────────────────────────────
// helper_returns_existing_when_present — second call returns canonical
// ────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn helper_returns_existing_when_present(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let content = format!("existing {}", Uuid::new_v4());
    let claim_a = make_claim(&content, agent_id);
    let claim_b = make_claim(&content, agent_id);

    // `create_claim_idempotent` takes `&mut PgConnection` rather than a pool
    // now — the whole point of the change is that a submission's claim, trace,
    // evidence and AUTHORED edge share ONE stamped connection. A bare checkout
    // is the minimum shape that satisfies that here; `tx_is_not_poisoned_...`
    // below is the arm that drives the transactional one.
    let mut conn = pool.acquire().await.expect("checkout");
    let (first, first_created) =
        create_claim_idempotent(&mut conn, &viewer, &claim_a, None, "test_tool")
            .await
            .expect("first call");
    let (second, second_created) =
        create_claim_idempotent(&mut conn, &viewer, &claim_b, None, "test_tool")
            .await
            .expect("second call");
    drop(conn);

    assert!(first_created);
    assert!(!second_created, "second call should be was_created=false");

    let first_uuid: Uuid = first.id.into();
    let second_uuid: Uuid = second.id.into();
    assert_eq!(
        first_uuid, second_uuid,
        "second call returns canonical UUID"
    );

    let claim_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(ContentHasher::hash(content.as_bytes()).as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claim_count.0, 1, "still only one claim row");

    let authored_total: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'AUTHORED'",
    )
    .bind(agent_id)
    .bind(first_uuid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(authored_total.0, 2, "two AUTHORED edges (one per call)");

    let resubmit_authored: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'AUTHORED'
           AND properties->>'was_created' = 'false'",
    )
    .bind(agent_id)
    .bind(first_uuid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        resubmit_authored.0, 1,
        "second call's AUTHORED has was_created=false"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// helper_emits_authored_on_both_branches — sanity cross-check
// ────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn helper_emits_authored_on_both_branches(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let content = format!("both-branches {}", Uuid::new_v4());
    let claim = make_claim(&content, agent_id);

    // `create_claim_idempotent` takes `&mut PgConnection` rather than a pool
    // now — the whole point of the change is that a submission's claim, trace,
    // evidence and AUTHORED edge share ONE stamped connection. A bare checkout
    // is the minimum shape that satisfies that here; `tx_is_not_poisoned_...`
    // below is the arm that drives the transactional one.
    let mut conn = pool.acquire().await.expect("checkout");
    let _ = create_claim_idempotent(&mut conn, &viewer, &claim, None, "test_tool")
        .await
        .expect("first");
    let _ = create_claim_idempotent(&mut conn, &viewer, &claim, None, "test_tool")
        .await
        .expect("second");
    drop(conn);

    let claim_uuid: (Uuid,) =
        sqlx::query_as("SELECT id FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(ContentHasher::hash(content.as_bytes()).as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let true_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges
         WHERE target_id = $1 AND relationship = 'AUTHORED'
           AND properties->>'was_created' = 'true'",
    )
    .bind(claim_uuid.0)
    .fetch_one(&pool)
    .await
    .unwrap();
    let false_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges
         WHERE target_id = $1 AND relationship = 'AUTHORED'
           AND properties->>'was_created' = 'false'",
    )
    .bind(claim_uuid.0)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(true_count.0, 1, "one was_created=true edge");
    assert_eq!(false_count.0, 1, "one was_created=false edge");
}

// ────────────────────────────────────────────────────────────────────────────
// helper_post_107_idempotent — second call returns existing post-constraint
// ────────────────────────────────────────────────────────────────────────────
//
// Single-threaded tests cannot deterministically exercise the catch path in
// create_or_get (the unique-violation recovery from a concurrent INSERT) —
// the find-by-(content_hash, agent_id) lookup runs first and returns the
// existing row before the INSERT is attempted. This test instead verifies
// that post-107 idempotency holds: a second helper call for the same
// (content_hash, agent_id) returns the canonical row regardless of whether
// the find-then-return or INSERT-catch-refind branch fired internally.
// Mirrors the equivalent test in crates/epigraph-db/tests/claim_repo_helpers.rs.

#[sqlx::test(migrations = "../../migrations")]
async fn helper_post_107_idempotent(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    add_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let content = format!("post-107 {}", Uuid::new_v4());
    let claim = make_claim(&content, agent_id);

    // `create_claim_idempotent` takes `&mut PgConnection` rather than a pool
    // now — the whole point of the change is that a submission's claim, trace,
    // evidence and AUTHORED edge share ONE stamped connection. A bare checkout
    // is the minimum shape that satisfies that here; `tx_is_not_poisoned_...`
    // below is the arm that drives the transactional one.
    let mut conn = pool.acquire().await.expect("checkout");
    let (first, first_created) =
        create_claim_idempotent(&mut conn, &viewer, &claim, None, "test_tool")
            .await
            .expect("first call");
    let (second, second_created) =
        create_claim_idempotent(&mut conn, &viewer, &claim, None, "test_tool")
            .await
            .expect("second call");
    drop(conn);

    assert!(first_created);
    assert!(!second_created);
    let first_uuid: Uuid = first.id.into();
    let second_uuid: Uuid = second.id.into();
    assert_eq!(first_uuid, second_uuid);
}

// ────────────────────────────────────────────────────────────────────────────
// helper_pre_107_no_constraint — find-then-return path under pre-107 fixture
// ────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn helper_pre_107_no_constraint(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let content = format!("pre-107 {}", Uuid::new_v4());
    let claim = make_claim(&content, agent_id);

    // `create_claim_idempotent` takes `&mut PgConnection` rather than a pool
    // now — the whole point of the change is that a submission's claim, trace,
    // evidence and AUTHORED edge share ONE stamped connection. A bare checkout
    // is the minimum shape that satisfies that here; `tx_is_not_poisoned_...`
    // below is the arm that drives the transactional one.
    let mut conn = pool.acquire().await.expect("checkout");
    let (_first, first_created) =
        create_claim_idempotent(&mut conn, &viewer, &claim, None, "test_tool")
            .await
            .expect("first call");
    let (_second, second_created) =
        create_claim_idempotent(&mut conn, &viewer, &claim, None, "test_tool")
            .await
            .expect("second call");
    drop(conn);

    assert!(first_created);
    assert!(
        !second_created,
        "find-then-return path returns existing row"
    );

    let claim_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(ContentHasher::hash(content.as_bytes()).as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claim_count.0, 1, "exactly one row, no pre-107 dup created");
}

// ────────────────────────────────────────────────────────────────────────────
// helper_authored_failure_does_not_propagate — log warn, return Ok
// ────────────────────────────────────────────────────────────────────────────
//
// Forces an AUTHORED INSERT failure by adding a temporary CHECK constraint
// that rejects AUTHORED edges, runs the helper, asserts Ok with a warn-level
// log, then drops the constraint. Earlier versions tried renaming `edges`
// away — that doesn't work because sqlx prepared statements bind to table
// OIDs (RENAME preserves OID, so the INSERT still hits the renamed table).
//
// What makes the constraint safe is now the per-test database, not
// `--test-threads=1`: no other arm and no other process shares this `edges`.
// The DROP below is kept anyway — the constraint is dropped before the result
// is unwrapped, so a failing assertion still cannot leave it installed if this
// arm is ever run against a shared pool again.

#[traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn helper_authored_failure_does_not_propagate(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(&format!("authored-fail {}", Uuid::new_v4()), agent_id);

    // NOT VALID skips the existing-row scan — earlier tests in this file
    // legitimately created AUTHORED edges that would otherwise fail validation.
    // The constraint still rejects new INSERTs.
    sqlx::query(
        "ALTER TABLE edges ADD CONSTRAINT no_authored_edges_for_test \
         CHECK (relationship != 'AUTHORED') NOT VALID",
    )
    .execute(&pool)
    .await
    .expect("add no-AUTHORED constraint");

    // RUN IT IN A TRANSACTION, which is the shape `submit_claim` / `memorize`
    // now use, and the only shape that can show the savepoint is doing work.
    //
    // WHY THIS ARM CHANGED RATHER THAN JUST HAVING ITS ARGUMENT SWAPPED: a
    // failed statement aborts the WHOLE PostgreSQL transaction, so the old
    // `let _ = EdgeRepository::create(...)` — an error swallowed into a warn —
    // stops preserving "AUTHORED failure does not propagate" the instant the
    // claim INSERT shares a transaction with it. It becomes "the claim is lost
    // at COMMIT, with `current transaction is aborted` in place of the real
    // cause". `emit_verb_edge_best_effort` wraps the edge in a SAVEPOINT for
    // exactly that reason, and the assertions below are what distinguish the two
    // implementations: a plain swallow makes the `SELECT` after the failure and
    // then the `commit()` both fail.
    let mut tx = pool.begin().await.expect("begin");
    let result = create_claim_idempotent(&mut tx, &viewer, &claim, None, "test_tool").await;

    let (returned, was_created) = result.expect("helper must not propagate AUTHORED failure");
    assert!(
        was_created,
        "claim insert succeeded even though edge insert failed"
    );
    let claim_uuid: Uuid = returned.id.into();

    // THE TRANSACTION IS STILL USABLE. On a swallowed-error implementation this
    // statement fails with 25P02 `current transaction is aborted`.
    let in_tx_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM claims WHERE id = $1")
        .bind(claim_uuid)
        .fetch_one(&mut *tx)
        .await
        .expect(
            "the outer transaction must still be usable after a refused verb-edge; a              swallowed error would have left it in the aborted state (25P02)",
        );
    assert_eq!(in_tx_count.0, 1, "claim row is visible inside the tx");

    tx.commit()
        .await
        .expect("the commit must succeed: only the edge was rolled back, to its savepoint");

    sqlx::query("ALTER TABLE edges DROP CONSTRAINT no_authored_edges_for_test")
        .execute(&pool)
        .await
        .expect("drop no-AUTHORED constraint");

    // The claim survived the commit...
    let claim_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM claims WHERE id = $1")
        .bind(claim_uuid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(claim_count.0, 1, "claim row persisted");

    // ...and the edge did not. The savepoint rolled back exactly one statement.
    let authored_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE target_id = $1 AND relationship = 'AUTHORED'",
    )
    .bind(claim_uuid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        authored_count.0, 0,
        "the refused AUTHORED edge must not have been committed"
    );

    // Confirm the warn fired
    assert!(
        logs_contain("verb-edge emit failed"),
        "tracing::warn! must fire on AUTHORED failure"
    );
}
