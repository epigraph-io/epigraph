//! Tier-1 unit tests for create_claim_idempotent.
//! Patterns after crates/epigraph-db/tests/claim_repo_helpers.rs.

#[macro_use]
mod common;

use common::*;
use epigraph_crypto::ContentHasher;
use epigraph_mcp::claim_helper::create_claim_idempotent;
use tracing_test::traced_test;
use uuid::Uuid;

// ────────────────────────────────────────────────────────────────────────────
// helper_creates_when_absent — first call inserts and emits AUTHORED
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn helper_creates_when_absent() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(&format!("absent {}", Uuid::new_v4()), agent_id);

    let (returned, was_created) = create_claim_idempotent(&pool, &claim, "test_tool")
        .await
        .expect("helper call");
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

#[tokio::test]
async fn helper_returns_existing_when_present() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let content = format!("existing {}", Uuid::new_v4());
    let claim_a = make_claim(&content, agent_id);
    let claim_b = make_claim(&content, agent_id);

    let (first, first_created) = create_claim_idempotent(&pool, &claim_a, "test_tool")
        .await
        .expect("first call");
    let (second, second_created) = create_claim_idempotent(&pool, &claim_b, "test_tool")
        .await
        .expect("second call");

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

#[tokio::test]
async fn helper_emits_authored_on_both_branches() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let content = format!("both-branches {}", Uuid::new_v4());
    let claim = make_claim(&content, agent_id);

    let _ = create_claim_idempotent(&pool, &claim, "test_tool")
        .await
        .expect("first");
    let _ = create_claim_idempotent(&pool, &claim, "test_tool")
        .await
        .expect("second");

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

#[tokio::test]
async fn helper_post_107_idempotent() {
    let pool = test_pool_or_skip!();
    add_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let content = format!("post-107 {}", Uuid::new_v4());
    let claim = make_claim(&content, agent_id);

    let (first, first_created) = create_claim_idempotent(&pool, &claim, "test_tool")
        .await
        .expect("first call");
    let (second, second_created) = create_claim_idempotent(&pool, &claim, "test_tool")
        .await
        .expect("second call");

    assert!(first_created);
    assert!(!second_created);
    let first_uuid: Uuid = first.id.into();
    let second_uuid: Uuid = second.id.into();
    assert_eq!(first_uuid, second_uuid);
}

// ────────────────────────────────────────────────────────────────────────────
// helper_pre_107_no_constraint — find-then-return path under pre-107 fixture
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn helper_pre_107_no_constraint() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let content = format!("pre-107 {}", Uuid::new_v4());
    let claim = make_claim(&content, agent_id);

    let (_first, first_created) = create_claim_idempotent(&pool, &claim, "test_tool")
        .await
        .expect("first call");
    let (_second, second_created) = create_claim_idempotent(&pool, &claim, "test_tool")
        .await
        .expect("second call");

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
// `--test-threads=1` makes this safe (no other test sees the constraint).

#[traced_test]
#[tokio::test]
async fn helper_authored_failure_does_not_propagate() {
    let pool = test_pool_or_skip!();
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

    let result = create_claim_idempotent(&pool, &claim, "test_tool").await;

    sqlx::query("ALTER TABLE edges DROP CONSTRAINT no_authored_edges_for_test")
        .execute(&pool)
        .await
        .expect("drop no-AUTHORED constraint");

    let (returned, was_created) = result.expect("helper must not propagate AUTHORED failure");
    assert!(
        was_created,
        "claim insert succeeded even though edge insert failed"
    );
    let claim_uuid: Uuid = returned.id.into();

    // Claim row exists despite AUTHORED edge missing
    let claim_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM claims WHERE id = $1")
        .bind(claim_uuid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(claim_count.0, 1, "orphan claim row persisted");

    // Confirm the warn fired
    assert!(
        logs_contain("AUTHORED verb-edge emit failed"),
        "tracing::warn! must fire on AUTHORED failure"
    );
}
