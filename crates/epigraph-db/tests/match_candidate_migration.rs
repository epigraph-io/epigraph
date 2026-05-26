//! Integration tests for the `match_candidates` migration (110).
//!
//! Verifies that:
//! - The table is created by the migration.
//! - The `match_candidates_canonical_order` CHECK constraint (claim_a < claim_b)
//!   rejects rows where claim_a > claim_b.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.expect("test DB migrations failed — likely a description/version mismatch with existing _sqlx_migrations; use a fresh DB");
    Some(pool)
}

macro_rules! test_pool_or_skip {
    () => {{
        match try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                return;
            }
        }
    }};
}

/// Insert a minimal agent row, returning its UUID.
async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO agents (id, public_key, created_at, updated_at)
           VALUES ($1, sha256($1::text::bytea), NOW(), NOW())"#,
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("insert agent");
    id
}

/// Insert a minimal claim row for `agent_id`, returning its UUID.
async fn insert_claim(pool: &PgPool, agent_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("test claim {}", id);
    // content_hash must be exactly 32 bytes (BLAKE3 placeholder — sha256 also returns 32 bytes, satisfying the claims_content_hash_length CHECK)
    sqlx::query(
        r#"INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
           VALUES ($1, $2, sha256($2::bytea), 0.5, $3)"#,
    )
    .bind(id)
    .bind(content.as_str())
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

// ────────────────────────────────────────────────────────────────────────────
// Test 1: table exists
// ────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn match_candidates_table_exists(pool: PgPool) {
    let row: (bool,) = sqlx::query_as(
        r#"SELECT EXISTS (
               SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public'
                 AND table_name   = 'match_candidates'
           )"#,
    )
    .fetch_one(&pool)
    .await
    .expect("query information_schema");

    assert!(
        row.0,
        "match_candidates table should exist after migration 035"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2: canonical-order constraint rejects claim_a > claim_b
// ────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn match_candidates_enforces_canonical_order(pool: PgPool) {
    let agent_id = insert_agent(&pool).await;
    let id_a = insert_claim(&pool, agent_id).await;
    let id_b = insert_claim(&pool, agent_id).await;

    // Ensure claim_a > claim_b so the CHECK constraint fires.
    let (bigger, smaller) = if id_a > id_b {
        (id_a, id_b)
    } else {
        (id_b, id_a)
    };

    let result = sqlx::query(
        r#"INSERT INTO match_candidates
               (claim_a, claim_b, score, features, status)
           VALUES ($1, $2, 0.9, '{}', 'pending')"#,
    )
    .bind(bigger) // claim_a > claim_b — violates CHECK
    .bind(smaller)
    .execute(&pool)
    .await;

    let err = result.expect_err("expected CHECK violation when claim_a > claim_b");
    let db_err = err
        .as_database_error()
        .expect("expected a database error, not a connection error");
    assert_eq!(
        db_err.code().as_deref(),
        Some("23514"),
        "expected SQLSTATE 23514 (check_violation), got {:?}",
        db_err.code()
    );
    assert_eq!(
        db_err.constraint(),
        Some("match_candidates_canonical_order"),
        "expected match_candidates_canonical_order constraint, got {:?}",
        db_err.constraint()
    );
}
