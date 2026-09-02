//! Hard-delete test claims that leak into a database.
//!
//! This replaces the `DELETE /api/v1/claims/:id` + `POST
//! /api/v1/claims/:id/confirm-delete` endpoint pair. Those implemented a
//! two-phase governed deletion — `claims:delete` scope plus an *approved*
//! `proposed_deletion` challenge — but the capability they governed is one this
//! system should not have: EpiGraph is an epistemic ledger, claims are retired by
//! supersession, and edges are now retracted rather than deleted. A production
//! path that destroys a claim and hard-deletes every edge touching it is the last
//! hole in that policy.
//!
//! Test cleanup is the only legitimate use, so it lives here, in a test target,
//! where it cannot be reached over HTTP by any principal at any scope.
//!
//! The challenge/approval machinery is deliberately NOT carried over. It existed
//! to make a production deletion auditable; auditing the removal of a row that a
//! test created two seconds ago is ceremony, and it would have been the only
//! consumer of `challenge_type = 'proposed_deletion'`.

use sqlx::PgPool;
use uuid::Uuid;

/// Databases a destructive helper may point at.
///
/// Mirrors `epigraph-db/tests/claim_repo_helpers.rs::db_is_disposable`, and
/// exists for the same recorded reason: test fixtures issuing unguarded DDL
/// against bare `DATABASE_URL` dropped `uq_claims_content_hash_agent` off the
/// live `epigraph` database out-of-band, and the constraint is still absent
/// (95,381 duplicate `(content_hash, agent_id)` groups accumulated since).
///
/// An allowlist of shapes, not a blocklist: CI names its throwaway service
/// database `epigraph` too, identically to the long-lived deployment, so no
/// name-based rule alone can separate them — CI sets the opt-in instead.
/// `_e2e` and `_dev` are deliberately excluded; `epigraph_internal_e2e` is
/// long-lived despite the test-sounding name.
fn db_is_disposable(name: &str) -> bool {
    name.starts_with("_sqlx_test") || name.ends_with("_test")
}

const DESTRUCTIVE_OPT_IN: &str = "EPIGRAPH_TEST_DESTRUCTIVE_DB";

/// Panics unless `pool` points at a database this helper is allowed to destroy.
///
/// Panics rather than skips: a silent skip would let a misdirected cleanup look
/// like it succeeded, and the caller would go on believing the rows are gone.
async fn assert_disposable(pool: &PgPool) {
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("current_database()");
    assert!(
        db_is_disposable(&db) || std::env::var(DESTRUCTIVE_OPT_IN).as_deref() == Ok("1"),
        "refusing to hard-delete claims from {db:?}: not a disposable database. \
         Use a `*_test` database or an `_sqlx_test*` fixture; set \
         {DESTRUCTIVE_OPT_IN}=1 if {db:?} really is disposable."
    );
}

/// Hard-delete the named claims and every edge touching them.
///
/// Returns `(claims_deleted, edges_deleted)`.
///
/// This is the ONE place in the workspace where deleting a claim's edges is
/// correct rather than a policy violation: the claim row itself is going away,
/// and `edges` has no FK cascade to `claims`, so retracting them would leave
/// rows pointing at a claim that no longer exists. Elsewhere, edge removal is
/// `EdgeRepository::retract_by_id`.
///
/// Ordering matters — edges first. The reverse leaves a window where an edge
/// references a deleted claim, which trips `edges_validate_refs`.
pub async fn hard_delete_test_claims(pool: &PgPool, ids: &[Uuid]) -> (u64, u64) {
    assert_disposable(pool).await;
    if ids.is_empty() {
        return (0, 0);
    }

    let edges = sqlx::query(
        "DELETE FROM edges
          WHERE (source_id = ANY($1) AND source_type = 'claim')
             OR (target_id = ANY($1) AND target_type = 'claim')",
    )
    .bind(ids)
    .execute(pool)
    .await
    .expect("delete edges")
    .rows_affected();

    let claims = sqlx::query("DELETE FROM claims WHERE id = ANY($1)")
        .bind(ids)
        .execute(pool)
        .await
        .expect("delete claims")
        .rows_affected();

    (claims, edges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposable_allowlist_admits_fixtures_and_test_suffixes_only() {
        assert!(db_is_disposable("_sqlx_test_1234"));
        assert!(db_is_disposable("epigraph_db_repo_test"));
        assert!(db_is_disposable("epigraph_e2e_20260820_test"));
        // The live deployment, and the two names that look disposable but are not.
        assert!(!db_is_disposable("epigraph"));
        assert!(!db_is_disposable("epigraph_internal_e2e"));
        assert!(!db_is_disposable("epigraph_dev"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn deletes_the_claim_and_its_edges(pool: PgPool) {
        let agent: Uuid = sqlx::query_scalar(
            "INSERT INTO agents (id, public_key, created_at, updated_at)
             VALUES (gen_random_uuid(), sha256(gen_random_uuid()::text::bytea), NOW(), NOW())
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let mut ids = Vec::new();
        for i in 0..2 {
            let content = format!("cleanup fixture {i}");
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
                 VALUES (gen_random_uuid(), $1, sha256($1::bytea), 0.5, $2) RETURNING id",
            )
            .bind(&content)
            .bind(agent)
            .fetch_one(&pool)
            .await
            .unwrap();
            ids.push(id);
        }
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
             VALUES ($1, 'claim', $2, 'claim', 'supports')",
        )
        .bind(ids[0])
        .bind(ids[1])
        .execute(&pool)
        .await
        .unwrap();

        let (claims, edges) = hard_delete_test_claims(&pool, &ids).await;
        assert_eq!(claims, 2);
        assert_eq!(edges, 1);

        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = ANY($1)")
            .bind(&ids)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0, "claims must be gone");
        let dangling: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE source_id = ANY($1) OR target_id = ANY($1)",
        )
        .bind(&ids)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(dangling, 0, "no edge may outlive the claim it references");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn empty_input_is_a_no_op(pool: PgPool) {
        assert_eq!(hard_delete_test_claims(&pool, &[]).await, (0, 0));
    }
}
