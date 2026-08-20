//! Does retraction actually take an edge out of the belief-bearing reads?
//!
//! Before `EDGE_IN_FORCE` these tests could not fail: `valid_to` was set on 6 of
//! 987,857 production rows and exactly one query in the workspace filtered on it,
//! so a "retracted" edge kept feeding belief. Retirement therefore hard-DELETEd
//! the edge, destroying `properties.decided_by` along with it. These pin the
//! property that lets retirement stop deleting.

use epigraph_db::repos::edge::EdgeRepository;
use epigraph_db::repos::sheaf::SheafRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

/// A claim with a concrete belief interval — `get_epistemic_edge_pairs` requires
/// `pignistic_prob IS NOT NULL` on both endpoints, so a bare fixture claim with
/// NULL belief would make these tests pass for the wrong reason.
async fn insert_believed_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id,
                             belief, plausibility, pignistic_prob)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, 0.6, 0.9, 0.75)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

async fn insert_supports_edge(pool: &PgPool, src: Uuid, tgt: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, $2, 'claim', $3, 'claim', 'supports')",
    )
    .bind(id)
    .bind(src)
    .bind(tgt)
    .execute(pool)
    .await
    .expect("edge");
    id
}

/// The core property. An edge that is in force participates in the sheaf
/// consistency scan; the same edge, once retracted, does not — while the row
/// itself survives.
#[sqlx::test(migrations = "../../migrations")]
async fn retracting_an_edge_removes_it_from_the_sheaf_scan_but_keeps_the_row(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_believed_claim(&pool, agent).await;
    let b = insert_believed_claim(&pool, agent).await;
    let edge = insert_supports_edge(&pool, a, b).await;

    let seen = |pairs: &[epigraph_db::repos::sheaf::EpistemicEdgePairRow]| {
        pairs.iter().any(|p| p.source_id == a && p.target_id == b)
    };

    let before = SheafRepository::get_epistemic_edge_pairs(&pool, None)
        .await
        .expect("scan before");
    assert!(
        seen(&before),
        "precondition: an in-force supports edge must appear in the epistemic scan, \
         otherwise this test cannot detect the change it exists to detect"
    );

    let closed = EdgeRepository::retract(&pool, &[edge])
        .await
        .expect("retract");
    assert_eq!(closed, vec![edge], "retract must report the edge it closed");

    let after = SheafRepository::get_epistemic_edge_pairs(&pool, None)
        .await
        .expect("scan after");
    assert!(
        !seen(&after),
        "a retracted edge must not appear in the epistemic scan — if it does, \
         retraction is decorative and retirement has to keep deleting"
    );

    // The row survives. This is the entire reason for preferring retraction.
    let (present, closed_at): (i64, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT count(*), max(valid_to) FROM edges WHERE id = $1")
            .bind(edge)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(present, 1, "the edge row must survive retraction");
    assert!(closed_at.is_some(), "the surviving row must carry valid_to");
}

/// Retraction is idempotent and does not rewrite history forward. A second
/// retire must not advance an existing `valid_to`, or the audit trail would drift
/// every time an operator re-ran a cleanup.
#[sqlx::test(migrations = "../../migrations")]
async fn retracting_twice_preserves_the_original_timestamp(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_believed_claim(&pool, agent).await;
    let b = insert_believed_claim(&pool, agent).await;
    let edge = insert_supports_edge(&pool, a, b).await;

    let first = EdgeRepository::retract(&pool, &[edge])
        .await
        .expect("first");
    assert_eq!(first, vec![edge]);
    let t1: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT valid_to FROM edges WHERE id = $1")
            .bind(edge)
            .fetch_one(&pool)
            .await
            .unwrap();

    let second = EdgeRepository::retract(&pool, &[edge])
        .await
        .expect("second");
    assert!(
        second.is_empty(),
        "a re-retract must report nothing newly closed, got {second:?}"
    );
    let t2: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT valid_to FROM edges WHERE id = $1")
            .bind(edge)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(t1, t2, "re-retracting must not advance valid_to");
}

/// The re-derivation guard. `is_in_force` is what stops a later recompute waking
/// a retracted edge back into a BBA — without it the retraction silently undoes
/// itself on the next sweep.
#[sqlx::test(migrations = "../../migrations")]
async fn is_in_force_tracks_retraction_and_is_false_for_unknown_edges(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_believed_claim(&pool, agent).await;
    let b = insert_believed_claim(&pool, agent).await;
    let edge = insert_supports_edge(&pool, a, b).await;

    assert!(
        EdgeRepository::is_in_force(&pool, edge).await.unwrap(),
        "a fresh edge is in force"
    );
    EdgeRepository::retract(&pool, &[edge])
        .await
        .expect("retract");
    assert!(
        !EdgeRepository::is_in_force(&pool, edge).await.unwrap(),
        "a retracted edge is not in force"
    );
    assert!(
        !EdgeRepository::is_in_force(&pool, Uuid::new_v4())
            .await
            .unwrap(),
        "an edge that does not exist is not in force — the auto-wire guard must \
         not treat a missing row as permission to wire"
    );
}

/// A future-dated `valid_to` means "in force until then", not "already retracted".
/// Guards against the predicate being simplified to a bare `valid_to IS NULL`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_future_dated_valid_to_is_still_in_force(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_believed_claim(&pool, agent).await;
    let b = insert_believed_claim(&pool, agent).await;
    let edge = insert_supports_edge(&pool, a, b).await;

    sqlx::query("UPDATE edges SET valid_to = now() + interval '1 year' WHERE id = $1")
        .bind(edge)
        .execute(&pool)
        .await
        .unwrap();

    assert!(
        EdgeRepository::is_in_force(&pool, edge).await.unwrap(),
        "an edge valid until next year is in force now"
    );
    let pairs = SheafRepository::get_epistemic_edge_pairs(&pool, None)
        .await
        .expect("scan");
    assert!(
        pairs.iter().any(|p| p.source_id == a && p.target_id == b),
        "a future-dated edge must still participate in the epistemic scan"
    );
}
