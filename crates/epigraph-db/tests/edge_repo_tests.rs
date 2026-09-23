//! `EdgeRepository` integration tests.

mod helpers;

use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, PaperRepository, PgPool};
use helpers::{make_agent, make_claim};

#[sqlx::test(migrations = "../../migrations")]
async fn create_if_not_exists_is_idempotent(pool: PgPool) {
    // Set up real source (paper) and target (claim) so the edge-validation
    // trigger doesn't reject the insert.
    let paper_id = PaperRepository::get_or_create(&pool, "10.1234/idem", Some("Idempotency"), None)
        .await
        .expect("create paper");

    let agent = make_agent(Some("a"));
    let agent_row = AgentRepository::create(&pool, &agent).await.unwrap();
    let claim = make_claim(agent_row.id, "the claim", 0.5);
    let claim_row = ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
        .await
        .unwrap();
    let claim_id: uuid::Uuid = claim_row.id.into();

    let (row1, was_created1) = EdgeRepository::create_if_not_exists(
        &pool, paper_id, "paper", claim_id, "claim", "asserts", None, None, None,
    )
    .await
    .expect("first call inserts");
    assert!(was_created1, "first call must report was_created=true");

    let (row2, was_created2) = EdgeRepository::create_if_not_exists(
        &pool,
        paper_id,
        "paper",
        claim_id,
        "claim",
        "asserts",
        Some(serde_json::json!({"different": "props"})),
        None,
        None,
    )
    .await
    .expect("second call returns existing");

    assert_eq!(row1.id, row2.id, "second call must return existing edge id");
    assert!(
        !was_created2,
        "second call must report was_created=false on dedup hit"
    );
    // Dedup hit must return the STORED properties, not the new request's.
    assert_eq!(
        row2.properties,
        serde_json::json!({}),
        "dedup hit must surface stored properties (empty), not the second call's"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_if_not_exists_distinguishes_by_relationship(pool: PgPool) {
    let paper_id = PaperRepository::get_or_create(&pool, "10.1234/rel", Some("Relationship"), None)
        .await
        .expect("create paper");

    let agent = make_agent(Some("b"));
    let agent_row = AgentRepository::create(&pool, &agent).await.unwrap();
    let claim = make_claim(agent_row.id, "another", 0.5);
    let claim_row = ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
        .await
        .unwrap();
    let claim_id: uuid::Uuid = claim_row.id.into();

    let (row_a, _) = EdgeRepository::create_if_not_exists(
        &pool, paper_id, "paper", claim_id, "claim", "asserts", None, None, None,
    )
    .await
    .unwrap();

    let (row_b, _) = EdgeRepository::create_if_not_exists(
        &pool,
        paper_id,
        "paper",
        claim_id,
        "claim",
        "processed_by",
        None,
        None,
        None,
    )
    .await
    .unwrap();

    assert_ne!(
        row_a.id, row_b.id,
        "different relationship → different edge"
    );
}

/// Count edges incident on either of two claims for a given relationship,
/// in EITHER direction. The matcher treats CORROBORATES as symmetric, so this
/// is the metric that proves bidirectional dedup.
async fn incident_edge_count(pool: &PgPool, a: uuid::Uuid, b: uuid::Uuid, rel: &str) -> i64 {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE relationship = $3
           AND ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))",
    )
    .bind(a)
    .bind(b)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("count edges");
    count
}

/// LOAD-BEARING: `create_symmetric_if_absent` dedups in BOTH directions.
///
/// The forward call (A→B) inserts one CORROBORATES edge. The crucial assertion
/// is the REVERSE call (B→A, same relationship): it must return `false` and
/// must NOT add a second edge. A same-direction-only implementation would
/// insert the reverse edge (returning `true`, count → 2); this is the only
/// assertion that distinguishes symmetric dedup from a plain
/// `(source,target,relationship)` check, so it is the heart of the refactor.
#[sqlx::test(migrations = "../../migrations")]
async fn reverse_direction_dedup_returns_false(pool: PgPool) {
    let agent = make_agent(Some("sym"));
    let agent_row = AgentRepository::create(&pool, &agent).await.unwrap();
    let claim_a = make_claim(agent_row.id, "claim A for symmetric dedup", 0.5);
    let claim_b = make_claim(agent_row.id, "claim B for symmetric dedup", 0.5);
    let a: uuid::Uuid =
        ClaimRepository::create(&pool, &claim_a, epigraph_core::TenancyDecl::Inherited)
            .await
            .unwrap()
            .id
            .into();
    let b: uuid::Uuid =
        ClaimRepository::create(&pool, &claim_b, epigraph_core::TenancyDecl::Inherited)
            .await
            .unwrap()
            .id
            .into();

    let props = serde_json::json!({"source": "cross_source_matcher", "score": 0.91});

    // Forward A→B: first edge of this relationship → inserts.
    let inserted =
        EdgeRepository::create_symmetric_if_absent(&pool, a, b, "CORROBORATES", props.clone())
            .await
            .expect("forward insert");
    assert!(inserted, "first call must insert and return true");
    assert_eq!(
        incident_edge_count(&pool, a, b, "CORROBORATES").await,
        1,
        "exactly one CORROBORATES edge after the forward call"
    );

    // Reverse B→A, same relationship: the symmetric existence check must see
    // the existing (a→b) edge and SKIP. Returns false; count stays 1.
    let inserted_reverse =
        EdgeRepository::create_symmetric_if_absent(&pool, b, a, "CORROBORATES", props.clone())
            .await
            .expect("reverse call runs");
    assert!(
        !inserted_reverse,
        "REVERSE-direction call must dedup (return false) — symmetric, not directional"
    );
    assert_eq!(
        incident_edge_count(&pool, a, b, "CORROBORATES").await,
        1,
        "reverse call must NOT add a second edge — count stays exactly 1"
    );
}

/// Different relationships between the same pair are distinct edges — the
/// dedup is scoped to `relationship`, not just the endpoints.
#[sqlx::test(migrations = "../../migrations")]
async fn create_symmetric_if_absent_distinguishes_by_relationship(pool: PgPool) {
    let agent = make_agent(Some("symrel"));
    let agent_row = AgentRepository::create(&pool, &agent).await.unwrap();
    let claim_a = make_claim(agent_row.id, "claim A for rel discrimination", 0.5);
    let claim_b = make_claim(agent_row.id, "claim B for rel discrimination", 0.5);
    let a: uuid::Uuid =
        ClaimRepository::create(&pool, &claim_a, epigraph_core::TenancyDecl::Inherited)
            .await
            .unwrap()
            .id
            .into();
    let b: uuid::Uuid =
        ClaimRepository::create(&pool, &claim_b, epigraph_core::TenancyDecl::Inherited)
            .await
            .unwrap()
            .id
            .into();

    let props = serde_json::json!({"source": "cross_source_matcher"});

    let first =
        EdgeRepository::create_symmetric_if_absent(&pool, a, b, "CORROBORATES", props.clone())
            .await
            .expect("corroborates insert");
    assert!(first, "CORROBORATES must insert");

    // A→B with a DIFFERENT relationship is a different edge → must insert.
    let second =
        EdgeRepository::create_symmetric_if_absent(&pool, a, b, "contradicts", props.clone())
            .await
            .expect("contradicts insert");
    assert!(
        second,
        "contradicts is a distinct relationship → must insert"
    );

    assert_eq!(
        incident_edge_count(&pool, a, b, "CORROBORATES").await,
        1,
        "one CORROBORATES edge"
    );
    assert_eq!(
        incident_edge_count(&pool, a, b, "contradicts").await,
        1,
        "one contradicts edge"
    );
    let total: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE (source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        total.0, 2,
        "two distinct edges total (one per relationship)"
    );
}

// ── create_symmetric_if_absent_returning ────────────────────────────────────
//
// The one writer behind MCP `link_alternative`. Its statement has three exits:
// a fresh insert, the guard's dedup hit (`NOT EXISTS` saw the pair), and
// `ON CONFLICT DO NOTHING` (the guard saw nothing and
// `edges_alternative_of_symmetric_uniq` refused the row). Until these tests
// nothing in the tree called it, so every exit was asserted by inspection. The
// fourth case, a conflicting row the WRITER cannot see, needs an app-role pool
// and lives in `rls_enforcement.rs`.

/// Two `ClaimRepository::create` claims (public by migration 062's default).
async fn two_claims(pool: &PgPool, label: &str) -> (uuid::Uuid, uuid::Uuid) {
    let agent = make_agent(Some(label));
    let agent_row = AgentRepository::create(pool, &agent).await.unwrap();
    let mut ids = Vec::with_capacity(2);
    for side in ["a", "b"] {
        let claim = make_claim(agent_row.id, &format!("{label} claim {side}"), 0.5);
        let id: uuid::Uuid =
            ClaimRepository::create(pool, &claim, epigraph_core::TenancyDecl::Inherited)
                .await
                .unwrap()
                .id
                .into();
        ids.push(id);
    }
    (ids[0], ids[1])
}

/// The guard's dedup-hit exit: a reverse-direction second call returns the
/// FIRST edge's id with `created = false`, writes nothing, and leaves the stored
/// properties alone.
#[sqlx::test(migrations = "../../migrations")]
async fn create_symmetric_if_absent_returning_dedups_in_both_directions(pool: PgPool) {
    let (a, b) = two_claims(&pool, "ret-dedup").await;

    let (id, created) = EdgeRepository::create_symmetric_if_absent_returning(
        &pool,
        a,
        b,
        "alternative_of",
        serde_json::json!({"rationale": "first"}),
    )
    .await
    .expect("first link");
    assert!(created, "the first link must insert");

    let (again, created_again) = EdgeRepository::create_symmetric_if_absent_returning(
        &pool,
        b,
        a,
        "alternative_of",
        serde_json::json!({"rationale": "second"}),
    )
    .await
    .expect("reverse-direction link");
    assert_eq!(
        (again, created_again),
        (id, false),
        "the REVERSE-direction call must answer with the existing edge's id and \
         created=false: alternative_of is symmetric"
    );
    assert_eq!(
        incident_edge_count(&pool, a, b, "alternative_of").await,
        1,
        "the dedup hit must not write a second row"
    );
    let stored: serde_json::Value =
        sqlx::query_scalar("SELECT properties FROM edges WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        stored,
        serde_json::json!({"rationale": "first"}),
        "a dedup hit must not overwrite the stored properties"
    );
}

/// Wait until some backend is blocked by `blocker_pid`, polling on a connection
/// of its own so the pool under test is not starved. Panics after ~10s.
async fn wait_until_blocked_by(pool: &PgPool, blocker_pid: i32) {
    use sqlx::Connection;
    let mut probe = sqlx::PgConnection::connect_with(&pool.connect_options())
        .await
        .expect("probe connection");
    for _ in 0..200 {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))",
        )
        .bind(blocker_pid)
        .fetch_one(&mut probe)
        .await
        .expect("read pg_blocking_pids");
        if blocked > 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!(
        "no backend blocked on pid {blocker_pid} within 10s: the writer never reached \
         the unique index, so this test cannot claim to exercise ON CONFLICT"
    );
}

/// The `ON CONFLICT DO NOTHING` exit, with the conflicting row VISIBLE to the
/// writer once it commits.
///
/// A sequential second call never reaches this exit, because the guard sees the
/// first row and skips the insert. It is reached only when the guard's snapshot
/// is older than the conflicting row, which is the concurrent-duplicate case.
/// The test builds that case on purpose rather than racing for it:
///
/// 1. A second connection inserts the REVERSE-direction row and holds its
///    transaction open.
/// 2. The writer runs. Its `NOT EXISTS` snapshot cannot see an uncommitted row,
///    so the guard passes and the INSERT blocks on
///    `edges_alternative_of_symmetric_uniq`. The test waits until
///    `pg_blocking_pids` shows it blocked, which proves the statement started
///    before the commit.
/// 3. The holder commits. `DO NOTHING` resolves the conflict and the dedup
///    probe, a new statement, sees the committed row.
///
/// Without `ON CONFLICT DO NOTHING` step 3 is a 23505, which `DbError` turns
/// into `DuplicateKey` and `link_alternative` into an internal error.
#[sqlx::test(migrations = "../../migrations")]
async fn create_symmetric_if_absent_returning_resolves_a_concurrent_duplicate_through_on_conflict(
    pool: PgPool,
) {
    use sqlx::Connection;
    let (a, b) = two_claims(&pool, "ret-race").await;

    let mut holder = sqlx::PgConnection::connect_with(&pool.connect_options())
        .await
        .expect("holder connection");
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut holder)
        .await
        .unwrap();
    let mut tx = holder.begin().await.expect("holder BEGIN");
    let held: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, \
                            relationship, properties) \
         VALUES ($1, 'claim', $2, 'claim', 'alternative_of', '{}'::jsonb) \
         RETURNING id",
    )
    .bind(b)
    .bind(a)
    .fetch_one(&mut *tx)
    .await
    .expect("holder inserts the reverse-direction row");

    let writer = tokio::spawn({
        let pool = pool.clone();
        async move {
            EdgeRepository::create_symmetric_if_absent_returning(
                &pool,
                a,
                b,
                "alternative_of",
                serde_json::json!({}),
            )
            .await
        }
    });

    wait_until_blocked_by(&pool, holder_pid).await;
    tx.commit().await.expect("holder COMMIT");

    let answer = writer
        .await
        .expect("writer task")
        .expect("the ON CONFLICT exit must resolve to an answer, not a unique violation");
    assert_eq!(
        answer,
        (held, false),
        "a concurrent duplicate must resolve to the committed row's id with created=false"
    );
    assert_eq!(
        incident_edge_count(&pool, a, b, "alternative_of").await,
        1,
        "exactly one alternative_of row for the pair"
    );
}

/// In-force and total `alternative_of` rows for the unordered pair.
async fn alternative_of_rows(pool: &PgPool, a: uuid::Uuid, b: uuid::Uuid) -> (i64, i64) {
    sqlx::query_as(
        "SELECT count(*) FILTER (WHERE valid_to IS NULL OR valid_to > now()), count(*)
           FROM edges
          WHERE relationship = 'alternative_of'
            AND ((source_id = $1 AND target_id = $2)
              OR (source_id = $2 AND target_id = $1))",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("count alternative_of rows")
}

/// A RETRACTED `alternative_of` edge does not block re-linking the pair.
///
/// Edge removal is a retraction (`valid_to = now()`, a6adf739), and migration
/// 091 narrowed `edges_alternative_of_symmetric_uniq` to `valid_to IS NULL` on
/// the rule that "any uniqueness constraint over edges must exclude retracted
/// rows or retraction silently becomes a weaker operation than deletion". This
/// writer's guard and probe did not follow it. After `delete_edge`, a relink
/// returned the RETRACTED edge's id with `created = false` and wrote nothing, so
/// no tool could restore the pair.
///
/// The third call checks the probe as well as the guard. With both a retracted
/// and a live row for the pair, a probe without the in-force filter could
/// return either one from its `LIMIT 1`.
#[sqlx::test(migrations = "../../migrations")]
async fn create_symmetric_if_absent_returning_relinks_a_retracted_pair(pool: PgPool) {
    let (a, b) = two_claims(&pool, "ret-relink").await;

    let (first, created) = EdgeRepository::create_symmetric_if_absent_returning(
        &pool,
        a,
        b,
        "alternative_of",
        serde_json::json!({}),
    )
    .await
    .expect("first link");
    assert!(created);
    assert_eq!(
        EdgeRepository::retract(&pool, &[first]).await.unwrap(),
        vec![first],
        "the first edge must retract"
    );

    let (second, relinked) = EdgeRepository::create_symmetric_if_absent_returning(
        &pool,
        b,
        a,
        "alternative_of",
        serde_json::json!({}),
    )
    .await
    .expect("relink after retraction");
    assert!(
        relinked && second != first,
        "a relink after retraction must write a NEW live edge; got ({second}, {relinked}) \
         where the retracted edge is {first}"
    );

    let third = EdgeRepository::create_symmetric_if_absent_returning(
        &pool,
        a,
        b,
        "alternative_of",
        serde_json::json!({}),
    )
    .await
    .expect("dedup against the live edge");
    assert_eq!(
        third,
        (second, false),
        "with a retracted and a live row for the pair, the dedup hit must name the LIVE one"
    );
    assert_eq!(
        alternative_of_rows(&pool, a, b).await,
        (1, 2),
        "one live edge, and the retracted one kept for audit"
    );
}

/// A FUTURE-dated `valid_to` is still in force, and it still dedups.
///
/// Such a row (written by `patch_edge` / `PATCH /edges/:id` with a future
/// `valid_to`) is outside 091's index, whose predicate can only say
/// `valid_to IS NULL`. The guard is the only thing that stops a second row
/// here, so narrowing the guard to `valid_to IS NULL` to match the index would
/// let a duplicate land.
#[sqlx::test(migrations = "../../migrations")]
async fn create_symmetric_if_absent_returning_dedups_against_a_future_dated_edge(pool: PgPool) {
    let (a, b) = two_claims(&pool, "ret-future").await;

    let (first, _) = EdgeRepository::create_symmetric_if_absent_returning(
        &pool,
        a,
        b,
        "alternative_of",
        serde_json::json!({}),
    )
    .await
    .expect("first link");
    sqlx::query("UPDATE edges SET valid_to = now() + interval '1 day' WHERE id = $1")
        .bind(first)
        .execute(&pool)
        .await
        .expect("future-date the edge");

    let again = EdgeRepository::create_symmetric_if_absent_returning(
        &pool,
        b,
        a,
        "alternative_of",
        serde_json::json!({}),
    )
    .await
    .expect("dedup against a future-dated edge");
    assert_eq!(
        again,
        (first, false),
        "an edge that is still in force must dedup even outside the index"
    );
    assert_eq!(alternative_of_rows(&pool, a, b).await, (1, 1));
}

/// `create_symmetric_if_absent`, the cross-source matcher's writer, still
/// treats a RETRACTED edge as "already linked".
///
/// Migration 090 kept that guard wider than its index on purpose: narrowing it
/// "would change what re-linking a retracted pair does, which is a production
/// behaviour question no obligation in this batch asks". For the matcher, the
/// wide guard means a re-run cannot bring back an edge a human retracted. The
/// `_returning` variant's guard is now in-force only, because its one caller is
/// an explicit operator relink. This test pins that the two functions differ ON
/// PURPOSE. Harmonising them has to be a decision that edits this test, not a
/// side effect.
#[sqlx::test(migrations = "../../migrations")]
async fn create_symmetric_if_absent_still_refuses_to_relink_a_retracted_pair(pool: PgPool) {
    let (a, b) = two_claims(&pool, "sym-retracted").await;
    let props = serde_json::json!({"source": "cross_source_matcher"});

    assert!(
        EdgeRepository::create_symmetric_if_absent(&pool, a, b, "CORROBORATES", props.clone())
            .await
            .expect("first link")
    );
    let (id,): (uuid::Uuid,) = sqlx::query_as(
        "SELECT id FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = 'CORROBORATES'",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    EdgeRepository::retract(&pool, &[id]).await.unwrap();

    let relinked =
        EdgeRepository::create_symmetric_if_absent(&pool, b, a, "CORROBORATES", props.clone())
            .await
            .expect("matcher re-run");
    assert!(
        !relinked,
        "the matcher's writer must NOT revive a retracted pair (migration 090's decision)"
    );
    assert_eq!(incident_edge_count(&pool, a, b, "CORROBORATES").await, 1);
}
