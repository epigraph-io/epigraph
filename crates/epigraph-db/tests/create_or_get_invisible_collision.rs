//! `ClaimRepository::create_or_get` when `uq_claims_content_hash_agent` refuses
//! the INSERT and the Viewer-scoped re-find comes back empty (plan §8.5,
//! acceptance item 21).
//!
//! The find is filtered and the constraint is not, so a colliding row the
//! viewer cannot read reaches the catch path exactly like a lost race does,
//! and the re-find has nothing to return. The answer must be a
//! `DbError::Conflict` carrying the one fixed literal every collision gets, so
//! that the HTTP and MCP layers render it identically to a VISIBLE collision.
//! Before, it was `InvalidData("… no row found on re-find")` on a bare
//! connection and a `25P02` (current transaction is aborted) inside a caller's
//! transaction — each an outcome no other case produced.
//!
//! The third arm pins the savepoint that change needed, from the other side: a
//! genuinely lost race inside a transaction now returns the winner's row. It
//! used to fail with the same `25P02`, so the race handling `create_or_get`
//! documents had never worked for either caller that passes a transaction.
//!
//! Every arm first asserts the constraint is present: other test binaries drop
//! it, and without it nothing collides and every assertion here is vacuous.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, DbError};
use sqlx::PgPool;
use uuid::Uuid;

async fn assert_constraint_present(pool: &PgPool) {
    let present: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint \
         WHERE conname = 'uq_claims_content_hash_agent' AND conrelid = 'claims'::regclass",
    )
    .fetch_one(pool)
    .await
    .expect("inspect pg_constraint");
    assert_eq!(
        present, 1,
        "uq_claims_content_hash_agent must be present, or nothing collides and \
         this file asserts nothing"
    );
}

/// Insert `content` for `agent` with its REAL content hash, on `executor`.
/// (`fixture::seed_*_claim` writes a stand-in hash that can never collide with
/// what `create_strict` computes.)
async fn insert_hashed<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    agent: Uuid,
    content: &str,
    visibility: &str,
    owner_group_id: Uuid,
) -> Uuid {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, 0.5, $3, true, $4, $5) RETURNING id",
    )
    .bind(content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(visibility)
    .bind(owner_group_id)
    .fetch_one(executor)
    .await
    .expect("insert hashed claim")
}

fn claim_for(agent: Uuid, content: &str) -> Claim {
    Claim::new(
        content.to_string(),
        AgentId::from_uuid(agent),
        [0u8; 32],
        TruthValue::new(0.5).expect("truth value"),
    )
}

/// A victim's group-private claim, and a stranger aimed at its
/// `(content, agent_id)`. Returns `(victim, stranger_viewer, private_id, content)`.
async fn invisible_collision(pool: &PgPool, label: &str) -> (Uuid, Viewer, Uuid, String) {
    assert_constraint_present(pool).await;
    let (victim, group) = fixture::seed_agent_with_group(pool, &format!("{label}-victim")).await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, &format!("{label}-stranger")).await;
    let content = format!("n21 {label} {}", Uuid::new_v4());
    let private = insert_hashed(pool, victim, &content, "group", group).await;
    let stranger_viewer = Viewer::resolve(pool, stranger).await.expect("resolve");
    (victim, stranger_viewer, private, content)
}

fn assert_fixed_conflict(result: Result<(Claim, bool), DbError>, private: Uuid, content: &str) {
    match result {
        Err(DbError::Conflict { reason }) => {
            assert_eq!(
                reason,
                ClaimRepository::CONTENT_COLLISION_REASON,
                "an invisible collision must carry the one fixed literal every \
                 collision gets"
            );
            assert!(!reason.contains(&private.to_string()) && !reason.contains(content));
        }
        other => panic!(
            "an invisible collision must be DbError::Conflict with the fixed \
             literal — never InvalidData, never an aborted-transaction error, and \
             never the row. Got {other:?}"
        ),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_invisible_collision_is_the_fixed_conflict_on_a_bare_connection(pool: PgPool) {
    let (victim, stranger_viewer, private, content) = invisible_collision(&pool, "bare").await;

    let mut conn = pool.acquire().await.expect("acquire");
    let decl = ClaimRepository::default_decl_for_author(
        &mut conn,
        stranger_viewer.principal().expect("principal"),
    )
    .await
    .expect("decl");
    let result = ClaimRepository::create_or_get(
        &mut conn,
        &stranger_viewer,
        &claim_for(victim, &content),
        decl,
    )
    .await;
    assert_fixed_conflict(result, private, &content);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_invisible_collision_is_the_fixed_conflict_inside_a_transaction(pool: PgPool) {
    let (victim, stranger_viewer, private, content) = invisible_collision(&pool, "tx").await;

    let mut tx = pool.begin().await.expect("begin");
    let decl = ClaimRepository::default_decl_for_author(
        &mut tx,
        stranger_viewer.principal().expect("principal"),
    )
    .await
    .expect("decl");
    let result = ClaimRepository::create_or_get(
        &mut tx,
        &stranger_viewer,
        &claim_for(victim, &content),
        decl,
    )
    .await;
    assert_fixed_conflict(result, private, &content);

    // The caller's transaction survives the refusal: only the savepoint was
    // rolled back. A caller that maps the conflict and carries on (or rolls
    // back cleanly) must not be handed a poisoned transaction.
    let alive: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&mut *tx)
        .await
        .expect("the caller's transaction must still be usable after the conflict");
    assert_eq!(alive, 1);
    tx.rollback().await.expect("rollback");
}

/// A genuine lost race INSIDE a caller's transaction returns the winner's row.
///
/// Made deterministic rather than timing-dependent: the winner's INSERT is left
/// uncommitted, so the loser's INSERT blocks on the unique index; the test
/// waits until `pg_stat_activity` shows that wait before committing the winner, which
/// guarantees the loser's find ran BEFORE the commit and its INSERT hit the
/// constraint AFTER it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_lost_race_inside_a_transaction_returns_the_winners_row(pool: PgPool) {
    assert_constraint_present(&pool).await;
    let (author, group) = fixture::seed_agent_with_group(&pool, "race").await;
    let content = format!("n21 race {}", Uuid::new_v4());

    let mut winner = pool.begin().await.expect("begin winner");
    let winner_id = insert_hashed(&mut *winner, author, &content, "public", group).await;

    let loser = {
        let pool = pool.clone();
        let content = content.clone();
        tokio::spawn(async move {
            let viewer = Viewer::resolve(&pool, author).await.expect("resolve");
            let mut tx = pool.begin().await.expect("begin loser");
            let decl = ClaimRepository::default_decl_for_author(&mut tx, author)
                .await
                .expect("decl");
            let out = ClaimRepository::create_or_get(
                &mut tx,
                &viewer,
                &claim_for(author, &content),
                decl,
            )
            .await;
            tx.commit().await.expect("commit loser");
            out
        })
    };

    let mut waited = 0;
    loop {
        // `pg_stat_activity`, scoped to THIS database, rather than `pg_locks`:
        // a transaction-id wait carries no database oid, so a `pg_locks` probe
        // cannot tell this test's wait from another binary's on the cluster.
        let blocked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(&pool)
        .await
        .expect("pg_stat_activity");
        if blocked > 0 {
            break;
        }
        waited += 1;
        assert!(
            waited < 200,
            "the loser's INSERT never blocked on the winner"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    winner.commit().await.expect("commit winner");

    let (row, was_created) = loser
        .await
        .expect("join loser")
        .expect("a lost race inside a transaction must return the winner's row");
    assert!(!was_created);
    assert_eq!(Uuid::from(row.id), winner_id);
}
