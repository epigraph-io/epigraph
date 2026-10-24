//! Two concurrent supersessions of ONE claim must produce ONE current successor.
//!
//! `ClaimRepository::supersede_act_conn` used to read the old claim's
//! `is_current` with a plain `SELECT` (no row lock) and then retire it with
//! `UPDATE claims … WHERE id = $1` (no `AND is_current`). Under READ COMMITTED
//! two transactions could both pass the currency check; the second then blocked
//! on the first's row lock, and once the first committed its `WHERE id = $1`
//! still matched, so it inserted a SECOND current successor. Nothing in the
//! schema refuses that: `claims.supersedes` has no unique index.
//!
//! The retirement is now one `UPDATE … WHERE id = $1 AND is_current RETURNING
//! …`: the second transaction re-evaluates `is_current` after the lock is
//! released, matches no row, and is refused as "already superseded".
//!
//! The interleaving is made deterministic, not timed: B's backend pid is read
//! first and A commits only once `pg_stat_activity` shows B waiting on a lock.

use std::time::{Duration, Instant};

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_current_claim(pool: &PgPool) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'supersede-race', 'system') \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent");
    let text = format!("supersede race original {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(&text)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_supersede_of_one_claim_yields_one_successor(pool: PgPool) {
    let old = seed_current_claim(&pool).await;

    // A: supersede inside an open transaction; it now holds old's row lock.
    let mut a = pool.begin().await.expect("begin A");
    let (a_new, _) = ClaimRepository::supersede_act_conn(
        &mut a,
        ClaimId::from_uuid(old),
        "revision from A",
        TruthValue::clamped(0.6),
        "race A",
    )
    .await
    .expect("A's supersession succeeds");

    // B: the same supersession on its own transaction, in a task, so it can
    // block on A's row lock while this task decides when A commits.
    let (pid_tx, pid_rx) = tokio::sync::oneshot::channel::<i32>();
    let pool_b = pool.clone();
    let b = tokio::spawn(async move {
        let mut tx = pool_b.begin().await.expect("begin B");
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .expect("B pid");
        pid_tx.send(pid).expect("send pid");
        let r = ClaimRepository::supersede_act_conn(
            &mut tx,
            ClaimId::from_uuid(old),
            "revision from B",
            TruthValue::clamped(0.7),
            "race B",
        )
        .await;
        match r {
            Ok(ids) => {
                tx.commit().await.expect("commit B");
                Ok(ids)
            }
            Err(e) => Err(e.to_string()),
        }
    });

    let b_pid = pid_rx.await.expect("B reports its pid");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                            WHERE pid = $1 AND wait_event_type = 'Lock')",
        )
        .bind(b_pid)
        .fetch_one(&pool)
        .await
        .expect("poll pg_stat_activity");
        if waiting {
            break;
        }
        assert!(
            !b.is_finished(),
            "B finished without ever waiting on A's row lock; the interleaving this \
             test exists for did not happen"
        );
        assert!(
            Instant::now() < deadline,
            "B never blocked on A's row lock within 30 s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    a.commit().await.expect("commit A");
    let b_result = b.await.expect("B task");

    let current_successors: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM claims WHERE supersedes = $1 AND is_current")
            .bind(old)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        current_successors,
        vec![a_new],
        "exactly one current successor (A's) may exist; B returned {b_result:?}"
    );
    let err = b_result.expect_err("the second concurrent supersession must be refused");
    assert!(
        err.contains("already been superseded"),
        "B must be refused as already superseded, got: {err}"
    );
}

/// The single-statement retirement keeps both pre-existing refusals' shapes:
/// a missing claim is `NotFound`, a retired one is "already superseded".
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_act_conn_keeps_not_found_and_already_superseded_shapes(pool: PgPool) {
    let old = seed_current_claim(&pool).await;
    // Both vector columns populated, so "the retirement clears both" below can
    // fail: a current claim may carry embeddings, a retired one may not.
    sqlx::query(
        "UPDATE claims SET embedding = array_fill(0.01::real, ARRAY[1536])::vector, \
                           embedding_3072 = array_fill(0.01::real, ARRAY[3072])::vector \
         WHERE id = $1",
    )
    .bind(old)
    .execute(&pool)
    .await
    .expect("seed both embeddings");
    let both_vectors: bool = sqlx::query_scalar(
        "SELECT embedding IS NOT NULL AND embedding_3072 IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(old)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        both_vectors,
        "calibration: the claim starts with both vectors"
    );
    let mut tx = pool.begin().await.unwrap();
    ClaimRepository::supersede_act_conn(
        &mut tx,
        ClaimId::from_uuid(old),
        "first revision",
        TruthValue::clamped(0.6),
        "first",
    )
    .await
    .expect("first supersession succeeds");

    let again = ClaimRepository::supersede_act_conn(
        &mut tx,
        ClaimId::from_uuid(old),
        "second revision",
        TruthValue::clamped(0.6),
        "second",
    )
    .await
    .expect_err("a retired claim cannot be superseded again");
    assert!(
        again.to_string().contains("already been superseded"),
        "got: {again}"
    );

    let missing = Uuid::new_v4();
    let gone = ClaimRepository::supersede_act_conn(
        &mut tx,
        ClaimId::from_uuid(missing),
        "revision of nothing",
        TruthValue::clamped(0.6),
        "missing",
    )
    .await
    .expect_err("a missing claim cannot be superseded");
    assert!(
        matches!(gone, epigraph_db::DbError::NotFound { id, .. } if id == missing),
        "got: {gone:?}"
    );

    // The old claim was retired exactly once, with both vectors cleared, and
    // the successor carries the supersedes pointer and edge.
    let (is_current, has_vec): (bool, bool) = sqlx::query_as(
        "SELECT is_current, (embedding IS NOT NULL OR embedding_3072 IS NOT NULL) \
         FROM claims WHERE id = $1",
    )
    .bind(old)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(!is_current, "the old claim is retired");
    assert!(!has_vec, "the retirement cleared both vector columns");
    let successors: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE target_id = $1 AND relationship = 'supersedes'",
    )
    .bind(old)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(successors, 1);
}

/// A claim the session can READ as current but whose retirement `UPDATE`
/// matches no row must be refused, with nothing written.
///
/// The production producer is an elevated session: `claims_elevated_read`
/// admits its SELECT while `claims_elevated_no_update`'s USING is false, so the
/// `UPDATE` silently matches nothing. Before the single-statement retirement,
/// the function then inserted a successor and a `supersedes` edge next to a
/// claim that was still current. Here a `BEFORE UPDATE` trigger that skips
/// this one row stands in for that policy deterministically (named to fire
/// before every other `BEFORE UPDATE` trigger on `claims`).
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_act_conn_refuses_a_current_claim_it_cannot_retire(pool: PgPool) {
    let old = seed_current_claim(&pool).await;
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION aaa_test_skip_retire() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RETURN NULL; END $$; \
         CREATE TRIGGER aaa_test_skip_retire BEFORE UPDATE ON claims FOR EACH ROW \
         WHEN (OLD.id = '{old}'::uuid) EXECUTE FUNCTION aaa_test_skip_retire();"
    ))
    .execute(&pool)
    .await
    .expect("install the retirement stand-in");

    let mut tx = pool.begin().await.unwrap();
    let r = ClaimRepository::supersede_act_conn(
        &mut tx,
        ClaimId::from_uuid(old),
        "revision that cannot retire its original",
        TruthValue::clamped(0.6),
        "unretirable",
    )
    .await;
    // Commit whatever the call left on the transaction: a refusal must have
    // written nothing for this to observe.
    tx.commit().await.expect("commit");

    let err = r.expect_err("a claim this session cannot retire must not be superseded");
    assert!(
        matches!(&err, epigraph_db::DbError::WriteRefused { id, .. } if *id == old),
        "a readable, current claim the session cannot retire is WriteRefused; got: {err:?}"
    );
    let still_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(old)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(still_current, "the original is untouched");
    let successors: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE supersedes = $1")
        .bind(old)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(successors, 0, "no successor row was inserted");
    let edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE target_id = $1 AND relationship = 'supersedes'",
    )
    .bind(old)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(edges, 0, "no supersedes edge was inserted");
}
