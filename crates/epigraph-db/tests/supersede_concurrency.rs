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

#[path = "viewer_fixture.rs"]
mod fixture;

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
    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(old)
            .fetch_one(&mut *a)
            .await
            .expect("the superseded claim's author");
    let (a_new, _) = ClaimRepository::supersede_act_conn(
        &mut a,
        None,
        ClaimId::from_uuid(old),
        "revision from A",
        TruthValue::clamped(0.6),
        "race A",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
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
        // The acting agent the act records (backlog 73085534): this
        // fixture acts as the claim's own author.
        let supersede_actor: uuid::Uuid =
            sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
                .bind(old)
                .fetch_one(&mut *tx)
                .await
                .expect("the superseded claim's author");
        let r = ClaimRepository::supersede_act_conn(
            &mut tx,
            None,
            ClaimId::from_uuid(old),
            "revision from B",
            TruthValue::clamped(0.7),
            "race B",
            epigraph_db::SupersedeActor::new(
                supersede_actor,
                epigraph_db::SupersedeTool::SupersedeClaim,
            ),
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
    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(old)
            .fetch_one(&mut *tx)
            .await
            .expect("the superseded claim's author");
    ClaimRepository::supersede_act_conn(
        &mut tx,
        None,
        ClaimId::from_uuid(old),
        "first revision",
        TruthValue::clamped(0.6),
        "first",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
    )
    .await
    .expect("first supersession succeeds");

    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(old)
            .fetch_one(&mut *tx)
            .await
            .expect("the superseded claim's author");
    let again = ClaimRepository::supersede_act_conn(
        &mut tx,
        None,
        ClaimId::from_uuid(old),
        "second revision",
        TruthValue::clamped(0.6),
        "second",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
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
        None,
        ClaimId::from_uuid(missing),
        "revision of nothing",
        TruthValue::clamped(0.6),
        "missing",
        epigraph_db::SupersedeActor::new(
            Uuid::new_v4(),
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
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
    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(old)
            .fetch_one(&mut *tx)
            .await
            .expect("the superseded claim's author");
    let r = ClaimRepository::supersede_act_conn(
        &mut tx,
        None,
        ClaimId::from_uuid(old),
        "revision that cannot retire its original",
        TruthValue::clamped(0.6),
        "unretirable",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
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

/// `supersede_act_conn` on `conn` as `actor`, in a transaction that is
/// committed on success and rolled back on a refusal.
async fn supersede_as(
    conn: &mut sqlx::PgConnection,
    actor: Uuid,
    old: Uuid,
) -> Result<(Uuid, Uuid), epigraph_db::DbError> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
    let r = ClaimRepository::supersede_act_conn(
        &mut tx,
        None,
        ClaimId::from_uuid(old),
        "a revision the caller asked for",
        TruthValue::clamped(0.6),
        "visibility probe",
        epigraph_db::SupersedeActor::new(actor, epigraph_db::SupersedeTool::SupersedeClaim),
    )
    .await;
    if r.is_ok() {
        tx.commit().await.expect("commit");
    } else {
        tx.rollback().await.expect("rollback");
    }
    r
}

/// The zero-row classification read (backlog efa3c0fe) runs on the caller's
/// stamped connection, under row security. So a claim the caller cannot read
/// classifies exactly as a missing one, `NotFound`, and the refusal discloses
/// nothing a read would not; only a claim the caller CAN read is told apart
/// (here "already superseded", for a readable retired claim).
///
/// Verified to fail: the classification read's existence test moved to a
/// definer that bypasses row security (`epigraph_claim_tenancy_by_ids`),
/// currency still read under it -> the hidden claim is `WriteRefused`, not
/// `NotFound`. The tests above, which run unstamped, cannot see that.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_act_conn_answers_not_found_for_a_claim_the_caller_cannot_read(pool: PgPool) {
    let (a, ag) = fixture::seed_agent_with_group(&pool, "supersede-reader").await;
    let (b, bg) = fixture::seed_agent_with_group(&pool, "supersede-owner").await;
    let hidden = fixture::seed_group_claim(&pool, b, bg, "B's group-private claim").await;
    let readable = fixture::seed_public_claim(&pool, b, "B's retired public claim").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(readable)
        .execute(&pool)
        .await
        .expect("retire B's public claim");
    let missing = Uuid::new_v4();

    let (seen, on_hidden, on_missing, on_readable) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            sqlx::query(
                "SELECT set_config('epigraph.principal_id', $1, false), \
                        set_config('epigraph.group_ids', $2, false), \
                        set_config('epigraph.writable_group_ids', $2, false)",
            )
            .bind(a.to_string())
            .bind(ag.to_string())
            .execute(&mut *conn)
            .await
            .expect("stamp A");
            let seen: Vec<Uuid> =
                sqlx::query_scalar("SELECT id FROM claims WHERE id = ANY($1) ORDER BY id")
                    .bind(vec![hidden, readable])
                    .fetch_all(&mut *conn)
                    .await
                    .expect("calibration read");
            let on_hidden = supersede_as(&mut conn, a, hidden).await;
            let on_missing = supersede_as(&mut conn, a, missing).await;
            let on_readable = supersede_as(&mut conn, a, readable).await;
            sqlx::query(
                "SELECT set_config('epigraph.principal_id', '', false), \
                        set_config('epigraph.group_ids', '', false), \
                        set_config('epigraph.writable_group_ids', '', false)",
            )
            .execute(&mut *conn)
            .await
            .expect("unstamp");
            (conn, (seen, on_hidden, on_missing, on_readable))
        })
        .await;

    // CALIBRATION: A's session reads B's public claim and not the private one.
    assert_eq!(
        seen,
        vec![readable],
        "A's stamped session must read the public claim and not B's private one"
    );

    let hidden_err = on_hidden.expect_err("a claim the caller cannot read is not superseded");
    assert!(
        matches!(&hidden_err, epigraph_db::DbError::NotFound { id, .. } if *id == hidden),
        "a claim the caller cannot read must classify as NotFound, like a missing one; \
         got: {hidden_err:?}"
    );
    let missing_err = on_missing.expect_err("a missing claim is not superseded");
    assert!(
        matches!(&missing_err, epigraph_db::DbError::NotFound { id, .. } if *id == missing),
        "got: {missing_err:?}"
    );
    // The same session's classification DOES see a claim it can read: B's
    // retired public claim is told apart as "already superseded".
    let readable_err = on_readable.expect_err("a retired claim is not superseded again");
    assert!(
        matches!(
            &readable_err,
            epigraph_db::DbError::Refused {
                kind: epigraph_db::RefusalKind::State,
                ..
            }
        ),
        "a readable, retired claim is the State refusal; got: {readable_err:?}"
    );

    // Nothing was written for either of B's claims.
    for (old, was_current) in [(hidden, true), (readable, false)] {
        let (is_current, successors, edges): (bool, i64, i64) = sqlx::query_as(
            "SELECT (SELECT is_current FROM claims WHERE id = $1), \
                    (SELECT count(*) FROM claims WHERE supersedes = $1), \
                    (SELECT count(*) FROM edges \
                      WHERE target_id = $1 AND relationship = 'supersedes')",
        )
        .bind(old)
        .fetch_one(&pool)
        .await
        .expect("post-state");
        assert_eq!(is_current, was_current, "{old} is untouched");
        assert_eq!(
            (successors, edges),
            (0, 0),
            "no successor or edge for {old}"
        );
    }
}
