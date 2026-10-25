//! Regression test for backlog bug `5c7fc645`: `decide_match_candidate`
//! wrote CORROBORATES edges without checking that both endpoints were still
//! current, so a near-duplicate that had since been superseded/marked-duplicate
//! could end up with a structural edge (e.g. a bidirectional support cycle on
//! near-identical content).
//!
//! The fix routes the check through `ClaimRepository::are_all_current`, which
//! this test pins: a superseded or missing endpoint must make the guard fail.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_claim(
    pool: &PgPool,
    agent_id: Uuid,
    is_current: bool,
    supersedes: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, supersedes) \
         VALUES ($1, $2, $3, 0.6, $4, $5, $6)",
    )
    .bind(id)
    .bind(format!("claim {id}"))
    .bind(hash)
    .bind(agent_id)
    .bind(is_current)
    .bind(supersedes)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn are_all_current_rejects_stale_or_missing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let live_a = seed_claim(&pool, agent, true, None).await;
    let live_b = seed_claim(&pool, agent, true, None).await;
    // A superseded claim: is_current = false, pointing at live_a as its successor.
    let superseded = seed_claim(&pool, agent, false, Some(live_a)).await;
    let missing = Uuid::new_v4();

    // Two live claims → guard passes (a CORROBORATES edge would be allowed).
    assert!(
        ClaimRepository::are_all_current(&pool, &viewer, &[live_a, live_b])
            .await
            .unwrap()
    );

    // Any superseded endpoint → guard fails (the bug scenario).
    assert!(
        !ClaimRepository::are_all_current(&pool, &viewer, &[live_a, superseded])
            .await
            .unwrap()
    );

    // A missing id → guard fails.
    assert!(
        !ClaimRepository::are_all_current(&pool, &viewer, &[live_a, missing])
            .await
            .unwrap()
    );

    // Empty set is vacuously true.
    assert!(ClaimRepository::are_all_current(&pool, &viewer, &[])
        .await
        .unwrap());
}

/// The SQLSTATE a `lock_timeout` raises (`lock_not_available`).
const LOCK_NOT_AVAILABLE: &str = "55P03";

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

/// `current_state_locked`, the locking twin of `are_all_current` that
/// label-dedup apply reads its canonical through, holds the row to the
/// caller's commit against the writes that matter: a retiring UPDATE started
/// after the lock waits (here, times out), and so does a SECOND locker (two
/// applies racing one canonical serialize, rather than both holding a shared
/// lock and deadlocking when each relabels it). A foreign-key style
/// `FOR KEY SHARE` read is not blocked. Once the holder commits, the
/// retirement goes through and a fresh locked read reports it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_locked_current_state_holds_off_a_retirement_and_a_second_locker(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, true, None).await;
    let missing = Uuid::new_v4();

    let mut held = pool.begin().await.expect("begin holder");
    let got = ClaimRepository::current_state_locked(&mut *held, &viewer, &[missing, canonical])
        .await
        .expect("locked read");
    assert_eq!(got, vec![(canonical, true)], "missing ids are absent");

    let short = |label: &'static str| {
        let pool = pool.clone();
        async move {
            let mut tx = pool.begin().await.expect(label);
            sqlx::query("SET LOCAL lock_timeout = '300ms'")
                .execute(&mut *tx)
                .await
                .expect("lock_timeout");
            tx
        }
    };

    let mut retire = short("begin retirement").await;
    let err = sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(canonical)
        .execute(&mut *retire)
        .await
        .expect_err("a retirement must wait for the holder's commit");
    assert_eq!(sqlstate(&err).as_deref(), Some(LOCK_NOT_AVAILABLE), "{err}");
    retire.rollback().await.expect("rollback");

    let mut second = short("begin second locker").await;
    let err = ClaimRepository::current_state_locked(&mut *second, &viewer, &[canonical])
        .await
        .expect_err("a second locker must wait for the holder's commit");
    let source = match &err {
        epigraph_db::DbError::QueryFailed { source } => source,
        other => panic!("want QueryFailed, got {other:?}"),
    };
    assert_eq!(
        sqlstate(source).as_deref(),
        Some(LOCK_NOT_AVAILABLE),
        "{err}"
    );
    second.rollback().await.expect("rollback");

    let mut fk = short("begin key-share read").await;
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT 1 FROM claims WHERE id = $1 FOR KEY SHARE) k",
    )
    .bind(canonical)
    .fetch_one(&mut *fk)
    .await
    .expect("a FOR KEY SHARE read is not blocked by the lock");
    assert_eq!(n, 1);
    fk.rollback().await.expect("rollback");

    held.commit().await.expect("release");
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(canonical)
        .execute(&pool)
        .await
        .expect("the retirement goes through once the lock is released");
    let mut after = pool.begin().await.expect("begin");
    assert_eq!(
        ClaimRepository::current_state_locked(&mut *after, &viewer, &[canonical])
            .await
            .expect("locked read"),
        vec![(canonical, false)],
        "a non-current row is returned as false, not dropped"
    );
    after.rollback().await.expect("rollback");
}
