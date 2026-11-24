//! The `(content_hash, agent_id)` dedup lock taken by a writer that holds
//! more than one pair in a transaction (backlog 5b587ae8).
//!
//! `ClaimRepository::lock_content_hash_agent` is transaction-scoped. A writer
//! that took it one create at a time, in its own input order (the document
//! ingest's atom walk), could deadlock (40P01) against another multi-pair
//! writer meeting the same new pairs in the opposite order. Every multi-pair
//! writer now takes all its pairs first, in lock-key order
//! (`lock_content_hash_agents` / `lock_new_content_hash_agents`).
//!
//! * the order is the KEY order, whatever the input order (measured on
//!   `pg_locks` while the call waits, not inferred from a lucky schedule);
//! * an ingest-shaped transaction against a transaction of plain
//!   `create_or_get`s (no pre-lock of its own), and two ingests against each
//!   other, interleaved the way that deadlocked, complete;
//! * the lock-table use of a large pre-lock, measured.
//!
//! Runs on the superuser harness: the lock is a pure advisory lock, and the
//! creates' tenancy is not what is under test.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::time::Duration;

use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_crypto::ContentHasher;
use epigraph_db::ClaimRepository;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

async fn insert_test_agent(pool: &PgPool, agent_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO agents (id, public_key, created_at, updated_at)
           VALUES ($1, sha256($1::text::bytea), NOW(), NOW())
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("upsert agent");
}

fn make_claim(content: &str, agent_id: Uuid) -> Claim {
    Claim::new(
        content.to_string(),
        AgentId::from_uuid(agent_id),
        [0u8; 32],
        TruthValue::new(0.5).unwrap(),
    )
}

fn pair(content: &str, agent: Uuid) -> (Vec<u8>, Uuid) {
    (ContentHasher::hash(content.as_bytes()).to_vec(), agent)
}

/// The second key of the pair's advisory lock, as `lock_content_hash_agent`
/// computes it.
async fn key_of(pool: &PgPool, (hash, agent): &(Vec<u8>, Uuid)) -> i32 {
    sqlx::query_scalar("SELECT hashtext(encode($1, 'hex') || $2::text)")
        .bind(hash)
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("key")
}

async fn backend_pid(conn: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .expect("pid")
}

/// `(key, granted)` of every dedup-lock row `pid` has in `pg_locks`.
async fn dedup_locks_of(pool: &PgPool, pid: i32) -> Vec<(i64, bool)> {
    sqlx::query_as(
        "SELECT objid::bigint, granted FROM pg_locks \
          WHERE locktype = 'advisory' AND pid = $1 AND objsubid = 2 \
            AND classid::bigint = (hashtext('epigraph.claim_dedup')::bigint & 4294967295) \
          ORDER BY objid",
    )
    .bind(pid)
    .fetch_all(pool)
    .await
    .expect("pg_locks")
}

/// `key` as `pg_locks.objid` shows it (an oid: the int4 read unsigned).
fn as_objid(key: i32) -> i64 {
    i64::from(key) & 0xffff_ffff
}

/// Poll until `pid` waits on a dedup lock; panic after 10 s.
async fn wait_until_waiting(pool: &PgPool, pid: i32) {
    for _ in 0..200 {
        if dedup_locks_of(pool, pid).await.iter().any(|(_, g)| !g) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("backend {pid} never waited on a dedup lock");
}

/// Two pairs ordered by their lock key: `(low, high)`.
async fn ordered_pairs(pool: &PgPool, agent: Uuid) -> ((Vec<u8>, Uuid), (Vec<u8>, Uuid)) {
    let a = pair(&format!("lock order a {}", Uuid::new_v4()), agent);
    let b = pair(&format!("lock order b {}", Uuid::new_v4()), agent);
    let (ka, kb) = (key_of(pool, &a).await, key_of(pool, &b).await);
    assert_ne!(ka, kb, "fixture: two distinct keys");
    if ka < kb {
        (a, b)
    } else {
        (b, a)
    }
}

/// Handed `[high, low]` while another transaction holds `high`, the call must
/// take `low` FIRST and then wait on `high`: `pg_locks` shows `low` granted
/// and `high` waiting. Locked in input order it would wait on `high` holding
/// nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_prelock_takes_pairs_in_key_order_not_input_order(pool: PgPool) {
    let agent = Uuid::new_v4();
    let (low, high) = ordered_pairs(&pool, agent).await;
    let (k_low, k_high) = (key_of(&pool, &low).await, key_of(&pool, &high).await);

    let mut holder = pool.begin().await.expect("holder");
    ClaimRepository::lock_content_hash_agent(&mut holder, &high.0, high.1)
        .await
        .expect("hold the high pair");

    let mut conn = pool.acquire().await.expect("conn");
    let pid = backend_pid(&mut conn).await;
    let input = vec![high.clone(), low.clone()];
    let task = tokio::spawn(async move {
        let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
        let n = ClaimRepository::lock_content_hash_agents(&mut tx, &input)
            .await
            .expect("pre-lock");
        tx.commit().await.expect("commit");
        n
    });
    wait_until_waiting(&pool, pid).await;
    let mut want = vec![(as_objid(k_low), true), (as_objid(k_high), false)];
    want.sort_unstable();
    assert_eq!(
        dedup_locks_of(&pool, pid).await,
        want,
        "the low key is held and the high key awaited: the keys were taken in key order"
    );
    holder.commit().await.expect("release the high pair");
    assert_eq!(task.await.expect("join"), 2, "two distinct locks");
}

/// The shape that deadlocked (40P01): an ingest-shaped transaction (legacy
/// creates of two NEW atoms, in document order `low, high`) against a
/// transaction running two plain `create_or_get`s over the same two pairs in
/// the opposite order, with NO pre-lock of its own. The ingest creates `low`,
/// the other transaction starts and blocks, and only then does the ingest
/// create `high`.
///
/// Only the ingest's pre-lock stands between the two: without it the other
/// transaction's first `create_or_get` takes `high` and waits on `low`, and
/// the ingest's second create then waits on `high`, a cycle. With it the
/// ingest already holds both pairs, so the other transaction's first
/// `create_or_get` waits on `high` holding nothing, the ingest finishes, and
/// the other transaction finds both rows.
#[sqlx::test(migrations = "../../migrations")]
async fn an_ingest_and_a_multi_pair_create_or_get_do_not_deadlock(pool: PgPool) {
    let agent = Uuid::new_v4();
    insert_test_agent(&pool, agent).await;
    let viewer = fixture::public_viewer(&pool).await;
    let low_content = format!("ingest atom low {}", Uuid::new_v4());
    let high_content = format!("ingest atom high {}", Uuid::new_v4());
    let (mut low_content, mut high_content) = (low_content, high_content);
    if key_of(&pool, &pair(&low_content, agent)).await
        > key_of(&pool, &pair(&high_content, agent)).await
    {
        std::mem::swap(&mut low_content, &mut high_content);
    }
    let low = make_claim(&low_content, agent);
    let high = make_claim(&high_content, agent);

    // The ingest: pre-lock its new atoms, create `low`, then wait for the
    // other writer to block before creating `high`.
    let mut ingest = pool.acquire().await.expect("ingest conn");
    let mut other = pool.acquire().await.expect("other conn");
    let other_pid = backend_pid(&mut other).await;
    let mut ingest_tx = sqlx::Connection::begin(&mut *ingest)
        .await
        .expect("ingest begin");
    ClaimRepository::lock_new_content_hash_agents(
        &mut ingest_tx,
        &[pair(&low_content, agent), pair(&high_content, agent)],
    )
    .await
    .expect("the ingest's pre-lock");
    ClaimRepository::create_conn(&mut ingest_tx, &low, epigraph_core::TenancyDecl::Inherited)
        .await
        .expect("ingest creates low");

    let (o_low, o_high) = (low.clone(), high.clone());
    let other_task = tokio::spawn(async move {
        let mut tx = sqlx::Connection::begin(&mut *other)
            .await
            .expect("other begin");
        let (h, h_new) = ClaimRepository::create_or_get(
            &mut tx,
            &viewer,
            &o_high,
            epigraph_core::TenancyDecl::Inherited,
        )
        .await?;
        let (l, l_new) = ClaimRepository::create_or_get(
            &mut tx,
            &viewer,
            &o_low,
            epigraph_core::TenancyDecl::Inherited,
        )
        .await?;
        tx.commit().await.expect("other commit");
        Ok::<_, epigraph_db::DbError>((h.id, h_new, l.id, l_new))
    });
    wait_until_waiting(&pool, other_pid).await;

    let created_high =
        ClaimRepository::create_conn(&mut ingest_tx, &high, epigraph_core::TenancyDecl::Inherited)
            .await
            .expect("the ingest's second create completes (no 40P01)");
    ingest_tx.commit().await.expect("ingest commit");

    let (h_id, h_new, l_id, l_new) = tokio::time::timeout(Duration::from_secs(20), other_task)
        .await
        .expect("the other writer finishes")
        .expect("join")
        .expect("the other writer's create_or_gets complete (no 40P01)");
    assert_eq!(
        (h_id, h_new, l_id, l_new),
        (created_high.id, false, low.id, false),
        "the other writer found the ingest's two rows"
    );
    for content in [&low_content, &high_content] {
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM claims WHERE content_hash = $1 AND agent_id = $2",
        )
        .bind(ContentHasher::hash(content.as_bytes()).to_vec())
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(rows, 1, "one row per pair");
    }
}

/// Two ingests sharing two NEW atoms in opposite document orders: the shape
/// every shipped multi-pair writer now has (no shipped transaction runs more
/// than one `create_or_get`). Ingest A pre-locks and creates `low`; ingest B
/// (document order `high, low`) starts, and only once it waits does A create
/// `high`.
///
/// Taking the pairs one create at a time, B would take `high` and wait on
/// `low` while A waits on `high`: a cycle. With the key-ordered pre-lock B
/// waits on `low` holding nothing, A finishes, and B's creates find A's rows.
#[sqlx::test(migrations = "../../migrations")]
async fn two_ingests_sharing_new_atoms_in_opposite_orders_do_not_deadlock(pool: PgPool) {
    let agent = Uuid::new_v4();
    insert_test_agent(&pool, agent).await;
    let mut low_content = format!("shared atom low {}", Uuid::new_v4());
    let mut high_content = format!("shared atom high {}", Uuid::new_v4());
    if key_of(&pool, &pair(&low_content, agent)).await
        > key_of(&pool, &pair(&high_content, agent)).await
    {
        std::mem::swap(&mut low_content, &mut high_content);
    }
    let low = make_claim(&low_content, agent);
    let high = make_claim(&high_content, agent);

    let mut a = pool.acquire().await.expect("ingest A conn");
    let mut b = pool.acquire().await.expect("ingest B conn");
    let b_pid = backend_pid(&mut b).await;
    let mut a_tx = sqlx::Connection::begin(&mut *a).await.expect("A begin");
    ClaimRepository::lock_new_content_hash_agents(
        &mut a_tx,
        &[pair(&low_content, agent), pair(&high_content, agent)],
    )
    .await
    .expect("A's pre-lock");
    let a_low =
        ClaimRepository::create_conn(&mut a_tx, &low, epigraph_core::TenancyDecl::Inherited)
            .await
            .expect("A creates low");

    // B's own claims carry fresh ids: what it gets back must be A's rows.
    let (b_high_claim, b_low_claim) = (
        make_claim(&high_content, agent),
        make_claim(&low_content, agent),
    );
    let (bh, bl) = (pair(&high_content, agent), pair(&low_content, agent));
    let b_task = tokio::spawn(async move {
        let mut tx = sqlx::Connection::begin(&mut *b).await.expect("B begin");
        ClaimRepository::lock_new_content_hash_agents(&mut tx, &[bh, bl]).await?;
        let h = ClaimRepository::create_conn(
            &mut tx,
            &b_high_claim,
            epigraph_core::TenancyDecl::Inherited,
        )
        .await?;
        let l = ClaimRepository::create_conn(
            &mut tx,
            &b_low_claim,
            epigraph_core::TenancyDecl::Inherited,
        )
        .await?;
        tx.commit().await.expect("B commit");
        Ok::<_, epigraph_db::DbError>((h.id, l.id))
    });
    wait_until_waiting(&pool, b_pid).await;

    let a_high =
        ClaimRepository::create_conn(&mut a_tx, &high, epigraph_core::TenancyDecl::Inherited)
            .await
            .expect("A's second create completes (no 40P01)");
    a_tx.commit().await.expect("A commit");

    let (b_high, b_low) = tokio::time::timeout(Duration::from_secs(20), b_task)
        .await
        .expect("ingest B finishes")
        .expect("join")
        .expect("ingest B completes (no 40P01)");
    assert_eq!(
        (b_high, b_low),
        (a_high.id, a_low.id),
        "ingest B resolved both atoms to A's rows"
    );
    for content in [&low_content, &high_content] {
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM claims WHERE content_hash = $1 AND agent_id = $2",
        )
        .bind(ContentHasher::hash(content.as_bytes()).to_vec())
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(rows, 1, "one row per pair");
    }
}

/// Lock-table use, measured: a pre-lock of N new pairs holds one advisory
/// lock (one shared lock-table entry) per distinct pair until commit, and
/// `lock_new_content_hash_agents` skips a pair whose content already has a
/// row, as `create_conn`'s unlocked find does. The figure is recorded on
/// `ClaimRepository::lock_content_hash_agent` ("Deadlocks and lock-table
/// use").
#[sqlx::test(migrations = "../../migrations")]
async fn a_large_prelock_holds_one_lock_table_entry_per_new_pair(pool: PgPool) {
    const NEW: usize = 2_000;
    let agent = Uuid::new_v4();
    insert_test_agent(&pool, agent).await;
    let existing = make_claim(&format!("already ingested {}", Uuid::new_v4()), agent);
    ClaimRepository::create(&pool, &existing, epigraph_core::TenancyDecl::Inherited)
        .await
        .expect("an existing atom");

    let mut pairs: Vec<(Vec<u8>, Uuid)> = (0..NEW)
        .map(|i| pair(&format!("large ingest atom {i} {}", Uuid::new_v4()), agent))
        .collect();
    pairs.push(pair(&existing.content, agent));
    let mut distinct: Vec<i32> = Vec::with_capacity(NEW);
    for p in &pairs[..NEW] {
        distinct.push(key_of(&pool, p).await);
    }
    distinct.sort_unstable();
    distinct.dedup();

    let mut conn = pool.acquire().await.expect("conn");
    let pid = backend_pid(&mut conn).await;
    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
    let locked = ClaimRepository::lock_new_content_hash_agents(&mut tx, &pairs)
        .await
        .expect("pre-lock");
    let held = dedup_locks_of(&pool, pid).await;
    eprintln!(
        "lock-table measurement: {NEW} new pairs (+1 existing) -> {locked} locks taken, \
         {} dedup rows in pg_locks for the backend",
        held.len()
    );
    assert_eq!(
        locked,
        distinct.len(),
        "one lock per distinct NEW pair; the existing one is skipped"
    );
    assert_eq!(
        held.len(),
        locked,
        "each lock is one pg_locks row until commit"
    );
    assert!(held.iter().all(|(_, g)| *g), "all granted");
    tx.commit().await.expect("commit");
    assert!(
        dedup_locks_of(&pool, pid).await.is_empty(),
        "released at commit"
    );
}
