#![cfg(feature = "db")]
//! Regression test for backlog bug `c11c1295`: POST /api/v1/claims with the
//! default `if_not_exists=false` silently inserted duplicate
//! `(content_hash, agent_id)` rows (20+ identical refuted claims accumulated
//! this way) because the UNIQUE constraint create_strict relied on for its
//! documented "409 on duplicate" contract was dropped in migration 107.
//!
//! The fix re-asserts that contract at the app layer. A second identical create
//! must now return 409 Conflict instead of inserting a duplicate.

use sqlx::postgres::PgPoolOptions;
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_create_strict_returns_409() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = common::seed_system_agent(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    // PR-03: `create_claim` derives the author's public key from the token's
    // `agent_id` and 401s when there is none — the `[0u8; 32]` fallback is gone.
    let (token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["claims:write"], agent)
            .await;

    // Unique content per run so the test is independent of prior DB state.
    let content = format!("c11c1295 dedup regression {}", uuid::Uuid::new_v4());
    let body = serde_json::json!({ "content": content, "agent_id": agent });
    let client = reqwest::Client::new();
    let endpoint = format!("http://{addr}/api/v1/claims");

    // First create (if_not_exists omitted → defaults false) succeeds.
    let r1 = client
        .post(&endpoint)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let s1 = r1.status();
    assert!(
        s1.is_success(),
        "first create should succeed; got {s1} body={}",
        r1.text().await.unwrap_or_default()
    );

    // Second identical create must be refused with 409 — NOT a silent duplicate.
    let r2 = client
        .post(&endpoint)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let s2 = r2.status();
    assert_eq!(
        s2,
        409,
        "duplicate create must return 409 Conflict; got {s2} body={}",
        r2.text().await.unwrap_or_default()
    );

    // And exactly one row exists for this (content, agent) — no duplicate landed.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1 AND agent_id = $2")
            .bind(&content)
            .bind(agent)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count, 1,
        "exactly one claim row should exist, found {count}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Two CONCURRENT first creates, on the constraint-less (production) shape
// ────────────────────────────────────────────────────────────────────────────

/// The advisory-lock key the barrier trigger parks on. Arbitrary; scoped to the
/// private `#[sqlx::test]` database. One-key, so `objsubid = 1`: never counted
/// as a waiter on the two-key dedup lock.
const BARRIER_KEY: i64 = 515_151;

/// The per-test database's URL, for `spawn_app` (which takes a URL, not a pool).
async fn url_for(pool: &sqlx::PgPool) -> String {
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("current_database()");
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let prefix = base
        .split_once('?')
        .map_or(base.as_str(), |(a, _)| a)
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0
        .to_string();
    format!("{prefix}/{db}")
}

/// Backends parked on the barrier (inside an `INSERT INTO claims`).
///
/// Both probes count only waiters in THIS test's database: `pg_locks` is
/// cluster-wide, and other `#[sqlx::test]` databases on the same server hold
/// advisory locks of their own.
async fn on_the_barrier(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_locks \
          WHERE locktype = 'advisory' AND objid = $1::bigint AND objsubid = 1 AND NOT granted \
              AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
    )
    .bind(BARRIER_KEY)
    .fetch_one(pool)
    .await
    .expect("read pg_locks")
}

/// Backends waiting on a two-key advisory lock: the dedup lock's shape. The
/// POST path takes no other two-key lock.
async fn on_a_two_key_lock(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_locks \
          WHERE locktype = 'advisory' AND objsubid = 2 AND NOT granted \
              AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
    )
    .fetch_one(pool)
    .await
    .expect("read pg_locks")
}

/// Two concurrent `POST /api/v1/claims` (`if_not_exists` defaulted to false)
/// of one `(content, agent_id)` on a database WITHOUT
/// `uq_claims_content_hash_agent` — the long-lived database's shape and, from
/// migration 150, the migrated shape — must leave ONE row and answer one 2xx
/// and one 409. Backlog 00f1a517.
///
/// # The interleaving is forced
///
/// A `BEFORE INSERT` trigger keyed on the content parks request 1 INSIDE its
/// INSERT (its row is uncommitted, so invisible to request 2's find). Only then
/// is request 2 sent. Unserialized, request 2's find misses, its INSERT parks on
/// the same barrier, and both commit once it lifts: two rows, two 2xx — the
/// production race. Serialized, request 2 waits on the two-key dedup lock that
/// request 1 holds until it commits, then finds the row and answers 409. The
/// arm releases the barrier once it has seen one of those two states, so the
/// oracle is the row count and the statuses, never a 23505.
///
/// A seed POST by the same author runs first, so request 1 and request 2 do not
/// also contend on provisioning the author's personal group.
#[sqlx::test(migrations = "../../migrations")]
async fn post_claims_concurrent_duplicates_yield_one_row_and_one_409(pool: sqlx::PgPool) {
    sqlx::query("ALTER TABLE claims DROP CONSTRAINT IF EXISTS uq_claims_content_hash_agent")
        .execute(&pool)
        .await
        .expect("drop the constraint: the production shape");

    let agent = common::seed_system_agent(&pool).await;
    let url = url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["claims:write"], agent)
            .await;
    let client = reqwest::Client::new();
    let endpoint = format!("http://{addr}/api/v1/claims");

    let seed = client
        .post(&endpoint)
        .bearer_auth(&token)
        .json(&serde_json::json!({ "content": format!("seed {}", uuid::Uuid::new_v4()), "agent_id": agent }))
        .send()
        .await
        .unwrap();
    assert!(seed.status().is_success(), "seed create: {}", seed.status());

    let content = format!("00f1a517 concurrent dedup {}", uuid::Uuid::new_v4());
    sqlx::query(
        &"CREATE OR REPLACE FUNCTION zz_post_claims_barrier() RETURNS trigger
          LANGUAGE plpgsql AS $$
          BEGIN
              PERFORM pg_advisory_lock(KEY);
              PERFORM pg_advisory_unlock(KEY);
              RETURN NEW;
          END $$"
            .replace("KEY", &BARRIER_KEY.to_string()),
    )
    .execute(&pool)
    .await
    .expect("create the barrier function");
    // The content is a test-local string with no quotes; a trigger WHEN takes
    // no binds.
    sqlx::query(&format!(
        "CREATE TRIGGER zz_post_claims_barrier BEFORE INSERT ON claims
         FOR EACH ROW WHEN (NEW.content = '{content}')
         EXECUTE FUNCTION zz_post_claims_barrier()"
    ))
    .execute(&pool)
    .await
    .expect("install the barrier trigger");

    let mut holder = pool.acquire().await.expect("acquire the barrier holder");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(BARRIER_KEY)
        .execute(&mut *holder)
        .await
        .expect("take the barrier");

    let body = serde_json::json!({ "content": content, "agent_id": agent });
    let send = |client: reqwest::Client,
                endpoint: String,
                token: String,
                body: serde_json::Value| async move {
        let r = client
            .post(&endpoint)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .expect("send");
        let status = r.status().as_u16();
        (status, r.text().await.unwrap_or_default())
    };

    let req_1 = tokio::spawn(send(
        client.clone(),
        endpoint.clone(),
        token.clone(),
        body.clone(),
    ));
    let mut parked = false;
    for _ in 0..600 {
        if on_the_barrier(&pool).await >= 1 {
            parked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        parked,
        "request 1 never reached its INSERT; the arm proves nothing"
    );

    let req_2 = tokio::spawn(send(client.clone(), endpoint.clone(), token.clone(), body));
    let mut settled = None;
    for _ in 0..600 {
        if on_the_barrier(&pool).await >= 2 {
            settled = Some("both requests parked in their INSERTs (unserialized)");
            break;
        }
        if on_a_two_key_lock(&pool).await >= 1 {
            settled = Some("request 2 waits on the dedup lock (serialized)");
            break;
        }
        if req_2.is_finished() {
            settled = Some("request 2 finished while request 1 was parked");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        settled.is_some(),
        "request 2 neither parked in its INSERT nor waited on the dedup lock nor finished"
    );

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(BARRIER_KEY)
        .execute(&mut *holder)
        .await
        .expect("release the barrier");
    drop(holder);

    let r1 = req_1.await.expect("request 1 task");
    let r2 = req_2.await.expect("request 2 task");

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(epigraph_crypto::ContentHasher::hash(content.as_bytes()).as_slice())
            .bind(agent)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        rows, 1,
        "two concurrent POST /claims of one (content_hash, agent_id) left {rows} rows ({settled:?}); \
         request 1: {r1:?}, request 2: {r2:?}"
    );
    let mut statuses = [r1.0, r2.0];
    statuses.sort_unstable();
    assert!(
        (200..300).contains(&statuses[0]) && statuses[1] == 409,
        "expected one 2xx and one 409 ({settled:?}); request 1: {r1:?}, request 2: {r2:?}"
    );
}
