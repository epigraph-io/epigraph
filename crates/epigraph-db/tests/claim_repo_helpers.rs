//! Integration tests for ClaimRepository find/create-or-get/create-strict helpers
//! introduced in S1 of the noun-claims-and-verb-edges architecture
//! (see docs/architecture/noun-claims-and-verb-edges.md).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_crypto::ContentHasher;
use epigraph_db::ClaimRepository;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

/// Names this file is allowed to mutate without an explicit opt-in.
///
/// `#[sqlx::test]` template/instance databases are `_sqlx_test*`; the
/// hand-rolled scratch databases this repo documents for integration work
/// (`epigraph_db_repo_test`, `epigraph_frame_test`, …) all end in `_test`.
/// Both are disposable by construction.
///
/// Deliberately *not* name-based beyond that: CI's postgres service database
/// is named `epigraph`, exactly like the long-lived deployment, so no
/// blocklist can separate them. Everything outside the disposable set must
/// opt in via `EPIGRAPH_TEST_DESTRUCTIVE_DB=1`.
fn db_is_disposable(name: &str) -> bool {
    name.starts_with("_sqlx_test") || name.ends_with("_test")
}

/// Environment opt-in for running these fixtures against a
/// non-disposable-looking database (set by CI, whose DB is named `epigraph`).
const DESTRUCTIVE_OPT_IN: &str = "EPIGRAPH_TEST_DESTRUCTIVE_DB";

/// Refuse to hand back a pool onto a database these fixtures must not touch.
///
/// This guard sits at pool construction rather than on the individual
/// destructive helpers because `try_test_pool` *itself* mutates: it runs
/// `sqlx::migrate!` against whatever `DATABASE_URL` names. Guarding only
/// `drop_unique_constraint`/`add_unique_constraint` would leave that hole
/// open.
///
/// This is not hypothetical. The deployed `epigraph` database records
/// migration 013 as applied (`_sqlx_migrations.success = true`) while
/// `uq_claims_content_hash_agent` is absent from `claims` — the signature of
/// `drop_unique_constraint` having run against it and never being restored.
/// Panicking (rather than skipping) is deliberate: a silent skip would let a
/// misdirected `DATABASE_URL` look like a green test run.
async fn assert_disposable_db(pool: &PgPool) {
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("query current_database()");

    if db_is_disposable(&db) || std::env::var(DESTRUCTIVE_OPT_IN).as_deref() == Ok("1") {
        return;
    }

    panic!(
        "refusing to run destructive claim fixtures against database {db:?}.\n\
         These tests DROP the uq_claims_content_hash_agent constraint and run a \
         table-wide dedup DELETE on `claims`.\n\
         Point DATABASE_URL at a scratch database (e.g. epigraph_db_repo_test), or \
         set {DESTRUCTIVE_OPT_IN}=1 if {db:?} really is disposable."
    );
}

async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    assert_disposable_db(&pool).await;
    sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
    Some(pool)
}

#[test]
fn disposable_db_classification() {
    // #[sqlx::test] template + instance databases.
    assert!(db_is_disposable("_sqlx_test_7228"));
    assert!(db_is_disposable("_sqlx_test_pIYMM_s7GsH9D_KCYP1I"));
    // Documented scratch databases.
    assert!(db_is_disposable("epigraph_db_repo_test"));
    assert!(db_is_disposable("epigraph_frame_test"));

    // The long-lived deployments this guard exists to protect.
    assert!(!db_is_disposable("epigraph"));
    assert!(!db_is_disposable("epigraph_internal_e2e"));
    // `_e2e` / `_dev` suffixes are NOT disposable: epigraph_internal_e2e is a
    // long-lived database despite the test-sounding name.
    assert!(!db_is_disposable("epigraph_e2e"));
    assert!(!db_is_disposable("epigraph_demo_dev"));
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

/// Drop the (content_hash, agent_id) UNIQUE constraint if present so this
/// test exercises the pre-107 path. See docs/architecture/noun-claims-and-verb-edges.md
/// for the rationale of running both pre- and post-107 fixtures.
async fn drop_unique_constraint(pool: &PgPool) {
    sqlx::query("ALTER TABLE claims DROP CONSTRAINT IF EXISTS uq_claims_content_hash_agent")
        .execute(pool)
        .await
        .expect("drop constraint");
}

/// Add the (content_hash, agent_id) UNIQUE constraint, ignoring the case
/// where it already exists. Postgres has no `ADD CONSTRAINT IF NOT EXISTS`,
/// so the DO block swallows the duplicate_object SQLSTATE.
///
/// Dedups any (content_hash, agent_id) duplicate rows first — earlier tests
/// in this file may have inserted rows under the pre-107 fixture that would
/// otherwise prevent the constraint from being created. Mirrors the S2
/// backfill semantics required by production migration 107.
async fn add_unique_constraint(pool: &PgPool) {
    sqlx::query(
        "DELETE FROM claims a USING claims b
         WHERE a.ctid > b.ctid
           AND a.content_hash = b.content_hash
           AND a.agent_id = b.agent_id",
    )
    .execute(pool)
    .await
    .expect("dedup before constraint");

    sqlx::query(
        r#"DO $$ BEGIN
              ALTER TABLE claims ADD CONSTRAINT uq_claims_content_hash_agent
                  UNIQUE (content_hash, agent_id);
           EXCEPTION WHEN duplicate_object THEN NULL;
           END $$"#,
    )
    .execute(pool)
    .await
    .expect("add constraint");
}

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

// ────────────────────────────────────────────────────────────────────────────
// find_by_content_hash_and_agent
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn find_by_content_hash_and_agent_returns_none_when_no_row() {
    let pool = test_pool_or_skip!();
    let viewer = fixture::public_viewer(&pool).await;
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let mut conn = pool.acquire().await.expect("acquire conn");
    let content = format!("test content {}", Uuid::new_v4());
    let hash = ContentHasher::hash(content.as_bytes());

    let found = ClaimRepository::find_by_content_hash_and_agent(
        &mut conn,
        &viewer,
        hash.as_slice(),
        agent_id,
    )
    .await
    .expect("find call");

    assert!(found.is_none(), "expected None, got {:?}", found);
}

#[tokio::test]
async fn find_by_content_hash_and_agent_returns_some_when_matching() {
    let pool = test_pool_or_skip!();
    let viewer = fixture::public_viewer(&pool).await;
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(&format!("matching {}", Uuid::new_v4()), agent_id);
    let _ = ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
        .await
        .expect("create");

    let mut conn = pool.acquire().await.expect("acquire conn");
    let hash = ContentHasher::hash(claim.content.as_bytes());

    let found = ClaimRepository::find_by_content_hash_and_agent(
        &mut conn,
        &viewer,
        hash.as_slice(),
        agent_id,
    )
    .await
    .expect("find call");

    let found = found.expect("expected Some");
    assert_eq!(found.content, claim.content);
    let found_agent: Uuid = found.agent_id.into();
    assert_eq!(found_agent, agent_id);
}

// ────────────────────────────────────────────────────────────────────────────
// create_strict — pre-107 (no constraint)
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_strict_inserts_unconditionally_pre_107() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    // Two claims with the same content (identical content_hash) but distinct
    // ClaimIds — required so the second INSERT does not collide on the
    // primary key, which would mask the (content_hash, agent_id) test.
    let content = format!("strict pre-107 {}", Uuid::new_v4());
    let claim_a = make_claim(&content, agent_id);
    let claim_b = make_claim(&content, agent_id);

    let mut conn = pool.acquire().await.expect("acquire conn");
    let first =
        ClaimRepository::create_strict(&mut conn, &claim_a, epigraph_core::TenancyDecl::Inherited)
            .await
            .expect("first");
    drop(conn);

    // Second insert with same (content_hash, agent_id) — pre-107 produces a duplicate
    let mut conn = pool.acquire().await.expect("acquire conn");
    let second =
        ClaimRepository::create_strict(&mut conn, &claim_b, epigraph_core::TenancyDecl::Inherited)
            .await
            .expect("second");
    drop(conn);

    let first_id: Uuid = first.id.into();
    let second_id: Uuid = second.id.into();
    assert_ne!(
        first_id, second_id,
        "pre-107 strict insert should produce two rows for the same (content_hash, agent_id)"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// create_strict — post-107 (constraint applied)
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_strict_returns_duplicate_key_post_107() {
    let pool = test_pool_or_skip!();
    add_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    // Two claims with identical content (matching content_hash) but distinct
    // ClaimIds — so the second INSERT trips the (content_hash, agent_id)
    // unique constraint rather than the primary key.
    let content = format!("strict post-107 {}", Uuid::new_v4());
    let claim_a = make_claim(&content, agent_id);
    let claim_b = make_claim(&content, agent_id);

    let mut conn = pool.acquire().await.expect("acquire conn");
    let _ =
        ClaimRepository::create_strict(&mut conn, &claim_a, epigraph_core::TenancyDecl::Inherited)
            .await
            .expect("first");
    drop(conn);

    let mut conn = pool.acquire().await.expect("acquire conn");
    let result =
        ClaimRepository::create_strict(&mut conn, &claim_b, epigraph_core::TenancyDecl::Inherited)
            .await;
    assert!(
        matches!(result, Err(epigraph_db::DbError::DuplicateKey { .. })),
        "expected DuplicateKey, got {:?}",
        result
    );
}

// ────────────────────────────────────────────────────────────────────────────
// create_or_get — pre-107
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_or_get_inserts_when_no_existing() {
    let pool = test_pool_or_skip!();
    let viewer = fixture::public_viewer(&pool).await;
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(&format!("cog insert {}", Uuid::new_v4()), agent_id);
    let mut conn = pool.acquire().await.expect("acquire conn");

    let (returned, was_created) = ClaimRepository::create_or_get(
        &mut conn,
        &viewer,
        &claim,
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("create_or_get");

    assert!(was_created, "first call should report was_created=true");
    assert_eq!(returned.content, claim.content);
}

#[tokio::test]
async fn create_or_get_returns_existing_when_present() {
    let pool = test_pool_or_skip!();
    let viewer = fixture::public_viewer(&pool).await;
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(&format!("cog existing {}", Uuid::new_v4()), agent_id);
    let mut conn = pool.acquire().await.expect("acquire conn");
    let (first, first_created) = ClaimRepository::create_or_get(
        &mut conn,
        &viewer,
        &claim,
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("first call");
    drop(conn);

    let mut conn = pool.acquire().await.expect("acquire conn");
    let (second, second_created) = ClaimRepository::create_or_get(
        &mut conn,
        &viewer,
        &claim,
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("second call");

    assert!(first_created, "first call should be was_created=true");
    assert!(!second_created, "second call should be was_created=false");
    let first_id: Uuid = first.id.into();
    let second_id: Uuid = second.id.into();
    assert_eq!(
        first_id, second_id,
        "create_or_get should return the same row id on subsequent calls"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// create_or_get — post-107 idempotency (single-thread)
//
// Single-threaded tests cannot deterministically exercise the catch path in
// create_or_get (the unique-violation recovery from a concurrent INSERT) —
// the find-by-(content_hash, agent_id) lookup runs first and returns the
// existing row before the INSERT is attempted. This test instead verifies
// that post-107 idempotency holds: a second create_or_get for the same
// (content_hash, agent_id) returns the canonical row with was_created=false
// regardless of which internal branch (find-then-return or
// INSERT-catch-refind) actually fires. The catch path is verified by
// inspection of the create_or_get implementation; a true concurrent test
// would be inherently racy and is intentionally omitted (spec lines 99–101).
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_or_get_is_idempotent_post_107() {
    let pool = test_pool_or_skip!();
    let viewer = fixture::public_viewer(&pool).await;
    add_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(&format!("cog post107 {}", Uuid::new_v4()), agent_id);

    let mut conn = pool.acquire().await.expect("acquire conn");
    let (first, first_created) = ClaimRepository::create_or_get(
        &mut conn,
        &viewer,
        &claim,
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("first call");
    drop(conn);

    let mut conn = pool.acquire().await.expect("acquire conn");
    let (second, second_created) = ClaimRepository::create_or_get(
        &mut conn,
        &viewer,
        &claim,
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("second call");

    assert!(first_created, "first call should be was_created=true");
    assert!(!second_created, "second call should be was_created=false");
    let first_id: Uuid = first.id.into();
    let second_id: Uuid = second.id.into();
    assert_eq!(first_id, second_id);
}
