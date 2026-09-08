//! Integration tests for ClaimRepository find/create-or-get/create-strict helpers
//! introduced in S1 of the noun-claims-and-verb-edges architecture
//! (see docs/architecture/noun-claims-and-verb-edges.md).
//!
//! # Why every arm here takes an injected `pool`
//!
//! These fixtures are the only ones in `epigraph-db` that issue **global DDL**:
//! [`drop_unique_constraint`] and [`add_unique_constraint`] add and remove
//! `uq_claims_content_hash_agent` on `claims` in contradictory directions, and
//! `add_unique_constraint` additionally runs a table-wide dedup `DELETE`. On a
//! shared database that is not a per-test detail — it is a schema change every
//! other connection observes immediately.
//!
//! The consequences were both measured on this tree:
//!
//! * **In-binary.** At `--test-threads=4` this binary failed on 4 of 4 runs,
//!   and the IDENTITY of the failing arm varied run to run
//!   (`create_or_get_is_idempotent_post_107`, then
//!   `create_strict_inserts_unconditionally_pre_107` +
//!   `create_strict_returns_duplicate_key_post_107`, then …). A pre-107 arm
//!   dropping the constraint while a post-107 arm depends on it is a race with
//!   no fixed loser.
//! * **Across binaries.** The file left the shared database's schema mutated on
//!   exit, with no restore — the exact signature migrations/README.md records
//!   for the deployed drift, where `_sqlx_migrations` reports 013 applied while
//!   the constraint is absent from `claims`.
//!
//! `#[sqlx::test]` provisions a freshly-migrated private database per test,
//! which is the precondition each of these arms was previously trying to
//! manufacture by mutating a shared one. **The DDL and the dedup DELETE are
//! unchanged and every assertion is unchanged** — only their blast radius is.
//! Note that the constraint is now PRESENT at test start (migration 013 runs),
//! so the pre-107 arms must drop it explicitly; that explicit drop is what
//! establishes the pre-107 fixture rather than an accident of shared state.
//!
//! Transactional rollback was rejected: a wrapping transaction cannot contain
//! `ALTER TABLE` for a concurrent observer, and `ClaimRepository::create` takes
//! its own pool connection, which would not see the fixture's uncommitted rows.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_crypto::ContentHasher;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// Names a destructive claim fixture may mutate without an explicit opt-in.
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
///
/// # This is the reference implementation, and that is why it outlived its
/// # caller here
///
/// The arms in this file no longer need the guard: `#[sqlx::test]` hands each
/// one a private `_sqlx_test*` database, so there is no shared database left to
/// misdirect and the pool-construction guard that used to call this function
/// was removed with the shared-pool harness.
///
/// The classifier itself stays because **two other files mirror it by name and
/// defer to this one for the rationale** —
/// `crates/epigraph-mcp/tests/common/mod.rs::db_is_disposable` ("see that file
/// for the full rationale") and
/// `crates/epigraph-api/tests/integration/test_claim_cleanup.rs::db_is_disposable`
/// ("Mirrors `epigraph-db/tests/claim_repo_helpers.rs::db_is_disposable`").
/// Those callers are still on shared pools and still need the rule. Deleting
/// the definition the others cite would leave two live guards with no stated
/// contract and no test pinning the `_e2e` / `_dev` exclusions below.
fn db_is_disposable(name: &str) -> bool {
    name.starts_with("_sqlx_test") || name.ends_with("_test")
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

/// Drop the (content_hash, agent_id) UNIQUE constraint if present so this
/// test exercises the pre-107 path. See docs/architecture/noun-claims-and-verb-edges.md
/// for the rationale of running both pre- and post-107 fixtures.
///
/// `IF EXISTS` is still the right spelling even though migration 013 now always
/// leaves the constraint in place on the injected database: the helper states
/// "afterwards the constraint is absent", which is the fixture's contract, not
/// "a constraint was removed".
async fn drop_unique_constraint(pool: &PgPool) {
    sqlx::query("ALTER TABLE claims DROP CONSTRAINT IF EXISTS uq_claims_content_hash_agent")
        .execute(pool)
        .await
        .expect("drop constraint");
}

/// Add the (content_hash, agent_id) UNIQUE constraint, ignoring the case
/// where it already exists. Postgres has no `ADD CONSTRAINT IF NOT EXISTS`,
/// so the DO block swallows the already-present SQLSTATEs.
///
/// # The handler must name `duplicate_table`, and the old one did not
///
/// This block previously caught `duplicate_object` (42710) alone, which made
/// the "ignoring the case where it already exists" contract **unsatisfiable**:
/// `ALTER TABLE … ADD CONSTRAINT … UNIQUE` implements the constraint as an
/// INDEX, so when the name is taken Postgres reports the INDEX collision —
/// `42P07 duplicate_table`, `relation "uq_claims_content_hash_agent" already
/// exists` — and 42710 never fires. Measured directly against a migrated
/// database: the `duplicate_object`-only block errors out; adding
/// `duplicate_table` catches it.
///
/// It went unnoticed because on a SHARED database the constraint was reliably
/// absent by the time this ran — migration 013 creates it, and a sibling arm's
/// `drop_unique_constraint` had already removed it globally. So the helper only
/// ever took the succeed-outright path, and the exception handler was dead code
/// that had never once executed. Per-test isolation removed the sibling that
/// was silently preparing the ground, and the latent defect became a
/// deterministic failure in both post-107 arms.
///
/// This is a fixture repair, not a relaxation: the post-107 arms still require
/// the constraint to be PRESENT, and still assert `DuplicateKey` /
/// `was_created` false-on-second-call against it.
///
/// # The ADD is now a fallback, and the helper proves its post-condition
///
/// Say plainly what the isolation changed: migration 013 creates
/// `uq_claims_content_hash_agent` and no later migration drops it, so on the
/// freshly-migrated per-test database the constraint is ALREADY there and the
/// ALTER always takes the exception path. The ADD adds nothing; it is a
/// fallback for a database that arrives without it. Because a helper whose
/// every statement can be swallowed cannot fail, the post-condition is
/// asserted against `pg_constraint` at the end rather than assumed.
///
/// Dedups any (content_hash, agent_id) duplicate rows first. The dedup is
/// RETAINED rather than dropped along with the shared pool, and the reason is
/// not defensive: it mirrors the S2 backfill semantics production migration 107
/// requires, so it is part of what "add the constraint the way 107 does" means.
///
/// What changed is only who it can reach. It used to be a table-wide DELETE
/// over a database every other test binary was also writing — it existed
/// because an EARLIER ARM IN THIS FILE had inserted duplicates under the
/// pre-107 fixture, and it removed rows it had never heard of on the way past.
/// On the injected `#[sqlx::test]` database the only rows in `claims` are the
/// ones the calling arm created, so the statement is unchanged and its blast
/// radius is one test.
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
           EXCEPTION WHEN duplicate_object OR duplicate_table THEN NULL;
           END $$"#,
    )
    .execute(pool)
    .await
    .expect("add constraint");

    // Assert the POST-CONDITION rather than trusting the swallow.
    //
    // On a freshly-migrated database migration 013 has already created this
    // constraint, so the ALTER above always raises 42P07 and is always caught:
    // the ADD is a fallback, not the normal path, and the helper can no longer
    // fail by itself. That is fine for the post-107 arms — the constraint is
    // genuinely present — but it means a future edit that renamed the
    // constraint, named the wrong columns or targeted the wrong table would be
    // swallowed identically and leave the arms asserting DuplicateKey against
    // whatever 013 happens to provide. Checking pg_constraint closes that gap:
    // the fixture now proves the precondition it claims to establish.
    let present: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint
         WHERE conname = 'uq_claims_content_hash_agent'
           AND conrelid = 'claims'::regclass",
    )
    .fetch_one(pool)
    .await
    .expect("inspect pg_constraint");
    assert_eq!(
        present, 1,
        "post-107 fixture requires uq_claims_content_hash_agent on `claims`"
    );
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

#[sqlx::test(migrations = "../../migrations")]
async fn find_by_content_hash_and_agent_returns_none_when_no_row(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let content = format!("test content {}", Uuid::new_v4());

    // Seed the SAME content under a DIFFERENT agent. This is the row the
    // helper exists to exclude: wrong-agent leakage — returning another
    // agent's claim for an identical content_hash — is exactly the S1 hazard
    // documented in this file's header. On the shared database a stray sibling
    // row sometimes played this part; on a private database we must seed it
    // deliberately, or dropping the `agent_id = $2` predicate would pass.
    let other_agent = Uuid::new_v4();
    insert_test_agent(&pool, other_agent).await;
    ClaimRepository::create(
        &pool,
        &make_claim(&content, other_agent),
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("create other-agent claim");

    let mut conn = pool.acquire().await.expect("acquire conn");
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

    // The decoy must be findable under ITS OWN agent, or the None above is
    // explained by the row being invisible rather than by the agent predicate.
    let found_other = ClaimRepository::find_by_content_hash_and_agent(
        &mut conn,
        &viewer,
        hash.as_slice(),
        other_agent,
    )
    .await
    .expect("find call")
    .expect("decoy must be findable under its own agent");
    let found_other_agent: Uuid = found_other.agent_id.into();
    assert_eq!(found_other_agent, other_agent);
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_by_content_hash_and_agent_returns_some_when_matching(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(&format!("matching {}", Uuid::new_v4()), agent_id);
    let _ = ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
        .await
        .expect("create");

    // A competing row with an IDENTICAL content_hash under a different agent.
    // The `found_agent == agent_id` assertion below is only meaningful if
    // another agent's row with the same hash is present to be picked wrongly.
    let other_agent = Uuid::new_v4();
    insert_test_agent(&pool, other_agent).await;
    ClaimRepository::create(
        &pool,
        &make_claim(&claim.content, other_agent),
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("create other-agent claim");

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

#[sqlx::test(migrations = "../../migrations")]
async fn create_strict_inserts_unconditionally_pre_107(pool: PgPool) {
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

#[sqlx::test(migrations = "../../migrations")]
async fn create_strict_returns_duplicate_key_post_107(pool: PgPool) {
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

#[sqlx::test(migrations = "../../migrations")]
async fn create_or_get_inserts_when_no_existing(pool: PgPool) {
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

#[sqlx::test(migrations = "../../migrations")]
async fn create_or_get_returns_existing_when_present(pool: PgPool) {
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

#[sqlx::test(migrations = "../../migrations")]
async fn create_or_get_is_idempotent_post_107(pool: PgPool) {
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
