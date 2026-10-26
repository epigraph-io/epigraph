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
//! Since migration 150 (backlog 00f1a517) the constraint is ABSENT at test
//! start — 013 adds it and 150 drops it, matching the long-lived database — so
//! the post-107 arms add it explicitly and the pre-107 arms still drop it
//! explicitly; each fixture states its own precondition rather than inheriting
//! one from shared state or migration order.
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
/// `IF EXISTS` is the right spelling: from migration 150 the injected database
/// already lacks the constraint, and the helper states "afterwards the
/// constraint is absent", which is the fixture's contract, not "a constraint
/// was removed".
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
/// # The ADD is the normal path again, and the helper proves its post-condition
///
/// Migration 013 creates `uq_claims_content_hash_agent` and migration 150 drops
/// it again (backlog 00f1a517: the long-lived database never had it), so on
/// the freshly-migrated per-test database the constraint is ABSENT and the
/// ALTER really adds it. The exception path remains for a database that
/// arrives with it (one migrated only to 013-149). Because a helper whose
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
    // On a database that already has this constraint the ALTER above raises
    // 42P07 and is caught, so the helper cannot fail by itself there; a future
    // edit that renamed the constraint, named the wrong columns or targeted the
    // wrong table would be swallowed identically. Checking pg_constraint closes
    // that gap: the fixture proves the precondition it claims to establish.
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
// A plain single-threaded arm cannot reach the catch path in create_or_get (the
// unique-violation recovery from a concurrent INSERT) — the
// find-by-(content_hash, agent_id) lookup runs first and returns the existing
// row before the INSERT is attempted. This arm instead verifies that post-107
// idempotency holds: a second create_or_get for the same
// (content_hash, agent_id) returns the canonical row with was_created=false
// regardless of which internal branch (find-then-return or
// INSERT-catch-refind) actually fires.
//
// The catch path itself is NO LONGER left to inspection. It is driven
// deterministically — a losing race, synthesised with a trigger rather than with
// concurrency — by `the_dedup_race_is_absorbed_inside_a_caller_transaction`
// below, which is the arm that distinguishes "absorbed" from "the caller's whole
// transaction is aborted".
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

// ────────────────────────────────────────────────────────────────────────────
// create_or_get — the dedup race, INSIDE a caller's transaction
// ────────────────────────────────────────────────────────────────────────────

/// The advisory-lock key the race barrier uses. Arbitrary; scoped to the private
/// `#[sqlx::test]` database.
const RACE_BARRIER_KEY: i64 = 424_242;

/// Hold the caller's `INSERT INTO claims` still, INSIDE the statement, until the
/// test says go.
///
/// # Why a barrier and not a trigger that simply raises `23505`
///
/// The catch path's whole point is that a row committed by ANOTHER writer is
/// findable on the re-read, and nothing the failing statement itself does can
/// play that part: a trigger that inserted the winner would have that insert
/// rolled back with the savepoint (MEASURED — the re-find then reported
/// `DuplicateKey from create_strict but no row found on re-find`), and a trigger
/// that only raised `23505` leaves nothing to find either. The winner has to be
/// committed by a different session while the caller's INSERT is in flight, which
/// is precisely the interleaving the production race is.
///
/// So the barrier is deterministic rather than timed: a `BEFORE INSERT` trigger
/// scoped by `WHEN (NEW.id = <the caller's id>)` takes a session advisory lock
/// the test already holds. The caller's statement parks there; the test commits
/// the winner on its own connection — whose insert carries a different id and so
/// does NOT fire the trigger — and then releases the lock. No `pg_sleep`, no
/// polling window that can be too short on a loaded machine: the wait is the
/// lock.
///
/// The trigger releases the lock immediately after taking it, so the pooled
/// connection is not returned holding one. Never cleaned up: `#[sqlx::test]`
/// throws the database away.
async fn install_race_barrier(pool: &PgPool, caller_claim: Uuid) {
    sqlx::query(
        "CREATE OR REPLACE FUNCTION zz_race_barrier_for_test() RETURNS trigger
         LANGUAGE plpgsql AS $$
         BEGIN
             PERFORM pg_advisory_lock($1);
             PERFORM pg_advisory_unlock($1);
             RETURN NEW;
         END $$"
            .replace("$1", &RACE_BARRIER_KEY.to_string())
            .as_str(),
    )
    .execute(pool)
    .await
    .expect("create the barrier trigger function");
    // The id is a test-local UUID, never caller data, and a trigger `WHEN` clause
    // takes no binds.
    sqlx::query(&format!(
        "CREATE TRIGGER zz_race_barrier_for_test BEFORE INSERT ON claims
         FOR EACH ROW WHEN (NEW.id = '{caller_claim}'::uuid)
         EXECUTE FUNCTION zz_race_barrier_for_test()"
    ))
    .execute(pool)
    .await
    .expect("install the barrier trigger");
}

/// Wait until some backend is BLOCKED on the race barrier — i.e. the caller's
/// INSERT has reached the trigger and parked.
///
/// Reads `pg_locks` rather than sleeping, so the handshake is observed and not
/// assumed. The bound exists only so a broken fixture fails instead of hanging
/// the suite.
///
/// `pg_locks` is CLUSTER-wide and every `#[sqlx::test]` gets its own database
/// on one server, while the arms in this binary run in parallel and share
/// [`RACE_BARRIER_KEY`]. Unscoped, this probe could see ANOTHER arm's parked
/// caller and start this arm's caller 2 too early; so it, and the two-key
/// probe in [`race_two_first_creates`], count only waiters in THIS database.
async fn wait_until_blocked_on_the_barrier(pool: &PgPool) {
    for _ in 0..600 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_locks \
              WHERE locktype = 'advisory' AND objid = $1::bigint AND NOT granted \
              AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .bind(RACE_BARRIER_KEY)
        .fetch_one(pool)
        .await
        .expect("read pg_locks");
        if waiting > 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!(
        "no backend ever blocked on the race barrier, so the caller's INSERT never reached the \
         trigger and this arm would have proved nothing"
    );
}

/// A lost `(content_hash, agent_id)` race must still DEDUP when the caller holds
/// a transaction — and the caller's transaction must still be usable afterwards.
///
/// # The defect this pins
///
/// `create_or_get`'s race recovery catches `DbError::DuplicateKey` from
/// `create_strict` and re-runs `find_by_content_hash_and_agent` **on the same
/// connection**. That is expressible on an autocommit pool checkout and NOT
/// inside a transaction: PostgreSQL aborts the whole transaction on the first
/// failed statement, so the re-find cannot execute and the caller gets
/// `25P02 current transaction is aborted, commands ignored until end of
/// transaction block` instead of `(existing, false)`. The method's entire dedup
/// contract therefore evaporated the moment a writer wrapped it in a transaction
/// — which `epigraph-mcp`'s submission path now does for every `submit_claim` and
/// `memorize`. The repair is a SAVEPOINT around the insert attempt.
///
/// # Why the last assertions are the ones that matter
///
/// `was_created == false` alone could be satisfied by a savepoint that swallowed
/// the failure and left the transaction aborted — the error would then surface at
/// the caller's NEXT statement, which is exactly the failure mode being repaired.
/// So the arm runs one more statement and commits, on the same transaction, and
/// reads the row back afterwards.
#[sqlx::test(migrations = "../../migrations")]
async fn the_dedup_race_is_absorbed_inside_a_caller_transaction(pool: PgPool) {
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;
    let content = format!("cog race {}", Uuid::new_v4());
    let claim = make_claim(&content, agent_id);
    let caller_claim_id: Uuid = claim.id.into();

    add_unique_constraint(&pool).await;
    install_race_barrier(&pool, caller_claim_id).await;

    // THE OTHER WRITER's connection, holding the barrier so the caller parks
    // inside its INSERT.
    let mut other = pool
        .acquire()
        .await
        .expect("acquire the winner's connection");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(RACE_BARRIER_KEY)
        .execute(&mut *other)
        .await
        .expect("take the barrier");

    let caller_pool = pool.clone();
    let caller_claim = claim.clone();
    let caller = tokio::spawn(async move {
        let viewer = fixture::public_viewer(&caller_pool).await;
        let mut tx = caller_pool
            .begin()
            .await
            .expect("begin the caller's transaction");
        let outcome = ClaimRepository::create_or_get(
            &mut tx,
            &viewer,
            &caller_claim,
            epigraph_core::TenancyDecl::Inherited,
        )
        .await;
        let (returned, was_created) = outcome.expect(
            "a lost race must be absorbed and reported as a dedup hit. A `25P02 current \
             transaction is aborted` here is the defect: the catch path's re-find cannot run \
             because the failed INSERT aborted the caller's transaction.",
        );
        let returned_id: Uuid = returned.id.into();

        // THE HALF THAT DISTINGUISHES FIXED FROM UNFIXED: the transaction is
        // still usable, so the submission can go on to write its trace and
        // commit.
        sqlx::query("UPDATE claims SET labels = ARRAY['race-survivor'] WHERE id = $1")
            .bind(returned_id)
            .execute(&mut *tx)
            .await
            .expect(
                "the caller's transaction must still be usable after the absorbed race — the \
                 refused INSERT was rolled back to a savepoint, not left aborting everything \
                 after it",
            );
        tx.commit().await.expect("commit the caller's transaction");
        (returned_id, was_created)
    });

    wait_until_blocked_on_the_barrier(&pool).await;

    // The winner commits, THEN the barrier lifts. Its id differs, so the
    // `WHEN` clause keeps it out of the trigger.
    let winner = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, $2, $3, 0.5, $4, true)",
    )
    .bind(winner)
    .bind(&content)
    .bind(ContentHasher::hash(content.as_bytes()).as_slice())
    .bind(agent_id)
    .execute(&mut *other)
    .await
    .expect("the other writer commits the winning row");
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(RACE_BARRIER_KEY)
        .execute(&mut *other)
        .await
        .expect("release the barrier");
    drop(other);

    let (returned_id, was_created) = caller.await.expect("the caller task must not panic");

    assert!(
        !was_created,
        "the winning row already existed by the time the INSERT ran, so this call did not \
         create one"
    );
    assert_eq!(
        returned_id, winner,
        "the row returned must be the RACE WINNER's, not the id this call tried to insert — \
         that is what 'absorbed' means. The caller's own id here would mean the insert somehow \
         succeeded and the constraint did not fire."
    );

    let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(returned_id)
        .fetch_one(&pool)
        .await
        .expect("read the committed row back");
    assert_eq!(
        labels,
        vec!["race-survivor".to_string()],
        "the whole transaction must have committed, not just the statements before the race"
    );
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(&content)
        .fetch_one(&pool)
        .await
        .expect("count rows for this content");
    assert_eq!(
        rows, 1,
        "exactly one row for the content: the race winner. A second row means the dedup was \
         bypassed rather than absorbed."
    );
}

// ────────────────────────────────────────────────────────────────────────────
// create_or_get — the dedup race WITHOUT the constraint (the production shape)
// ────────────────────────────────────────────────────────────────────────────

/// How a racer reaches `create_or_get`: inside a transaction it opened itself
/// (the `epigraph-mcp` submission path, POST /claims `if_not_exists=true`), or
/// on a bare pool connection with no transaction around the call.
///
/// Both shapes are raced because they fail differently. A serialization taken
/// with a transaction-scoped lock on a connection that is NOT in a transaction
/// is released at the end of the lock's own statement, before the find even
/// runs — so an implementation can pass the in-transaction arm and still mint
/// duplicates for every autocommit caller.
#[derive(Clone, Copy, Debug)]
enum Racer {
    InCallerTransaction,
    OnBareConnection,
}

async fn run_racer(pool: PgPool, claim: Claim, how: Racer, writer: PairWriter) -> (Uuid, bool) {
    match how {
        Racer::InCallerTransaction => {
            let mut tx = pool.begin().await.expect("begin the racer's transaction");
            let out = write_pair(&mut tx, &pool, writer, &claim, &[]).await;
            tx.commit().await.expect("commit the racer's transaction");
            out
        }
        Racer::OnBareConnection => {
            let mut conn = pool
                .acquire()
                .await
                .expect("acquire the racer's connection");
            write_pair(&mut conn, &pool, writer, &claim, &[]).await
        }
    }
}

/// Two FIRST creates of one `(content_hash, agent_id)`, interleaved the way
/// production interleaves them, on a database WITHOUT
/// `uq_claims_content_hash_agent` — which is the long-lived database's shape
/// (migrations/README.md, "Known schema drift") and, from migration 150, the
/// migrated shape everywhere.
///
/// # The interleaving, and why it is forced rather than hoped for
///
/// Caller 1 is parked INSIDE its `INSERT` by the race barrier (its row exists
/// but is uncommitted, so no other session can see it). Only then does caller 2
/// start: its find misses caller 1's invisible row. With nothing serializing
/// them, caller 2 inserts and commits, then caller 1 is released and commits
/// too — two live rows for one `(content_hash, agent_id)`, which is how
/// production keeps minting race duplicates. Caller 2 must start AFTER caller 1
/// is parked: started first, it would commit before caller 1's find, and
/// caller 1 would dedup against it whether or not anything serializes them.
///
/// Before releasing the barrier the arm waits until caller 2 has either
/// FINISHED (unserialized: it inserted past caller 1) or is BLOCKED on a
/// two-key advisory lock (`objsubid = 2`; the barrier is a one-key lock, so it
/// is never counted). Either observation is final; the assertions decide which
/// one was correct.
///
/// Returns the number of rows for the pair and each caller's
/// `(returned id, was_created)`.
async fn race_two_first_creates(pool: &PgPool, how: Racer) -> (i64, [(Uuid, bool); 2]) {
    race_two_first_creates_with(pool, how, PairWriter::CreateOrGet).await
}

/// [`race_two_first_creates`] with both callers running `writer`.
async fn race_two_first_creates_with(
    pool: &PgPool,
    how: Racer,
    writer: PairWriter,
) -> (i64, [(Uuid, bool); 2]) {
    // The production shape. Explicit, so the arm cannot pass on the constraint.
    drop_unique_constraint(pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(pool, agent_id).await;
    let content = format!("cog unconstrained race {how:?} {}", Uuid::new_v4());
    // Same content and author, distinct ids: only caller 1's id fires the barrier.
    let first = make_claim(&content, agent_id);
    let second = make_claim(&content, agent_id);
    install_race_barrier(pool, first.id.into()).await;

    let mut holder = pool.acquire().await.expect("acquire the barrier holder");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(RACE_BARRIER_KEY)
        .execute(&mut *holder)
        .await
        .expect("take the barrier");

    let caller_1 = tokio::spawn(run_racer(pool.clone(), first, how, writer));
    wait_until_blocked_on_the_barrier(pool).await;
    let caller_2 = tokio::spawn(run_racer(pool.clone(), second, how, writer));

    let mut settled = false;
    for _ in 0..600 {
        if caller_2.is_finished() {
            settled = true;
            break;
        }
        let blocked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_locks \
              WHERE locktype = 'advisory' AND objsubid = 2 AND NOT granted \
              AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .fetch_one(pool)
        .await
        .expect("read pg_locks");
        if blocked > 0 {
            settled = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        settled,
        "caller 2 neither finished nor blocked on a dedup lock while caller 1 was parked in its \
         INSERT; the arm cannot tell serialized from unserialized"
    );

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(RACE_BARRIER_KEY)
        .execute(&mut *holder)
        .await
        .expect("release the barrier");
    drop(holder);

    let r1 = caller_1.await.expect("caller 1 must not panic");
    let r2 = caller_2.await.expect("caller 2 must not panic");

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(ContentHasher::hash(content.as_bytes()).as_slice())
            .bind(agent_id)
            .fetch_one(pool)
            .await
            .expect("count rows for the pair");
    (rows, [r1, r2])
}

fn assert_one_row_one_creator(rows: i64, outcomes: [(Uuid, bool); 2]) {
    assert_eq!(
        rows, 1,
        "two concurrent first creates of one (content_hash, agent_id) left {rows} rows: the find \
         ran against a snapshot that could not see the other caller's uncommitted insert, and \
         nothing serialized them. Outcomes: {outcomes:?}"
    );
    let creators = outcomes.iter().filter(|(_, created)| *created).count();
    assert_eq!(
        creators, 1,
        "exactly one caller may report was_created=true: {outcomes:?}"
    );
    assert_eq!(
        outcomes[0].0, outcomes[1].0,
        "both callers must answer with the one surviving row: {outcomes:?}"
    );
}

/// The race inside a caller's transaction, with the constraint absent.
#[sqlx::test(migrations = "../../migrations")]
async fn the_dedup_race_is_serialized_without_the_constraint(pool: PgPool) {
    let (rows, outcomes) = race_two_first_creates(&pool, Racer::InCallerTransaction).await;
    assert_one_row_one_creator(rows, outcomes);
}

/// The race on bare (autocommit) connections, with the constraint absent.
#[sqlx::test(migrations = "../../migrations")]
async fn the_dedup_race_is_serialized_on_a_bare_connection_without_the_constraint(pool: PgPool) {
    let (rows, outcomes) = race_two_first_creates(&pool, Racer::OnBareConnection).await;
    assert_one_row_one_creator(rows, outcomes);
}

/// The dedup lock must be held until the CALLER's transaction commits, not
/// just until `create_or_get` returns.
///
/// # The window this pins, which the barrier arms do not
///
/// The barrier arms park caller 1 INSIDE its INSERT, so they prove only that
/// the lock is held DURING the insert. Production callers in a transaction do
/// more work after `create_or_get` returns and before they commit (the MCP
/// submission path writes its trace and verb edges; POST /claims
/// `if_not_exists=true` and /submit commit later). That post-return window is
/// the widest real race window: caller 1's row exists but is uncommitted, so a
/// caller 2 that is not made to wait misses it and inserts a second row.
///
/// A regression that releases the lock early — a session lock unlocked at the
/// end of `create_or_get_signed`, or the lock taken on another connection —
/// still holds it while caller 1 is parked in its INSERT, so the barrier arms
/// stay green. This arm, which has no barrier, goes red.
///
/// # The interleaving
///
/// Caller 1 runs `create_or_get` in its own transaction, which RETURNS, and the
/// transaction is kept open. Caller 2 then starts on the same pair. The arm
/// waits until caller 2 has either FINISHED (nothing made it wait: it inserted
/// past caller 1's uncommitted row) or is BLOCKED on a two-key advisory lock in
/// this database. Only then does caller 1 commit; the assertions decide which
/// observation was correct.
#[sqlx::test(migrations = "../../migrations")]
async fn the_dedup_lock_is_held_until_the_callers_transaction_commits(pool: PgPool) {
    // The production shape. Explicit, so the arm cannot pass on the constraint
    // (where it is present, caller 2 would wait on the unique index instead).
    drop_unique_constraint(&pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;
    let content = format!("cog held until commit {}", Uuid::new_v4());
    let first = make_claim(&content, agent_id);
    let second = make_claim(&content, agent_id);

    let viewer = fixture::public_viewer(&pool).await;
    let mut tx_1 = pool.begin().await.expect("begin caller 1's transaction");
    let (created_1, was_created_1) = ClaimRepository::create_or_get(
        &mut tx_1,
        &viewer,
        &first,
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("caller 1's create_or_get");
    assert!(was_created_1, "caller 1 is the first create of the pair");
    let id_1: Uuid = created_1.id.into();

    // tx_1 stays OPEN: create_or_get has returned, the row is uncommitted.
    let caller_2 = tokio::spawn(run_racer(
        pool.clone(),
        second,
        Racer::InCallerTransaction,
        PairWriter::CreateOrGet,
    ));

    let mut blocked = false;
    for _ in 0..600 {
        if caller_2.is_finished() {
            break;
        }
        let waiting: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_locks \
              WHERE locktype = 'advisory' AND objsubid = 2 AND NOT granted \
              AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .fetch_one(&pool)
        .await
        .expect("read pg_locks");
        if waiting > 0 {
            blocked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        blocked || caller_2.is_finished(),
        "caller 2 neither finished nor blocked on a dedup lock while caller 1's transaction was \
         open; the arm cannot tell held from released"
    );

    tx_1.commit().await.expect("commit caller 1's transaction");
    let (id_2, was_created_2) = caller_2.await.expect("caller 2 must not panic");

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(ContentHasher::hash(content.as_bytes()).as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .expect("count rows for the pair");
    assert_eq!(
        rows, 1,
        "caller 2 inserted a second row for one (content_hash, agent_id) while caller 1's \
         transaction was still open: the dedup lock was released before caller 1 committed \
         (caller 2 blocked first: {blocked})"
    );
    assert!(
        blocked,
        "caller 2 finished while caller 1's transaction was open, so nothing made it wait for \
         caller 1's row"
    );
    assert!(
        !was_created_2,
        "caller 2 ran after caller 1 committed, so it must report the existing row"
    );
    assert_eq!(id_2, id_1, "caller 2 must answer with caller 1's row");
}

// ────────────────────────────────────────────────────────────────────────────
// Every OTHER find-then-insert writer of one (content_hash, agent_id) takes the
// same dedup lock (backlog 00f1a517, the writers #582 listed as unserialized)
// ────────────────────────────────────────────────────────────────────────────

/// A writer that looks for an existing row of the pair and inserts on a miss.
///
/// `create_or_get` is the reference (#582). The others each run their OWN find
/// before their INSERT, so a lock taken only inside `create_or_get` does not
/// serialize them, against each other or against `create_or_get`:
///
/// * `CreateConn` — `ClaimRepository::create_conn`, the legacy content-hash
///   dedup (`create(pool)` delegates to it). Production callers:
///   `ingest_document`'s level-3 atoms and the conventions routes.
/// * `CreateWithTx` — `ClaimRepository::create_with_tx`, the same legacy
///   contract on a caller's connection.
/// * `Consolidate` — `ClaimRepository::consolidate_act_conn`, whose
///   "identical merged claim by this agent already exists" probe is a find on
///   `(content_hash, acting agent)`. Production caller: MCP
///   `consolidate_claims`.
#[derive(Clone, Copy, Debug)]
enum PairWriter {
    CreateOrGet,
    CreateConn,
    CreateWithTx,
    Consolidate,
}

/// Two committed, current, public source claims for one consolidation. Each
/// call seeds fresh content, so two consolidations never contend on a source
/// row lock — the only lock they can share is the pair's.
async fn seed_consolidation_sources(pool: &PgPool, author: Uuid) -> Vec<Uuid> {
    let mut ids = Vec::with_capacity(2);
    for _ in 0..2 {
        let content = format!("consolidation source {}", Uuid::new_v4());
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current) \
             VALUES ($1, $2, 0.5, $3, true) RETURNING id",
        )
        .bind(&content)
        .bind(ContentHasher::hash(content.as_bytes()).as_slice())
        .bind(author)
        .fetch_one(pool)
        .await
        .expect("seed a consolidation source");
        ids.push(id);
    }
    ids
}

/// Run `writer` for `claim`'s `(content, agent_id)` on `conn` (a transaction
/// or a bare connection). Returns the row the writer answered with and whether
/// THIS call inserted it. `sources` is used by `Consolidate` only, which
/// writes `claim.content` as its merged content and ignores `claim.id`.
async fn write_pair(
    conn: &mut sqlx::PgConnection,
    pool: &PgPool,
    writer: PairWriter,
    claim: &Claim,
    sources: &[Uuid],
) -> (Uuid, bool) {
    let own_id: Uuid = claim.id.into();
    let agent_id: Uuid = claim.agent_id.into();
    let decl = epigraph_core::TenancyDecl::Inherited;
    match writer {
        PairWriter::CreateOrGet => {
            let viewer = fixture::public_viewer(pool).await;
            let (row, created) = ClaimRepository::create_or_get(conn, &viewer, claim, decl)
                .await
                .expect("create_or_get");
            (row.id.into(), created)
        }
        PairWriter::CreateConn => {
            let row = ClaimRepository::create_conn(conn, claim, decl)
                .await
                .expect("create_conn");
            let id: Uuid = row.id.into();
            (id, id == own_id)
        }
        PairWriter::CreateWithTx => {
            let row = ClaimRepository::create_with_tx(conn, claim, decl)
                .await
                .expect("create_with_tx");
            let id: Uuid = row.id.into();
            (id, id == own_id)
        }
        PairWriter::Consolidate => {
            let res = ClaimRepository::consolidate_act_conn(
                conn,
                sources,
                &claim.content,
                0.6,
                epigraph_db::ConsolidateMode::Merge,
                "dedup-lock race",
                agent_id,
            )
            .await
            .expect("consolidate_act_conn");
            (res.merged_id, !res.already_existed)
        }
    }
}

/// Wait until `task` has FINISHED or some backend in THIS database is BLOCKED
/// on a two-key advisory lock (`objsubid = 2`, the dedup lock's shape; the race
/// barrier is a one-key lock and is never counted). Returns whether it blocked.
/// Either observation is final; the caller's assertions decide which one was
/// correct. Panics if neither happens, so a fixture that waits on something
/// else (a row lock, a group upsert) cannot pass as "serialized".
async fn settle_on_the_dedup_lock<T>(pool: &PgPool, task: &tokio::task::JoinHandle<T>) -> bool {
    for _ in 0..600 {
        if task.is_finished() {
            return false;
        }
        let waiting: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_locks \
              WHERE locktype = 'advisory' AND objsubid = 2 AND NOT granted \
              AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .fetch_one(pool)
        .await
        .expect("read pg_locks");
        if waiting > 0 {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!(
        "caller 2 neither finished nor blocked on a dedup lock while caller 1's transaction was \
         open; it is waiting on something else, so the arm cannot tell serialized from not"
    );
}

/// Caller 1 runs `first` in a transaction and keeps it OPEN (its row exists,
/// uncommitted, invisible to every other snapshot). Caller 2 then runs
/// `second` on the same `(content_hash, agent_id)` in its own transaction. The
/// arm waits until caller 2 finished (nothing made it wait: its find missed
/// caller 1's row and it inserted a second one) or blocked on the dedup lock,
/// then commits caller 1 and counts the pair's rows.
///
/// With `first != second` this is also the KEY test: a writer that locks a
/// different key (another namespace, another encoding of the hash) passes its
/// own self-race and fails here.
async fn race_held_open(pool: &PgPool, first: PairWriter, second: PairWriter) {
    // The production shape. Explicit, so no arm can pass on the constraint.
    drop_unique_constraint(pool).await;

    let agent_id = Uuid::new_v4();
    insert_test_agent(pool, agent_id).await;
    // Mint the author's personal group NOW, committed: a consolidation of
    // public sources resolves it, and a first resolution WRITES. Left to the
    // racers, caller 2 would wait on caller 1's uncommitted group upsert — a
    // row lock, not the dedup lock — and the arm would observe the wrong wait.
    {
        let mut conn = pool.acquire().await.expect("acquire for the group mint");
        ClaimRepository::default_decl_for_author(&mut conn, agent_id)
            .await
            .expect("mint the author's personal group");
    }
    let content = format!("held-open {first:?} then {second:?} {}", Uuid::new_v4());
    let sources_1 = seed_consolidation_sources(pool, agent_id).await;
    let sources_2 = seed_consolidation_sources(pool, agent_id).await;

    let mut tx_1 = pool.begin().await.expect("begin caller 1's transaction");
    let r1 = write_pair(
        &mut tx_1,
        pool,
        first,
        &make_claim(&content, agent_id),
        &sources_1,
    )
    .await;
    assert!(r1.1, "caller 1 is the first write of the pair: {r1:?}");

    let caller_2 = {
        let pool = pool.clone();
        let content = content.clone();
        let sources_2 = sources_2.clone();
        tokio::spawn(async move {
            let mut tx = pool.begin().await.expect("begin caller 2's transaction");
            let claim = make_claim(&content, agent_id);
            let out = write_pair(&mut tx, &pool, second, &claim, &sources_2).await;
            tx.commit().await.expect("commit caller 2's transaction");
            out
        })
    };
    let blocked = settle_on_the_dedup_lock(pool, &caller_2).await;

    tx_1.commit().await.expect("commit caller 1's transaction");
    let r2 = caller_2.await.expect("caller 2 must not panic");

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(ContentHasher::hash(content.as_bytes()).as_slice())
            .bind(agent_id)
            .fetch_one(pool)
            .await
            .expect("count rows for the pair");
    assert_eq!(
        rows, 1,
        "{second:?} racing an open {first:?} of one (content_hash, agent_id) left {rows} rows: \
         its find could not see caller 1's uncommitted row and nothing made it wait. \
         Outcomes: {r1:?} then {r2:?}"
    );
    assert!(
        blocked,
        "caller 2 finished while caller 1's transaction was open: nothing made it wait"
    );
    assert!(
        !r2.1,
        "caller 2 ran after caller 1 committed, so it must report the existing row: {r2:?}"
    );
    assert_eq!(r2.0, r1.0, "caller 2 must answer with caller 1's row");

    // A consolidation's sources: the merge that inserted retires its own
    // sources into the merged row; a merge that answered with an existing row
    // retires nothing, so its sources stay current and unsuperseded (the
    // semantics a sequential retry already had).
    if matches!(first, PairWriter::Consolidate) {
        assert_sources(
            pool,
            &sources_1,
            Some(r1.0),
            "caller 1 (the merge that inserted)",
        )
        .await;
    }
    if matches!(second, PairWriter::Consolidate) {
        assert_sources(
            pool,
            &sources_2,
            None,
            "caller 2 (the merge that found the row)",
        )
        .await;
    }
}

/// Assert every claim in `sources` is retired into `merged` (`Some`), or is
/// still current and supersedes nothing (`None`).
async fn assert_sources(pool: &PgPool, sources: &[Uuid], merged: Option<Uuid>, who: &str) {
    for id in sources {
        let (is_current, supersedes): (bool, Option<Uuid>) =
            sqlx::query_as("SELECT is_current, supersedes FROM claims WHERE id = $1")
                .bind(id)
                .fetch_one(pool)
                .await
                .expect("read a consolidation source");
        match merged {
            Some(m) => {
                assert!(!is_current, "{who}: source {id} must be retired");
                assert_eq!(
                    supersedes,
                    Some(m),
                    "{who}: source {id} must point at the merged row"
                );
            }
            None => {
                assert!(is_current, "{who}: source {id} must stay current");
                assert_eq!(
                    supersedes, None,
                    "{who}: source {id} must supersede nothing"
                );
            }
        }
    }
}

/// Two legacy content-hash creates of one pair (`ingest_document` atoms, the
/// conventions routes).
#[sqlx::test(migrations = "../../migrations")]
async fn create_conn_races_create_conn_into_one_row(pool: PgPool) {
    race_held_open(&pool, PairWriter::CreateConn, PairWriter::CreateConn).await;
}

/// `create_conn` waits on the SAME lock `create_or_get` holds.
#[sqlx::test(migrations = "../../migrations")]
async fn create_conn_waits_on_create_or_gets_dedup_lock(pool: PgPool) {
    race_held_open(&pool, PairWriter::CreateOrGet, PairWriter::CreateConn).await;
}

/// `create_with_tx` (the legacy contract on a caller's connection) waits on
/// the same lock.
#[sqlx::test(migrations = "../../migrations")]
async fn create_with_tx_waits_on_create_or_gets_dedup_lock(pool: PgPool) {
    race_held_open(&pool, PairWriter::CreateOrGet, PairWriter::CreateWithTx).await;
}

/// Two consolidations by one agent into identical merged content, over
/// disjoint sources: the second answers with the first's merged claim, which
/// is what a sequential retry already gets.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_races_consolidate_into_one_merged_row(pool: PgPool) {
    race_held_open(&pool, PairWriter::Consolidate, PairWriter::Consolidate).await;
}

/// A consolidation waits on the SAME lock `create_or_get` holds.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_waits_on_create_or_gets_dedup_lock(pool: PgPool) {
    race_held_open(&pool, PairWriter::CreateOrGet, PairWriter::Consolidate).await;
}

/// The reverse order: `create_or_get` waits on a held-open legacy create of
/// the pair, then dedups against its committed row. Proves `create_or_get`'s
/// find (viewer-filtered) answers with a row the legacy create wrote, not only
/// that the two share a key.
#[sqlx::test(migrations = "../../migrations")]
async fn create_or_get_waits_on_create_conns_dedup_lock(pool: PgPool) {
    race_held_open(&pool, PairWriter::CreateConn, PairWriter::CreateOrGet).await;
}

/// The reverse order for a consolidation: `create_or_get` of the merged
/// content waits on the held-open merge, then returns the merged row.
#[sqlx::test(migrations = "../../migrations")]
async fn create_or_get_waits_on_consolidates_dedup_lock(pool: PgPool) {
    race_held_open(&pool, PairWriter::Consolidate, PairWriter::CreateOrGet).await;
}

/// The legacy create on BARE (autocommit) connections — the `create(pool)`
/// shape the conventions routes use — with caller 1 parked inside its INSERT.
///
/// A transaction-scoped lock taken in autocommit is released at the end of its
/// own statement, so an implementation that locks without opening a scope
/// passes every held-open arm above (those run in transactions) and still
/// mints duplicates here.
#[sqlx::test(migrations = "../../migrations")]
async fn create_conn_race_is_serialized_on_a_bare_connection(pool: PgPool) {
    let (rows, outcomes) =
        race_two_first_creates_with(&pool, Racer::OnBareConnection, PairWriter::CreateConn).await;
    assert_one_row_one_creator(rows, outcomes);
}

/// A dedup HIT on an already-committed row takes no dedup lock.
///
/// `ingest_document` writes every atom through `create_conn` inside one
/// document transaction, so a lock taken on a hit would be held until the
/// whole document commits. Two same-author ingests that share PRE-EXISTING
/// atoms would then serialize on them, and deadlock (40P01) when they meet
/// them in opposite orders, where before a hit was a plain read that waited
/// on nothing. Only a MISS may take the lock; the find that decides the
/// insert re-runs under it.
///
/// Caller 1 hits the committed row inside a transaction it keeps open.
/// Caller 2 then writes the same pair on its own connection: it must finish
/// without waiting, and answer with the committed row.
#[sqlx::test(migrations = "../../migrations")]
async fn create_conn_hit_on_a_committed_row_takes_no_dedup_lock(pool: PgPool) {
    drop_unique_constraint(&pool).await;
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;
    let decl = epigraph_core::TenancyDecl::Inherited;
    let content = format!("committed before both callers {}", Uuid::new_v4());
    let seeded: Uuid = ClaimRepository::create(&pool, &make_claim(&content, agent_id), decl)
        .await
        .expect("seed the committed row")
        .id
        .into();

    let mut tx_1 = pool.begin().await.expect("begin caller 1's transaction");
    let hit_1: Uuid =
        ClaimRepository::create_conn(&mut tx_1, &make_claim(&content, agent_id), decl)
            .await
            .expect("caller 1 create_conn")
            .id
            .into();
    assert_eq!(hit_1, seeded, "caller 1 must answer with the committed row");

    let caller_2 = {
        let pool = pool.clone();
        let content = content.clone();
        tokio::spawn(async move {
            let mut conn = pool.acquire().await.expect("acquire caller 2's connection");
            let id: Uuid =
                ClaimRepository::create_conn(&mut conn, &make_claim(&content, agent_id), decl)
                    .await
                    .expect("caller 2 create_conn")
                    .id
                    .into();
            id
        })
    };
    let blocked = settle_on_the_dedup_lock(&pool, &caller_2).await;
    let held_by_caller_1: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_locks \
          WHERE locktype = 'advisory' AND objsubid = 2 AND granted \
          AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
    )
    .fetch_one(&pool)
    .await
    .expect("read pg_locks");

    tx_1.commit().await.expect("commit caller 1's transaction");
    let id_2 = caller_2.await.expect("caller 2 must not panic");

    assert!(
        !blocked,
        "caller 2 waited on the dedup lock for a pair whose row was already committed: \
         caller 1's dedup HIT took the lock and holds it until its transaction ends"
    );
    assert_eq!(
        held_by_caller_1, 0,
        "caller 1's open transaction holds a dedup lock after a dedup HIT"
    );
    assert_eq!(id_2, seeded, "caller 2 must answer with the committed row");
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(ContentHasher::hash(content.as_bytes()).as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .expect("count rows for the pair");
    assert_eq!(rows, 1, "a dedup hit must not insert");
}

/// Migration 150 leaves no `uq_claims_content_hash_agent` on a database
/// migrated to head — CI's shape equals the long-lived database's.
///
/// Every race arm above drops the constraint itself, so without this pin
/// deleting 150, no-op'ing it, or a later migration that re-adds the full
/// UNIQUE (migrations/README.md forbids it) would leave the suite green while
/// CI again proved a dedup guarantee production lacks. Checks the named
/// constraint AND any unique index over exactly `(content_hash, agent_id)`;
/// a future PARTIAL index (`WHERE is_current`) is the sanctioned target and is
/// not counted.
#[sqlx::test(migrations = "../../migrations")]
async fn migrated_claims_carry_no_full_content_hash_agent_unique(pool: PgPool) {
    let named: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint
         WHERE conrelid = 'claims'::regclass AND conname = 'uq_claims_content_hash_agent'",
    )
    .fetch_one(&pool)
    .await
    .expect("inspect pg_constraint");
    assert_eq!(
        named, 0,
        "uq_claims_content_hash_agent is present after a full migrate: migration 150 must drop it \
         so CI has the long-lived database's claims shape (backlog 00f1a517)"
    );

    let full_unique: Vec<String> = sqlx::query_scalar(
        "SELECT i.indexrelid::regclass::text FROM pg_index i
         WHERE i.indrelid = 'claims'::regclass
           AND i.indisunique
           AND i.indpred IS NULL
           AND i.indnkeyatts = 2
           AND (SELECT array_agg(a.attname::text ORDER BY a.attname)
                  FROM pg_attribute a
                 WHERE a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey))
               = ARRAY['agent_id', 'content_hash']",
    )
    .fetch_all(&pool)
    .await
    .expect("inspect pg_index");
    assert!(
        full_unique.is_empty(),
        "a non-partial unique index over (content_hash, agent_id) exists after a full migrate: \
         {full_unique:?}"
    );
}
