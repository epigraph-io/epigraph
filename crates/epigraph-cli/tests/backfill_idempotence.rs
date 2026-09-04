//! `epigraph-tenancy-backfill` — idempotence, resumability and the `verify`
//! exit code.
//!
//! # These tests invoke the real binary
//!
//! Every assertion here runs the compiled `epigraph-tenancy-backfill` via
//! `CARGO_BIN_EXE_…` against a `#[sqlx::test]` database. Reimplementing the
//! backfill's SQL in the test and asserting on that would be a tautology: it
//! would pass against a binary that had been deleted. The cost is that these
//! are slower and need `DATABASE_URL` set; the benefit is that they test the
//! thing that ships.
//!
//! # What the exit code means
//!
//! `verify`'s non-zero exit **is** the contract — migration 070's header names
//! it as the guard that replaces an in-transaction check (the plan calls that
//! file 066; `migrations/README.md` pins it at 070), and PR-16's acceptance
//! runs it as a deploy pre-flight. So it is asserted directly, not via stdout
//! parsing.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const WORLD: Uuid = Uuid::nil();
const BIN: &str = env!("CARGO_BIN_EXE_epigraph-tenancy-backfill");

/// Run the binary against `pool`'s database. Returns `(exit_code, stderr)`.
async fn run_backfill(pool: &PgPool, args: &[&str]) -> (i32, String) {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
        .args(args)
        .env("DATABASE_URL", &url)
        // Quiet: these tests care about exit codes and database state, and the
        // binary's INFO logging is per-batch.
        .env("RUST_LOG", "warn")
        .output()
        .expect("spawn epigraph-tenancy-backfill");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A claim naming neither tenancy column, so migration 062's DEFAULT supplies
/// the world group — the state the backfill exists to clear.
async fn seed_undeclared_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    for (i, b) in content.as_bytes().iter().enumerate() {
        hash[i % 32] ^= *b;
    }
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, $2, $3, 0.8, $4, true)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed undeclared claim");
    id
}

async fn world_owned(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT count(*) FROM {table} WHERE owner_group_id = $1"
    ))
    .bind(WORLD)
    .fetch_one(pool)
    .await
    .expect("count world-owned")
}

/// `verify` must FAIL before the backfill and SUCCEED after.
///
/// Both halves matter. A `verify` that always exits 0 is worse than no guard,
/// because the deploy step that consumes it reads green and proceeds.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_fails_before_the_backfill_and_succeeds_after(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    seed_undeclared_claim(&pool, agent, "undeclared").await;

    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(
        code, 1,
        "verify must exit non-zero while a claim is still world-owned; stderr: {stderr}"
    );
    assert!(
        stderr.contains("still owned by the world group"),
        "verify must NAME the offending rows, not just fail; stderr: {stderr}"
    );

    let (code, stderr) = run_backfill(&pool, &["run"]).await;
    assert_eq!(code, 0, "run must succeed; stderr: {stderr}");

    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(
        code, 0,
        "verify must exit 0 once every entity is declared; stderr: {stderr}"
    );
}

/// Running the backfill twice must leave the database byte-identical.
///
/// Idempotence is what makes a `kill -9` recoverable, so it is load-bearing
/// rather than hygiene. The assertion is on the actual `(id, owner_group_id,
/// visibility)` tuples, not on a row count — a second pass that re-stamped
/// every row to a *different* owner would keep the counts identical.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_run_changes_nothing(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    for i in 0..5 {
        seed_undeclared_claim(&pool, agent, &format!("claim {i}")).await;
    }

    let (code, stderr) = run_backfill(&pool, &["run"]).await;
    assert_eq!(code, 0, "first run: {stderr}");

    let after_first: Vec<(Uuid, Uuid, String)> =
        sqlx::query_as("SELECT id, owner_group_id, visibility::text FROM claims ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("snapshot after first run");
    assert_eq!(after_first.len(), 5, "the fixture must actually seed rows");

    let (code, stderr) = run_backfill(&pool, &["run"]).await;
    assert_eq!(code, 0, "second run: {stderr}");

    let after_second: Vec<(Uuid, Uuid, String)> =
        sqlx::query_as("SELECT id, owner_group_id, visibility::text FROM claims ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("snapshot after second run");

    assert_eq!(
        after_first, after_second,
        "a second run must be a no-op; the backfill is re-run after any interruption"
    );
}

/// Resumability: a cursor left mid-walk resumes rather than restarting, and the
/// end state is the same as an uninterrupted run.
///
/// `kill -9` is simulated by doing what a `kill -9` leaves behind — a committed
/// batch and a committed cursor, with the remaining rows untouched. That is the
/// honest simulation: the binary commits the cursor in the SAME transaction as
/// its batch, so no other intermediate state is reachable.
#[sqlx::test(migrations = "../../migrations")]
async fn an_interrupted_run_resumes_from_its_cursor(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    for i in 0..6 {
        seed_undeclared_claim(&pool, agent, &format!("claim {i}")).await;
    }

    // A batch size of 2 over 6 rows guarantees the walk is genuinely multi-batch;
    // a single-batch walk would make "resumes" vacuous.
    let (code, stderr) = run_backfill(&pool, &["run", "--batch-size", "2"]).await;
    assert_eq!(code, 0, "run: {stderr}");
    assert_eq!(world_owned(&pool, "claims").await, 0);

    // Now rewind: return three claims to the undeclared state and reset the
    // cursor to just before them, exactly as a crash mid-walk would leave it.
    let rewind: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM claims ORDER BY id OFFSET 3")
        .fetch_all(&pool)
        .await
        .expect("pick rows to rewind");
    assert_eq!(rewind.len(), 3);
    sqlx::query("UPDATE claims SET owner_group_id = $1, visibility = 'public' WHERE id = ANY($2)")
        .bind(WORLD)
        .bind(&rewind)
        .execute(&pool)
        .await
        .expect("rewind rows");
    let resume_from: Uuid =
        sqlx::query_scalar("SELECT id FROM claims ORDER BY id OFFSET 2 LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("pick cursor");
    sqlx::query(
        "UPDATE tenancy_backfill_progress SET last_id = $1, complete = false WHERE entity = 'claims'",
    )
    .bind(resume_from)
    .execute(&pool)
    .await
    .expect("rewind cursor");

    assert_eq!(
        world_owned(&pool, "claims").await,
        3,
        "precondition: three rows are undeclared again"
    );

    let (code, stderr) = run_backfill(&pool, &["run", "--batch-size", "2"]).await;
    assert_eq!(code, 0, "resumed run: {stderr}");
    assert_eq!(
        world_owned(&pool, "claims").await,
        0,
        "a resumed run must finish the walk from its cursor"
    );
}

/// The backfill stamps the AUTHOR'S PERSONAL GROUP — not `world`, and
/// **not `seed`**.
///
/// PR-12's scope recon says "stamp the SEED group, not `world`". That is wrong
/// for the backfill and wrong in the dangerous direction: seed is migration
/// **074 arm 4**'s `epigraph_seed`-role escape hatch (062: *"Migration 074 arm
/// 4 stamps THIS"*), 074 is PR-16, and plan D2 requires the author's personal
/// group. Stamping seed would still satisfy acceptance A4 literally, so no
/// acceptance query in the plan would catch it — while leaving every claim
/// owned by a group with zero `group_memberships` rows by design.
///
/// This test is what catches it.
#[sqlx::test(migrations = "../../migrations")]
async fn claims_are_stamped_with_the_authors_personal_group_never_world_or_seed(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "author").await;
    let claim = seed_undeclared_claim(&pool, agent, "mine").await;

    let (code, stderr) = run_backfill(&pool, &["run"]).await;
    assert_eq!(code, 0, "run: {stderr}");

    let (owner, vis): (Uuid, String) =
        sqlx::query_as("SELECT owner_group_id, visibility::text FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read stamped claim");

    assert_eq!(
        owner, group,
        "D2: owner_group_id must be the AUTHOR'S personal group"
    );
    assert_eq!(
        vis, "public",
        "D2: pre-existing rows were already world-readable, so `public` is a \
         no-op declaration rather than a new disclosure"
    );

    let seed: Option<Uuid> = sqlx::query_scalar("SELECT id FROM groups WHERE kind = 'seed'")
        .fetch_optional(&pool)
        .await
        .expect("read seed group");
    let seed = seed.expect("migration 062 seeds the seed group");
    assert_ne!(owner, seed, "the seed group is PR-16's, not the backfill's");
    assert_ne!(owner, WORLD, "world is a shape constant, never an owner");

    // The owner must be a group the author can actually READ BACK — the
    // property that stamping seed would silently destroy.
    let live_members: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(owner)
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("count memberships");
    assert_eq!(
        live_members, 1,
        "the stamped owner must be a group the author is a LIVE member of, or the \
         backfill has produced a corpus nobody can read"
    );
}

/// An author with no personal group gets one — the ~1,198 orphan-agent case
/// migration 057 documents, and the single largest piece of work PR-12's
/// *Files* line does not mention.
///
/// `AgentRepository::ensure_personal_group` is only ever called from the OAuth
/// mint path and the MCP server's agent resolution, so an agent that has never
/// authenticated has no group and its claims have no derivable owner.
#[sqlx::test(migrations = "../../migrations")]
async fn an_author_with_no_personal_group_is_given_one(pool: PgPool) {
    let orphan = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(orphan)
        .bind(vec![11u8; 32])
        .execute(&pool)
        .await
        .expect("seed orphan agent");
    let claim = seed_undeclared_claim(&pool, orphan, "orphan's claim").await;

    let before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM groups WHERE kind = 'personal' AND created_by_agent_id = $1",
    )
    .bind(orphan)
    .fetch_one(&pool)
    .await
    .expect("count groups");
    assert_eq!(before, 0, "precondition: the agent has no personal group");

    let (code, stderr) = run_backfill(&pool, &["run"]).await;
    assert_eq!(code, 0, "run: {stderr}");

    let (owner, vis): (Uuid, String) =
        sqlx::query_as("SELECT owner_group_id, visibility::text FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read stamped claim");
    assert_ne!(owner, WORLD, "the orphan's claim must have a real owner");
    assert_eq!(vis, "public");

    let did_key: String = sqlx::query_scalar("SELECT did_key FROM groups WHERE id = $1")
        .bind(owner)
        .fetch_one(&pool)
        .await
        .expect("read group");
    assert_eq!(
        did_key,
        format!("did:epigraph:personal:{orphan}"),
        "a materialized personal group must carry the canonical did_key that \
         `ensure_personal_group` derives, or migration 071's shim cannot find it"
    );

    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL AND role = 'admin'",
    )
    .bind(owner)
    .bind(orphan)
    .fetch_one(&pool)
    .await
    .expect("count membership");
    assert_eq!(
        live, 1,
        "a materialized personal group without a live admin membership is a black \
         hole: the author could not read back their own corpus"
    );
}

/// The backfill REFUSES to run if migration 070 is not armed.
///
/// The backfill relies on arm (d) to reach the 17 claim-derived tables. Without
/// it, `UPDATE claims` stamps the roots and propagates to nothing, while
/// `tenancy_backfill_progress` reports every entity complete — a silent
/// half-backfill whose only symptom is world-owned evidence nobody looks at.
#[sqlx::test(migrations = "../../migrations")]
async fn the_backfill_refuses_to_run_without_migration_070(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    seed_undeclared_claim(&pool, agent, "claim").await;

    sqlx::query("ALTER TABLE claims DISABLE TRIGGER claims_propagate_tenancy")
        .execute(&pool)
        .await
        .expect("disable the propagation trigger");

    let (code, stderr) = run_backfill(&pool, &["run"]).await;
    assert_ne!(
        code, 0,
        "the backfill must refuse to start with arm (d) disabled; stderr: {stderr}"
    );
    assert!(
        stderr.contains("claims_propagate_tenancy"),
        "the refusal must name the missing trigger so it is actionable; stderr: {stderr}"
    );
    assert_eq!(
        world_owned(&pool, "claims").await,
        1,
        "refusing must mean writing nothing, not writing half"
    );
}

/// `--dry-run` reports and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn dry_run_writes_nothing(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    seed_undeclared_claim(&pool, agent, "claim").await;

    let (code, stderr) = run_backfill(&pool, &["run", "--dry-run"]).await;
    assert_eq!(code, 0, "dry run: {stderr}");
    assert_eq!(
        world_owned(&pool, "claims").await,
        1,
        "--dry-run must not stamp anything"
    );
}

/// **An `ownership` row that predates migration 071 is transcribed by `run`.**
///
/// # The hole this closes
///
/// Migration 071 installs only `CREATE TRIGGER ownership_transcribe AFTER
/// INSERT OR UPDATE ON public.ownership`. It performs no one-time pass, so a
/// row already in the table when the migration applied is never transcribed —
/// and `verify` counts exactly those rows, in two checks that were then
/// **unclearable by anything in the PR**:
///
/// * "N non-public ownership row(s) map to a still-public claim", and
/// * "N non-public ownership row(s) have no transcription log row".
///
/// `run` calls `verify` at the end, so `run` would have exited 1 forever too,
/// and the plan's acceptance line ("every `ownership` row it transcribes writes
/// a `tenancy_transcription_log` row") would have been satisfied only
/// vacuously, by transcribing zero.
///
/// # Why the fixture disables the trigger
///
/// Every other fixture in this suite inserts AFTER 071 applied, so the trigger
/// fires and the legacy shape is never exercised — which is precisely why the
/// suite was structurally blind to this. Disabling the trigger for one INSERT
/// reproduces the production shape: an `ownership` row whose claim is still
/// `('public', world)` and which has no ledger row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_ownership_row_is_transcribed_and_clears_verify(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let claim = seed_undeclared_claim(&pool, agent, "legacy private").await;

    sqlx::query("ALTER TABLE ownership DISABLE TRIGGER ownership_transcribe")
        .execute(&pool)
        .await
        .expect("disable transcription trigger");
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2)",
    )
    .bind(claim)
    .bind(agent)
    .execute(&pool)
    .await
    .expect("seed a pre-071 ownership row");
    sqlx::query("ALTER TABLE ownership ENABLE TRIGGER ownership_transcribe")
        .execute(&pool)
        .await
        .expect("re-enable transcription trigger");

    // Precondition: the row is genuinely untranscribed and `verify` says so.
    let vis: String = sqlx::query_scalar("SELECT visibility::text FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("read visibility");
    assert_eq!(
        vis, "public",
        "precondition: a legacy ownership row leaves its claim public — this is \
         the divergence 071's header says the shim exists to prevent"
    );
    let logged: i64 =
        sqlx::query_scalar("SELECT count(*) FROM tenancy_transcription_log WHERE node_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("count ledger rows");
    assert_eq!(logged, 0, "precondition: no ledger row yet");

    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(
        code, 1,
        "verify must FAIL while a non-public ownership row maps to a public \
         claim; stderr:\n{stderr}"
    );

    // The fix: `run` re-fires the trigger over every untranscribed row.
    let (code, stderr) = run_backfill(&pool, &["run"]).await;
    assert_eq!(
        code, 0,
        "run must transcribe the legacy row and then pass its own verify; \
         stderr:\n{stderr}"
    );

    let vis: String = sqlx::query_scalar("SELECT visibility::text FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("read visibility");
    assert_eq!(
        vis, "group",
        "the legacy 'private' declaration must now be on the LIVE tenancy column"
    );
    let logged: i64 =
        sqlx::query_scalar("SELECT count(*) FROM tenancy_transcription_log WHERE node_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("count ledger rows");
    assert_eq!(
        logged, 1,
        "and migration 080's pre-flight reads this ledger row — the acceptance \
         line is 'every ownership row it transcribes writes one'"
    );

    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(code, 0, "verify must now pass; stderr:\n{stderr}");

    // And it is idempotent: a second run selects nothing (every row now has a
    // ledger row) and still exits 0.
    let (code, stderr) = run_backfill(&pool, &["run"]).await;
    assert_eq!(code, 0, "a second run must be a no-op; stderr:\n{stderr}");
}

/// `verify` fails if migrations 070/071's `SECURITY DEFINER` bodies were not
/// re-owned to `epigraph_maintenance`.
///
/// # Why this check exists at all
///
/// Both migrations wrap their `ALTER FUNCTION … OWNER TO epigraph_maintenance`
/// in `IF EXISTS (SELECT 1 FROM pg_roles …)` and SILENTLY no-op when the role is
/// absent — which migration 060 makes possible on purpose, because it only
/// `RAISE NOTICE`s when the migration role lacks `CREATEROLE`. The two
/// consequences are opposite and both invisible at deploy time: 070's arm (b)
/// becomes RLS-filtered at PR-17 and stamps a private endpoint PUBLIC (a leak,
/// not an error), while 071's shim raises 42501 on every `ownership` write (a
/// total write outage). Nothing anywhere asserted the ALTER had happened.
///
/// A hard failure inside the migration would be wrong — a failed migration
/// records no row, so a missing role would become a permanent restart loop — so
/// the assertion lives in the one place an operator can act on it: `verify`,
/// whose exit code is the week-11c pre-flight.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_fails_when_a_definer_body_is_not_maintenance_owned(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    seed_undeclared_claim(&pool, agent, "ordinary").await;
    let (code, stderr) = run_backfill(&pool, &["run"]).await;
    assert_eq!(code, 0, "baseline run must pass; stderr:\n{stderr}");

    // Reproduce the missing-role deploy: the function exists but was never
    // re-owned.
    sqlx::query("ALTER FUNCTION public.epigraph_node_tenancy(uuid, text) OWNER TO epigraph_app")
        .execute(&pool)
        .await
        .expect("re-own the oracle to the app role");

    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(
        code, 1,
        "verify must refuse a deploy whose SECURITY DEFINER bodies are app-owned; \
         stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("epigraph_node_tenancy") && stderr.contains("epigraph_maintenance"),
        "and it must NAME the function and the required owner, or an operator \
         cannot act on it; stderr:\n{stderr}"
    );
}

/// The definer check keys on `pg_has_role(owner, 'epigraph_maintenance',
/// 'MEMBER')`, not on `rolname = 'epigraph_maintenance'` — so a SUPERUSER-owned
/// body PASSES.
///
/// This is the counterpart of the test above and it is what stops that gate
/// from blocking a valid deploy. `epigraph_definer_bypass()` (migration 067) is
/// `pg_has_role(current_user, 'epigraph_maintenance', 'MEMBER')` evaluated as
/// the function owner, and `pg_has_role` is true of a superuser for every role.
/// String equality would have been strictly stricter than the runtime control
/// it protects, and the documented remedy ("re-apply 070 and 071") would not
/// have cleared it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_superuser_owned_definer_body_satisfies_verify(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    seed_undeclared_claim(&pool, agent, "ordinary").await;
    let (code, stderr) = run_backfill(&pool, &["run"]).await;
    assert_eq!(code, 0, "baseline run must pass; stderr:\n{stderr}");

    let superuser: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&pool)
        .await
        .expect("read current_user");
    let is_super: bool =
        sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            .fetch_one(&pool)
            .await
            .expect("read rolsuper");
    assert!(
        is_super,
        "this test's premise is that the test connection is a superuser; it is not \
         ({superuser}), so re-derive the case rather than deleting the assertion"
    );

    sqlx::query(&format!(
        "ALTER FUNCTION public.epigraph_node_tenancy(uuid, text) OWNER TO \"{superuser}\""
    ))
    .execute(&pool)
    .await
    .expect("re-own the oracle to the superuser");

    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(
        code, 0,
        "a superuser-owned body satisfies epigraph_definer_bypass(), so verify must \
         NOT block it — the check mirrors the runtime control, it does not exceed it; \
         stderr:\n{stderr}"
    );
}
