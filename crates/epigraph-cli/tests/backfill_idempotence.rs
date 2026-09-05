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
///
/// **Both DSN variables are set explicitly.** PR-15 taught this binary to
/// prefer `MAINTENANCE_DATABASE_URL`, and `Command::env` adds to the parent
/// environment rather than replacing it — so an inherited value would point the
/// subprocess at a different database than the `#[sqlx::test]` template just
/// seeded, and every assertion here would pass or fail for reasons unrelated to
/// the code. Setting it also means the ordinary path through these tests
/// exercises the *configured* maintenance DSN rather than the WARN fallback.
async fn run_backfill(pool: &PgPool, args: &[&str]) -> (i32, String) {
    let url = fixture::database_url_for(pool).await;
    run_backfill_with_maintenance_dsn(pool, args, &url).await
}

/// [`run_backfill`] with an explicit `MAINTENANCE_DATABASE_URL`, so the
/// database-name guard can be exercised through the real binary.
async fn run_backfill_with_maintenance_dsn(
    pool: &PgPool,
    args: &[&str],
    maintenance_url: &str,
) -> (i32, String) {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
        .args(args)
        .env("DATABASE_URL", &url)
        .env("MAINTENANCE_DATABASE_URL", maintenance_url)
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

/// A claim that IS declared: owned by a real group and not public.
///
/// `claims.visibility` in this tree is `public | group` (migration 062's
/// `claims_visibility_check`), not `public | private` as the plan's prose says,
/// and `claims_group_needs_real_group` forbids `visibility = 'group'` on a
/// world- or dead-owned row. So a "private undeclared" row is not constructible
/// here at all — a non-public row is by construction already owned.
async fn seed_group_private_claim(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    for (i, b) in content.as_bytes().iter().enumerate() {
        hash[i % 32] ^= *b;
    }
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             owner_group_id, visibility) \
         VALUES ($1, $2, $3, 0.8, $4, true, $5, 'group')",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed group-private claim");
    id
}

/// `(owner_group_id, visibility)` for one claim.
async fn tenancy_of(pool: &PgPool, id: Uuid) -> (Uuid, String) {
    sqlx::query_as("SELECT owner_group_id, visibility::text FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read tenancy")
}

/// A **legacy** claim: `('public', <world group>)`, which is the state the
/// backfill exists to clear.
///
/// # Why this now stamps world EXPLICITLY — PR-16
///
/// This helper used to name neither tenancy column and let migration 062's
/// `DEFAULT` supply the world group. Migration 074 drops that default, and an
/// undeclared insert on the test harness role now takes the seed escape hatch
/// instead — landing on `('public', <seed group>)`. Every test in this file
/// then failed on its own precondition, because the backfill targets
/// `owner_group_id = <world>` and there was nothing there.
///
/// The right fix is to construct the state rather than to widen what the
/// backfill looks for. The world-owned corpus is **historical**: it is what
/// migration 062 created on a live database, and after 074 no write path
/// produces another one. A fixture that reproduced it by omission was only ever
/// getting it by accident of the default, and would have kept passing while
/// silently testing a different row shape.
///
/// The seed group is deliberately NOT what the backfill targets, and
/// `claims_are_stamped_with_the_authors_personal_group_never_world_or_seed`
/// below is what pins that distinction.
async fn seed_undeclared_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    for (i, b) in content.as_bytes().iter().enumerate() {
        hash[i % 32] ^= *b;
    }
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.8, $4, true, 'public', \
                 '00000000-0000-0000-0000-000000000000'::uuid)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed legacy world-owned claim");
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

/// PR-15's positive acceptance: the backfill **updates the row**, and leaves a
/// row that is already declared non-public alone.
///
/// # Why this is not "does not error"
///
/// `run` reports success whether it stamped a thousand rows or none. Under
/// FORCE on an unprivileged connection it would stamp none and still exit 0 —
/// plan §4.3's R2: *"fail-closed regressions look like data loss, not errors."*
/// So the assertion is on the value in the row, per claim id, before and after.
///
/// # And why the non-public row is the interesting one
///
/// It is the row an application connection cannot see once RLS is FORCEd. Its
/// presence in the corpus is what makes the whole run non-vacuous: a binary
/// pointed at a filtered connection would not see it, and — the direction that
/// matters — would not see the *undeclared* rows either, so the positive
/// assertion above is what fails first. That the declared row comes through
/// byte-identical is the second half: the backfill's `WHERE owner_group_id =
/// <world>` guard is the only thing stopping it from declassifying a row
/// somebody deliberately restricted, and nothing else pins it.
///
/// # What this test CANNOT claim
///
/// The plan's differential — `verify` failing on an app DSN and passing on the
/// maintenance DSN — is not constructible on this tree. `epigraph_app` is
/// NOLOGIN, so there is no second role a fixture can connect as, and BOTH
/// `relrowsecurity` and `relforcerowsecurity` are false on every protected
/// table (RLS arrives in PR-17), so a non-bypass role would see every row
/// anyway and the differential would be zero by construction. Both flags are
/// named, not just FORCE: a policy filters every non-owner without `BYPASSRLS`,
/// so ENABLE alone would already produce the differential. `GRANT
/// epigraph_maintenance TO
/// epigraph_admin` — a PR-17 deploy-runbook item, no migration — is what
/// unblocks the real two-role form.
#[sqlx::test(migrations = "../../migrations")]
async fn the_backfill_updates_the_undeclared_row_and_leaves_a_declared_one_alone(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "author").await;
    let (other, other_group) = fixture::seed_agent_with_group(&pool, "other").await;

    let undeclared = seed_undeclared_claim(&pool, author, "undeclared").await;
    let restricted = seed_group_private_claim(&pool, other, other_group, "restricted").await;

    // Preconditions, so a later assertion cannot pass because the fixture did
    // nothing.
    assert_eq!(
        tenancy_of(&pool, undeclared).await,
        (WORLD, "public".to_string()),
        "precondition: the undeclared claim is world-owned"
    );
    assert_eq!(
        tenancy_of(&pool, restricted).await,
        (other_group, "group".to_string()),
        "precondition: the restricted claim is declared and non-public"
    );

    // verify must FAIL, and it must fail because of the undeclared row — not
    // because the restricted row confused it.
    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(code, 1, "verify before the backfill; stderr: {stderr}");

    let (code, stderr) = run_backfill(&pool, &["run"]).await;
    assert_eq!(code, 0, "run must succeed; stderr: {stderr}");

    // THE POSITIVE ASSERTION.
    assert_eq!(
        tenancy_of(&pool, undeclared).await,
        (author_group, "public".to_string()),
        "the backfill must have UPDATED the undeclared claim to its author's personal group; \
         a run that stamped nothing also exits 0"
    );

    // THE PRESERVATION ASSERTION. `visibility = 'group'` on a row owned by a
    // real group is a deliberate restriction; the backfill's world-owner guard
    // is what keeps it from being flattened to `public`.
    assert_eq!(
        tenancy_of(&pool, restricted).await,
        (other_group, "group".to_string()),
        "the backfill must not declassify or re-own an already-declared claim"
    );

    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(code, 0, "verify after the backfill; stderr: {stderr}");
}

/// The database-name guard, end to end through the shipped binary.
///
/// A maintenance DSN pointing at a *different* database is the worst available
/// misconfiguration: it does not error, it reads zero rows and writes nowhere,
/// so `verify` reports success and `run` reports success and nothing happened.
/// It is also the realistic accident — one variable exported globally while
/// `DATABASE_URL` varies per process, or a test harness leaking its own.
///
/// This is the closest this tree can get to the plan's app-DSN-vs-maintenance-DSN
/// differential, and unlike that one it is testable today: the refusal is
/// keyed on configuration, not on a role and not on whether any table carries
/// row security. Both of those are fixed on this tree — `epigraph_app` is
/// NOLOGIN and no relation in `public` has RLS at head 91 — so a role-keyed
/// differential would have zero measurable difference by construction.
#[sqlx::test(migrations = "../../migrations")]
async fn a_maintenance_dsn_naming_another_database_is_refused(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let undeclared = seed_undeclared_claim(&pool, agent, "undeclared").await;

    // `postgres` exists on every cluster and is never this test's template DB.
    let url = fixture::database_url_for(&pool).await;
    let elsewhere = url.rsplit_once('/').expect("DSN has a path").0.to_string() + "/postgres";

    let (code, stderr) = run_backfill_with_maintenance_dsn(&pool, &["run"], &elsewhere).await;
    assert_ne!(
        code, 0,
        "a maintenance DSN on another database must refuse, not silently no-op; stderr: {stderr}"
    );
    // The QUOTED form, not the bare token. `resolve_maintenance_url` formats
    // the offending database with `{maint_db:?}`, so `"postgres"` can only come
    // from the mismatch itself — whereas a bare `postgres` also matches the
    // `postgres://` scheme in any DSN echoed to stderr, which would let this
    // assertion keep passing after the message stopped naming the database.
    assert!(
        stderr.contains("\"postgres\"") && stderr.contains("MAINTENANCE_DATABASE_URL"),
        "the refusal must name the variable and the mismatched database so it is \
         actionable: {stderr}"
    );

    // And it must have refused BEFORE doing anything.
    assert_eq!(
        tenancy_of(&pool, undeclared).await,
        (WORLD, "public".to_string()),
        "a refused run must not have written"
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

// ===========================================================================
// The stale cross-group edge — the shape migration 072 makes expressible but
// does not reconcile
// ===========================================================================

/// An edge with the tenancy of the `('group', G, co_owner = NULL)` shape,
/// written WITHOUT touching `source_id` / `target_id`.
///
/// That omission is the whole point. `edges_tenancy_meet` is
/// `BEFORE INSERT OR UPDATE OF source_id, target_id`, so an UPDATE that names
/// neither column never fires arm (b) and the tuple is stored verbatim. It is
/// the only way to construct the population from a `#[sqlx::test]` database:
/// every one of those runs migrations 001→073, so 070's arm (d) body is created
/// and immediately replaced by 072's, and no test can ever run a privatization
/// against the body that produced these rows in the first place.
async fn force_edge_tenancy(pool: &PgPool, edge: Uuid, owner: Uuid, co_owner: Option<Uuid>) {
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $1, co_owner_group_id = $2 \
         WHERE id = $3",
    )
    .bind(owner)
    .bind(co_owner)
    .bind(edge)
    .execute(pool)
    .await
    .expect("force edge tenancy without touching the endpoint columns");
}

/// A `visibility = 'public'` claim owned by a REAL group.
///
/// Not `fixture::seed_public_claim`, which owns its claim by the world group —
/// that is the pre-backfill shape and `verify`'s `residual("claims")` check
/// counts it as an undeclared row, so it would fail this test for an unrelated
/// reason and destroy the clean-corpus baseline the negative controls rest on.
/// `('public', <real group>)` is what the backfill actually produces:
/// [`claims_are_stamped_with_the_authors_personal_group_never_world_or_seed`]
/// pins that.
async fn seed_public_claim_owned_by(
    pool: &PgPool,
    agent: Uuid,
    group: Uuid,
    content: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    for (i, b) in content.as_bytes().iter().enumerate() {
        hash[i % 32] ^= *b;
    }
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.8, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a public claim owned by a real group");
    id
}

async fn seed_cross_group_edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'claim', $2, 'claim', 'supports', \
                 jsonb_build_object('created_by', $3::text, 'strength', 0.7)) \
         RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(Uuid::new_v4().to_string())
    .fetch_one(pool)
    .await
    .expect("insert edge")
}

/// `verify` must FLAG an edge that joins two group-private endpoints in
/// different groups while carrying no co-owner — and must NOT flag the two
/// legitimate shapes beside it.
///
/// # Why this is a `verify` check and not a statement in migration 072
///
/// The row is reachable under migration 070 alone, with **no cross-owner
/// write**: arm (b) stamps `('group', G)` while both endpoints are in G, then
/// one endpoint moves to H and 070's arm (d) — `ELSE NULL AS g`, guarded by
/// `AND m.g IS NOT NULL` — skips it. 070's header calls that fail-closed and
/// says "072 resolves it properly with `co_owner_group_id`". 072 resolves it
/// for FUTURE transitions; it reconciles nothing already stored, and under
/// `Viewer::edge_predicate_fragment` the `co_owner_group_id IS NULL` disjunct
/// then hands the row to every member of G.
///
/// A bulk reconciliation inside 072 was rejected: 072 holds ACCESS EXCLUSIVE on
/// `edges` for its `ADD COLUMN`, `SET LOCAL lock_timeout` bounds acquisition
/// and not hold, and `edges_co_owner_shape` is enforced on new writes despite
/// shipping `NOT VALID` — so a bad CASE would raise 23514 mid-migration, record
/// no sqlx row, and re-run on every restart. Plan §6.5 puts this same meet in
/// `repos/privatization.rs::seal_boundary_edges`, a batched resumable function
/// scoped to `batch_ids`, which is PR-18's.
///
/// # The controls
///
/// The negatives are what make the positive mean something. `leaky_edges`, the
/// check that already existed, filters `e.owner_group_id = WORLD` and therefore
/// cannot see this shape at all — so a check that merely "fails on a corpus
/// with edges in it" would look identical to a correct one.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_flags_a_cross_group_edge_that_carries_no_co_owner(pool: PgPool) {
    let (agent_g, group_g) = fixture::seed_agent_with_group(&pool, "g").await;
    let (agent_h, group_h) = fixture::seed_agent_with_group(&pool, "h").await;

    let g1 = fixture::seed_group_claim(&pool, agent_g, group_g, "g one").await;
    let g2 = fixture::seed_group_claim(&pool, agent_g, group_g, "g two").await;
    let h1 = fixture::seed_group_claim(&pool, agent_h, group_h, "h one").await;
    let pub1 = seed_public_claim_owned_by(&pool, agent_g, group_g, "public one").await;

    // NEGATIVE CONTROL 1 — same-group edge, correctly single-owner.
    let same_group = seed_cross_group_edge(&pool, g1, g2).await;
    // NEGATIVE CONTROL 2 — cross-group edge stamped CORRECTLY by 072's arm (b).
    let co_owned = seed_cross_group_edge(&pool, g1, h1).await;
    // NEGATIVE CONTROL 3 — one public endpoint: the meet is single-owner and a
    // NULL co-owner is right, so a check keyed on "NULL co-owner" alone would
    // false-positive here.
    let half_public = seed_cross_group_edge(&pool, pub1, h1).await;

    // Arm (b) must have produced exactly those three shapes, or the controls
    // are not controls.
    let co: Option<Uuid> = sqlx::query_scalar("SELECT co_owner_group_id FROM edges WHERE id = $1")
        .bind(co_owned)
        .fetch_one(&pool)
        .await
        .expect("read co_owner");
    assert_eq!(
        co,
        Some(group_h),
        "precondition: 072's arm (b) stamps a genuinely cross-group edge with a co-owner"
    );
    for (edge, label) in [(same_group, "same-group"), (half_public, "half-public")] {
        let co: Option<Uuid> =
            sqlx::query_scalar("SELECT co_owner_group_id FROM edges WHERE id = $1")
                .bind(edge)
                .fetch_one(&pool)
                .await
                .expect("read co_owner");
        assert_eq!(co, None, "precondition: a {label} edge carries no co-owner");
    }

    // The corpus is otherwise clean, so `verify` passes. This is the assertion
    // that stops the positive below from being "verify fails on any corpus".
    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(
        code, 0,
        "the three legitimate edge shapes must NOT be flagged; stderr:\n{stderr}"
    );

    // POSITIVE — the pre-072 population, forced into place without firing
    // arm (b): owner = G, co_owner = NULL, target still private to H.
    force_edge_tenancy(&pool, co_owned, group_g, None).await;

    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(
        code, 1,
        "a cross-group edge with no co-owner is visible to all of G while naming \
         H's private claim; verify is the deploy gate that must catch it. \
         stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("co_owner_group_id"),
        "the failure must NAME the shape so an operator can act on it; stderr:\n{stderr}"
    );

    // And the remediation the failure message prints must actually work.
    // PostgreSQL fires `UPDATE OF source_id` on column MENTION, not on value
    // change, so this no-op re-runs arm (b) and it re-derives the meet.
    sqlx::query("UPDATE edges SET source_id = source_id WHERE co_owner_group_id IS NULL")
        .execute(&pool)
        .await
        .expect("re-fire arm (b)");

    let co: Option<Uuid> = sqlx::query_scalar("SELECT co_owner_group_id FROM edges WHERE id = $1")
        .bind(co_owned)
        .fetch_one(&pool)
        .await
        .expect("read co_owner");
    assert_eq!(
        co,
        Some(group_h),
        "the documented remediation must restore the co-owner — if this fails, the \
         FAIL message in tenancy_backfill.rs::verify is telling operators to run \
         something that does not work"
    );

    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(
        code, 0,
        "and verify must clear once the meet is restamped; stderr:\n{stderr}"
    );
}
