//! `epigraph-tenancy-backfill` — the one-shot, batched, resumable backfill that
//! gives every pre-existing row an explicit tenancy declaration, plus the
//! `verify` subcommand whose exit code is the deploy pre-flight.
//!
//! # What it stamps, and why not `world` or `seed`
//!
//! Plan D2: *"the backfill sets explicit `public` for every pre-existing row,
//! `owner_group_id` = the author's personal group"*. Those rows were already
//! world-readable, so declaring `public` is a no-op rather than a new
//! disclosure — but a public row still has an OWNER, and `world` is a shape
//! constant, not an owner (§2.3).
//!
//! **This is not the seed group.** PR-12's scope recon says "stamp the SEED
//! group, not `world`"; that is wrong for this binary, and wrong in the
//! dangerous direction. Seed is migration **074 arm 4**'s `epigraph_seed`-ROLE
//! escape hatch, which exists so ~160 test-fixture `INSERT`s need not be
//! rewritten — and 074 is PR-16, not PR-12. Migration `062_tenancy_columns.sql`
//! says so in its own words: *"Migration 074 arm 4 stamps THIS"*. Stamping seed
//! here would still satisfy acceptance A4 literally (seed ≠ world), so no
//! acceptance query in the plan would catch it — and every claim would end up
//! owned by a group with **zero `group_memberships` rows by design**, i.e.
//! unreadable by its own author once PR-17 turns the predicate on.
//!
//! # The ordering decision this binary depends on
//!
//! **Migration 070 is applied BEFORE this runs.** The consequence is the whole
//! design: 070 arm (d) `claims_propagate_tenancy` is an `AFTER UPDATE ... FOR
//! EACH STATEMENT` trigger on `claims`, and this binary's own
//! `UPDATE claims SET owner_group_id = …` **is** that event. The 17 derived
//! tables, `harvester_fragments` and `edges` are therefore stamped by the
//! trigger, inside the same transaction, and this binary owes them no arm of
//! its own — only a residual check that the trigger did its job.
//!
//! Had the backfill run first, it would have owed its own propagation walk, and
//! PR-12's "each of the eight §2.4 tables inherits correctly" test would have
//! been testing the backfill rather than the trigger it is meant to pin.
//!
//! # Resumability
//!
//! `tenancy_backfill_progress` (migration 062, already seeded with one row per
//! tier-A entity) is keyed on `entity` with a `last_id` cursor. The cursor is
//! advanced **in the same transaction as the batch it describes**, not once per
//! entity — otherwise a `kill -9` mid-entity replays rows that were already
//! stamped. Replay is harmless for the stamping itself (every UPDATE is guarded
//! by `owner_group_id = <world>`), but re-firing arm (d) over already-propagated
//! rows is wasted work the cursor exists to avoid.
//!
//! `FOR UPDATE SKIP LOCKED` on the batch selection, per the acceptance line.
//!
//! **THIS BINARY IS SINGLE-OPERATOR. `SKIP LOCKED` DOES NOT MAKE IT
//! CONCURRENT.** An earlier revision of this comment claimed "two operators
//! running this concurrently divide the work instead of blocking". They do not:
//! both processes read and write the SAME `tenancy_backfill_progress.last_id`,
//! and the cursor advances to the last id RETURNED, so rows skipped because a
//! peer held their locks are stepped over and — the cursor being forward-only —
//! never revisited. `SKIP LOCKED` is here for the reason it is actually good
//! for: a batch does not block behind an unrelated application transaction
//! holding a row lock. Run one operator.
//!
//! The residual is what makes even that safe: `backfill_claims` re-measures
//! after its walk and RESETS `last_id` to NULL if anything is left, so a re-run
//! genuinely retries rather than looking complete.
//!
//! # Legacy `ownership` rows — retired in PR-22
//!
//! This binary used to carry a `transcribe_legacy_ownership` pass and two
//! `verify` checks over the `ownership` table. Migration 084 retires that table,
//! and its second pre-flight now holds the gate those checks held: it refuses to
//! drop the table while any non-public row lacks a `tenancy_transcription_log`
//! entry. See the comment where the pass used to live for why that ordering is
//! what makes the retirement safe.
//!
//! # `verify` keys on LIVE COUNTS, not on the `complete` boolean
//!
//! Migration 062 demotes that flag explicitly: *"DEMOTED TO OBSERVABILITY:
//! migration 075's guard is LIVE COUNTS, not this table's boolean, because a
//! boolean `complete` flag is hand-flippable by an on-call trying to unblock a
//! deploy at 2 a.m."* `verify` therefore recomputes, prints offending ids, and
//! exits non-zero on any residual. The boolean is reported, never trusted.
//!
//! Runtime `sqlx::query` / `query_scalar` throughout — never the compile-time
//! macros — so no `.sqlx/` cache entry is needed and `SQLX_OFFLINE=true` builds.
//!
//! Usage:
//!     epigraph-tenancy-backfill run [--batch-size 5000] [--dry-run]
//!     epigraph-tenancy-backfill verify

use clap::{Parser, Subcommand};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// The role migrations 070/071 re-own their `SECURITY DEFINER` bodies to, and
/// the role `epigraph_definer_bypass()` (migration 067) tests membership of.
const MAINTENANCE_ROLE: &str = "epigraph_maintenance";

/// The world group: a SHAPE CONSTANT, never an owner (plan §2.3).
const WORLD: Uuid = Uuid::nil();

/// Resolve an agent's personal group, as a correlated scalar subquery over an
/// `{agent}` expression the caller substitutes.
///
/// **Two ways to identify a personal group, and both are needed.** The
/// canonical one is `AgentRepository::ensure_personal_group`'s deterministic
/// `did:epigraph:personal:<agent uuid>` key. But that is a convention; the
/// semantics are `kind = 'personal'` created by this agent, and there are
/// personal groups in this tree that do not carry the canonical key — every
/// copy of `tests/viewer_fixture.rs::seed_agent_with_group` mints one as
/// `did:epigraph:test:<label>:<agent>`. Matching only the did_key would leave
/// those claims unstamped and `verify` failing against a group that plainly
/// exists.
///
/// `ORDER BY` puts the canonical key first so a database carrying both
/// resolves deterministically. Kept as one constant so migration 071's shim and
/// this binary cannot drift apart on the definition.
fn personal_group_sql(agent_expr: &str) -> String {
    format!(
        "(SELECT g.id FROM groups g
           WHERE (g.did_key = 'did:epigraph:personal:' || {agent_expr}::text)
              OR (g.kind = 'personal' AND g.created_by_agent_id = {agent_expr})
           ORDER BY (g.did_key = 'did:epigraph:personal:' || {agent_expr}::text) DESC,
                    g.created_at ASC
           LIMIT 1)"
    )
}

/// The 25 tier-A entities, exactly as `migrations/062_tenancy_columns.sql`
/// seeds them into `tenancy_backfill_progress`.
///
/// **25, not 24.** `docs/tenancy/HANDOFF.md` §4 M4 says "row counts across the
/// 24 tier-A tables"; 062's array and the seeded table both say 25 (verified:
/// `SELECT count(*) FROM tenancy_backfill_progress` = 25). An implementation
/// built against 24 leaves one entity permanently `complete = false` and
/// `verify` fails forever.
const TIER_A: &[&str] = &[
    "claims",
    "evidence",
    "edges",
    "triples",
    "entity_mentions",
    "claim_versions",
    "mass_functions",
    "ds_combined_beliefs",
    "ds_bayesian_divergence",
    "claim_frames",
    "harvester_claim_provenance",
    "challenges",
    "reasoning_traces",
    "experiment_triples",
    "experiment_entity_mentions",
    "claim_clusters",
    "claim_cluster_membership",
    "claim_neighborhood_membership",
    "claim_signature_revocations",
    "harvester_fragments",
    "frames",
    "contexts",
    "perspectives",
    "communities",
    "recall_events",
];

/// The 17 tables 070 arm (c)/(d) stamp from their parent claim. This binary
/// never writes them directly; it only checks the residual.
const CLAIM_DERIVED: &[&str] = &[
    "evidence",
    "triples",
    "entity_mentions",
    "claim_versions",
    "mass_functions",
    "ds_combined_beliefs",
    "ds_bayesian_divergence",
    "claim_frames",
    "harvester_claim_provenance",
    "challenges",
    "reasoning_traces",
    "experiment_triples",
    "experiment_entity_mentions",
    "claim_clusters",
    "claim_cluster_membership",
    "claim_neighborhood_membership",
    "claim_signature_revocations",
];

#[derive(Parser, Debug)]
#[command(
    name = "epigraph-tenancy-backfill",
    about = "Batched, resumable tenancy backfill (PR-12). Never run against production without a snapshot."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Stamp every pre-existing row with an explicit tenancy declaration.
    Run {
        /// Rows per batch. The acceptance line specifies 5–10k.
        #[arg(long, default_value_t = 5000)]
        batch_size: i64,
        /// Report what would be stamped without writing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Deploy pre-flight. Exits non-zero if any entity is incomplete.
    Verify,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    // THE VERIFIER MUST NOT BE ABLE TO PASS VACUOUSLY.
    //
    // Before PR-15 this binary read `DATABASE_URL` and handed it straight to
    // `PgPoolOptions`, bypassing the pool abstraction entirely — no
    // `ScopedPool`, no lease, no `Viewer`. That is tolerable for `run`, which
    // fails loudly if it cannot write. It is not tolerable for `verify`, whose
    // whole contract is a non-zero exit: `verify` counts rows that are *not*
    // yet declared, so on a connection that cannot see undeclared rows the
    // count is zero and it reports success. PR-16's acceptance consumes that
    // exit code as a deploy pre-flight, so a vacuously-green verifier turns
    // that gate into decoration.
    //
    // A `MaintenancePool` is therefore mandatory here rather than merely
    // preferable, and the constructor refuses outright if the connection is
    // unprivileged while any protected table carries row security — the one
    // condition under which the silent-zero could occur.
    //
    // SIZING CHANGED, and the old note claiming otherwise is gone. This bin
    // used to build its own pool with `max_connections(4)`, reasoned as "a
    // single-threaded batch walker, and a large pool against a live cluster is
    // a way to starve the application". `MaintenancePool` is one shared
    // constructor at 11 (10 for work, 1 for the held lease — see its comment),
    // so the cap here rose 4 -> 11. That is acceptable and not merely tolerated:
    // sqlx opens connections lazily, and a single-threaded walker holding one
    // lease and running one statement at a time never opens more than two, so
    // the cap is a ceiling this bin does not approach rather than a workload
    // increase. The trade is one sizing rule across the whole fleet instead of
    // twelve, which is the same reason the DSN rule is centralised.
    let maint = epigraph_cli::MaintenancePool::connect("epigraph-tenancy-backfill")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let pool = maint.pool().clone();

    match cli.command {
        Command::Run {
            batch_size,
            dry_run,
        } => {
            run(&pool, batch_size, dry_run).await?;
            Ok(())
        }
        Command::Verify => {
            let failures = verify(&pool).await?;
            if failures == 0 {
                println!("verify: OK — every tier-A entity is fully declared.");
                Ok(())
            } else {
                // NON-ZERO EXIT IS THE ENTIRE CONTRACT. `migrations/070`'s
                // header names this exit code as the guard (the plan calls that
                // file 066; README.md pins it at 070), and PR-16's acceptance
                // runs it before its own migration.
                eprintln!(
                    "verify: FAILED — {failures} entity/entities still carry undeclared rows."
                );
                std::process::exit(1);
            }
        }
    }
}

// =============================================================================
// run
// =============================================================================

async fn run(pool: &PgPool, batch_size: i64, dry_run: bool) -> anyhow::Result<()> {
    if batch_size <= 0 {
        anyhow::bail!("--batch-size must be positive");
    }
    preflight(pool).await?;

    // PHASE 0 is not in the plan's *Files* line and is the single largest piece
    // of unlisted work in PR-12. D2 derives every claim's owner from
    // `claims.agent_id`, but a personal group is only ever created by
    // `AgentRepository::ensure_personal_group`, called from the OAuth mint path
    // and the MCP server's agent resolution. Migration 057 documents ~1,198
    // one-shot orphan agents that have never authenticated and therefore have
    // NO personal group. Without this phase the claims arm cannot resolve an
    // owner for their claims and the backfill stalls on batch 1.
    materialize_personal_groups(pool, dry_run).await?;

    if dry_run {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE owner_group_id = $1")
            .bind(WORLD)
            .fetch_one(pool)
            .await?;
        println!("dry-run: {n} claims would be stamped; no writes performed.");
        return Ok(());
    }

    backfill_claims(pool, batch_size).await?;
    backfill_communities(pool).await?;
    backfill_agent_keyed(pool, "perspectives", "owner_agent_id").await?;
    backfill_agent_keyed(pool, "recall_events", "agent_id").await?;
    backfill_harvester_fragments(pool).await?;

    // The remaining entities are either trigger-propagated (the 17 claim-derived
    // tables and `edges`) or have nothing to derive from (`frames`, `contexts`).
    // Both are settled by measuring the residual, never by asserting.
    settle_remaining(pool).await?;

    let failures = verify(pool).await?;
    if failures == 0 {
        println!("run: complete — every tier-A entity is fully declared.");
    } else {
        eprintln!("run: finished with {failures} entity/entities still incomplete; see `verify`.");
        std::process::exit(1);
    }
    Ok(())
}

/// Refuse to run against a database that has not had migration 070 applied.
///
/// Fail CLOSED. If arm (d) is absent, the backfill's `UPDATE claims` stamps the
/// root and propagates to NOTHING — leaving 17 derived tables world-owned while
/// `tenancy_backfill_progress` cheerfully reports the claims entity complete.
/// That is a silent half-backfill, and the only cheap moment to catch it is
/// before the first batch.
async fn preflight(pool: &PgPool) -> anyhow::Result<()> {
    let armed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_trigger
                         WHERE tgname = 'claims_propagate_tenancy'
                           AND tgrelid = 'public.claims'::regclass
                           AND NOT tgisinternal
                           AND tgenabled = 'O')",
    )
    .fetch_one(pool)
    .await?;
    if !armed {
        anyhow::bail!(
            "migration 070's claims_propagate_tenancy trigger is absent or disabled. \
             Apply 070 BEFORE running the backfill: this binary relies on it to \
             propagate to the 17 claim-derived tables, harvester_fragments and edges. \
             Running without it produces a silent half-backfill."
        );
    }
    Ok(())
}

/// Give every author of a claim a personal group, idempotently.
///
/// Deliberately mirrors `AgentRepository::ensure_personal_group` rather than
/// calling it: that function takes a `&mut PgConnection` and this walk is a set
/// operation over ~1,198 rows. The `did_key` shape
/// (`did:epigraph:personal:<agent uuid>`) is the contract between the two, and
/// it is what migration 071's shim looks the group up by — so a drift here is a
/// drift there. Both statements are the same `ON CONFLICT` targets the repo
/// function uses, and for the same reasons: `groups_did_key_key` for the group,
/// and the composite `(group_id, agent_id, epoch)` for the membership, which
/// REVIVES a revoked row rather than silently no-opping.
async fn materialize_personal_groups(pool: &PgPool, dry_run: bool) -> anyhow::Result<()> {
    // The early-return gate covers BOTH statements below, so it must measure
    // both: an author with no personal group AND an author whose membership in
    // its own personal group is missing or revoked. Keying it on the group
    // alone made the membership repair conditional on unrelated state.
    let needing_repair: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM (
            SELECT DISTINCT c.agent_id FROM claims c
             WHERE {pg} IS NULL
                OR NOT EXISTS (SELECT 1 FROM group_memberships m
                                WHERE m.group_id = {pg}
                                  AND m.agent_id = c.agent_id
                                  AND m.revoked_at IS NULL)
         ) q",
        pg = personal_group_sql("c.agent_id")
    ))
    .fetch_one(pool)
    .await?;

    if needing_repair == 0 {
        tracing::info!(
            "personal groups: every claim author already has one, with a live membership"
        );
        return Ok(());
    }
    if dry_run {
        println!(
            "dry-run: {needing_repair} claim author(s) need a personal group or a live membership in it."
        );
        return Ok(());
    }

    let mut tx = pool.begin().await?;
    // The join to `agents` is not decoration: groups.created_by_agent_id is an
    // FK, and claims.agent_id has no FK to agents in this schema, so a claim
    // authored by a since-deleted agent would otherwise fail the insert.
    //
    // Only for agents that have NO personal group under either identification —
    // an agent whose group carries a non-canonical did_key (the test fixtures)
    // must not be given a second one.
    sqlx::query(&format!(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id)
         SELECT DISTINCT 'personal:' || a.id::text,
                'did:epigraph:personal:' || a.id::text,
                ''::bytea, 'personal', a.id
           FROM claims c JOIN agents a ON a.id = c.agent_id
          WHERE {} IS NULL
         ON CONFLICT (did_key) DO UPDATE SET updated_at = now()",
        personal_group_sql("a.id")
    ))
    .execute(&mut *tx)
    .await?;

    // ==================================================================
    // SCOPED TO AGENTS WITH NO LIVE MEMBERSHIP — NOT TO EVERY CLAIM AUTHOR.
    //
    // An earlier revision selected every agent that has ever authored a claim
    // and `DO UPDATE SET revoked_at = NULL, role = 'admin'`. That is a
    // privilege-RESTORING side effect over the whole agent population: a
    // deliberately revoked or deliberately demoted personal-group membership
    // was silently returned to live admin by a run of the backfill, and whether
    // it happened at all depended on the `missing == 0` early return above —
    // i.e. on whether some entirely unrelated agent lacked a group.
    //
    // The `NOT EXISTS` below narrows it to the set this phase is actually for:
    // an agent with NO live membership in its own personal group. Reviving THAT
    // is `ensure_personal_group`'s documented semantics and the reason its own
    // ON CONFLICT targets the composite — an untargeted DO NOTHING no-ops
    // against a revoked row and leaves the agent locked out of its own group
    // permanently. `role` is no longer written on conflict, so an existing
    // deliberate demotion survives.
    // ==================================================================
    sqlx::query(&format!(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
         SELECT {pg}, a.id, ''::bytea, 0, 'admin'
           FROM agents a
          WHERE EXISTS (SELECT 1 FROM claims c WHERE c.agent_id = a.id)
            AND {pg} IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM group_memberships m
                             WHERE m.group_id = {pg}
                               AND m.agent_id = a.id
                               AND m.revoked_at IS NULL)
         ON CONFLICT (group_id, agent_id, epoch)
         DO UPDATE SET revoked_at = NULL",
        pg = personal_group_sql("a.id")
    ))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    // `missing` is what was MEASURED, not what was written — log both, because
    // an earlier revision printed "personal groups materialized" on a run whose
    // two statements both affected zero rows.
    tracing::info!(
        authors_needing_repair = needing_repair,
        "personal groups materialized"
    );
    Ok(())
}

/// The root arm: `claims` → `('public', personal_group(agent_id))`.
///
/// Each batch is one transaction containing the row selection, the UPDATE
/// (which fires arm (d) and propagates to 18 more tables), and the cursor
/// advance. That grouping is what makes `kill -9` safe.
async fn backfill_claims(pool: &PgPool, batch_size: i64) -> anyhow::Result<()> {
    let mut cursor: Option<Uuid> = current_cursor(pool, "claims").await?;
    // SEEDED FROM THE PERSISTED COUNT, not from zero. `rows_done` is meant to
    // describe the BACKFILL, and re-initialising it on every process start made
    // a resume after `kill -9` overwrite the accumulated total with a smaller
    // number describing only the last run.
    let mut total: i64 = persisted_rows_done(pool, "claims").await?;

    loop {
        let mut tx = pool.begin().await?;

        // FOR UPDATE SKIP LOCKED per the acceptance line. The `id >` cursor and
        // the ORDER BY make the walk total; SKIP LOCKED makes a second operator
        // divide the work rather than block on it.
        let rows = sqlx::query(
            "SELECT c.id, c.agent_id FROM claims c
              WHERE c.owner_group_id = $1
                AND ($2::uuid IS NULL OR c.id > $2)
              ORDER BY c.id
              LIMIT $3
              FOR UPDATE SKIP LOCKED",
        )
        .bind(WORLD)
        .bind(cursor)
        .bind(batch_size)
        .fetch_all(&mut *tx)
        .await?;

        if rows.is_empty() {
            tx.rollback().await?;
            break;
        }

        let ids: Vec<Uuid> = rows.iter().map(|r| r.get::<Uuid, _>("id")).collect();
        let last = *ids.last().expect("non-empty batch");

        // Resolve the owner IN SQL, in the same statement as the write, so
        // there is no window in which the binary holds a mapping the database
        // disagrees with. A claim whose author has no personal group is LEFT
        // ALONE rather than stamped to world or seed — `verify` will then fail
        // and name it, which is the fail-closed outcome. Phase 0 makes this
        // set empty in the normal case.
        let n = sqlx::query(&format!(
            "UPDATE claims c
                SET owner_group_id = {}, visibility = 'public'
              WHERE c.id = ANY($1)
                AND c.owner_group_id = $2
                AND {} IS NOT NULL",
            personal_group_sql("c.agent_id"),
            personal_group_sql("c.agent_id")
        ))
        .bind(&ids)
        .bind(WORLD)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        total += n as i64;
        advance_cursor(&mut tx, "claims", Some(last), total).await?;
        tx.commit().await?;

        tracing::info!(batch = ids.len(), stamped = n, total, "claims batch");
        cursor = Some(last);
    }

    // ==================================================================
    // THE CURSOR IS RESET WHEN THE WALK LEFT WORK BEHIND. THIS IS NOT
    // BOOKKEEPING — WITHOUT IT A RE-RUN IS A SILENT NO-OP.
    //
    // The batch UPDATE above is guarded by `personal_group(agent_id) IS NOT
    // NULL`, so a claim whose author cannot be resolved is SKIPPED — while the
    // cursor advances to the last id SELECTED. `claims.agent_id` has no foreign
    // key to `agents` in this schema (see `materialize_personal_groups`, and
    // plan §9.1, which records that `routes/claims.rs` trusts a caller-supplied
    // `request.agent_id`), so dangling authors are EXPECTED in production and
    // phase 0 — which joins `agents` — cannot mint groups for them.
    //
    // Left alone, the second `run` would find nothing `> last_id`, break on
    // batch 1, and exit 1 again, with the acceptance line's "resumable" and
    // "every entity reaches complete" unreachable and no documented remedy.
    // Resetting `last_id` to NULL makes a re-run genuinely retry — which still
    // will not stamp an unresolvable author, but now fails LOUDLY and in the
    // same place every time rather than looking like a completed walk.
    //
    // Note this also corrects `verify`'s old comment "A4: the derivation is
    // total, because claims.agent_id is NOT NULL". NOT NULL does not imply
    // RESOLVABLE without a foreign key, and that is exactly the hole.
    // ==================================================================
    let left_behind = residual(pool, "claims").await?;
    if left_behind > 0 {
        reset_cursor(pool, "claims").await?;
        tracing::warn!(
            residual = left_behind,
            "claims walk finished with world-owned rows remaining (unresolvable author?); \
             last_id has been reset to NULL so a re-run retries from the start. \
             See docs/tenancy.md 'When the backfill leaves rows behind'."
        );
    }

    finish_entity(pool, "claims", total).await?;
    Ok(())
}

/// `communities` → `('public', communities.id)`.
///
/// Migration 068 projects each community onto a group **ID-preservingly**
/// ("Project each community into a group, ID-PRESERVING so no mapping table is
/// needed"), so the community's own id IS its group id. The join to `groups`
/// is a guard, not a lookup: a community created after 068 ran has no projected
/// group yet, and stamping a nonexistent group would trip the FK. Those are
/// left for `verify` to name.
async fn backfill_communities(pool: &PgPool) -> anyhow::Result<()> {
    let n = sqlx::query(
        "UPDATE communities c SET owner_group_id = g.id, visibility = 'public'
           FROM groups g
          WHERE g.id = c.id AND g.kind = 'community'
            AND c.owner_group_id = $1",
    )
    .bind(WORLD)
    .execute(pool)
    .await?
    .rows_affected();
    finish_entity(pool, "communities", n as i64).await?;
    Ok(())
}

/// `perspectives` / `recall_events` → the personal group of their agent column.
///
/// **These are two of the five entities the plan assigns no derivation at all**
/// (the others are `frames`, `contexts`, `communities`). Both agent columns are
/// NULLABLE — `perspectives.owner_agent_id` is the hole 068's projection
/// comment already documents, and `recall_events.agent_id` is annotated by 062
/// as "keyed on the QUERYING agent, not on a claim". A NULL row therefore has
/// no derivable owner and is left `('public', world)`: see `settle_remaining`
/// for why that is legal.
async fn backfill_agent_keyed(pool: &PgPool, table: &str, agent_col: &str) -> anyhow::Result<()> {
    // `table` and `agent_col` are compile-time constants from this file, never
    // caller input, so the format! is not an injection surface.
    let resolver = personal_group_sql(&format!("t.{agent_col}"));
    let sql = format!(
        "UPDATE {table} t SET owner_group_id = {resolver}, visibility = 'public'
          WHERE t.{agent_col} IS NOT NULL
            AND t.owner_group_id = $1
            AND {resolver} IS NOT NULL"
    );
    let n = sqlx::query(&sql)
        .bind(WORLD)
        .execute(pool)
        .await?
        .rows_affected();
    finish_entity(pool, table, n as i64).await?;
    Ok(())
}

/// `harvester_fragments` → its claim's tenancy, via the provenance join.
///
/// This arm exists because arm (c) CANNOT cover this table (it has no
/// `claim_id`) and arm (d) only fires on a claims *UPDATE*. A fragment inserted
/// **before** its `harvester_claim_provenance` row was therefore stamped by no
/// trigger at all — an insert-order hole the plan does not mention.
///
/// # Migration 089 closed the forward half; this pass is for the backlog
///
/// Since migration 089 a fragment written in that order IS stamped, at the
/// moment the `harvester_claim_provenance` row linking it to its claim is
/// inserted (`harvester_claim_provenance_fragment_inherit_tenancy`). So the
/// residual this pass exists for is rows that were already on disk when 089
/// applied, not new writes.
///
/// # ⚠ The two predicates are NOT the same, and the difference is measured
///
/// This one binds `f.owner_group_id = $1` with [`WORLD`] alone; 089's target side
/// matches BOTH sentinels, `(world, seed)`. 089 names the seed sentinel because
/// migration 074 made this table a parentless root whose seed arm COALESCEs an
/// undeclared insert to `('public', <seed group>)` on a session that is a member
/// of `epigraph_seed`. A seed-owned fragment already on disk is therefore
/// reachable by NEITHER instrument: 089 fires only on a new provenance insert,
/// and this predicate skips it. [`residual`] has the same world-only binding, so
/// `verify` does not count those rows either. No code change here: widening this
/// predicate changes what the backfill does to existing rows, which is outside
/// this batch. Recorded as finding `F-089-D` in `docs/tenancy/progress.json`.
async fn backfill_harvester_fragments(pool: &PgPool) -> anyhow::Result<()> {
    let n = sqlx::query(
        "UPDATE harvester_fragments f
            SET owner_group_id = c.owner_group_id, visibility = c.visibility
           FROM harvester_claim_provenance p
           JOIN claims c ON c.id = p.claim_id
          WHERE f.id = p.fragment_id
            AND f.owner_group_id = $1
            AND c.owner_group_id <> $1",
    )
    .bind(WORLD)
    .execute(pool)
    .await?
    .rows_affected();
    finish_entity(pool, "harvester_fragments", n as i64).await?;
    Ok(())
}

// `transcribe_legacy_ownership` lived here until PR-22.
//
// It re-fired migration 071's `ownership_transcribe` trigger over every
// `ownership` row that predated the trigger, by writing `owner_id` back to
// itself, and it was what made `verify`'s two `ownership` checks clearable at
// all. Migration 084 retires the table, so the pass has nothing left to walk.
//
// THE ORDER MATTERS AND IT IS NOT INCIDENTAL. Retiring the transcription pass is
// only safe because transcription is complete, and 084's second pre-flight is
// what proves it: the migration refuses to drop the table while any non-public
// row lacks a `tenancy_transcription_log` entry. The gate moved from a binary an
// operator has to remember to run into the migration that does the destructive
// thing; it was not removed. `docs/deploy.md` records the same sequence from the
// operator's side.

/// Settle the entities this binary does not stamp directly.
///
/// Two groups, and they are legal for different reasons:
///
/// * **The 17 claim-derived tables and `edges`** are stamped by 070 arms (c)
///   and (d). Their residual should already be zero; this records the measured
///   count rather than asserting it.
/// * **`frames` and `contexts` carry no owner column of any kind** — verified
///   against `information_schema`: `frames` has `parent_frame_id`, `contexts`
///   has none. There is nothing to derive an owner from, so they stay
///   `('public', world)`.
///
/// That is legal, and the constraint that says so is narrow enough to be worth
/// naming: the "deferred strong CHECK `owner_group_id <> world`" is scoped to
/// **`claims`** (plan Q5: *"The unconditional CHECK (owner_group_id <> world)
/// on `claims`"*), and acceptance A4 counts `claims` only. 062's
/// `<table>_group_needs_real_group` forbids only `('group', world)` — a
/// world-owned row that is `visibility = 'public'` is explicitly permitted, and
/// that is exactly what these rows are. It also matches 070 arm (b), which
/// stamps `('public', world)` for an edge between two public endpoints.
async fn settle_remaining(pool: &PgPool) -> anyhow::Result<()> {
    for t in CLAIM_DERIVED
        .iter()
        .chain(["edges", "frames", "contexts"].iter())
    {
        let n = residual(pool, t).await?;
        // `rows_done` means ROWS DECLARED, not table size. An earlier revision
        // stored `count(*)`, so an operator reading this table to judge
        // progress saw the table's size on all 20 of these entities.
        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {t}"))
            .fetch_one(pool)
            .await?;
        let done = total - n;
        if n > 0 && *t != "frames" && *t != "contexts" && *t != "edges" {
            tracing::warn!(
                table = t,
                residual = n,
                "claim-derived table still has world-owned rows after propagation"
            );
        }
        finish_entity(pool, t, done).await?;
    }
    Ok(())
}

// =============================================================================
// progress bookkeeping
// =============================================================================

async fn current_cursor(pool: &PgPool, entity: &str) -> anyhow::Result<Option<Uuid>> {
    Ok(
        sqlx::query_scalar("SELECT last_id FROM tenancy_backfill_progress WHERE entity = $1")
            .bind(entity)
            .fetch_optional(pool)
            .await?
            .flatten(),
    )
}

/// The `rows_done` already recorded for an entity, so a resumed walk continues
/// the count instead of restarting it.
async fn persisted_rows_done(pool: &PgPool, entity: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT rows_done FROM tenancy_backfill_progress WHERE entity = $1",
    )
    .bind(entity)
    .fetch_optional(pool)
    .await?
    .unwrap_or(0))
}

/// Rewind an entity's cursor so the next `run` re-walks it from the start.
async fn reset_cursor(pool: &PgPool, entity: &str) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE tenancy_backfill_progress SET last_id = NULL, updated_at = now()
          WHERE entity = $1",
    )
    .bind(entity)
    .execute(pool)
    .await?;
    Ok(())
}

/// Advance the cursor **inside the caller's transaction**. Taking `&mut
/// Transaction` rather than `&PgPool` is the whole point: a cursor committed
/// separately from its batch is a cursor that can describe work that did not
/// happen.
async fn advance_cursor(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entity: &str,
    last_id: Option<Uuid>,
    rows_done: i64,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE tenancy_backfill_progress
            SET last_id = $2, rows_done = $3, updated_at = now()
          WHERE entity = $1",
    )
    .bind(entity)
    .bind(last_id)
    .bind(rows_done)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Mark an entity complete. The flag is OBSERVABILITY ONLY — `verify` never
/// reads it (062: "a boolean `complete` flag is hand-flippable by an on-call
/// trying to unblock a deploy at 2 a.m.").
///
/// Deliberately an UPDATE, never an upsert: `tenancy_migration_shape.rs` asserts
/// this table has EXACTLY `TIER_A.len()` rows, one per tier-A table. Inserting a
/// row here would fail that test.
async fn finish_entity(pool: &PgPool, entity: &str, rows_done: i64) -> anyhow::Result<()> {
    let n = sqlx::query(
        "UPDATE tenancy_backfill_progress
            SET rows_done = $2, complete = true, updated_at = now()
          WHERE entity = $1",
    )
    .bind(entity)
    .bind(rows_done)
    .execute(pool)
    .await?
    .rows_affected();
    if n == 0 {
        anyhow::bail!(
            "tenancy_backfill_progress has no row for entity '{entity}'. Migration 062 \
             seeds one per tier-A table; this binary must not create one."
        );
    }
    Ok(())
}

// =============================================================================
// verify
// =============================================================================

/// The five `SECURITY DEFINER` bodies migration 070 installs, whose owner must
/// satisfy `epigraph_definer_bypass()`.
///
/// It was six until PR-22: 071's `epigraph_ownership_transcribe` is dropped by
/// migration 084 with the table it wrote through.
///
/// Migration 086's read helper is subject to the same check but lives in
/// [`DEFERRED_DEFINER_FUNCTIONS`]; [`applicable_definer_functions`] joins the
/// two. The rest of this comment explains why it is checked here at all, and
/// why it is not checked unconditionally.
///
/// # Why 086's function is checked by THIS gate and not by a new one (PR-24)
///
/// `epigraph_claim_tenancy_by_ids` is what `epigraph-db`'s
/// `ClaimRepository::hidden_claim_ids` **and `EventRepository::list` (both
/// arms)** read `claims` through — the stake is TWO repo functions, not one,
/// and the wider set is what an operator needs when deciding how load-bearing a
/// skipped or failing entry is. Between them they back five read surfaces: the
/// in-process half of `GET /api/v1/events` and the webhook fan-out (both
/// through `hidden_claim_ids`), and the persisted half of `GET /api/v1/events`,
/// `GET /api/v1/graph/snapshot/:version` and all of MCP `list_events` (through
/// `EventRepository::list`). Only the first two have a Rust-side backstop; the
/// other three are filtered in SQL by this function alone — and that filter
/// classifies `claims` rows only, so a payload naming a row in another tenanted
/// table is not classified at all
/// (`F-PR25-event-suppression-is-claims-keyed-only`). Read the three as a
/// statement about AUTHORITY, not COVERAGE. It reaches `claims` only because
/// `claims_tenancy`'s
/// `OR (SELECT public.epigraph_definer_bypass())` disjunct admits a frame whose
/// `current_user` is a member of `epigraph_maintenance`. If the guarded
/// `ALTER FUNCTION ... OWNER TO` in 086 silently no-ops — which is exactly what
/// 060's `RAISE NOTICE`-only role creation makes possible — the function returns
/// FEWER rows with no error, and the suppression control it backs degrades to
/// reporting nothing hidden. That is the same silent failure mode this check
/// exists for, on a READ path rather than a write one, so it takes the same
/// instrument rather than a second one.
///
/// The predicate is unchanged and is inherited deliberately:
/// `pg_has_role(owner, 'epigraph_maintenance', 'MEMBER')`, not string equality —
/// see the comment inside [`verify_definer_ownership`]. This entry therefore
/// also passes on a superuser-owned body, which is correct, because such a body
/// satisfies `epigraph_definer_bypass()` too.
///
/// It is NOT added to `tenancy_triggers.rs::propagation_function_is_owned_by_the_maintenance_role`
/// or to `schema_contract.rs::the_five_session_functions_exist`: the first is
/// scoped to the tenancy STAMPING TRIGGER BODIES and the second to 067's five
/// session functions, and widening either past its own scope would make its doc
/// comment false.
///
/// The first scope is "070's five plus migration 089's
/// `epigraph_inherit_fragment_tenancy_stmt`" — it was 070's five alone until
/// 089, and the sentence above is restated here rather than left as written
/// because 089 moved it. `epigraph_claim_tenancy_by_ids` still does not belong
/// there: it is a READ helper backing a suppression control, not a body any
/// trigger fires, so it would widen that test from "trigger bodies" to
/// "definer bodies" and leave it asserting a different claim than its name and
/// its own comment make.
///
/// # ⚠ WHY THE 086 ENTRY IS DEFERRED AND THE OTHER SIX ARE NOT
///
/// `verify`'s exit code is the plan's **week-11c** pre-flight, and §9.2 runs it
/// *before* applying 070/071/072 — 077/078/079 come at 11d and 086 later still.
/// So at the moment this binary is meant to run, a legitimately-sequenced
/// database has **not** applied 086, and an unconditional entry would report
/// `does not exist` and block a working deploy. That is exactly the failure this
/// check's own predicate comment refuses to commit for the string-equality case,
/// and it would be worse here, because the documented remedy would be "apply a
/// migration you are not supposed to have applied yet".
///
/// So the 086 entry is skipped **only while the FUNCTION ITSELF is absent from
/// `pg_proc`**, by [`applicable_definer_functions`]. The five from 070 keep
/// their unconditional semantics: that IS a migration 11c applies, so a missing
/// one there is a real finding.
///
/// ## The gate reads `pg_proc`, NOT `_sqlx_migrations` (PR-24 land phase)
///
/// The first draft of this gate asked `_sqlx_migrations` whether version 86 was
/// recorded applied. That is bookkeeping, and bookkeeping and objects drift
/// apart in BOTH directions: `migrations/README.md` documents version-recorded/
/// object-gone for 013, and object-present/row-gone is just as reachable —
/// deleting the version row is the documented way to clear a checksum mismatch,
/// and a dump/restore or a baselined database can carry the function with no row
/// at all. On that database the bookkeeping gate would have SKIPPED the only
/// catalog check for a silently no-opped `OWNER TO` and still exited 0, i.e. a
/// green pre-flight over a possibly app-owned definer frame.
///
/// Gating on the object is strictly stronger and costs nothing operationally:
/// at step 11c the function legitimately does not exist yet, so the skip still
/// fires exactly where it was designed to. The version in the tuple survives
/// only to name the migration in the NOTE an operator reads.
const DEFINER_FUNCTIONS: &[&str] = &[
    "epigraph_claims_require_tenancy",
    "epigraph_node_tenancy",
    "epigraph_edges_tenancy",
    "epigraph_inherit_tenancy_stmt",
    "epigraph_propagate_tenancy",
    // `epigraph_ownership_transcribe` (071) was the sixth entry until PR-22.
    // Migration 084 drops the function with the table it wrote through, so an
    // unconditional entry would report `does not exist` on every database at
    // head and block a working deploy.
];

/// Definer bodies installed by a migration LATER than the ones 11c applies, as
/// `(function name, the migration version that installs it)`.
///
/// The version is NOT the gate — [`applicable_definer_functions`] gates on the
/// function's presence in `pg_proc`. It is carried so the skip NOTE can name the
/// migration an operator has to apply. See [`DEFINER_FUNCTIONS`]' last section.
/// `epigraph_is_instance_admin` (83) is deferred for the same reason as 086's
/// entry and carries the same stake in a different direction. Its `ALTER
/// FUNCTION ... OWNER TO epigraph_maintenance` is inside 083's guarded `DO`
/// block, so on a cluster where 060 could only `RAISE NOTICE` the ownership
/// silently stays with the migration runner. The body still reaches
/// `instance_admins` — through the runner's superuser bypass rather than through
/// `epigraph_definer_bypass()` — so it FAILS SAFE but with more authority than
/// intended, and nothing in `_sqlx_migrations` records the difference. This gate
/// is the only instrument that reports it.
///
/// `epigraph_inherit_fragment_tenancy_stmt` (89) is deferred for the structural
/// reason, not a judgement call: 089 is LATER than every migration week 11c
/// applies, so at the moment this pre-flight runs the function legitimately does
/// not exist. An entry in [`DEFINER_FUNCTIONS`] would therefore report `does not
/// exist` and fail a correctly-sequenced deploy — turning the control that
/// prevents an outage into the outage.
///
/// ## What this entry catches, scoped to what is reachable
///
/// 089's `ALTER FUNCTION ... OWNER TO` is inside a guarded `DO` block, so it can
/// silently no-op. But the two failure states are reported by DIFFERENT branches
/// of [`verify_definer_ownership`] and only one of them is this entry's:
///
/// * **Role absent** (the cluster the guard exists for — 060 could only
///   `RAISE NOTICE`): reported by the role-existence branch, which returns before
///   the per-function loop and says so. Not this entry.
/// * **Owner present but not a MEMBER of `epigraph_maintenance`** — an operator
///   re-own, a restore, a migration runner that is neither a superuser nor a
///   member: this entry, via the `pg_has_role` predicate below.
///
/// A **superuser-owned** body passes, as 086's entry already records, and that is
/// correct: it satisfies `epigraph_definer_bypass()` and bypasses row security
/// outright, so nothing is degraded.
///
/// # ⚠ `epigraph_group_roster_admits_principal` (92) — THE FOURTH DIRECTION
///
/// Deferred for the same structural reason as 083/086/089: 092 is later than
/// every migration step 11c applies, so an unconditional entry would report
/// `does not exist` and fail a correctly sequenced deploy.
///
/// **Its failure direction is the one none of the other entries has, and it is
/// why this entry is not optional.** 070's five lose a WRITE, 071's lost a LEAK,
/// 086's degrades a READ CONTROL, 089's loses COVERAGE — all of them fail
/// closed-ish, because their bodies ask `EXISTS` and an RLS-filtered read
/// answers "no". This body's first disjunct asks `NOT EXISTS (any roster row for
/// this group)`, so an RLS-filtered read answers **yes** and the predicate
/// ADMITS. An app-owned or runner-owned body therefore does not degrade the
/// narrowing migration 092 installs — it SILENTLY REVERTS it to migration 077's
/// unbounded arm, with no error, no catalog symptom and a green test suite.
///
/// The predicate this gate applies —
/// `pg_has_role(owner, 'epigraph_maintenance', 'MEMBER')` — is exactly the
/// condition `epigraph_definer_bypass()` itself tests, so this entry checks the
/// thing the correctness of 092 rests on rather than a proxy for it. The CI half
/// is `schema_contract.rs::migration_092_roster_definer_is_revoked_from_public`,
/// which pins `proowner` by string equality; this half is what an operator gets
/// on a cluster whose catalog CI never sees.
///
/// ## And what a non-member owner actually costs, measured
///
/// Not "the stamp is filtered away silently" — that was an earlier draft's claim
/// and it is wrong. Measured out of band on a scratch database at head, from a
/// genuine non-bypassing application-role session (`#[sqlx::test]` cannot ask:
/// `session_user` is the superuser — see finding
/// `F-PR12-ci-runs-as-superuser-so-the-42501-arm-is-untestable`): a non-member
/// owner still stamps a link whose claim the writing session can already see,
/// because `harvester_fragments_tenancy`'s WITH CHECK is satisfied by that
/// session's own writable groups. What it loses is the link whose claim the
/// session CANNOT see — the body's own read of `public.claims` is RLS-filtered,
/// so the join matches nothing and zero rows are stamped with no error. The
/// ownership is load-bearing for COVERAGE, which is why a catalog gate rather
/// than a runtime one is the right instrument.
const DEFERRED_DEFINER_FUNCTIONS: &[(&str, i64)] = &[
    ("epigraph_claim_tenancy_by_ids", 86),
    ("epigraph_is_instance_admin", 83),
    ("epigraph_inherit_fragment_tenancy_stmt", 89),
    ("epigraph_group_roster_admits_principal", 92),
    // 102, operator-scoped ownership. Deferred for the same structural reason
    // as 092. Both fail CLOSED under a non-member owner: `epigraph_operator_of`
    // reads no link (operated agents silently author into their own group
    // again) and `epigraph_link_operator` is refused by the tenancy policies —
    // so the stake is a feature silently OFF, which is exactly what a green
    // pre-flight must not hide.
    ("epigraph_operator_of", 102),
    ("epigraph_link_operator", 102),
];

/// [`DEFINER_FUNCTIONS`] plus every [`DEFERRED_DEFINER_FUNCTIONS`] entry that
/// actually EXISTS on this database.
///
/// Presence is read from `pg_proc`, not from `_sqlx_migrations`: a database can
/// hold the function without the bookkeeping row (a deleted version row after a
/// checksum re-sync, a dump/restore, a baselined database), and on that shape a
/// bookkeeping gate would skip the only catalog check for a silently no-opped
/// `OWNER TO` while still exiting 0.
///
/// A skipped entry is announced on stderr rather than dropped silently: an
/// operator reading a green `verify` must be able to tell "checked and passed"
/// from "not checked yet".
async fn applicable_definer_functions(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    let mut out: Vec<String> = DEFINER_FUNCTIONS.iter().map(|s| (*s).to_string()).collect();
    for (name, version) in DEFERRED_DEFINER_FUNCTIONS {
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_proc p
                              JOIN pg_namespace n ON n.oid = p.pronamespace
                             WHERE n.nspname = 'public' AND p.proname = $1)",
        )
        .bind(name)
        .fetch_one(pool)
        .await?;
        if present {
            out.push((*name).to_string());
        } else {
            eprintln!(
                "NOTE: skipping the ownership check for public.{name} — the function does not \
                 exist on this database, so migration {version}, which installs it, has not \
                 been applied. That is the \
                 EXPECTED state at plan 9.2 step 11c, which runs this pre-flight before the \
                 later migrations. Re-run verify after {version} applies; until then this \
                 definer body is UNCHECKED, not passing."
            );
        }
    }
    Ok(out)
}

/// Assert that migrations 070/086 actually re-owned their `SECURITY DEFINER`
/// bodies. Returns the number of failing checks.
///
/// # Why this is a `verify` check and not a migration assertion
///
/// All three migrations wrap their `ALTER FUNCTION … OWNER TO
/// epigraph_maintenance` in
/// `IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')`
/// and **silently no-op** when the role is absent. That is not hypothetical:
/// migration 060 creates the roles inside a `DO` block that catches
/// `insufficient_privilege` and only `RAISE NOTICE`s, precisely because a
/// managed-PostgreSQL migration role may lack `CREATEROLE`.
///
/// The two failure modes are opposite and both silent at deploy time:
///
/// * **070 — a LEAK.** 070's own comment: *"a filtered read of `claims` returns
///   NOT FOUND, epigraph_node_tenancy then yields its ('public', world)
///   fallback, and a private endpoint would be stamped PUBLIC. That is a LEAK,
///   not an error, so ownership is a security control here and not tidiness."*
///   An app-owned body is RLS-filtered the moment PR-17 arms the predicate.
/// * **071 — an OUTAGE.** `epigraph_definer_bypass()` is
///   `pg_has_role(CURRENT_USER, …)` evaluated as the FUNCTION OWNER, so an
///   app-owned shim returned false and every `ownership` write raised 42501.
///   Historical since PR-22: migration 084 drops both the table and 071's shim,
///   so this arm has no subject left and its entry is gone from
///   [`DEFINER_FUNCTIONS`]. The other three arms are unaffected.
/// * **086 — a DEGRADED READ CONTROL (PR-24).** `epigraph_claim_tenancy_by_ids`
///   reaches `claims` only through `claims_tenancy`'s definer-bypass disjunct.
///   An app-owned body is policy-filtered like any other reader, so it returns
///   FEWER rows with no error, and `ClaimRepository::hidden_claim_ids` — which
///   decides what `GET /api/v1/events` and the webhook fan-out suppress —
///   degrades back toward reporting nothing hidden. Same silent shape as 070's,
///   on a read path. **And the stake is wider than that one function**: as of
///   PR-25 `EventRepository::list` reads both of its arms through the same
///   body, so the degradation also reaches the persisted half of
///   `GET /api/v1/events`, `GET /api/v1/graph/snapshot/:version` and MCP
///   `list_events` — three surfaces with no Rust-side backstop, where this
///   function is the sole filter. Sole filter, not total coverage: the
///   predicate classifies `claims` rows only, and that scope limit is ledgered
///   separately as `F-PR25-event-suppression-is-claims-keyed-only` and
///   documented at `EventRepository::list` itself.
///
/// A hard failure inside the migration is the wrong instrument (a failed
/// migration records no row, so a missing role becomes a permanent restart
/// loop). `verify`'s exit code is the documented week-11c pre-flight, so the
/// check belongs here, where an operator can act on it.
///
/// A missing FUNCTION is reported too: 070/086 may have been rolled back
/// without the code being rolled back with them.
async fn verify_definer_ownership(pool: &PgPool) -> anyhow::Result<usize> {
    // The role must exist at all. `epigraph_definer_bypass()` is written to
    // return FALSE rather than error when it is missing, so every definer body
    // below is silently downgraded with no other signal.
    let role_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(MAINTENANCE_ROLE)
            .fetch_one(pool)
            .await?;
    if !role_exists {
        eprintln!(
            "FAIL: role '{MAINTENANCE_ROLE}' does not exist. Migration 060 only RAISE NOTICEs \
             when the migration role lacks CREATEROLE, and 070 and 086 then SKIP their \
             ALTER FUNCTION ... OWNER TO, so both migrations reported success with the \
             control absent. This branch returns BEFORE the per-function checks below, so \
             none of them ran. Provision the role out of band and re-apply 070 and 086."
        );
        return Ok(1);
    }

    let mut failures = 0usize;
    for f in &applicable_definer_functions(pool).await? {
        // ==============================================================
        // THE PREDICATE IS `pg_has_role(owner, epigraph_maintenance,
        // MEMBER)`, NOT `rolname = 'epigraph_maintenance'`.
        //
        // That is EXACTLY what `epigraph_definer_bypass()` (migration 067)
        // evaluates -- `pg_has_role(current_user, 'epigraph_maintenance',
        // 'MEMBER')`, with current_user being the FUNCTION OWNER inside a
        // SECURITY DEFINER frame. String equality would be strictly stricter
        // than the control it protects and would fail two VALID deploys:
        // a body owned by a role that is a MEMBER of epigraph_maintenance, and
        // a superuser-owned body (pg_has_role is true of a superuser for every
        // role). A deploy gate that blocks a working configuration, whose only
        // documented remedy is "re-apply 070", would not clear.
        //
        // MEASURED on the throwaway: pg_has_role('epigraph_app', ..) = false,
        // ('epigraph_maintenance', ..) = true, ('epigraph', ..) = true
        // (superuser), ('epigraph_seed', ..) = false. So the app-owned case
        // this exists to catch still fails, which is the point.
        // ==============================================================
        let owner: Option<(String, bool)> = sqlx::query_as(
            "SELECT r.rolname, pg_has_role(r.rolname, $2, 'MEMBER')
               FROM pg_proc p
               JOIN pg_namespace n ON n.oid = p.pronamespace
               JOIN pg_roles r ON r.oid = p.proowner
              WHERE n.nspname = 'public' AND p.proname = $1
              LIMIT 1",
        )
        .bind(f)
        .bind(MAINTENANCE_ROLE)
        .fetch_optional(pool)
        .await?;

        match owner {
            None => {
                failures += 1;
                eprintln!(
                    "FAIL: SECURITY DEFINER function public.{f} does not exist. \
                     Apply migrations 070 and 086 before running this."
                );
            }
            Some((_, true)) => {}
            Some((rolname, false)) => {
                failures += 1;
                eprintln!(
                    "FAIL: public.{f} is owned by '{rolname}', which is not a member of \
                     '{MAINTENANCE_ROLE}'. Migrations 070/086 skip their ALTER FUNCTION \
                     when the role is absent (060 only NOTICEs on insufficient_privilege), so \
                     this is a SILENT no-op: 070's bodies become RLS-filtered at PR-17 -- arm \
                     (b) then stamps a private endpoint PUBLIC -- and 086's read helper returns \
                     fewer rows with no error, which degrades the read-side suppression control \
                     it backs. Re-apply 070 and 086 with the role provisioned."
                );
            }
        }
    }
    Ok(failures)
}

/// Count rows still owned by the world group on `table`.
///
/// **The world group ONLY, which is narrower than "carries no real owner".** 062
/// names two sentinels and 074's seed arm produces the other one, so a
/// seed-stamped row is not counted here and `verify`'s tier-A residual line reads
/// zero over it. Left as-is deliberately: this is the gate's reporting predicate,
/// changing it changes what `verify` prints for every tier-A table, and the census
/// that would replace it is an operator decision rather than a fix. Recorded with
/// [`backfill_harvester_fragments`]' matching asymmetry as finding `F-089-D`.
async fn residual(pool: &PgPool, table: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(&format!(
        "SELECT count(*) FROM {table} WHERE owner_group_id = $1"
    ))
    .bind(WORLD)
    .fetch_one(pool)
    .await?)
}

/// The deploy pre-flight. Returns the number of FAILING checks.
///
/// Live counts, per plan §3 (ops F16): the `SECURITY DEFINER` ownership
/// precondition, world-owned claims, world-owned evidence, non-public
/// `ownership` rows that map to a still-public claim or carry no ledger row,
/// world-owned edges touching a non-public endpoint, and a per-entity residual
/// over the rest. Offending ids are PRINTED, because a guard that says "3 rows
/// are wrong" and not which ones cannot be acted on.
///
/// `frames` and `contexts` are exempt from the residual check for the reason
/// `settle_remaining` documents: a `('public', world)` row on those tables is a
/// correct declaration, not an undeclared one. `edges` is exempt from the
/// blanket residual but gets the sharper endpoint predicate instead.
async fn verify(pool: &PgPool) -> anyhow::Result<usize> {
    let mut failures = 0usize;

    failures += verify_definer_ownership(pool).await?;

    // A4. NOT the plan's rationale: an earlier revision of this comment said
    // "the derivation is total, because claims.agent_id is NOT NULL". NOT NULL
    // does not imply RESOLVABLE — `claims.agent_id` has no foreign key to
    // `agents`, so a dangling author yields no personal group and the claim is
    // deliberately left world-owned rather than mis-stamped. THIS check is what
    // catches that, by counting rather than by reasoning.
    let world_claims = residual(pool, "claims").await?;
    if world_claims > 0 {
        failures += 1;
        eprintln!("FAIL: {world_claims} claims still owned by the world group.");
        print_offenders(pool, "claims").await?;
    }

    let world_evidence = residual(pool, "evidence").await?;
    if world_evidence > 0 {
        failures += 1;
        eprintln!("FAIL: {world_evidence} evidence rows still owned by the world group.");
        print_offenders(pool, "evidence").await?;
    }

    // Two `ownership` checks lived here until PR-22: a non-public row whose
    // claim was still public (`untranscribed`), and a non-public row with no
    // `tenancy_transcription_log` entry (`unlogged`). Migration 084 retires the
    // table. ONLY ONE OF THE TWO MOVED, AND THIS SAYS SO RATHER THAN IMPLYING
    // BOTH DID.
    //
    // `unlogged` IS migration 084's pre-flight (2) — superseded exactly, then
    // STRENGTHENED: the pre-flight additionally requires the ledger entry to
    // record the partition the row currently holds, because the ledger is
    // `node_id PRIMARY KEY` overwritten on every firing and a presence-only
    // check is satisfied by a stale entry. That gate did not disappear; it moved
    // into the statement that does the destructive thing, where an operator
    // cannot skip it.
    //
    // `untranscribed` HAS NO COUNTERPART IN 084 AND DELIBERATELY GETS NONE. As a
    // third pre-flight it would false-positive on a legitimate declassification,
    // which leaves a stale non-public `ownership` row behind by design. A node
    // can therefore satisfy pre-flight (2) while its claim never actually landed
    // non-public, and 084 will not refuse. That check is carried by DEPLOY ORDER
    // instead — `docs/deploy.md` steps 1-2 require running this binary and
    // confirming `verify` exits 0 on the release that STILL HAS this check,
    // before 084 is applied. An operator who skips step 2 loses a check that
    // used to exist.

    // `edges` is NOT blanket-exempt. A world-owned edge is legitimate exactly
    // when BOTH its endpoints are public — that is 070 arm (b)'s
    // `sv = 'public' AND tv = 'public'` branch, and it is a checkable predicate
    // rather than a reason to skip the table. An earlier revision skipped
    // `edges` outright, which meant a mis-stamped edge passed the deploy
    // pre-flight whose exit code is supposed to be the gate.
    //
    // Written against `claims` / `evidence` directly rather than through
    // `epigraph_node_tenancy`, which carries `REVOKE EXECUTE … FROM PUBLIC`:
    // `verify` must be runnable by an operator who is neither superuser nor the
    // function owner.
    let leaky_edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges e
          WHERE e.owner_group_id = $1
            AND (EXISTS (SELECT 1 FROM claims c
                          WHERE c.id = e.source_id AND e.source_type = 'claim'
                            AND c.visibility <> 'public')
              OR EXISTS (SELECT 1 FROM claims c
                          WHERE c.id = e.target_id AND e.target_type = 'claim'
                            AND c.visibility <> 'public')
              OR EXISTS (SELECT 1 FROM evidence v
                          WHERE v.id = e.source_id AND e.source_type = 'evidence'
                            AND v.visibility <> 'public')
              OR EXISTS (SELECT 1 FROM evidence v
                          WHERE v.id = e.target_id AND e.target_type = 'evidence'
                            AND v.visibility <> 'public'))",
    )
    .bind(WORLD)
    .fetch_one(pool)
    .await?;
    if leaky_edges > 0 {
        failures += 1;
        eprintln!(
            "FAIL: {leaky_edges} world-owned edge(s) touch a non-public endpoint. \
             A ('public', world) edge onto a private node discloses that the node \
             exists and stands in a named relationship — 070 arm (b)'s meet must \
             have stamped it group-private."
        );
    }

    // The SECOND edge shape, and the one `leaky_edges` above structurally
    // cannot see: an edge whose endpoints are group-private in DIFFERENT groups
    // but which carries NO co-owner.
    //
    // WHY IT EXISTS AND WHY NOTHING REPAIRS IT. Migration 072 makes the
    // cross-group case expressible and both stamping arms write it from then
    // on, but 072 reconciles nothing that is already stored. A row can reach
    // this shape entirely under 070, with no cross-owner write: arm (b) stamps
    // an edge ('group', G) while both endpoints are in G, then one endpoint
    // moves to H. 070's arm (d) computed `ELSE NULL AS g` for that transition
    // and its `AND m.g IS NOT NULL` guard SKIPPED the row — 070's own header
    // calls that "stale-but-still-private is fail-closed, and 072 resolves it
    // properly with co_owner_group_id". 072 resolves it for FUTURE transitions.
    // For a row already in this shape, `Viewer::edge_predicate_fragment`'s
    // `co_owner_group_id IS NULL` disjunct short-circuits and the edge stays
    // visible to every member of G while naming H's private claim. The read
    // predicate is exactly as good as the stamp, and here the stamp is missing.
    //
    // Nor does a no-op `UPDATE claims` repair it: arm (d)'s firing gate is
    // `(ch.owner_group_id, ch.visibility) IS DISTINCT FROM (p.…)`, so an
    // UPDATE that changes no tenancy returns NULL before reaching the meet.
    //
    // So it is a PRE-FLIGHT obligation, checked here where the deploy gate is,
    // rather than a bulk UPDATE inside 072: 072 already holds ACCESS EXCLUSIVE
    // on `edges` for its ADD COLUMN, `lock_timeout` bounds acquisition and not
    // hold, and `edges_co_owner_shape` is enforced on new writes even though it
    // ships NOT VALID — so a full-table reconciliation there could raise 23514
    // mid-migration, record no sqlx row, and re-run on every restart. Plan
    // §6.5 puts this meet in `repos/privatization.rs::seal_boundary_edges`, a
    // BATCHED, RESUMABLE function scoped to `batch_ids`, which is PR-18's.
    //
    // Same house style as `leaky_edges`: written against `claims` / `evidence`
    // directly, never through `epigraph_node_tenancy` (which carries
    // `REVOKE EXECUTE … FROM PUBLIC`), so `verify` stays runnable by an
    // operator who is neither superuser nor the function owner. The
    // `COALESCE(…, 'public')` on a missing endpoint is plan §6.5's rule: an
    // edge onto a frame/agent/paper/task has no tenancy and contributes public.
    let stale_cross_group_edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (
           SELECT COALESCE(cs.visibility, es.visibility, 'public')      AS sv,
                  COALESCE(cs.owner_group_id, es.owner_group_id, $1)    AS sg,
                  COALESCE(ct.visibility, et.visibility, 'public')      AS tv,
                  COALESCE(ct.owner_group_id, et.owner_group_id, $1)    AS tg
             FROM edges e
             LEFT JOIN claims   cs ON e.source_type = 'claim'    AND cs.id = e.source_id
             LEFT JOIN evidence es ON e.source_type = 'evidence' AND es.id = e.source_id
             LEFT JOIN claims   ct ON e.target_type = 'claim'    AND ct.id = e.target_id
             LEFT JOIN evidence et ON e.target_type = 'evidence' AND et.id = e.target_id
            WHERE e.co_owner_group_id IS NULL
         ) m
          WHERE m.sv = 'group' AND m.tv = 'group' AND m.sg <> m.tg",
    )
    .bind(WORLD)
    .fetch_one(pool)
    .await?;
    if stale_cross_group_edges > 0 {
        failures += 1;
        eprintln!(
            "FAIL: {stale_cross_group_edges} edge(s) join two group-private \
             endpoints in DIFFERENT groups but carry no co_owner_group_id. \
             Each is visible to every member of its single owner group while \
             naming the other group's private node — migration 072 makes that \
             case expressible but does not reconcile rows stamped before it. \
             Remediation: re-fire the stamping arm by naming an endpoint column \
             in an UPDATE that changes nothing, e.g. \
             `UPDATE edges SET source_id = source_id WHERE co_owner_group_id IS NULL;` \
             — PostgreSQL fires `UPDATE OF source_id` on column MENTION, not on \
             value change, so arm (b) re-runs and stamps the meet."
        );
    }

    for t in TIER_A {
        if matches!(*t, "frames" | "contexts" | "edges" | "claims" | "evidence") {
            continue;
        }
        let n = residual(pool, t).await?;
        if n > 0 {
            failures += 1;
            eprintln!("FAIL: {n} row(s) in {t} still owned by the world group.");
            print_offenders(pool, t).await?;
        }
    }

    // Reported, never trusted (062's demotion).
    let incomplete: Vec<String> = sqlx::query_scalar(
        "SELECT entity FROM tenancy_backfill_progress WHERE NOT complete ORDER BY entity",
    )
    .fetch_all(pool)
    .await?;
    if !incomplete.is_empty() {
        eprintln!(
            "note: tenancy_backfill_progress reports these entities incomplete: {}",
            incomplete.join(", ")
        );
    }

    Ok(failures)
}

/// Print up to 20 offending ids. Tables without an `id` column
/// (`claim_frames`, `claim_cluster_membership`, `claim_neighborhood_membership`)
/// are keyed on `claim_id` instead — a per-entity fact, not the uniform PK the
/// acceptance line implies.
async fn print_offenders(pool: &PgPool, table: &str) -> anyhow::Result<()> {
    let key = match table {
        "claim_frames" | "claim_cluster_membership" | "claim_neighborhood_membership" => "claim_id",
        _ => "id",
    };
    let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT {key} FROM {table} WHERE owner_group_id = $1 ORDER BY {key} LIMIT 20"
    ))
    .bind(WORLD)
    .fetch_all(pool)
    .await?;
    for id in ids {
        eprintln!("    {table}.{key} = {id}");
    }
    Ok(())
}
