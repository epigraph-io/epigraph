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
//! # Legacy `ownership` rows
//!
//! Migration 071 installs only an `AFTER INSERT OR UPDATE` trigger, so rows
//! already in `ownership` when it applied are never transcribed —
//! and `verify` fails on exactly those, permanently. `transcribe_legacy_ownership`
//! re-fires the trigger over them; see its doc comment.
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
use sqlx::postgres::PgPoolOptions;
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
    let url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL is not set"))?;

    // A modest pool: this is a single-threaded batch walker, and a large pool
    // against a live cluster is a way to starve the application.
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await?;

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
    transcribe_legacy_ownership(pool, batch_size).await?;

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
/// **before** its `harvester_claim_provenance` row is therefore never stamped
/// by any trigger — an insert-order hole the plan does not mention. The
/// backfill closes it for existing rows; new rows in that order remain a live
/// gap, recorded in the PR body.
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

/// Re-fire migration 071's `ownership_transcribe` trigger over every
/// `ownership` row that predates it.
///
/// # Why this arm has to exist — `verify` is otherwise unpassable
///
/// Migration 071 installs **only** `CREATE TRIGGER ownership_transcribe AFTER
/// INSERT OR UPDATE ON public.ownership`. It contains no one-time pass over the
/// rows already in the table, so on any database that held `ownership` rows
/// before the migration those rows are never transcribed. `verify` counts
/// exactly them, in two checks:
///
/// * *"N non-public ownership row(s) map to a still-public claim"*, and
/// * *"N non-public ownership row(s) have no transcription log row"*.
///
/// Without this pass those failures are **unclearable by anything in the PR**,
/// and since `run` calls `verify` at the end, `run` exits 1 forever too. That
/// would make the plan's own acceptance line — *"every `ownership` row it
/// transcribes writes a `tenancy_transcription_log` row"* — true only
/// vacuously, because it would transcribe zero. It also leaves 071's stated
/// purpose unmet for the legacy corpus: a pre-existing `private` row would keep
/// its claim at `visibility = 'public'`, which is precisely the silent
/// divergence 071's header says it exists to prevent.
///
/// Severity in production is contingent on `HANDOFF.md` §4 **M1** (the
/// `ownership` row census), which has never been performed — but every staging
/// and development database hits it, and the deliverable must be correct
/// regardless.
///
/// # `SET owner_id = owner_id` is deliberate
///
/// The trigger is `FOR EACH ROW`, so any UPDATE re-fires it; writing a column
/// back to itself changes no information while still producing a `NEW` record.
/// Transcription is idempotent by construction (every stamping UPDATE in 071
/// carries `IS DISTINCT FROM`, and the ledger insert is `ON CONFLICT DO
/// UPDATE`), so a re-run is a no-op rather than a second transition.
///
/// # The selection is "no ledger row", not "all rows"
///
/// 071 writes a `tenancy_transcription_log` row for **every** partition_type,
/// including `public`. So "has no ledger row" is exactly "was never seen by the
/// trigger" — the legacy set — and a second `run` selects nothing.
///
/// # One bad row must not kill the walk
///
/// 071 RAISEs `23514` rather than stamp a group with no live members. A single
/// such row inside a 5,000-row batch would abort the whole batch and, without
/// this fallback, the whole backfill — leaving the operator with no way
/// forward. On a batch failure each row is retried alone; the offenders are
/// named on stderr and left for `verify` to fail on, which is the fail-closed
/// outcome.
async fn transcribe_legacy_ownership(pool: &PgPool, batch_size: i64) -> anyhow::Result<()> {
    let mut cursor: Option<Uuid> = None;
    let mut total: i64 = 0;
    let mut refused: i64 = 0;

    loop {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT o.node_id FROM ownership o
              WHERE NOT EXISTS (SELECT 1 FROM tenancy_transcription_log l
                                 WHERE l.node_id = o.node_id)
                AND ($1::uuid IS NULL OR o.node_id > $1)
              ORDER BY o.node_id
              LIMIT $2",
        )
        .bind(cursor)
        .bind(batch_size)
        .fetch_all(pool)
        .await?;

        if ids.is_empty() {
            break;
        }
        cursor = Some(*ids.last().expect("non-empty batch"));

        match sqlx::query("UPDATE ownership SET owner_id = owner_id WHERE node_id = ANY($1)")
            .bind(&ids)
            .execute(pool)
            .await
        {
            Ok(r) => total += r.rows_affected() as i64,
            Err(batch_err) => {
                tracing::warn!(
                    error = %batch_err,
                    batch = ids.len(),
                    "ownership transcription batch failed; retrying row by row"
                );
                for id in &ids {
                    match sqlx::query("UPDATE ownership SET owner_id = owner_id WHERE node_id = $1")
                        .bind(id)
                        .execute(pool)
                        .await
                    {
                        Ok(r) => total += r.rows_affected() as i64,
                        Err(e) => {
                            refused += 1;
                            eprintln!(
                                "REFUSED: ownership.node_id = {id} could not be transcribed: {e}"
                            );
                        }
                    }
                }
            }
        }
    }

    if refused > 0 {
        tracing::warn!(
            transcribed = total,
            refused,
            "some legacy ownership rows were refused by migration 071; `verify` will name them"
        );
    } else {
        tracing::info!(transcribed = total, "legacy ownership rows transcribed");
    }
    Ok(())
}

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

/// The six `SECURITY DEFINER` bodies migrations 070 and 071 install, whose owner
/// must satisfy `epigraph_definer_bypass()`.
const DEFINER_FUNCTIONS: &[&str] = &[
    "epigraph_claims_require_tenancy",
    "epigraph_node_tenancy",
    "epigraph_edges_tenancy",
    "epigraph_inherit_tenancy_stmt",
    "epigraph_propagate_tenancy",
    "epigraph_ownership_transcribe",
];

/// Assert that migrations 070/071 actually re-owned their `SECURITY DEFINER`
/// bodies. Returns the number of failing checks.
///
/// # Why this is a `verify` check and not a migration assertion
///
/// Both migrations wrap their `ALTER FUNCTION … OWNER TO epigraph_maintenance`
/// in `IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')`
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
///   app-owned shim returns false and every `ownership` write raises 42501.
///
/// A hard failure inside the migration is the wrong instrument (a failed
/// migration records no row, so a missing role becomes a permanent restart
/// loop). `verify`'s exit code is the documented week-11c pre-flight, so the
/// check belongs here, where an operator can act on it.
///
/// A missing FUNCTION is reported too: 070/071 may have been rolled back
/// without the code being rolled back with them.
async fn verify_definer_ownership(pool: &PgPool) -> anyhow::Result<usize> {
    // The role must exist at all. `epigraph_definer_bypass()` is written to
    // return FALSE rather than error when it is missing, so 071's shim would
    // raise 42501 on every ownership write with no other signal.
    let role_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(MAINTENANCE_ROLE)
            .fetch_one(pool)
            .await?;
    if !role_exists {
        eprintln!(
            "FAIL: role '{MAINTENANCE_ROLE}' does not exist. Migration 060 only RAISE NOTICEs \
             when the migration role lacks CREATEROLE, and 070/071 then SKIP their \
             ALTER FUNCTION ... OWNER TO, so both migrations reported success with the \
             control absent. Provision the role out of band and re-apply 070 and 071."
        );
        return Ok(1);
    }

    let mut failures = 0usize;
    for f in DEFINER_FUNCTIONS {
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
        // documented remedy is "re-apply 070 and 071", would not clear.
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
                     Apply migrations 070 and 071 before running this."
                );
            }
            Some((_, true)) => {}
            Some((rolname, false)) => {
                failures += 1;
                eprintln!(
                    "FAIL: public.{f} is owned by '{rolname}', which is not a member of \
                     '{MAINTENANCE_ROLE}'. Migrations 070/071 skip their ALTER FUNCTION when \
                     the role is absent (060 only NOTICEs on insufficient_privilege), so this \
                     is a SILENT no-op: 070's bodies become RLS-filtered at PR-17 -- arm (b) \
                     then stamps a private endpoint PUBLIC -- and 071's shim raises 42501 on \
                     every ownership write. Re-apply 070 and 071 with the role provisioned."
                );
            }
        }
    }
    Ok(failures)
}

/// Count rows still owned by the world group on `table`.
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

    // The transcription check: a non-public ownership row whose claim is still
    // public means the 071 shim did not fire (or predates it).
    let untranscribed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ownership o
           JOIN claims c ON c.id = o.node_id
          WHERE o.node_type = 'claim'
            AND o.partition_type <> 'public'
            AND c.visibility = 'public'",
    )
    .fetch_one(pool)
    .await?;
    if untranscribed > 0 {
        failures += 1;
        eprintln!("FAIL: {untranscribed} non-public ownership row(s) map to a still-public claim.");
    }

    // And a ledger row for every non-public ownership row — migration 084's
    // pre-flight reads exactly this.
    let unlogged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ownership o
          WHERE o.partition_type <> 'public'
            AND NOT EXISTS (SELECT 1 FROM tenancy_transcription_log l
                             WHERE l.node_id = o.node_id)",
    )
    .fetch_one(pool)
    .await?;
    if unlogged > 0 {
        failures += 1;
        eprintln!("FAIL: {unlogged} non-public ownership row(s) have no transcription log row.");
    }

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
