//! Schema-head verification around `sqlx::migrate!` (issue #492).
//!
//! `sqlx::migrate!("../../migrations")` embeds the migration set **at compile
//! time**, and [`run_migrations`] must keep `set_ignore_missing(true)` (see its
//! doc). Together those used to mean that neither direction was checked: a
//! binary built before migration N applied its subset, stopped, and printed
//! `migrations: ok`, and a stale binary run against a database migrated by a
//! newer build also printed `migrations: ok`.
//!
//! [`run_migrations`] now brackets `Migrator::run` with two checks and returns
//! a [`MigrationReport`] naming both heads:
//!
//! * **before** running: if the database has applied a version this binary
//!   does not embed — above its head, OR a gap-filler below it (a newer
//!   build's migration in reserved headroom such as `093`–`099`) — refuse,
//!   unless the caller opted in with [`MigrateOptions::allow_db_ahead`] (the
//!   rollback case). [`KNOWN_FOREIGN_VERSIONS`] are exempt. The refusal
//!   happens before anything is applied, because a stale binary against a
//!   newer database can still apply an older embedded migration the database
//!   lacks.
//! * **after** running: every embedded (up) migration must be recorded in
//!   `_sqlx_migrations` with `success = true`. This is a SET check, not
//!   `max >= head`, so a gap under a present head cannot hide. The unknown-
//!   version gate is evaluated again here, so a strict run never reports
//!   success against a database carrying a version it does not embed.
//!
//! Both reads and the run happen on ONE connection holding sqlx's migration
//! advisory lock, so no other lock-respecting migrator can change
//! `_sqlx_migrations` between the checks and the run.
//!
//! The comparison itself is the pure [`compare_schema_heads`] plus the pure
//! gates [`check_before_run`] / [`check_after_run`], so every branch —
//! including the post-run floor, which a successful `Migrator::run` can never
//! trip against a real database — is unit-testable.
//!
//! All queries are the non-macro `sqlx::query_scalar` form so the offline
//! (`.sqlx/`) prepare cache needs no new entries (CI builds `SQLX_OFFLINE=true`).

use std::collections::BTreeSet;
use std::fmt;

use sqlx::migrate::Migrate;
use sqlx::Connection;

/// Environment variable that opts in to running against a database that has
/// applied migrations this binary does not embed. Parsed with the same
/// trim/case-fold rule as `EPIGRAPH_MIGRATE_ON_BOOT` (`1`/`true`/`yes`).
pub const ALLOW_DB_AHEAD_ENV: &str = "EPIGRAPH_MIGRATE_ALLOW_DB_AHEAD";

/// `epigraph-migrate` command-line spelling of the same opt-in.
pub const ALLOW_DB_AHEAD_FLAG: &str = "--allow-db-ahead";

/// Applied versions that no public build embeds and that are nonetheless
/// benign, so they never count as "unknown to this binary".
///
/// * `35` — `epigraph-internal`'s `claim_supersession`, applied to prod on
///   2026-05-22. Public has no `035_*.sql`; it renumbered the same files to
///   `036`–`038`, and prod's 036/037/038 descriptions match the public
///   filenames (`migrations/README.md`, "The epigraph-internal overlap").
///
/// This list rests on that README's 2026-09-02 measurement of prod, not on a
/// fresh read. If a deployed database carries any OTHER version the binary
/// does not embed, a strict run refuses (nothing applied, nonzero exit) until
/// the version is either added here with its provenance or the operator opts
/// in.
pub const KNOWN_FOREIGN_VERSIONS: &[i64] = &[35];

/// Caller policy for [`run_migrations`].
///
/// `Default` is the strict policy: a database carrying migrations this binary
/// does not embed is refused.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MigrateOptions {
    /// Proceed (with a WARN) when the database has applied migrations this
    /// binary does not embed. Meant for a deliberate rollback to an older
    /// build; never set it to silence a refusal you have not diagnosed.
    pub allow_db_ahead: bool,
}

impl MigrateOptions {
    /// Read the opt-in from [`ALLOW_DB_AHEAD_ENV`]. Callers that also accept a
    /// command-line flag OR it in themselves.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            allow_db_ahead: crate::env_flag_enabled(
                std::env::var(ALLOW_DB_AHEAD_ENV).ok().as_deref(),
            ),
        }
    }
}

/// Where the database stands relative to the binary's embedded migration set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaHeads {
    /// Highest embedded up-migration version. `0` only for an empty set.
    pub binary_head: i64,
    /// Highest version recorded with `success = true`; `None` when
    /// `_sqlx_migrations` is absent or has no successful row.
    pub db_head: Option<i64>,
    /// Embedded versions NOT recorded as successfully applied.
    pub missing: Vec<i64>,
    /// Successfully applied versions this binary does NOT embed, above or
    /// below `binary_head`, excluding [`KNOWN_FOREIGN_VERSIONS`]: the
    /// migrations a newer (or different) build applied that this binary knows
    /// nothing about.
    pub ahead: Vec<i64>,
}

impl SchemaHeads {
    /// The database has applied a migration this binary does not embed.
    #[must_use]
    pub fn db_ahead(&self) -> bool {
        !self.ahead.is_empty()
    }
}

/// Pure comparison of the applied set against the embedded set.
///
/// `applied_ok` must hold only versions whose row has `success = true`.
/// A version that is applied but not embedded is `ahead` wherever it sits —
/// above the head, or in a gap below it — unless it is one of
/// [`KNOWN_FOREIGN_VERSIONS`], the gap `set_ignore_missing(true)` exists to
/// tolerate.
#[must_use]
pub fn compare_schema_heads(applied_ok: &[i64], embedded: &[i64]) -> SchemaHeads {
    let applied: BTreeSet<i64> = applied_ok.iter().copied().collect();
    let embedded: BTreeSet<i64> = embedded.iter().copied().collect();
    let binary_head = embedded.iter().next_back().copied().unwrap_or(0);
    SchemaHeads {
        binary_head,
        db_head: applied.iter().next_back().copied(),
        missing: embedded.difference(&applied).copied().collect(),
        ahead: applied
            .difference(&embedded)
            .copied()
            .filter(|v| !KNOWN_FOREIGN_VERSIONS.contains(v))
            .collect(),
    }
}

/// Embedded versions recorded as applied after the run that were not recorded
/// before it. Rows that are not in this binary's embedded set are never
/// counted: this process cannot have applied them.
#[must_use]
pub fn newly_applied(applied_before: &[i64], applied_after: &[i64], embedded: &[i64]) -> usize {
    let before: BTreeSet<i64> = applied_before.iter().copied().collect();
    let embedded: BTreeSet<i64> = embedded.iter().copied().collect();
    applied_after
        .iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|v| embedded.contains(v) && !before.contains(v))
        .count()
}

/// Why [`run_migrations`] refused or failed.
#[derive(Debug)]
pub enum MigrationError {
    /// Reading `_sqlx_migrations` failed.
    Query(sqlx::Error),
    /// `sqlx::migrate::Migrator::run` failed (checksum mismatch, dirty
    /// version, a migration that RAISEd, ...), or taking sqlx's migration lock
    /// failed.
    Migrate(sqlx::migrate::MigrateError),
    /// The database has applied migrations this binary does not embed
    /// (`ahead`, above or below `binary_head`). When raised before the run,
    /// nothing was applied.
    DbAheadOfBinary {
        db_head: i64,
        binary_head: i64,
        ahead: Vec<i64>,
    },
    /// After a successful run, embedded migrations are still not recorded as
    /// applied. The database is BELOW the schema this binary requires.
    DbBehindBinary {
        db_head: Option<i64>,
        binary_head: i64,
        missing: Vec<i64>,
    },
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query(e) => write!(f, "reading _sqlx_migrations failed: {e}"),
            Self::Migrate(e) => write!(f, "sqlx::migrate failed: {e}"),
            Self::DbAheadOfBinary {
                db_head,
                binary_head,
                ahead,
            } => write!(
                f,
                "REFUSING: the database has {n} applied migration version(s) this binary does \
                 not embed: {ahead:?} (database head {db_head}, binary head {binary_head}). A \
                 newer or different build migrated this database, so this binary is older \
                 than the schema, and a stale build must not report success. Deploy a binary \
                 built from the revision that applied {ahead:?}. If this is a DELIBERATE \
                 rollback to an older build, re-run with {ALLOW_DB_AHEAD_FLAG} \
                 (epigraph-migrate) or {ALLOW_DB_AHEAD_ENV}=1 (any entry point); pending \
                 migrations this binary embeds are then applied and the unknown ones are left \
                 in place.",
                n = ahead.len(),
            ),
            Self::DbBehindBinary {
                db_head,
                binary_head,
                missing,
            } => write!(
                f,
                "database schema head is {db} after migrating, below this binary's embedded \
                 head {binary_head}: {n} embedded migration(s) not recorded as applied: \
                 {missing:?}",
                db = db_head.map_or_else(|| "<none>".to_string(), |v| v.to_string()),
                n = missing.len(),
            ),
        }
    }
}

impl std::error::Error for MigrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Query(e) => Some(e),
            Self::Migrate(e) => Some(e),
            _ => None,
        }
    }
}

/// What [`run_migrations`] did and where the database ended up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// Highest version this binary embeds.
    pub binary_head: i64,
    /// Database head before this run (`None`: fresh database).
    pub db_head_before: Option<i64>,
    /// Database head after this run. Always `>= binary_head` on success.
    pub db_head: i64,
    /// Embedded migrations this run applied. Read under sqlx's migration lock
    /// and restricted to the embedded set, so another migrator's rows are not
    /// counted.
    pub applied_this_run: usize,
    /// The database carries migrations this binary does not embed. Only ever
    /// `true` when the caller set [`MigrateOptions::allow_db_ahead`]; a strict
    /// run returns [`MigrationError::DbAheadOfBinary`] instead.
    pub db_ahead: bool,
    /// The applied versions this binary does not embed (empty unless
    /// `db_ahead`).
    pub ahead: Vec<i64>,
}

impl fmt::Display for MigrationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "db_head={} binary_head={} applied={}",
            self.db_head, self.binary_head, self.applied_this_run
        )?;
        if self.db_ahead {
            write!(f, " db_ahead_of_binary=allowed")?;
        }
        Ok(())
    }
}

fn refuse_ahead(heads: &SchemaHeads, opts: MigrateOptions) -> Result<(), MigrationError> {
    match heads.db_head {
        Some(db_head) if heads.db_ahead() && !opts.allow_db_ahead => {
            Err(MigrationError::DbAheadOfBinary {
                db_head,
                binary_head: heads.binary_head,
                ahead: heads.ahead.clone(),
            })
        }
        _ => Ok(()),
    }
}

/// Gate evaluated BEFORE `Migrator::run`: refuse a database carrying
/// migrations this binary does not embed unless `opts.allow_db_ahead`.
pub fn check_before_run(heads: &SchemaHeads, opts: MigrateOptions) -> Result<(), MigrationError> {
    refuse_ahead(heads, opts)
}

/// Gate evaluated AFTER `Migrator::run`: the unknown-version gate again (a
/// strict run never reports success against a database it does not fully
/// know, whatever happened between the reads), then every embedded migration
/// must be recorded as successfully applied.
pub fn check_after_run(
    before: &SchemaHeads,
    after: &SchemaHeads,
    applied_this_run: usize,
    opts: MigrateOptions,
) -> Result<MigrationReport, MigrationError> {
    refuse_ahead(after, opts)?;
    match after.db_head {
        Some(db_head) if after.missing.is_empty() && db_head >= after.binary_head => {
            Ok(MigrationReport {
                binary_head: after.binary_head,
                db_head_before: before.db_head,
                db_head,
                applied_this_run,
                db_ahead: after.db_ahead(),
                ahead: after.ahead.clone(),
            })
        }
        _ => Err(MigrationError::DbBehindBinary {
            db_head: after.db_head,
            binary_head: after.binary_head,
            missing: after.missing.clone(),
        }),
    }
}

/// The migrator every production entry point runs.
///
/// `ignore_missing(true)` is KEPT, and is required for two separate reasons:
///
/// 1. **Gaps below the head.** A database may carry versions this repo never
///    shipped. Production records `epigraph-internal`'s version 035, which has
///    no public file (`migrations/README.md`, "The epigraph-internal overlap");
///    without the flag every run there fails `VersionMissing(35)`.
/// 2. **The rollback case.** Running an older build against a database a newer
///    build migrated means the database holds versions this binary does not
///    embed. Without the flag sqlx rejects that with `VersionMissing` before
///    the [`MigrateOptions::allow_db_ahead`] opt-in could ever take effect.
///
/// What the flag no longer does is make an unknown version SILENT: that is
/// [`check_before_run`]'s job, which refuses it by default unless it is one of
/// [`KNOWN_FOREIGN_VERSIONS`]. (A database that ever ran `epigraph-internal`'s
/// 060–112 therefore now trips the refusal — intended: `migrations/README.md`
/// calls that version space a minefield.)
fn embedded_migrator() -> sqlx::migrate::Migrator {
    let mut migrator = sqlx::migrate!("../../migrations");
    migrator.set_ignore_missing(true);
    migrator
}

/// Versions of the up-migrations embedded in this binary, ascending.
#[must_use]
pub fn embedded_migration_versions() -> Vec<i64> {
    versions_of(&embedded_migrator())
}

fn versions_of(migrator: &sqlx::migrate::Migrator) -> Vec<i64> {
    migrator
        .iter()
        .filter(|m| !m.migration_type.is_down_migration())
        .map(|m| m.version)
        .collect()
}

/// Versions recorded with `success = true`; empty when `_sqlx_migrations`
/// does not exist yet (a fresh database).
async fn applied_versions(conn: &mut sqlx::PgConnection) -> Result<Vec<i64>, sqlx::Error> {
    let exists: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
        .fetch_one(&mut *conn)
        .await?;
    if !exists {
        return Ok(Vec::new());
    }
    sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
        .fetch_all(&mut *conn)
        .await
}

/// Apply all pending embedded migrations, then prove the database reached this
/// binary's head.
///
/// Refuses (before applying anything) when the database carries a migration
/// this binary does not embed, unless `opts.allow_db_ahead`; fails when, after
/// running, any embedded migration is not recorded as applied. On success the
/// returned [`MigrationReport`] names both heads — callers log it rather than a
/// bare "ok".
///
/// **Locking.** The pre-run read, `Migrator::run` and the post-run read all
/// happen on one dedicated connection that holds sqlx's migration advisory
/// lock (the same key `Migrator::run` takes, which is re-entrant per session)
/// for the whole sequence. A second lock-respecting migrator therefore cannot
/// write `_sqlx_migrations` between the check and the run — the window the
/// #492 review measured a strict head-59 run reporting success against a
/// head-101 database through. The connection is detached from the pool and
/// CLOSED on every exit path, which releases the lock even when sqlx's own
/// `run` returns early on error without unlocking.
pub async fn run_migrations(
    pool: &epigraph_db::PgPool,
    opts: MigrateOptions,
) -> Result<MigrationReport, MigrationError> {
    run_migrator(&embedded_migrator(), pool, opts).await
}

/// [`run_migrations`] for an arbitrary migrator. Hidden: exists so tests can
/// reproduce a STALE binary (an embedded set truncated at an older head)
/// through the exact code path production runs.
#[doc(hidden)]
pub async fn run_migrator(
    migrator: &sqlx::migrate::Migrator,
    pool: &epigraph_db::PgPool,
    opts: MigrateOptions,
) -> Result<MigrationReport, MigrationError> {
    // Detached: a connection holding a session-level advisory lock must never
    // go back into the pool, where the next borrower would silently inherit it.
    let mut conn = pool
        .acquire()
        .await
        .map_err(MigrationError::Query)?
        .detach();
    let result = run_locked(migrator, &mut conn, opts).await;
    // Ending the session releases every advisory lock it holds, including the
    // extra re-entrant hold sqlx's `run` leaves behind when it errors.
    if let Err(e) = conn.close().await {
        tracing::warn!(error = %e, "closing the migration connection failed");
    }
    result
}

async fn run_locked(
    migrator: &sqlx::migrate::Migrator,
    conn: &mut sqlx::PgConnection,
    opts: MigrateOptions,
) -> Result<MigrationReport, MigrationError> {
    conn.lock().await.map_err(MigrationError::Migrate)?;

    let embedded = versions_of(migrator);
    let applied_before = applied_versions(conn)
        .await
        .map_err(MigrationError::Query)?;
    let before = compare_schema_heads(&applied_before, &embedded);
    check_before_run(&before, opts)?;
    if before.db_ahead() {
        tracing::warn!(
            db_head = before.db_head,
            binary_head = before.binary_head,
            ahead = ?before.ahead,
            "database has applied migrations this binary does not embed; proceeding because \
             {} / {} opted in (rollback case). This binary does not know the schema it is \
             running against.",
            ALLOW_DB_AHEAD_FLAG,
            ALLOW_DB_AHEAD_ENV,
        );
    }

    // On THIS session, so sqlx's own `pg_advisory_lock` nests inside ours.
    // `run_direct` rather than `run(&mut *conn)`: the latter makes this
    // future fail "implementation of `Acquire` is not general enough" as soon
    // as it must be `Send` (a `tokio::spawn`), which is the case sqlx added
    // `run_direct` for. It is `#[doc(hidden)]` in sqlx 0.8.6 — pinned by
    // Cargo.lock, so an upgrade that drops it fails to compile, not silently.
    migrator
        .run_direct(&mut *conn)
        .await
        .map_err(MigrationError::Migrate)?;

    let applied_after = applied_versions(conn)
        .await
        .map_err(MigrationError::Query)?;
    let after = compare_schema_heads(&applied_after, &embedded);
    let applied_this_run = newly_applied(&applied_before, &applied_after, &embedded);
    let report = check_after_run(&before, &after, applied_this_run, opts)?;

    conn.unlock().await.map_err(MigrationError::Migrate)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMBEDDED: &[i64] = &[1, 2, 3, 36, 37, 38, 59, 60, 101];
    const STRICT: MigrateOptions = MigrateOptions {
        allow_db_ahead: false,
    };
    const ALLOW: MigrateOptions = MigrateOptions {
        allow_db_ahead: true,
    };

    #[test]
    fn fresh_database_is_missing_everything_and_not_ahead() {
        let h = compare_schema_heads(&[], EMBEDDED);
        assert_eq!(h.binary_head, 101);
        assert_eq!(h.db_head, None);
        assert_eq!(h.missing, EMBEDDED.to_vec());
        assert!(!h.db_ahead());
        check_before_run(&h, STRICT).expect("fresh DB is not ahead");
    }

    #[test]
    fn known_foreign_version_below_head_is_a_tolerated_gap() {
        // prod's epigraph-internal 035: applied, not embedded, below the head.
        let mut applied = EMBEDDED.to_vec();
        applied.push(35);
        let h = compare_schema_heads(&applied, EMBEDDED);
        assert!(h.missing.is_empty());
        assert!(!h.db_ahead(), "035 is a known foreign version: {h:?}");
        check_before_run(&h, STRICT).expect("gap is tolerated");
        let r = check_after_run(&h, &h, 0, STRICT).expect("at head");
        assert_eq!((r.db_head, r.binary_head, r.db_ahead), (101, 101, false));
    }

    #[test]
    fn unknown_version_below_head_is_refused_like_one_above_it() {
        // Review finding 3: a newer build's migration in reserved headroom
        // (093-099) sits BELOW a head-101 binary's head. It is still a
        // migration this binary does not know.
        let mut applied = EMBEDDED.to_vec();
        applied.push(95);
        let h = compare_schema_heads(&applied, EMBEDDED);
        assert_eq!(h.ahead, vec![95]);
        assert_eq!(h.db_head, Some(101), "the head alone cannot see it");
        let err = check_before_run(&h, STRICT).expect_err("gap-filler must be refused");
        let msg = err.to_string();
        assert!(msg.contains("[95]"), "refusal must name the version: {msg}");
        assert!(msg.contains("REFUSING"), "{msg}");
        check_before_run(&h, ALLOW).expect("opt-in proceeds");
        let r = check_after_run(&h, &h, 0, ALLOW).expect("opt-in reports");
        assert!(r.db_ahead);
        assert_eq!(r.ahead, vec![95]);
    }

    #[test]
    fn stale_head_reached_is_behind_and_refused_after_run() {
        // The #492 measurement: the database stops at 59 while the binary
        // embeds up to 101. A successful Migrator::run cannot produce this
        // against a real database, so this is the only proof the floor bites.
        let before = compare_schema_heads(&[], EMBEDDED);
        let after = compare_schema_heads(&[1, 2, 3, 36, 37, 38, 59], EMBEDDED);
        assert_eq!(after.missing, vec![60, 101]);
        let err = check_after_run(&before, &after, 7, STRICT).expect_err("behind must fail");
        match &err {
            MigrationError::DbBehindBinary {
                db_head,
                binary_head,
                missing,
            } => {
                assert_eq!((*db_head, *binary_head), (Some(59), 101));
                assert_eq!(missing, &vec![60, 101]);
            }
            other => panic!("wrong error: {other:?}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("59") && msg.contains("101"), "{msg}");
    }

    #[test]
    fn gap_under_a_present_head_is_behind() {
        // max(applied) == binary_head but 60 never applied: a max-only check
        // would pass this.
        let applied: Vec<i64> = EMBEDDED.iter().copied().filter(|v| *v != 60).collect();
        let h = compare_schema_heads(&applied, EMBEDDED);
        assert_eq!(h.db_head, Some(101));
        assert!(matches!(
            check_after_run(&h, &h, 0, STRICT),
            Err(MigrationError::DbBehindBinary { ref missing, .. }) if missing == &vec![60]
        ));
    }

    #[test]
    fn database_ahead_is_refused_by_default_naming_both_heads_and_the_opt_out() {
        let mut applied = EMBEDDED.to_vec();
        applied.extend([102, 107]);
        let h = compare_schema_heads(&applied, EMBEDDED);
        assert_eq!(h.ahead, vec![102, 107]);
        let err = check_before_run(&h, STRICT).expect_err("must refuse");
        let msg = err.to_string();
        for needle in [
            "107",
            "101",
            ALLOW_DB_AHEAD_FLAG,
            ALLOW_DB_AHEAD_ENV,
            "REFUSING",
        ] {
            assert!(msg.contains(needle), "refusal lacks {needle:?}: {msg}");
        }
        // Ops scripts grep for the success marker anywhere in the output, and
        // `epigraph-migrate` logs this text; it must never contain it.
        assert!(!msg.contains("migrations: ok"), "{msg}");
    }

    #[test]
    fn database_ahead_after_the_run_is_refused_on_a_strict_run() {
        // Review finding 1: the after-run gate used to ignore `opts` and
        // report `db_ahead: true` as success. Strict must refuse whenever the
        // post-run read shows an unknown version, whatever the pre-run read saw.
        let before = compare_schema_heads(EMBEDDED, EMBEDDED);
        let mut applied = EMBEDDED.to_vec();
        applied.push(102);
        let after = compare_schema_heads(&applied, EMBEDDED);
        assert!(matches!(
            check_after_run(&before, &after, 0, STRICT),
            Err(MigrationError::DbAheadOfBinary { ref ahead, .. }) if ahead == &vec![102]
        ));
        let r = check_after_run(&before, &after, 0, ALLOW).expect("opt-in reports");
        assert!(r.db_ahead && r.to_string().contains("db_ahead_of_binary=allowed"));
    }

    #[test]
    fn database_ahead_proceeds_when_opted_in_and_is_reported() {
        let mut applied = EMBEDDED.to_vec();
        applied.push(102);
        let h = compare_schema_heads(&applied, EMBEDDED);
        check_before_run(&h, ALLOW).expect("opt-in proceeds");
        let r = check_after_run(&h, &h, 0, ALLOW).expect("not behind");
        assert!(r.db_ahead);
        assert_eq!((r.db_head, r.binary_head), (102, 101));
        assert!(r.to_string().contains("db_ahead_of_binary=allowed"));
    }

    #[test]
    fn newly_applied_counts_only_embedded_versions_that_were_absent() {
        // Review finding 4: a row another build wrote (102, 95) or that was
        // already there (1, 2) is not a migration this run applied.
        let before = [1, 2, 35];
        let after = [1, 2, 3, 35, 36, 95, 102];
        assert_eq!(newly_applied(&before, &after, EMBEDDED), 2); // 3 and 36
        assert_eq!(newly_applied(&after, &after, EMBEDDED), 0);
        assert_eq!(newly_applied(&[], EMBEDDED, EMBEDDED), EMBEDDED.len());
    }

    #[test]
    fn report_line_carries_both_heads() {
        let r = MigrationReport {
            binary_head: 101,
            db_head_before: Some(59),
            db_head: 101,
            applied_this_run: 42,
            db_ahead: false,
            ahead: Vec::new(),
        };
        assert_eq!(r.to_string(), "db_head=101 binary_head=101 applied=42");
    }

    #[test]
    fn embedded_set_is_nonempty_and_ascending() {
        let v = embedded_migration_versions();
        assert!(v.len() > 50, "embedded set suspiciously small: {}", v.len());
        assert!(v.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn known_foreign_versions_are_not_embedded() {
        // An exemption for a version the binary itself ships would be dead
        // code at best and would hide a real gap at worst.
        let v = embedded_migration_versions();
        for f in KNOWN_FOREIGN_VERSIONS {
            assert!(!v.contains(f), "{f} is embedded; drop it from the list");
        }
    }
}
