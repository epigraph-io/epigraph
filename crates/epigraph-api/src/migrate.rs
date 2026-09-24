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
//! * **before** running: if the database's applied head is ABOVE the binary's
//!   embedded head, refuse — unless the caller opted in with
//!   [`MigrateOptions::allow_db_ahead`] (the rollback case). The refusal
//!   happens before anything is applied, because a stale binary against a newer
//!   database can still apply an older embedded migration the database lacks.
//! * **after** running: every embedded (up) migration must be recorded in
//!   `_sqlx_migrations` with `success = true`. This is a SET check, not
//!   `max >= head`, so a gap under a present head cannot hide.
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

/// Environment variable that opts in to running against a database whose
/// applied head is above this binary's embedded head. Parsed with the same
/// trim/case-fold rule as `EPIGRAPH_MIGRATE_ON_BOOT` (`1`/`true`/`yes`).
pub const ALLOW_DB_AHEAD_ENV: &str = "EPIGRAPH_MIGRATE_ALLOW_DB_AHEAD";

/// `epigraph-migrate` command-line spelling of the same opt-in.
pub const ALLOW_DB_AHEAD_FLAG: &str = "--allow-db-ahead";

/// Caller policy for [`run_migrations`].
///
/// `Default` is the strict policy: a database ahead of the binary is refused.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MigrateOptions {
    /// Proceed (with a WARN) when the database's applied head is above this
    /// binary's embedded head. Meant for a deliberate rollback to an older
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
    /// Successfully applied versions above `binary_head` — the migrations a
    /// newer build applied that this binary knows nothing about.
    pub ahead: Vec<i64>,
}

impl SchemaHeads {
    /// The database has applied a migration above this binary's head.
    #[must_use]
    pub fn db_ahead(&self) -> bool {
        !self.ahead.is_empty()
    }
}

/// Pure comparison of the applied set against the embedded set.
///
/// `applied_ok` must hold only versions whose row has `success = true`.
/// Versions below `binary_head` that the binary does not embed (e.g. prod's
/// `epigraph-internal` version 035, see `migrations/README.md`) are neither
/// `missing` nor `ahead`: they are the gap `set_ignore_missing(true)` exists to
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
        ahead: applied.range(binary_head + 1..).copied().collect(),
    }
}

/// Why [`run_migrations`] refused or failed.
#[derive(Debug)]
pub enum MigrationError {
    /// Reading `_sqlx_migrations` failed.
    Query(sqlx::Error),
    /// `sqlx::migrate::Migrator::run` failed (checksum mismatch, dirty
    /// version, a migration that RAISEd, ...).
    Migrate(sqlx::migrate::MigrateError),
    /// The database has applied migrations this binary does not embed. Nothing
    /// was applied.
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
                "REFUSING: database schema head is {db_head} but this binary embeds migrations \
                 only up to {binary_head} ({n} applied version(s) unknown to it: {ahead:?}). \
                 This binary is older than the schema, and a stale build must not report \
                 success. Deploy a binary built from the revision that applied \
                 {db_head}. If this is a DELIBERATE rollback to an older build, re-run with \
                 {ALLOW_DB_AHEAD_FLAG} (epigraph-migrate) or {ALLOW_DB_AHEAD_ENV}=1 (any \
                 entry point); pending migrations at or below {binary_head} are then applied \
                 and the newer ones are left in place.",
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
    /// Migrations this run applied.
    pub applied_this_run: usize,
    /// The database was ahead of the binary and the caller opted in.
    pub db_ahead: bool,
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

/// Gate evaluated BEFORE `Migrator::run`: refuse a database ahead of the
/// binary unless `opts.allow_db_ahead`.
pub fn check_before_run(heads: &SchemaHeads, opts: MigrateOptions) -> Result<(), MigrationError> {
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

/// Gate evaluated AFTER `Migrator::run`: every embedded migration must be
/// recorded as successfully applied.
pub fn check_after_run(
    before: &SchemaHeads,
    after: &SchemaHeads,
    applied_this_run: usize,
) -> Result<MigrationReport, MigrationError> {
    match after.db_head {
        Some(db_head) if after.missing.is_empty() && db_head >= after.binary_head => {
            Ok(MigrationReport {
                binary_head: after.binary_head,
                db_head_before: before.db_head,
                db_head,
                applied_this_run,
                db_ahead: after.db_ahead(),
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
///    build migrated means the database holds versions above this binary's
///    head. Without the flag sqlx rejects that with `VersionMissing` before the
///    [`MigrateOptions::allow_db_ahead`] opt-in could ever take effect.
///
/// What the flag no longer does is make the database-ahead case SILENT: that
/// is [`check_before_run`]'s job, which refuses it by default. (A database that
/// ever ran `epigraph-internal`'s 060–112 therefore now trips the refusal —
/// intended: `migrations/README.md` calls that version space a minefield.)
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
async fn applied_versions(pool: &epigraph_db::PgPool) -> Result<Vec<i64>, sqlx::Error> {
    let exists: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
        .fetch_one(pool)
        .await?;
    if !exists {
        return Ok(Vec::new());
    }
    sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
        .fetch_all(pool)
        .await
}

/// Apply all pending embedded migrations, then prove the database reached this
/// binary's head.
///
/// Refuses (before applying anything) when the database is ahead of the
/// binary, unless `opts.allow_db_ahead`; fails when, after running, any
/// embedded migration is not recorded as applied. On success the returned
/// [`MigrationReport`] names both heads — callers log it rather than a bare
/// "ok".
///
/// The pre-run read is outside sqlx's advisory lock. A concurrent migrator can
/// only move the head UP between that read and `run`, which the post-run check
/// re-reads, so the race cannot produce a false success.
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
    let embedded = versions_of(migrator);

    let applied_before = applied_versions(pool)
        .await
        .map_err(MigrationError::Query)?;
    let before = compare_schema_heads(&applied_before, &embedded);
    check_before_run(&before, opts)?;
    if before.db_ahead() {
        tracing::warn!(
            db_head = before.db_head,
            binary_head = before.binary_head,
            ahead = ?before.ahead,
            "database schema is AHEAD of this binary; proceeding because {} / {} opted in \
             (rollback case). This binary does not know the schema it is running against.",
            ALLOW_DB_AHEAD_FLAG,
            ALLOW_DB_AHEAD_ENV,
        );
    }

    migrator.run(pool).await.map_err(MigrationError::Migrate)?;

    let applied_after = applied_versions(pool)
        .await
        .map_err(MigrationError::Query)?;
    let after = compare_schema_heads(&applied_after, &embedded);
    let before_set: BTreeSet<i64> = applied_before.into_iter().collect();
    let applied_this_run = applied_after
        .iter()
        .filter(|v| !before_set.contains(v))
        .count();
    check_after_run(&before, &after, applied_this_run)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMBEDDED: &[i64] = &[1, 2, 3, 36, 37, 38, 59, 60, 101];

    #[test]
    fn fresh_database_is_missing_everything_and_not_ahead() {
        let h = compare_schema_heads(&[], EMBEDDED);
        assert_eq!(h.binary_head, 101);
        assert_eq!(h.db_head, None);
        assert_eq!(h.missing, EMBEDDED.to_vec());
        assert!(!h.db_ahead());
        check_before_run(&h, MigrateOptions::default()).expect("fresh DB is not ahead");
    }

    #[test]
    fn unknown_version_below_head_is_a_tolerated_gap() {
        // prod's epigraph-internal 035: applied, not embedded, below the head.
        let mut applied = EMBEDDED.to_vec();
        applied.push(35);
        let h = compare_schema_heads(&applied, EMBEDDED);
        assert!(h.missing.is_empty());
        assert!(!h.db_ahead(), "035 is below the head, not ahead: {h:?}");
        check_before_run(&h, MigrateOptions::default()).expect("gap is tolerated");
        let r = check_after_run(&h, &h, 0).expect("at head");
        assert_eq!((r.db_head, r.binary_head, r.db_ahead), (101, 101, false));
    }

    #[test]
    fn stale_head_reached_is_behind_and_refused_after_run() {
        // The #492 measurement: the database stops at 59 while the binary
        // embeds up to 101. A successful Migrator::run cannot produce this
        // against a real database, so this is the only proof the floor bites.
        let before = compare_schema_heads(&[], EMBEDDED);
        let after = compare_schema_heads(&[1, 2, 3, 36, 37, 38, 59], EMBEDDED);
        assert_eq!(after.missing, vec![60, 101]);
        let err = check_after_run(&before, &after, 7).expect_err("behind must fail");
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
            check_after_run(&h, &h, 0),
            Err(MigrationError::DbBehindBinary { ref missing, .. }) if missing == &vec![60]
        ));
    }

    #[test]
    fn database_ahead_is_refused_by_default_naming_both_heads_and_the_opt_out() {
        let mut applied = EMBEDDED.to_vec();
        applied.extend([102, 107]);
        let h = compare_schema_heads(&applied, EMBEDDED);
        assert_eq!(h.ahead, vec![102, 107]);
        let err = check_before_run(&h, MigrateOptions::default()).expect_err("must refuse");
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
    fn database_ahead_proceeds_when_opted_in_and_is_reported() {
        let mut applied = EMBEDDED.to_vec();
        applied.push(102);
        let h = compare_schema_heads(&applied, EMBEDDED);
        check_before_run(
            &h,
            MigrateOptions {
                allow_db_ahead: true,
            },
        )
        .expect("opt-in proceeds");
        let r = check_after_run(&h, &h, 0).expect("not behind");
        assert!(r.db_ahead);
        assert_eq!((r.db_head, r.binary_head), (102, 101));
        assert!(r.to_string().contains("db_ahead_of_binary=allowed"));
    }

    #[test]
    fn report_line_carries_both_heads() {
        let r = MigrationReport {
            binary_head: 101,
            db_head_before: Some(59),
            db_head: 101,
            applied_this_run: 42,
            db_ahead: false,
        };
        assert_eq!(r.to_string(), "db_head=101 binary_head=101 applied=42");
    }

    #[test]
    fn embedded_set_is_nonempty_and_ascending() {
        let v = embedded_migration_versions();
        assert!(v.len() > 50, "embedded set suspiciously small: {}", v.len());
        assert!(v.windows(2).all(|w| w[0] < w[1]));
    }
}
