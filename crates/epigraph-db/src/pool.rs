//! Database connection pool management.
//!
//! # `ScopedPool` — tenancy at connection checkout (plan §0.5)
//!
//! [`ScopedPool`] is the newtype that owns connection acquisition for
//! tenancy-aware work. It exists because the session GUCs the RLS policies read
//! (`epigraph.group_ids`, `epigraph.writable_group_ids`,
//! `epigraph.principal_id`) must be stamped from the **same** [`Viewer`] value
//! that supplies the in-query `$V` bind, and because the release-time scrub that
//! keeps a recycled connection from carrying one tenant's group set to the next
//! can only be installed at pool-construction time
//! (`PgPoolOptions::after_release`, which `PgPool` exposes no setter for).
//!
//! That second point is why `ScopedPool::connect` builds its own pool rather
//! than wrapping an existing `PgPool`: a scrub that cannot be attached is a
//! security control that exists only in the test suite.
//!
//! ## CLAUDE.md and "all SQL lives in `repos/`"
//!
//! The one statement this module emits — the `set_config` triple — is
//! deliberately here and not under `repos/`. It is not a query against a domain
//! table; it is connection *configuration*, the transport for the predicate the
//! repo layer binds. Putting it in a repository would mean a repository function
//! callable with a `Viewer` different from the one the caller later binds, which
//! is precisely the drift plan §4.5 requirement 1 exists to prevent. Instead it
//! lives in one private function, [`apply_session_gucs`], with no other caller.

use crate::errors::DbError;
use crate::visibility::{MaintenanceLease, SystemReason, Viewer};
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use std::marker::PhantomData;
use std::time::Duration;
use tracing::{info, instrument, warn};

/// Create a PostgreSQL connection pool with default settings
///
/// # Arguments
/// * `database_url` - PostgreSQL connection URL (e.g., "postgres://user:pass@host/db")
///
/// # Errors
/// Returns `DbError::ConnectionFailed` if the connection cannot be established.
#[instrument(skip(database_url))]
pub async fn create_pool(database_url: &str) -> Result<PgPool, DbError> {
    info!("Creating PostgreSQL connection pool");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .map_err(|source| DbError::ConnectionFailed { source })?;

    info!("PostgreSQL connection pool created successfully");
    Ok(pool)
}

/// Create a PostgreSQL connection pool with custom options
///
/// # Arguments
/// * `database_url` - PostgreSQL connection URL
/// * `max_connections` - Maximum number of connections in the pool
/// * `timeout` - Connection acquisition timeout in seconds
///
/// # Errors
/// Returns `DbError::ConnectionFailed` if the connection cannot be established.
#[instrument(skip(database_url))]
pub async fn create_pool_with_options(
    database_url: &str,
    max_connections: u32,
    timeout: u64,
) -> Result<PgPool, DbError> {
    info!(
        max_connections = max_connections,
        timeout_secs = timeout,
        "Creating PostgreSQL connection pool with custom options"
    );

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(timeout))
        .connect(database_url)
        .await
        .map_err(|source| DbError::ConnectionFailed { source })?;

    info!("PostgreSQL connection pool created successfully");
    Ok(pool)
}

/// Create a PostgreSQL connection pool from parsed options
///
/// This allows for more fine-grained control over connection parameters.
///
/// # Errors
/// Returns `DbError::ConnectionFailed` if the connection cannot be established.
#[instrument]
pub async fn create_pool_from_options(
    options: PgConnectOptions,
    max_connections: u32,
) -> Result<PgPool, DbError> {
    info!(
        max_connections = max_connections,
        "Creating PostgreSQL connection pool from options"
    );

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await
        .map_err(|source| DbError::ConnectionFailed { source })?;

    info!("PostgreSQL connection pool created successfully");
    Ok(pool)
}

// =============================================================================
// ScopedPool — plan §0.5
// =============================================================================

/// The three session GUCs the RLS policies (migration 077) read, and the one
/// statement that stamps them. Kept as a `const` so the scrub and both stamping
/// paths are provably the *same* statement.
const SET_SESSION_GUCS: &str = "SELECT set_config('epigraph.group_ids',          $1, $4), \
                                       set_config('epigraph.writable_group_ids', $2, $4), \
                                       set_config('epigraph.principal_id',       $3, $4)";

/// How a [`ScopedPool`] carries tenancy context to the database.
///
/// The default, [`SessionGucMode::Session`], is the fast path: one extra
/// statement at checkout and none afterwards, so an ordinary pooled `SELECT`
/// keeps working exactly as plan §4.3 describes.
///
/// [`SessionGucMode::Transaction`] is the supported, costed fallback for a
/// deployment behind a transaction-mode pooler (pgbouncer `pool_mode =
/// transaction`, RDS Proxy pinning off), where a session-scoped `set_config`
/// does not survive to the next statement. Every read then runs inside
/// [`ScopedPool::begin_as`], at a cost of two extra round trips (`BEGIN` plus
/// `COMMIT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionGucMode {
    /// Session-scoped `set_config`, stamped once at checkout.
    Session,
    /// Transaction-scoped `set_config`; every scoped statement runs in a
    /// transaction.
    Transaction,
}

impl SessionGucMode {
    /// Parse `EPIGRAPH_SESSION_GUC_MODE`.
    ///
    /// Only the exact value `transaction` (case-insensitive, trimmed) selects
    /// the fallback. Anything else — including unset, empty, and a typo —
    /// selects [`SessionGucMode::Session`], whose boot probe then *proves*
    /// whether the choice was right. Failing open to the slow-but-always-correct
    /// mode on a typo would be worse: it would hide the misconfiguration behind
    /// a permanent latency cost nobody attributes.
    #[must_use]
    pub fn from_env(raw: &str) -> Self {
        if raw.trim().eq_ignore_ascii_case("transaction") {
            Self::Transaction
        } else {
            Self::Session
        }
    }
}

/// Render a group set as the comma-joined text form the GUC carries.
fn join_uuids(ids: Option<&[uuid::Uuid]>) -> String {
    ids.unwrap_or(&[])
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Stamp the three session GUCs from **this** viewer.
///
/// Plan §4.5 requirement 1 is enforced structurally rather than by review: this
/// function is private, takes the `&Viewer` itself, and has exactly two callers
/// ([`ScopedPool::acquire_as`] and [`ScopedPool::begin_as`]), so a `Viewer`
/// cannot be constructed and a connection then stamped from a different one.
///
/// `is_local = true` is a **silent no-op outside a transaction block**, which is
/// why `begin_as` verifies its effect in debug builds.
async fn apply_session_gucs(
    conn: &mut PgConnection,
    v: &Viewer,
    is_local: bool,
) -> Result<(), DbError> {
    sqlx::query(SET_SESSION_GUCS)
        .bind(join_uuids(v.group_bind()))
        .bind(join_uuids(v.writable_bind()))
        .bind(v.principal().map(|p| p.to_string()).unwrap_or_default())
        .bind(is_local)
        .execute(conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
    Ok(())
}

/// A pool that hands out connections already stamped with a [`Viewer`]'s
/// tenancy context, and scrubs them on release.
///
/// See the [module documentation](self) for why this type owns pool
/// construction instead of wrapping an existing [`PgPool`].
#[derive(Clone, Debug)]
pub struct ScopedPool {
    inner: PgPool,
    mode: SessionGucMode,
}

impl ScopedPool {
    /// Build the pool, installing the release scrub.
    ///
    /// The scrub is the single mechanism standing between a recycled connection
    /// and a cross-tenant read, and `PgPoolOptions::after_release` can only be
    /// installed at build time — hence this constructor rather than a wrapper
    /// around a pool someone else built.
    ///
    /// ## Pool sizing is deliberately sqlx's default, not this crate's
    ///
    /// `max_connections = 10` and `acquire_timeout = 30s` are the values
    /// `PgPool::connect` uses, and `bin/server.rs` called exactly that before
    /// PR-04. This constructor exists to install a *security* hook; changing the
    /// API's availability characteristics in the same hunk would be an
    /// unreviewable second decision. In particular it does **not** copy
    /// [`create_pool`]'s 5-second acquire timeout, which would have made a
    /// saturated server surface `PoolTimedOut` six times sooner than the day
    /// before. PR-15 threads `EPIGRAPH_DB_*` through so these become deployment
    /// decisions rather than constants.
    ///
    /// # Errors
    /// Returns `DbError::ConnectionFailed` if the pool cannot be established.
    #[instrument(skip(database_url))]
    pub async fn connect(database_url: &str, mode: SessionGucMode) -> Result<Self, DbError> {
        let inner = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(30))
            .after_release(|conn, _meta| {
                Box::pin(async move {
                    // The identical triple, three empty strings, session scope.
                    // `Ok(false)` makes sqlx CLOSE the connection instead of
                    // returning it to the pool: a connection whose group set we
                    // failed to clear must never be reused.
                    match sqlx::query(SET_SESSION_GUCS)
                        .bind("")
                        .bind("")
                        .bind("")
                        .bind(false)
                        .execute(&mut *conn)
                        .await
                    {
                        Ok(_) => Ok(true),
                        Err(e) => {
                            warn!(
                                error = %e,
                                "failed to scrub tenancy GUCs on release; closing the connection"
                            );
                            Ok(false)
                        }
                    }
                })
            })
            .connect(database_url)
            .await
            .map_err(|source| DbError::ConnectionFailed { source })?;

        info!(mode = ?mode, "ScopedPool created");
        Ok(Self { inner, mode })
    }

    /// The underlying pool.
    ///
    /// Present so PR-06/PR-07 call sites can migrate incrementally rather than
    /// in one commit. A connection taken from here carries **no** tenancy
    /// context; it is not a scoped acquire.
    #[must_use]
    pub const fn inner(&self) -> &PgPool {
        &self.inner
    }

    /// Which mechanism this pool uses to carry tenancy context.
    #[must_use]
    pub const fn mode(&self) -> SessionGucMode {
        self.mode
    }

    /// PRIMARY mechanism: acquire a connection and stamp it from `v`, in one
    /// extra statement and no transaction.
    ///
    /// # Errors
    /// * `DbError::InvalidData` if `v` is a bypass viewer — a bypass belongs on
    ///   [`Self::unscoped_for_maintenance`], because it emits no predicate and
    ///   would therefore read **zero** rows, not all rows, once RLS is FORCEd.
    /// * `DbError::InvalidData` if this pool is in
    ///   [`SessionGucMode::Transaction`], where a session-scoped `set_config`
    ///   does not survive to the next statement.
    /// * `DbError::ConnectionFailed` / `DbError::QueryFailed` on the acquire or
    ///   the stamp.
    pub async fn acquire_as(&self, v: &Viewer) -> Result<ScopedConn<'_>, DbError> {
        if v.is_bypass() {
            return Err(DbError::InvalidData {
                reason: "acquire_as refuses a Bypass viewer: an unrestricted viewer must come \
                         from ScopedPool::unscoped_for_maintenance, on a maintenance connection. \
                         A Bypass viewer on an application connection emits no predicate but is \
                         still filtered by RLS, so it returns zero rows, not all rows."
                    .to_string(),
            });
        }
        if self.mode == SessionGucMode::Transaction {
            return Err(DbError::InvalidData {
                reason: "EPIGRAPH_SESSION_GUC_MODE=transaction: session-scoped GUCs do not \
                         survive between statements behind a transaction-mode pooler. Use \
                         ScopedPool::begin_as instead."
                    .to_string(),
            });
        }

        let mut conn = self
            .inner
            .acquire()
            .await
            .map_err(|source| DbError::ConnectionFailed { source })?;
        apply_session_gucs(&mut conn, v, false).await?;
        Ok(ScopedConn(conn, PhantomData))
    }

    /// Transactional variant: `BEGIN`, then the identical triple with
    /// `is_local = true`.
    ///
    /// Required in [`SessionGucMode::Transaction`], and correct in either mode
    /// for writes and for anything that must be atomic.
    ///
    /// # Errors
    /// * `DbError::InvalidData` if `v` is a bypass viewer (see
    ///   [`Self::acquire_as`]).
    /// * `DbError::ConnectionFailed` / `DbError::QueryFailed` on `BEGIN` or the
    ///   stamp.
    ///
    /// # Panics
    /// In debug builds only, if the transaction-scoped `set_config` did not
    /// survive to a second statement — i.e. if the handle was somehow not inside
    /// a transaction block, where `set_config(…, true)` is a silent no-op
    /// (plan §4.5 requirement 2).
    pub async fn begin_as(&self, v: &Viewer) -> Result<ScopedTx<'_>, DbError> {
        if v.is_bypass() {
            return Err(DbError::InvalidData {
                reason: "begin_as refuses a Bypass viewer: an unrestricted viewer must come from \
                         ScopedPool::unscoped_for_maintenance, on a maintenance connection."
                    .to_string(),
            });
        }

        let mut tx = self
            .inner
            .begin()
            .await
            .map_err(|source| DbError::ConnectionFailed { source })?;
        apply_session_gucs(&mut tx, v, true).await?;

        // Plan §4.5 requirement 2. `set_config(…, is_local = true)` outside a
        // transaction block sets the value for the duration of the *implicit*
        // transaction — i.e. that one statement — and is invisible to the next.
        // Reading it back AS A SECOND STATEMENT is therefore a genuine test that
        // we are inside a transaction, not a restatement of the type.
        #[cfg(debug_assertions)]
        {
            let observed: (String,) =
                sqlx::query_as("SELECT current_setting('epigraph.principal_id', true)")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|source| DbError::QueryFailed { source })?;
            let expected = v.principal().map(|p| p.to_string()).unwrap_or_default();
            debug_assert_eq!(
                observed.0, expected,
                "begin_as: the transaction-scoped session GUCs did not survive to a second \
                 statement. set_config(…, is_local = true) is a silent no-op outside a \
                 transaction block, so this handle is not in one."
            );
        }

        Ok(ScopedTx(tx, PhantomData))
    }

    /// The maintenance escape hatch: an unstamped connection plus the
    /// [`MaintenanceLease`] that [`Viewer::system`] requires.
    ///
    /// `async` because it acquires a connection. (Plan §0.5 sketches this as a
    /// synchronous `fn`, which cannot.)
    ///
    /// **Known limitation until PR-15.** This draws from the same application
    /// pool. Between PR-04 and PR-17 that is harmless because no RLS policy is
    /// ENABLEd. From PR-17 on it is unsound in exactly the way plan §4.3 warns:
    /// a bypass viewer emits no predicate but the policy still filters, so it
    /// returns zero rows. PR-15 repoints this at `MAINTENANCE_DATABASE_URL`,
    /// and **must land before PR-17**. The lease makes the coupling unforgeable;
    /// it does not make the connection privileged.
    ///
    /// # Errors
    /// Returns `DbError::ConnectionFailed` if the connection cannot be acquired.
    pub async fn unscoped_for_maintenance(
        &self,
        r: SystemReason,
    ) -> Result<(MaintenanceConn<'_>, MaintenanceLease), DbError> {
        let conn = self
            .inner
            .acquire()
            .await
            .map_err(|source| DbError::ConnectionFailed { source })?;
        // Every bypass is logged at the point it is granted, with the closed-set
        // reason as the metric dimension.
        tracing::info!(reason = r.as_str(), "maintenance connection issued");
        Ok((MaintenanceConn(conn, PhantomData), MaintenanceLease::new()))
    }

    /// The plan §0.5 boot probe: prove session GUCs survive between statements
    /// on one pooled connection, and prove the release scrub clears them.
    ///
    /// Lives here rather than on `AppState` because `AppState::with_db` is
    /// synchronous and receives a possibly-lazy pool — the same wall PR-02 hit,
    /// and the reason `load_entity_type_cache` is a separate async call.
    ///
    /// ## Why it stamps the REAL three, and not a scratch GUC
    ///
    /// An earlier draft set `epigraph.probe` in the first half and then checked
    /// that the three tenancy GUCs were empty in the second. That second check
    /// was **vacuous**: nothing in this pool had ever set those three, so they
    /// read empty whether or not `after_release` was installed, and the "scrub
    /// is not running" branch was unreachable. The probe now stamps
    /// [`PROBE_SENTINEL`] into all three through the *same* [`SET_SESSION_GUCS`]
    /// statement the request path uses, so the emptiness check after release is
    /// a genuine observation about the scrub.
    ///
    /// # Errors
    /// Returns `DbError::InvalidData` naming `EPIGRAPH_SESSION_GUC_MODE=transaction`
    /// if a value set on one statement is not visible to the next (a
    /// transaction-mode pooler), or if a freshly acquired connection still
    /// carries a previous checkout's value (the scrub is not running).
    pub async fn probe_session_gucs(&self) -> Result<(), DbError> {
        let persisted = {
            let mut conn = self
                .inner
                .acquire()
                .await
                .map_err(|source| DbError::ConnectionFailed { source })?;

            // THE PRODUCTION STATEMENT, with a sentinel payload. Using
            // SET_SESSION_GUCS rather than a bespoke `set_config` is the point:
            // the probe proves the mechanism the request path actually uses.
            sqlx::query(SET_SESSION_GUCS)
                .bind(PROBE_SENTINEL)
                .bind(PROBE_SENTINEL)
                .bind(PROBE_SENTINEL)
                .bind(false)
                .execute(&mut *conn)
                .await
                .map_err(|source| DbError::QueryFailed { source })?;

            // A SECOND statement on the same handle. This is the persistence half.
            let observed: (String,) = sqlx::query_as(READ_SESSION_GUCS)
                .fetch_one(&mut *conn)
                .await
                .map_err(|source| DbError::QueryFailed { source })?;
            observed.0
        }; // drop -> release -> the after_release scrub runs

        // Second half: the SAME three GUCs, on a fresh checkout, must be empty.
        // Non-vacuous precisely because the block above set them.
        let mut conn = self
            .inner
            .acquire()
            .await
            .map_err(|source| DbError::ConnectionFailed { source })?;
        let after: (String,) = sqlx::query_as(READ_SESSION_GUCS)
            .fetch_one(&mut *conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;

        probe_verdict(&persisted, &after.0)?;

        info!("session-GUC probe passed: GUCs persist per statement and are scrubbed on release");
        Ok(())
    }
}

/// The sentinel the boot probe stamps into the three tenancy GUCs. A valid UUID
/// (so `epigraph_principal_id()` would parse it) that is not, and must never
/// be, a real group or principal.
const PROBE_SENTINEL: &str = "00000000-0000-0000-0000-00000000b0be";

/// Reads all three tenancy GUCs back as one concatenated string. Shared by both
/// halves of the probe so they observe exactly the same thing.
const READ_SESSION_GUCS: &str = "SELECT COALESCE(current_setting('epigraph.group_ids', true), '') \
     || COALESCE(current_setting('epigraph.writable_group_ids', true), '') \
     || COALESCE(current_setting('epigraph.principal_id', true), '')";

/// The boot probe's verdict, factored out of the I/O.
///
/// The message is the artifact an on-call operator acts on, and the *refusal*
/// path cannot be exercised in this repo's CI (there is no pgbouncer fixture —
/// blocked measurement M5). Making the verdict a pure function means at least
/// the diagnosis and the remedy it names are covered by a unit test; only the
/// pooler's behaviour remains unproven.
fn probe_verdict(persisted: &str, after_release: &str) -> Result<(), DbError> {
    let expected: String = PROBE_SENTINEL.repeat(3);
    if persisted != expected {
        return Err(DbError::InvalidData {
            reason: format!(
                "session GUCs do not survive between statements on one pooled connection \
                 (stamped {expected:?}, read back {persisted:?}). This deployment is behind a \
                 transaction-mode pooler. Set EPIGRAPH_SESSION_GUC_MODE=transaction to switch \
                 every read to begin_as, or point DATABASE_URL at a session-mode endpoint."
            ),
        });
    }
    if !after_release.is_empty() {
        return Err(DbError::InvalidData {
            reason: format!(
                "a freshly acquired connection still carries tenancy GUCs ({after_release:?}). \
                 The after_release scrub is not running, which means a recycled connection can \
                 carry one principal's group set into another's request. Refusing to serve. If \
                 this deployment is behind a transaction-mode pooler, set \
                 EPIGRAPH_SESSION_GUC_MODE=transaction."
            ),
        });
    }
    Ok(())
}

/// A pooled connection stamped with a [`Viewer`]'s tenancy context.
///
/// The lifetime is tied to the [`ScopedPool`] it came from, so a stamped
/// connection cannot outlive the pool whose scrub is responsible for clearing
/// it.
pub struct ScopedConn<'a>(PoolConnection<Postgres>, PhantomData<&'a ()>);

// Opaque `Debug`, deliberately. `PoolConnection` has no `Debug` of its own, and
// a derived one would be a way to print a connection carrying a principal's
// group set into a log line. The impl exists so `Result<ScopedConn, _>` supports
// `expect_err` in tests.
impl std::fmt::Debug for ScopedConn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopedConn")
    }
}

impl std::ops::Deref for ScopedConn<'_> {
    type Target = PgConnection;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ScopedConn<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A transaction whose session GUCs are stamped transaction-locally.
pub struct ScopedTx<'a>(Transaction<'static, Postgres>, PhantomData<&'a ()>);

impl std::fmt::Debug for ScopedTx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopedTx")
    }
}

impl ScopedTx<'_> {
    /// Commit the transaction.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the commit fails.
    pub async fn commit(self) -> Result<(), DbError> {
        self.0
            .commit()
            .await
            .map_err(|source| DbError::QueryFailed { source })
    }

    /// Roll the transaction back.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the rollback fails.
    pub async fn rollback(self) -> Result<(), DbError> {
        self.0
            .rollback()
            .await
            .map_err(|source| DbError::QueryFailed { source })
    }
}

impl std::ops::Deref for ScopedTx<'_> {
    type Target = PgConnection;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ScopedTx<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// An UNSTAMPED connection, handed out together with a [`MaintenanceLease`].
///
/// Distinct from [`ScopedConn`] at the type level so a maintenance connection
/// and a scoped one are never interchangeable at a call site.
pub struct MaintenanceConn<'a>(PoolConnection<Postgres>, PhantomData<&'a ()>);

impl std::fmt::Debug for MaintenanceConn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MaintenanceConn")
    }
}

impl std::ops::Deref for MaintenanceConn<'_> {
    type Target = PgConnection;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for MaintenanceConn<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_pool_requires_valid_url() {
        let result = create_pool("invalid://url").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_pool_with_options() {
        let result = create_pool_with_options("invalid://url", 5, 3).await;
        assert!(result.is_err());
    }

    // ---- boot-probe verdict (plan §0.5) ------------------------------------
    //
    // The REFUSAL half of the probe is blocked measurement M5: there is no
    // pgbouncer-in-transaction-mode fixture in this repo. Splitting the verdict
    // out of the I/O lets the diagnosis and the remedy it names be covered
    // here, leaving only the pooler's behaviour unproven.

    #[test]
    fn probe_verdict_accepts_a_session_mode_observation() {
        let stamped = PROBE_SENTINEL.repeat(3);
        assert!(probe_verdict(&stamped, "").is_ok());
    }

    #[test]
    fn probe_verdict_refuses_when_gucs_do_not_persist() {
        // What a transaction-mode pooler produces: the stamp is discarded with
        // the implicit transaction, so the second statement reads three empties.
        let err = probe_verdict("", "").expect_err("a lost stamp must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("EPIGRAPH_SESSION_GUC_MODE=transaction"),
            "the refusal must name the remedy env var: {msg}"
        );
        assert!(
            msg.contains("transaction-mode pooler"),
            "the refusal must name the diagnosis: {msg}"
        );
    }

    #[test]
    fn probe_verdict_refuses_when_the_scrub_did_not_run() {
        let stamped = PROBE_SENTINEL.repeat(3);
        let err = probe_verdict(&stamped, &stamped).expect_err("a live scrub must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("after_release scrub is not running"),
            "the refusal must name the scrub: {msg}"
        );
    }

    /// The persistence check must be checked BEFORE the scrub check: behind a
    /// transaction-mode pooler both observations are empty, and reporting
    /// "the scrub is not running" would send an operator after the wrong thing.
    #[test]
    fn probe_verdict_diagnoses_a_pooler_before_a_missing_scrub() {
        let err = probe_verdict("", "").expect_err("must refuse");
        assert!(
            !err.to_string().contains("after_release scrub is not running"),
            "an all-empty observation is a pooler, not a scrub failure"
        );
    }
}
