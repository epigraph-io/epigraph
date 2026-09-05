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
use std::str::FromStr;
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
// The maintenance DSN — plan PR-15
// =============================================================================

/// The environment variable naming the connection every background writer must
/// use once RLS is FORCEd (PR-17).
pub const MAINTENANCE_DATABASE_URL: &str = "MAINTENANCE_DATABASE_URL";

/// Where [`maintenance_database_url`] got its answer.
///
/// Carried rather than discarded because the two cases have different
/// consequences under FORCE, and the difference must reach the log line and the
/// verdict rather than being flattened at the call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintenanceDsnSource {
    /// `MAINTENANCE_DATABASE_URL` was set and used.
    Configured,
    /// `MAINTENANCE_DATABASE_URL` was unset or empty; the application DSN is
    /// being reused. Correct only while no protected table is FORCEd.
    FellBackToApplicationDsn,
}

impl MaintenanceDsnSource {
    /// A stable label for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            MaintenanceDsnSource::Configured => "maintenance_database_url",
            MaintenanceDsnSource::FellBackToApplicationDsn => "database_url_fallback",
        }
    }
}

/// Resolve the DSN a background writer should connect on.
///
/// `MAINTENANCE_DATABASE_URL` if set; otherwise `app_url` with a WARN. The
/// fallback is deliberately *not* dead code and deliberately *not* silent: a
/// hard refusal here would brick every background writer on any cluster where
/// migration 060's `CREATE ROLE` only `RAISE NOTICE`d (060 downgrades
/// `insufficient_privilege` to a notice), and a silent fallback is how a
/// maintenance job ends up on an application connection without anyone
/// noticing. The refusal lives in [`maintenance_verdict`] instead, where it is
/// conditioned on RLS actually being FORCEd — see that function for the rule
/// and why it was chosen over an unconditional `epigraph_bypass()` assertion.
///
/// ## The database-name guard, and exactly what it does and does not cover
///
/// A maintenance DSN that points at a *different database* than the
/// application DSN is the worst outcome available: every read succeeds and
/// returns nothing, every write succeeds and lands nowhere. That is the same
/// vacuous-green shape a bypass viewer on an unprivileged connection produces,
/// relocated into configuration. It is also the realistic accident — an
/// operator (or an inherited environment in a test harness) exporting one
/// variable globally while `DATABASE_URL` varies per process. So the two DSNs
/// must name the same **effective database**, and disagreement is a hard error.
///
/// The name is the only axis that refuses. HOST and PORT are compared too, but
/// they only WARN, and the asymmetry is deliberate rather than an oversight:
/// `localhost` / `127.0.0.1` / a container DNS name / a unix-socket DSN
/// routinely denote the same server, so a host-equality *refusal* would
/// boot-fail correctly-configured deployments — a self-inflicted outage to
/// prevent a misconfiguration. A same-name/different-cluster DSN (a
/// `MAINTENANCE_DATABASE_URL` copy-pasted from staging while `DATABASE_URL`
/// points at production; every environment names its database `epigraph`)
/// therefore produces a warning naming both endpoints, not a refusal. That
/// residual is stated rather than papered over.
///
/// # Errors
/// `DbError::InvalidData` if either DSN is unparseable, or if the two name
/// different databases.
pub fn maintenance_database_url(app_url: &str) -> Result<(String, MaintenanceDsnSource), DbError> {
    let configured = std::env::var(MAINTENANCE_DATABASE_URL).ok();
    resolve_maintenance_url(app_url, configured.as_deref())
}

/// [`maintenance_database_url`] with the environment read already done.
///
/// Separated so the resolution rule — including the database-name guard, whose
/// whole job is to refuse a misconfiguration — is testable without a test
/// mutating a process-global that every other test in the binary shares.
///
/// # Errors
/// See [`maintenance_database_url`].
pub fn resolve_maintenance_url(
    app_url: &str,
    configured: Option<&str>,
) -> Result<(String, MaintenanceDsnSource), DbError> {
    // An exported-but-empty variable is a container default, not a decision.
    let configured = configured.filter(|v| !v.trim().is_empty());

    let Some(maintenance_url) = configured else {
        warn!(
            "{MAINTENANCE_DATABASE_URL} is not set; background writes will run on the \
             application DSN. That is correct only while no protected table has FORCE ROW \
             LEVEL SECURITY: from PR-17 on, an unprivileged connection makes a bypass viewer \
             read zero rows and write nothing, with no error. Set \
             {MAINTENANCE_DATABASE_URL} before enabling FORCE."
        );
        return Ok((
            app_url.to_string(),
            MaintenanceDsnSource::FellBackToApplicationDsn,
        ));
    };

    // The EFFECTIVE database, not the written one. A DSN with no path — e.g.
    // `postgres://epigraph_admin:pw@host:5432` — carries `database = None`, and
    // both libpq and sqlx then connect to a database named after the *user*. So
    // two pathless DSNs differing only in role name would compare equal here
    // (None == None) while connecting to two different databases, which is
    // exactly the silent misdirection this guard exists to catch. Resolving the
    // default the same way the driver does closes that.
    let parse = |url: &str, which: &str| -> Result<PgConnectOptions, DbError> {
        PgConnectOptions::from_str(url).map_err(|e| DbError::InvalidData {
            reason: format!("{which} is not a parseable PostgreSQL DSN: {e}"),
        })
    };
    let db_of = |opts: &PgConnectOptions| -> String {
        opts.get_database()
            .unwrap_or_else(|| opts.get_username())
            .to_string()
    };

    let app_opts = parse(app_url, "the application DSN")?;
    let maint_opts = parse(maintenance_url, MAINTENANCE_DATABASE_URL)?;
    let app_db = db_of(&app_opts);
    let maint_db = db_of(&maint_opts);

    if app_db != maint_db {
        return Err(DbError::InvalidData {
            reason: format!(
                "{MAINTENANCE_DATABASE_URL} names database {maint_db:?} but the application \
                 DSN names {app_db:?}. A maintenance connection to a different database does \
                 not error — it reads zero rows and writes nowhere. Refusing to start. Point \
                 both at the same database and vary only the role."
            ),
        });
    }

    // Same database NAME, possibly a different SERVER. The endpoint axis WARNS
    // and does not refuse — see the documentation on `maintenance_database_url`
    // for why the two axes are not treated alike. Loopback spellings are folded
    // together first, because `localhost` vs `127.0.0.1` is a spelling
    // difference, not a cluster difference, and warning on it would train
    // operators to ignore the line.
    let app_endpoint = normalized_endpoint(&app_opts);
    let maint_endpoint = normalized_endpoint(&maint_opts);
    if app_endpoint != maint_endpoint {
        warn!(
            "{MAINTENANCE_DATABASE_URL} points at {}:{} but the application DSN points at \
             {}:{}. Both name database {maint_db:?}, so this is not refused — but a maintenance \
             connection to a same-named database on a DIFFERENT cluster reads and writes rows \
             nobody is looking at, without erroring. Confirm this is intended.",
            maint_endpoint.0, maint_endpoint.1, app_endpoint.0, app_endpoint.1,
        );
    }

    Ok((
        maintenance_url.to_string(),
        MaintenanceDsnSource::Configured,
    ))
}

/// The server a DSN denotes, with loopback spellings folded together.
///
/// `localhost`, `127.0.0.1` and `::1` are the same server written three ways,
/// and a divergence warning that fires on ordinary local configuration is a
/// warning operators learn to skip. Pulled out of [`resolve_maintenance_url`]
/// so the folding rule is testable without a DSN round trip.
fn normalized_endpoint(opts: &PgConnectOptions) -> (String, u16) {
    let host = match opts.get_host() {
        // `[::1]` WITH the brackets, and that is a measurement rather than
        // defensiveness: `PgConnectOptions::from_str` keeps the RFC 3986
        // bracket form an IPv6 authority must be written in, so `get_host()`
        // returns `[::1]` and a bare `"::1"` arm never matches. The
        // bare spelling is kept for a DSN built programmatically via
        // `PgConnectOptions::new().host("::1")`, which does not add them.
        "localhost" | "127.0.0.1" | "::1" | "[::1]" => "localhost",
        h => h,
    };
    (host.to_string(), opts.get_port())
}

/// What a connection actually observed about its own maintenance privilege.
///
/// Split from the verdict so the I/O and the decision can be tested
/// separately — the same reason [`probe_verdict`] exists. The refusal branch is
/// otherwise untestable in this repo: CI and every developer host connect as a
/// superuser, for whom `pg_has_role(session_user, 'epigraph_maintenance',
/// 'MEMBER')` is unconditionally true, so `bypass` is always `true` and the
/// interesting combination never occurs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaintenancePrivilege {
    /// `epigraph_bypass()` — is `session_user` a member of
    /// `epigraph_maintenance`? `false` also when the function does not exist
    /// yet (a database below migration 067).
    pub bypass: bool,
    /// Does *any* table in `public` carry `relrowsecurity` **or**
    /// `relforcerowsecurity`? This is the arming signal: below it a bypass
    /// viewer on an ordinary connection is harmless, above it the same viewer
    /// silently returns nothing.
    ///
    /// ## Why ENABLE and not only FORCE
    ///
    /// An earlier revision of this probe keyed on `relforcerowsecurity` alone,
    /// on the reading that FORCE is what PR-17 arms. That is the wrong column
    /// for every role this fleet actually connects as. In PostgreSQL a policy
    /// filters every role except the table's owner and holders of `BYPASSRLS`;
    /// `FORCE` only *additionally* subjects the owner. Measured on the
    /// throwaway at head 91: `claims`, `edges`, `recall_events`,
    /// `group_memberships` and `agents` are all owned by `epigraph`
    /// (`rolsuper`, `rolbypassrls = t`), while `epigraph_app`, `epigraph_admin`
    /// and `epigraph_maintenance` are non-owner with `rolbypassrls = f`. So a
    /// plain `ENABLE ROW LEVEL SECURITY` already filters every background
    /// writer, and `relforcerowsecurity` is irrelevant to them.
    ///
    /// A FORCE-only predicate would therefore be disarmed in exactly the two
    /// states it exists for: the window in which policies are applied but FORCE
    /// is not yet, and the state an operator lands in after pulling the
    /// documented `NO FORCE ROW LEVEL SECURITY` kill switch, which drops FORCE
    /// and leaves the policies enabled.
    ///
    /// This is not a novel reading. `repos/entity_type.rs` already reads BOTH
    /// flags and pins the converse trap in
    /// `force_without_enable_is_not_satisfied` — *"with `relrowsecurity = false`
    /// it applies NO policy at all"*. This probe had regressed from that.
    ///
    /// Counts `relkind IN ('r', 'p')` — ordinary AND **partitioned** tables. A
    /// partitioned table is `'p'`, and row security is recorded on the parent,
    /// so an `'r'`-only predicate would leave `rls_active` false forever on a
    /// partitioned corpus. (Measured on the same throwaway: zero `'p'`/`'f'`
    /// relations in `public` today, so that half is forward protection.)
    pub rls_active: bool,
}

/// The non-refusing outcomes of [`maintenance_verdict`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MaintenanceVerdict {
    /// The connection satisfies `epigraph_bypass()`. Nothing to say.
    Privileged,
    /// Not privileged, but no protected table has row security on it at all,
    /// so a bypass viewer still reads and writes normally. Carries the warning
    /// to emit.
    UnprivilegedButRlsIsNotActive(String),
}

/// The PR-15 rule, as a pure function.
///
/// ## Why this rule and not the plan's
///
/// The plan asks the shared constructor to do two incompatible things: fall
/// back to `DATABASE_URL` **with a WARN**, and assert `epigraph_bypass()` is
/// true, **refusing to run otherwise**. The second makes the first dead code.
///
/// Refusing unconditionally is also wrong on its own terms. `epigraph_bypass()`
/// (migration 067) is `pg_has_role(session_user, 'epigraph_maintenance',
/// 'MEMBER')` guarded by an `EXISTS` on `pg_roles`, and migration 060 downgrades
/// `insufficient_privilege` on its `CREATE ROLE` to a `RAISE NOTICE`. On any
/// managed cluster where that fired, the role does not exist, the function
/// returns `false`, and an unconditional refusal takes every background writer
/// down on the first restart after deploy — to prevent a failure mode that
/// cannot occur, because no policy is filtering anything yet.
///
/// So the rule is: **refuse only when row security is actually active on a
/// protected table** — `ENABLE` or `FORCE`, see [`MaintenancePrivilege::rls_active`]
/// for why ENABLE is the operative half for every role this fleet connects as.
/// Below that the bypass is inert and the correct response is a warning; at and
/// above it an unprivileged maintenance connection is a silent-data-loss
/// generator and the correct response is to refuse to start. The rule is inert
/// on every environment that exists today (measured: zero relations in `public`
/// carry either flag at head 91) and arms itself the moment PR-17's policies
/// land, with no second deploy step and nothing for an operator to remember.
///
/// # Errors
/// `DbError::InvalidData` when row security is active and the connection does
/// not satisfy `epigraph_bypass()`.
pub fn maintenance_verdict(
    p: MaintenancePrivilege,
    source: MaintenanceDsnSource,
) -> Result<MaintenanceVerdict, DbError> {
    if p.bypass {
        return Ok(MaintenanceVerdict::Privileged);
    }
    if p.rls_active {
        return Err(DbError::InvalidData {
            reason: format!(
                "this connection does not satisfy epigraph_bypass() (session_user is not a \
                 member of epigraph_maintenance) and at least one table in `public` has ROW \
                 LEVEL SECURITY enabled. A maintenance job here would read zero rows and \
                 update zero rows, and exit 0. Refusing to run. DSN source: {}. Fix by setting \
                 {MAINTENANCE_DATABASE_URL} to a role that is a member of \
                 epigraph_maintenance.",
                source.as_str()
            ),
        });
    }
    Ok(MaintenanceVerdict::UnprivilegedButRlsIsNotActive(format!(
        "this connection does not satisfy epigraph_bypass(); no table has row security on it \
         yet, so maintenance work still sees the whole corpus. This becomes a silent no-op the \
         moment RLS policies land (PR-17). DSN source: {}.",
        source.as_str()
    )))
}

/// Ask the database the two questions [`maintenance_verdict`] decides on.
///
/// ## Why this SQL is here and not under `repos/`
///
/// CLAUDE.md keeps domain SQL in `crates/epigraph-db/src/repos/`. These two
/// statements are not domain queries: they read `pg_catalog` and the session's
/// own role membership, which is connection *configuration* in exactly the
/// sense the module documentation above uses to justify `SET_SESSION_GUCS`
/// living here. Keeping them next to the pool also keeps them to **one** site
/// rather than one per converted binary.
///
/// `epigraph_bypass()` ships in migration 067, but a database below that head —
/// or one where 060's `CREATE ROLE` only raised a notice — must not make the
/// probe itself fail, so its existence is checked first rather than caught as a
/// `42883`.
///
/// # Errors
/// `DbError::QueryFailed` if the catalog cannot be read at all.
pub async fn probe_maintenance_privilege(pool: &PgPool) -> Result<MaintenancePrivilege, DbError> {
    let bypass_fn_exists: bool =
        sqlx::query_scalar("SELECT to_regprocedure('public.epigraph_bypass()') IS NOT NULL")
            .fetch_one(pool)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;

    let bypass = if bypass_fn_exists {
        sqlx::query_scalar::<_, Option<bool>>("SELECT epigraph_bypass()")
            .fetch_one(pool)
            .await
            .map_err(|source| DbError::QueryFailed { source })?
            .unwrap_or(false)
    } else {
        false
    };

    // ENABLE **or** FORCE. A policy filters every role except the owner and
    // BYPASSRLS holders, and every protected table here is owned by a superuser
    // no background writer connects as — so ENABLE alone is what arms the
    // failure this refusal exists to prevent. See
    // `MaintenancePrivilege::rls_active`.
    let rls_active: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_class c \
           JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') \
            AND (c.relrowsecurity OR c.relforcerowsecurity))",
    )
    .fetch_one(pool)
    .await
    .map_err(|source| DbError::QueryFailed { source })?;

    Ok(MaintenancePrivilege { bypass, rls_active })
}

/// Probe, decide, and either log or refuse.
///
/// The one call every background writer makes at startup. `context` names the
/// process in the log line so an operator reading a fleet's logs can tell which
/// binary is unprivileged.
///
/// # Errors
/// Propagates [`probe_maintenance_privilege`] and [`maintenance_verdict`].
pub async fn assert_maintenance_privilege(
    pool: &PgPool,
    source: MaintenanceDsnSource,
    context: &str,
) -> Result<(), DbError> {
    let privilege = probe_maintenance_privilege(pool).await?;
    match maintenance_verdict(privilege, source)? {
        MaintenanceVerdict::Privileged => {
            info!(
                context,
                dsn_source = source.as_str(),
                rls_active = privilege.rls_active,
                "maintenance connection satisfies epigraph_bypass()"
            );
        }
        MaintenanceVerdict::UnprivilegedButRlsIsNotActive(warning) => {
            warn!(context, dsn_source = source.as_str(), "{warning}");
        }
    }
    Ok(())
}

/// Bound every statement on this connection.
///
/// One definition, so the job pool's `after_connect` hook and any other pool
/// that wants the same bound are provably issuing the same statement — the
/// reason [`SET_SESSION_GUCS`] is a `const`. `epigraph_jobs::apply_job_connection_settings`
/// delegates here.
///
/// # Errors
/// Returns `sqlx::Error` if the `SET` fails.
pub async fn apply_statement_timeout(
    conn: &mut PgConnection,
    statement_timeout: Duration,
) -> Result<(), sqlx::Error> {
    // `SET` cannot be parameterized; the value is our own, not user input.
    let ms = statement_timeout.as_millis();
    sqlx::query(&format!("SET statement_timeout = {ms}"))
        .execute(conn)
        .await?;
    Ok(())
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
/// Deployment knobs for [`ScopedPool::connect_with_options`].
///
/// `ScopedPool::connect`'s doc has said since PR-04 that "PR-15 threads
/// `EPIGRAPH_DB_*` through so these become deployment decisions rather than
/// constants". This is that thread, in the narrow form PR-15 actually needs:
/// the background job pool has its own sizing and its own per-connection
/// `statement_timeout`, and it cannot be routed through `ScopedPool` (which is
/// the PR-15 obligation recorded in `bin/server.rs`) unless the constructor can
/// express them.
///
/// `Default` reproduces [`ScopedPool::connect`] exactly, so the nine existing
/// call sites keep their behaviour without being touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedPoolOptions {
    /// Maximum pooled connections.
    pub max_connections: u32,
    /// How long `acquire` waits before giving up.
    pub acquire_timeout: Duration,
    /// Per-connection `statement_timeout`, applied in `after_connect`.
    /// `None` leaves the server default in place.
    pub statement_timeout: Option<Duration>,
}

impl Default for ScopedPoolOptions {
    fn default() -> Self {
        // sqlx's own `PgPool::connect` defaults, which `bin/server.rs` used
        // before PR-04. See `ScopedPool::connect`'s doc for why this
        // constructor deliberately does not adopt `create_pool`'s 5s timeout.
        Self {
            max_connections: 10,
            acquire_timeout: Duration::from_secs(30),
            statement_timeout: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScopedPool {
    inner: PgPool,
    mode: SessionGucMode,
    /// The privileged pool [`ScopedPool::unscoped_for_maintenance`] draws from,
    /// when one has been attached by [`ScopedPool::with_maintenance_pool`].
    ///
    /// `None` means maintenance connections come from `inner` — the pre-PR-15
    /// behaviour, kept because it is what every test fixture wants (a
    /// `#[sqlx::test]` database has exactly one DSN and one role) and because
    /// it is sound for as long as no table is FORCEd.
    maintenance: Option<PgPool>,
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
        Self::connect_with_options(database_url, mode, ScopedPoolOptions::default()).await
    }

    /// [`Self::connect`] with explicit sizing and an optional per-connection
    /// `statement_timeout`.
    ///
    /// Exists so a pool that needs those knobs — the background job pool — can
    /// still be built through this constructor and therefore still get the
    /// `after_release` scrub. Retrofitting either hook onto an existing
    /// `PgPool` is impossible for the same reason stated in the module doc, so
    /// without this the job pool's only options were "no scrub" or "no
    /// timeout".
    ///
    /// # Errors
    /// Returns `DbError::ConnectionFailed` if the pool cannot be established.
    #[instrument(skip(database_url))]
    pub async fn connect_with_options(
        database_url: &str,
        mode: SessionGucMode,
        options: ScopedPoolOptions,
    ) -> Result<Self, DbError> {
        let statement_timeout = options.statement_timeout;
        let inner = PgPoolOptions::new()
            .max_connections(options.max_connections)
            .acquire_timeout(options.acquire_timeout)
            .after_connect(move |conn, _meta| {
                Box::pin(async move {
                    if let Some(t) = statement_timeout {
                        apply_statement_timeout(conn, t).await?;
                    }
                    Ok(())
                })
            })
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

        info!(
            mode = ?mode,
            max_connections = options.max_connections,
            statement_timeout_ms = options.statement_timeout.map(|t| t.as_millis() as u64),
            "ScopedPool created"
        );
        Ok(Self {
            inner,
            mode,
            maintenance: None,
        })
    }

    /// Attach the privileged pool [`Self::unscoped_for_maintenance`] draws from.
    ///
    /// This is the PR-15 repoint. Before it, a maintenance connection came from
    /// the application pool, which plan §4.3 spells out is unsound from PR-17
    /// on: a bypass viewer emits no predicate but the policy still filters, so
    /// it returns zero rows rather than all rows.
    ///
    /// Attaching is explicit rather than automatic (a `ScopedPool::connect`
    /// that read `MAINTENANCE_DATABASE_URL` itself would silently repoint every
    /// `#[sqlx::test]` fixture in the workspace at whatever DSN happened to be
    /// exported, which is the same "reads nothing, writes nowhere" failure this
    /// PR exists to remove). `bin/server.rs` attaches one; test fixtures do not,
    /// and keep the pre-PR-15 behaviour that is correct for a single-role
    /// throwaway database.
    ///
    /// The pool passed here should itself be built by [`Self::connect`] or
    /// [`Self::connect_with_options`] on the DSN [`maintenance_database_url`]
    /// returned, and vetted with [`assert_maintenance_privilege`].
    #[must_use]
    pub fn with_maintenance_pool(mut self, maintenance: PgPool) -> Self {
        self.maintenance = Some(maintenance);
        self
    }

    /// The pool maintenance connections are drawn from: the attached
    /// maintenance pool if there is one, otherwise the application pool.
    #[must_use]
    pub const fn maintenance_inner(&self) -> &PgPool {
        match self.maintenance.as_ref() {
            Some(p) => p,
            None => &self.inner,
        }
    }

    /// Whether a distinct maintenance pool has been attached.
    ///
    /// `false` means [`Self::unscoped_for_maintenance`] falls back to the
    /// application pool.
    #[must_use]
    pub const fn has_maintenance_pool(&self) -> bool {
        self.maintenance.is_some()
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
    /// **Repointed by PR-15.** This draws from the pool
    /// [`Self::with_maintenance_pool`] attached, falling back to the
    /// application pool when none was. Between PR-04 and PR-17 the fallback is
    /// harmless because no RLS policy is ENABLEd; from PR-17 on it is unsound
    /// in exactly the way plan §4.3 warns — a bypass viewer emits no predicate
    /// but the policy still filters, so it returns zero rows. The lease makes
    /// the coupling unforgeable; it does not make the connection privileged,
    /// which is why the privilege is checked separately by
    /// [`assert_maintenance_privilege`] at process start.
    ///
    /// # Errors
    /// Returns `DbError::ConnectionFailed` if the connection cannot be acquired.
    pub async fn unscoped_for_maintenance(
        &self,
        r: SystemReason,
    ) -> Result<(MaintenanceConn<'_>, MaintenanceLease), DbError> {
        let conn = self
            .maintenance_inner()
            .acquire()
            .await
            .map_err(|source| DbError::ConnectionFailed { source })?;
        // Every bypass is logged at the point it is granted, with the closed-set
        // reason as the metric dimension.
        tracing::info!(
            reason = r.as_str(),
            dedicated_maintenance_pool = self.maintenance.is_some(),
            "maintenance connection issued"
        );
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

    // ---- the PR-15 maintenance verdict ------------------------------------
    //
    // The refusal branch cannot be reached through the database in this repo:
    // CI (`ci.yml` connects as `epigraph`) and every developer host connect as
    // a superuser, for whom `pg_has_role(session_user, 'epigraph_maintenance',
    // 'MEMBER')` is unconditionally true, so `bypass` is always `true`. An
    // integration test asserting "epigraph_bypass() is true at startup" would
    // therefore pass vacuously and prove nothing about the rule. Splitting the
    // verdict out of the probe is what makes all four combinations reachable.

    const CONFIGURED: MaintenanceDsnSource = MaintenanceDsnSource::Configured;
    const FALLBACK: MaintenanceDsnSource = MaintenanceDsnSource::FellBackToApplicationDsn;

    #[test]
    fn a_privileged_connection_is_accepted_whether_or_not_rls_is_active() {
        for rls_active in [false, true] {
            let v = maintenance_verdict(
                MaintenancePrivilege {
                    bypass: true,
                    rls_active,
                },
                CONFIGURED,
            )
            .expect("a bypass-capable connection is always acceptable");
            assert_eq!(v, MaintenanceVerdict::Privileged);
        }
    }

    /// The whole point of choosing the RLS-gated rule over the plan's
    /// unconditional assertion: today, on every environment that exists, an
    /// unprivileged maintenance connection must WARN and keep running.
    #[test]
    fn an_unprivileged_connection_warns_while_no_table_has_row_security() {
        let v = maintenance_verdict(
            MaintenancePrivilege {
                bypass: false,
                rls_active: false,
            },
            FALLBACK,
        )
        .expect("must not refuse before any policy arms");
        let MaintenanceVerdict::UnprivilegedButRlsIsNotActive(warning) = v else {
            panic!("expected the warning branch");
        };
        assert!(
            warning.contains("epigraph_bypass()"),
            "the warning must name what is missing: {warning}"
        );
        assert!(
            warning.contains("silent no-op"),
            "the warning must name the consequence, not just the state: {warning}"
        );
    }

    /// And the self-arming half: the same connection, once any table carries
    /// row security, is a silent-data-loss generator and must refuse.
    ///
    /// `rls_active` is deliberately true for a merely-ENABLEd table, not only a
    /// FORCEd one — see [`MaintenancePrivilege::rls_active`]. Keying on FORCE
    /// alone would leave this refusal disarmed through PR-17's own
    /// policies-before-FORCE migration window and after the documented `NO
    /// FORCE ROW LEVEL SECURITY` kill switch, the two moments it exists for.
    #[test]
    fn an_unprivileged_connection_refuses_once_a_table_has_row_security() {
        let err = maintenance_verdict(
            MaintenancePrivilege {
                bypass: false,
                rls_active: true,
            },
            FALLBACK,
        )
        .expect_err("row security plus no bypass must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("zero rows"),
            "the refusal must name the failure shape, which is not an error: {msg}"
        );
        assert!(
            msg.contains(MAINTENANCE_DATABASE_URL),
            "the refusal must name the remedy env var: {msg}"
        );
    }

    /// The DSN source reaches the operator either way — "which of my forty
    /// background writers is on the fallback" is the question this answers.
    #[test]
    fn the_verdict_reports_which_dsn_was_used() {
        let err = maintenance_verdict(
            MaintenancePrivilege {
                bypass: false,
                rls_active: true,
            },
            CONFIGURED,
        )
        .expect_err("must refuse");
        assert!(err.to_string().contains("maintenance_database_url"));

        let MaintenanceVerdict::UnprivilegedButRlsIsNotActive(w) = maintenance_verdict(
            MaintenancePrivilege {
                bypass: false,
                rls_active: false,
            },
            FALLBACK,
        )
        .expect("warn") else {
            panic!("expected the warning branch");
        };
        assert!(w.contains("database_url_fallback"));
    }

    /// The verdict tests above are pure, so they prove the RULE and nothing
    /// about the PROBE that feeds it. This one closes that gap against a real
    /// catalog: a fresh database at head must report `rls_active = false`, and
    /// a plain `ENABLE ROW LEVEL SECURITY` — no `FORCE` — must flip it true.
    ///
    /// Without this, the whole ENABLE-vs-FORCE correction would be asserted
    /// only in prose. The earlier `relforcerowsecurity`-only predicate passes
    /// the first half of this test and FAILS the second, which is exactly the
    /// discrimination that matters: policies are applied (074) before FORCE is
    /// (076), and the documented emergency lever drops FORCE while leaving the
    /// policies enabled.
    ///
    /// `#[sqlx::test]` gives this test its own throwaway database, so the DDL
    /// cannot reach any shared table — and the scratch table is created here
    /// rather than in a migration precisely so no migration number is spent.
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_probe_observes_enable_row_level_security_not_only_force(pool: PgPool) {
        let before = probe_maintenance_privilege(&pool)
            .await
            .expect("probe a fresh database");
        assert!(
            !before.rls_active,
            "no relation in `public` carries row security at head; if this fails the fixture \
             changed and the arming signal below proves nothing"
        );

        sqlx::query("CREATE TABLE rls_probe_scratch (id int primary key)")
            .execute(&pool)
            .await
            .expect("create scratch table");
        sqlx::query("ALTER TABLE rls_probe_scratch ENABLE ROW LEVEL SECURITY")
            .execute(&pool)
            .await
            .expect("enable row security");

        let after = probe_maintenance_privilege(&pool)
            .await
            .expect("probe after ENABLE");
        assert!(
            after.rls_active,
            "ENABLE ROW LEVEL SECURITY alone must arm the probe. A policy filters every role \
             except the table owner and BYPASSRLS holders, so for every role a background \
             writer connects as, ENABLE is what starts truncating results — FORCE only \
             additionally subjects the owner."
        );

        // And the arming is what the verdict keys on: the same unprivileged
        // connection that warned before must now refuse.
        assert!(
            maintenance_verdict(
                MaintenancePrivilege {
                    bypass: false,
                    rls_active: after.rls_active,
                },
                FALLBACK,
            )
            .is_err(),
            "an unprivileged connection must refuse once a table has row security"
        );
    }

    // ---- maintenance DSN resolution ---------------------------------------

    const APP_DSN: &str = "postgres://epigraph_app:pw@localhost:5432/epigraph";

    #[test]
    fn an_unset_or_empty_maintenance_dsn_falls_back_rather_than_refusing() {
        for configured in [None, Some(""), Some("   ")] {
            let (url, source) =
                resolve_maintenance_url(APP_DSN, configured).expect("must not be fatal");
            assert_eq!(url, APP_DSN);
            assert_eq!(
                source,
                MaintenanceDsnSource::FellBackToApplicationDsn,
                "an exported-but-empty variable is a container default, not a decision"
            );
        }
    }

    #[test]
    fn a_maintenance_dsn_on_the_same_database_is_accepted() {
        const MAINT: &str = "postgres://epigraph_maint:pw@localhost:5432/epigraph";
        let (url, source) = resolve_maintenance_url(APP_DSN, Some(MAINT)).expect("same database");
        assert_eq!(url, MAINT);
        assert_eq!(source, MaintenanceDsnSource::Configured);
    }

    /// The residual the guard does NOT close, pinned so nobody reads the
    /// docstring as covering it. Every environment names its database
    /// `epigraph`, so the likeliest form of the copy-paste accident is a
    /// staging maintenance DSN beside a production application DSN — identical
    /// database name, different cluster. That WARNS and proceeds; refusing on
    /// host equality would boot-fail every deployment where `localhost`,
    /// `127.0.0.1` and a container DNS name denote the same server.
    #[test]
    fn a_maintenance_dsn_on_another_cluster_with_the_same_database_name_is_allowed() {
        const MAINT: &str = "postgres://epigraph_maint:pw@staging-db:5432/epigraph";
        let (url, source) =
            resolve_maintenance_url(APP_DSN, Some(MAINT)).expect("same database NAME, so allowed");
        assert_eq!(url, MAINT);
        assert_eq!(source, MaintenanceDsnSource::Configured);
    }

    /// The endpoint comparison itself: loopback spellings must fold together
    /// (or the warning fires on ordinary local configuration and gets ignored),
    /// and a genuinely different host or port must NOT.
    #[test]
    fn the_endpoint_comparison_folds_loopback_and_nothing_else() {
        let ep = |url: &str| normalized_endpoint(&PgConnectOptions::from_str(url).expect("dsn"));

        let local = ep(APP_DSN);
        for spelling in [
            "postgres://u:pw@localhost:5432/epigraph",
            "postgres://u:pw@127.0.0.1:5432/epigraph",
            "postgres://u:pw@[::1]:5432/epigraph",
        ] {
            assert_eq!(ep(spelling), local, "{spelling} is the same server");
        }

        assert_ne!(
            ep("postgres://u:pw@staging-db:5432/epigraph"),
            local,
            "a different host must be observed as a different endpoint"
        );
        assert_ne!(
            ep("postgres://u:pw@localhost:6432/epigraph"),
            local,
            "a different port must be observed as a different endpoint — 6432 is the pgbouncer \
             convention, and reaching the same cluster through a transaction-mode pooler is \
             exactly the configuration `probe_verdict` exists to catch"
        );
    }

    /// Two pathless DSNs differing only in role connect to two DIFFERENT
    /// databases, because libpq defaults the database name to the user name.
    /// Comparing the written path alone would read `None == None` and pass.
    #[test]
    fn a_pathless_maintenance_dsn_is_compared_on_its_effective_database() {
        let err = resolve_maintenance_url(
            "postgres://epigraph_app:pw@localhost:5432",
            Some("postgres://epigraph_maint:pw@localhost:5432"),
        )
        .expect_err("pathless DSNs differing in role name different databases");
        let msg = err.to_string();
        assert!(
            msg.contains("epigraph_maint") && msg.contains("epigraph_app"),
            "the refusal must name both effective databases: {msg}"
        );

        // ...and the same role on both is genuinely the same database.
        let (url, source) = resolve_maintenance_url(
            "postgres://epigraph_admin:pw@localhost:5432",
            Some("postgres://epigraph_admin:other@localhost:5432"),
        )
        .expect("same effective database");
        assert_eq!(url, "postgres://epigraph_admin:other@localhost:5432");
        assert_eq!(source, MaintenanceDsnSource::Configured);
    }

    /// The accident this guard exists for: one variable exported globally while
    /// `DATABASE_URL` varies per process. Every read succeeds and returns
    /// nothing; every write succeeds and lands nowhere; nothing errors.
    #[test]
    fn a_maintenance_dsn_on_a_different_database_refuses() {
        let err = resolve_maintenance_url(
            APP_DSN,
            Some("postgres://epigraph_maint:pw@localhost:5432/some_other_db"),
        )
        .expect_err("a database mismatch must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("some_other_db") && msg.contains("epigraph"),
            "the refusal must name both databases so the typo is visible: {msg}"
        );
    }

    /// The persistence check must be checked BEFORE the scrub check: behind a
    /// transaction-mode pooler both observations are empty, and reporting
    /// "the scrub is not running" would send an operator after the wrong thing.
    #[test]
    fn probe_verdict_diagnoses_a_pooler_before_a_missing_scrub() {
        let err = probe_verdict("", "").expect_err("must refuse");
        assert!(
            !err.to_string()
                .contains("after_release scrub is not running"),
            "an all-empty observation is a pooler, not a scrub failure"
        );
    }
}
