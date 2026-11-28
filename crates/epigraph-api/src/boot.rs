//! Startup gates a process must pass before it serves, as library calls.
//!
//! `bin/server.rs::main` calls them, and an embedder that builds its own
//! [`AppState`](crate::state::AppState) and mounts
//! [`create_router_with_extensions`](crate::routes::create_router_with_extensions)
//! must call them too: the router does not run them itself.
//!
//! [`check_db_posture`] is the database half: every read-only refusal the
//! server makes about the database its request pool reaches. It does not
//! migrate (`EPIGRAPH_MIGRATE_ON_BOOT` is an action on a different DSN, and
//! `epigraph-migrate` owns the database-ahead refusal), and it does not run
//! the session-GUC probe, which needs the
//! [`ScopedPool`](epigraph_db::ScopedPool) and its GUC mode
//! (`ScopedPool::probe_session_gucs`).

use std::fmt;

use epigraph_db::PgPool;

use crate::migrate::PgvectorVersionError;
use crate::state::AppState;

/// Why a startup gate refused to let this process serve. Its `Display` is
/// the line the server prints (after `ERROR: `) before it exits 1.
#[derive(Debug)]
#[non_exhaustive]
pub enum BootRefusal {
    /// The pgvector floor ([`crate::migrate::check_pgvector_version`]):
    /// below 0.8.0 every semantic search fails on `hnsw.iterative_scan`.
    Pgvector(PgvectorVersionError),
    /// The test-only software-attestation passkey policy on a database armed
    /// for operator binding
    /// ([`crate::passkey_boot::check_software_attestation_boot`]).
    SoftwareAttestation(String),
    /// A privileged DSN on a database armed for operator binding
    /// ([`epigraph_db::operator_binding::check_request_unit_boot`]).
    OperatorBinding(String),
    /// A tenancy trigger is missing or disabled
    /// ([`AppState::assert_tenancy_triggers_armed_on`]).
    TenancyTriggers(epigraph_db::DbError),
    /// The RLS posture verdict refused ([`AppState::assert_rls_posture_on`]).
    RlsPosture(epigraph_db::DbError),
}

impl fmt::Display for BootRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pgvector(e) => write!(f, "refusing to serve: {e}"),
            Self::SoftwareAttestation(refusal) | Self::OperatorBinding(refusal) => {
                f.write_str(refusal)
            }
            Self::TenancyTriggers(e) => {
                write!(f, "refusing to serve: tenancy triggers are not armed: {e}")
            }
            Self::RlsPosture(e) => {
                write!(f, "refusing to serve: RLS posture assertion failed: {e}")
            }
        }
    }
}

impl std::error::Error for BootRefusal {}

/// The inputs [`check_db_posture`] cannot read from the pool.
#[derive(Debug, Clone, Copy)]
pub struct DbPostureOptions<'a> {
    /// The unit name the operator-binding boot line is logged under (the
    /// server passes `"epigraph-api"`).
    pub unit: &'a str,
    /// Whether the configured passkey relying party took the TEST-ONLY
    /// software-attestation policy
    /// (`epigraph_passkey::PasskeyConfig::allows_software_attestation`);
    /// `false` when no relying party is configured.
    pub allows_software_attestation: bool,
}

/// Refuse to serve a database whose posture is unsafe, in the server's order:
///
/// 1. the pgvector floor: below 0.8.0 every semantic search fails, so a
///    corpus that cannot be searched is not served (`epigraph-migrate` runs
///    the same check after migrating; this also covers a server started
///    without that step);
/// 2. the software-attestation flag on an operator-binding-armed database
///    (before 3, so on a privileged DSN of an armed database the flag, not
///    the DSN, is the reason given);
/// 3. a privileged DSN on an operator-binding-armed database (operator
///    ruling OQ-7 (b): on such a DSN the trigger checks the author column
///    alone). An unarmed database (dev, CI) is not refused;
/// 4. missing or disabled tenancy triggers. After migration 074 there is no
///    DEFAULT left to catch an undeclared write, so a disabled trigger is not
///    a degraded mode;
/// 5. the connection-posture WARNINGS
///    ([`AppState::warn_on_privileged_connection_on`]; fatal would stop CI
///    and development booting), logged before 6 so a merely unusual posture
///    is described before it is judged;
/// 6. the RLS posture verdict, staged on the connecting role
///    ([`crate::state::rls_verdict`] carries the argument).
///
/// Call it on the request pool after migrations and before serving. It
/// spawns nothing: the server's running posture watch
/// (`epigraph_db::operator_binding::spawn_posture_watch`) is the caller's.
///
/// # Errors
/// The first [`BootRefusal`] met, in the order above.
pub async fn check_db_posture(
    pool: &PgPool,
    opts: DbPostureOptions<'_>,
) -> Result<(), BootRefusal> {
    let version = crate::migrate::check_pgvector_version(pool)
        .await
        .map_err(BootRefusal::Pgvector)?;
    tracing::info!(pgvector = %version, "pgvector version ok");

    crate::passkey_boot::check_software_attestation_boot(pool, opts.allows_software_attestation)
        .await
        .map_err(BootRefusal::SoftwareAttestation)?;

    epigraph_db::operator_binding::check_request_unit_boot(pool, opts.unit)
        .await
        .map_err(BootRefusal::OperatorBinding)?;

    AppState::assert_tenancy_triggers_armed_on(pool)
        .await
        .map_err(BootRefusal::TenancyTriggers)?;

    if let Err(e) = AppState::warn_on_privileged_connection_on(pool).await {
        tracing::warn!(error = %e, "could not read the connection posture");
    }

    AppState::assert_rls_posture_on(pool)
        .await
        .map_err(BootRefusal::RlsPosture)?;
    Ok(())
}
