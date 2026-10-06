//! The admin-scope arming switch's Rust half (elevation plan EL-9, migration
//! 128): read the switch, record the would-strip measurement, and (maintenance
//! only) arm or disarm.
//!
//! # Who reads it
//!
//! The token endpoint's mint chokepoint (`epigraph-api`'s
//! `oauth::scopes::grantable`) reads [`AdminScopeEnforcement::read`] only when
//! a mint would carry an admin-only scope, so an ordinary mint costs nothing.
//! Registration, client approval and `epigraph-operator grant-client-scope`
//! read it before handing an admin-only scope out.
//!
//! # A database without 128
//!
//! [`AdminScopeSwitch::Absent`]: the switch's function does not exist
//! (`42883`), so the database cannot have been armed. Every caller treats it
//! as unarmed, which keeps a binary built with 128 serving on a database that
//! has not run it. Any OTHER failure is an error, and the mint chokepoint
//! fails closed on it (it strips).

use crate::errors::DbError;
use uuid::Uuid;

/// SQLSTATE `undefined_function`: the database has not run migration 128.
const UNDEFINED_FUNCTION: &str = "42883";

/// What the switch says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminScopeSwitch {
    /// Admin-only scopes are standing authority (the shipped state).
    Unarmed,
    /// Admin-only scopes are stripped at every mint and refused at every grant.
    Armed,
    /// The database has no switch (migration 128 not applied): unarmed.
    Absent,
}

impl AdminScopeSwitch {
    /// Only [`Self::Armed`] is armed.
    #[must_use]
    pub const fn is_armed(self) -> bool {
        matches!(self, Self::Armed)
    }
}

/// The switch's row, for the operator's report.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AdminScopeState {
    pub armed: bool,
    pub changed_at: chrono::DateTime<chrono::Utc>,
    pub changed_by: String,
    pub reason: String,
}

/// What an arm or disarm did.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AdminScopeChange {
    /// `false` when the switch was already in the asked-for state (nothing
    /// changed and nothing was recorded).
    pub changed: bool,
    pub armed: bool,
    pub changed_at: chrono::DateTime<chrono::Utc>,
    pub changed_by: String,
}

/// Migration 128's switch.
pub struct AdminScopeEnforcement;

impl AdminScopeEnforcement {
    /// Read the switch (`epigraph_admin_scopes_armed()`, app-callable).
    ///
    /// # Errors
    /// Any failure but a missing function (which is [`AdminScopeSwitch::Absent`]).
    pub async fn read<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
    ) -> Result<AdminScopeSwitch, DbError> {
        match sqlx::query_scalar::<_, bool>("SELECT public.epigraph_admin_scopes_armed()")
            .fetch_one(executor)
            .await
        {
            Ok(true) => Ok(AdminScopeSwitch::Armed),
            Ok(false) => Ok(AdminScopeSwitch::Unarmed),
            Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some(UNDEFINED_FUNCTION) => {
                Ok(AdminScopeSwitch::Absent)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Record that an unarmed mint KEPT `scopes` (admin-only scopes an armed
    /// database would strip) for `client` on `grant`
    /// (`epigraph_record_admin_scope_would_strip`, app-callable). The definer
    /// writes at most one `oauth.admin_scope_would_strip` event per client per
    /// hour, nothing once armed, and refuses a grant label or scope that is not
    /// real (22023). Returns whether an event was written.
    ///
    /// # Errors
    /// The definer refuses, or the statement fails (e.g. no migration 128).
    pub async fn record_would_strip<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        client: Uuid,
        grant: &str,
        scopes: &[String],
    ) -> Result<bool, DbError> {
        Ok(
            sqlx::query_scalar("SELECT public.epigraph_record_admin_scope_would_strip($1, $2, $3)")
                .bind(client)
                .bind(grant)
                .bind(scopes)
                .fetch_one(executor)
                .await?,
        )
    }

    /// The switch's row (maintenance report).
    ///
    /// # Errors
    /// The read fails (e.g. migration 128 is not applied).
    pub async fn state(conn: &mut sqlx::PgConnection) -> Result<AdminScopeState, DbError> {
        Ok(sqlx::query_as(
            "SELECT armed, changed_at, changed_by, reason FROM public.admin_scope_enforcement",
        )
        .fetch_one(&mut *conn)
        .await?)
    }

    /// Arm (`true`) or disarm (`false`) with `reason`, on a MAINTENANCE
    /// connection (`epigraph_set_admin_scope_enforcement`; refused to every
    /// other login). The change is audited by the table's own trigger.
    ///
    /// # Errors
    /// Refused (not a maintenance session, empty reason) or the statement fails.
    pub async fn set(
        conn: &mut sqlx::PgConnection,
        armed: bool,
        reason: &str,
    ) -> Result<AdminScopeChange, DbError> {
        Ok(sqlx::query_as(
            "SELECT changed, armed, changed_at, changed_by \
               FROM public.epigraph_set_admin_scope_enforcement($1, $2)",
        )
        .bind(armed)
        .bind(reason)
        .fetch_one(&mut *conn)
        .await?)
    }
}

/// The admin-scope switch as a REQUEST UNIT reads it (elevation plan EL-10):
/// [`AdminScopeEnforcement::read`] behind a short cache, so the check
/// chokepoint (`epigraph_auth::AuthContext::has_scope`) costs one read per
/// interval per process instead of one per request.
///
/// The answer is a plain `armed` boolean, decided with
/// [`AdminScopeEnforcement::read`]'s semantics and failing CLOSED:
/// [`AdminScopeSwitch::Armed`] is armed; [`AdminScopeSwitch::Unarmed`] and
/// [`AdminScopeSwitch::Absent`] (no migration 128) are not; a read ERROR is
/// armed for that request and is NOT cached, so the next request reads again.
/// Arming or disarming therefore reaches a running unit within [`Self::ttl`].
///
/// One per process: the API keeps one in its state, the MCP server one shared
/// by every session it builds.
#[derive(Debug)]
pub struct AdminScopeArmingCache {
    ttl: std::time::Duration,
    slot: std::sync::Mutex<Option<(std::time::Instant, bool)>>,
}

impl Default for AdminScopeArmingCache {
    fn default() -> Self {
        Self::with_ttl(Self::DEFAULT_TTL)
    }
}

impl AdminScopeArmingCache {
    /// How long a read stands (elevation plan EL-10: 10 s).
    pub const DEFAULT_TTL: std::time::Duration = std::time::Duration::from_secs(10);

    /// A cache whose reads stand for `ttl` (`Duration::ZERO`: every call reads).
    #[must_use]
    pub fn with_ttl(ttl: std::time::Duration) -> Self {
        Self {
            ttl,
            slot: std::sync::Mutex::new(None),
        }
    }

    /// How long a read stands.
    #[must_use]
    pub const fn ttl(&self) -> std::time::Duration {
        self.ttl
    }

    /// Whether the admin-only scopes are armed, read on `pool` unless a read
    /// younger than [`Self::ttl`] stands. Fails closed (`true`) on a read
    /// error, which is logged and not cached.
    pub async fn armed(&self, pool: &sqlx::PgPool) -> bool {
        if let Ok(slot) = self.slot.lock() {
            if let Some((at, armed)) = *slot {
                if at.elapsed() < self.ttl {
                    return armed;
                }
            }
        }
        match AdminScopeEnforcement::read(pool).await {
            Ok(switch) => {
                let armed = switch.is_armed();
                if let Ok(mut slot) = self.slot.lock() {
                    *slot = Some((std::time::Instant::now(), armed));
                }
                armed
            }
            Err(e) => {
                tracing::warn!(
                    target: "elevation",
                    error = %e,
                    "could not read the admin-scope switch; treating admin-only scopes as \
                     armed (absent unless elevated) for this request"
                );
                true
            }
        }
    }
}
