//! Repository for platform-role assignments (migration 123): who holds
//! `role:platform-custodian` (or `role:auditor`), from when, until when.
//!
//! # Thin wrappers over 123's definers
//!
//! Every write goes through a migration-123 definer, never a raw statement
//! here: `epigraph_grant_role` / `epigraph_end_role_assignment` write
//! `role_assignments`, whose own triggers enforce the rules (CUS01 agents
//! never hold a role, CUS02 append-only, CUS03 the grantor rule) and write
//! the `platform.` audit row; `epigraph_record_custodial_act` refuses (CUS04)
//! unless the named assignment is live and held by the actor. So a caller of
//! this module cannot get a rule wrong: it can only be refused by one.
//!
//! # Connections
//!
//! The writes and [`RoleAssignmentRepository::list`] are MAINTENANCE acts:
//! 123 grants their definers, and INSERT/UPDATE on the table, to the
//! maintenance role only, and an application connection gets `42501`. That is
//! the posture, not a bug to work around. [`RoleAssignmentRepository::live_for`]
//! is subject-bound (it answers about the session principal, or anyone on a
//! privileged session) and works on either.
//!
//! # Why nothing here takes a `Viewer`
//!
//! These are authority records about principals, not corpus rows; a viewer
//! filter has nothing to narrow (`visibility_lint.rs` registers each function
//! with its reason).

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use tracing::instrument;
use uuid::Uuid;

/// The custodian role's catalog key.
pub const PLATFORM_CUSTODIAN: &str = "role:platform-custodian";

/// The acts `epigraph_record_custodial_act` accepts (migration 123).
pub const CUSTODIAL_ACTS: &[&str] = &[
    "claim.supersede",
    "privatization.plan_create",
    "privatization.plan_transition",
];

/// A row of `role_assignments`.
#[derive(Debug, Clone, FromRow)]
pub struct RoleAssignmentRow {
    pub id: Uuid,
    pub role: String,
    pub holder_person_id: Option<Uuid>,
    pub valid_from: DateTime<Utc>,
    pub valid_to: Option<DateTime<Utc>>,
    pub granted_by: Option<Uuid>,
    pub granted_via: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
    pub revoked_reason: Option<String>,
}

/// Repository for platform-role assignments.
pub struct RoleAssignmentRepository;

impl RoleAssignmentRepository {
    /// Grant `role` to `holder` (a registered human) through
    /// `epigraph_grant_role`. `valid_from` defaults to now (it is never
    /// back-dated); `valid_to` `None` is open-ended. Returns the assignment id.
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying the guard's SQLSTATE (`CUS01`..`CUS03`),
    /// or `42501` on a non-maintenance connection.
    #[instrument(skip(conn, reason))]
    pub async fn grant(
        conn: &mut sqlx::PgConnection,
        role: &str,
        holder: Uuid,
        valid_from: Option<DateTime<Utc>>,
        valid_to: Option<DateTime<Utc>>,
        granted_by: Option<Uuid>,
        reason: &str,
    ) -> Result<Uuid, DbError> {
        let id: Uuid =
            sqlx::query_scalar("SELECT public.epigraph_grant_role($1, $2, $3, $4, $5, $6)")
                .bind(role)
                .bind(holder)
                .bind(valid_from)
                .bind(valid_to)
                .bind(granted_by)
                .bind(reason)
                .fetch_one(&mut *conn)
                .await?;
        Ok(id)
    }

    /// [`Self::grant`] on a CONFIRMED `role.grant` act (migration 130's
    /// act-taking `epigraph_grant_role`): the table's guard recomputes the
    /// act's args from the new row and consumes the act inside the INSERT, so
    /// a rollback of the caller's transaction un-consumes it. `granted_by` is
    /// the act's proposer.
    ///
    /// # Errors
    /// [`Self::grant`]'s, plus `ELV08` (the act is not live: unknown, not
    /// confirmed, consumed, expired, its passkey revoked, its proposer no
    /// longer a custodian) and `ELV09` (another kind, other args, another
    /// grantor).
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(conn, reason))]
    pub async fn grant_on_act(
        conn: &mut sqlx::PgConnection,
        role: &str,
        holder: Uuid,
        valid_from: Option<DateTime<Utc>>,
        valid_to: Option<DateTime<Utc>>,
        granted_by: Uuid,
        reason: &str,
        admin_act: Uuid,
    ) -> Result<Uuid, DbError> {
        let id: Uuid =
            sqlx::query_scalar("SELECT public.epigraph_grant_role($1, $2, $3, $4, $5, $6, $7)")
                .bind(role)
                .bind(holder)
                .bind(valid_from)
                .bind(valid_to)
                .bind(granted_by)
                .bind(reason)
                .bind(admin_act)
                .fetch_one(&mut *conn)
                .await?;
        Ok(id)
    }

    /// End an assignment now (`epigraph_end_role_assignment`). `false` when it
    /// had already ended or does not exist: an end is never repeated.
    ///
    /// # Errors
    /// `DbError::QueryFailed`, including `42501` on a non-maintenance
    /// connection.
    #[instrument(skip(conn, reason))]
    pub async fn end(
        conn: &mut sqlx::PgConnection,
        assignment: Uuid,
        reason: &str,
    ) -> Result<bool, DbError> {
        let ended: bool = sqlx::query_scalar("SELECT public.epigraph_end_role_assignment($1, $2)")
            .bind(assignment)
            .bind(reason)
            .fetch_one(&mut *conn)
            .await?;
        Ok(ended)
    }

    /// [`Self::end`] on a CONFIRMED `role.end` act (migration 130): the guard
    /// recomputes the act's args (this assignment, this reason) and consumes
    /// the act inside the UPDATE. `false` when the assignment had already
    /// ended (nothing consumed).
    ///
    /// # Errors
    /// [`Self::end`]'s, plus `ELV08` / `ELV09` as for [`Self::grant_on_act`].
    #[instrument(skip(conn, reason))]
    pub async fn end_on_act(
        conn: &mut sqlx::PgConnection,
        assignment: Uuid,
        reason: &str,
        admin_act: Uuid,
    ) -> Result<bool, DbError> {
        let ended: bool =
            sqlx::query_scalar("SELECT public.epigraph_end_role_assignment($1, $2, $3)")
                .bind(assignment)
                .bind(reason)
                .bind(admin_act)
                .fetch_one(&mut *conn)
                .await?;
        Ok(ended)
    }

    /// One assignment by id. On an application connection row security
    /// narrows this to the caller's own assignments.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn get(
        conn: &mut sqlx::PgConnection,
        assignment: Uuid,
    ) -> Result<Option<RoleAssignmentRow>, DbError> {
        let row = sqlx::query_as::<_, RoleAssignmentRow>(
            "SELECT id, role, holder_person_id, valid_from, valid_to, granted_by, granted_via, \
                    reason, created_at, revoked_at, revoked_by, revoked_reason \
               FROM role_assignments WHERE id = $1",
        )
        .bind(assignment)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row)
    }

    /// Every assignment (of `role`, when given), un-ended ones only unless
    /// `include_ended`, newest first. On an application connection row
    /// security narrows it to the caller's own rows, which is why the operator
    /// CLI runs it on the maintenance connection.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn list(
        conn: &mut sqlx::PgConnection,
        role: Option<&str>,
        include_ended: bool,
    ) -> Result<Vec<RoleAssignmentRow>, DbError> {
        let rows = sqlx::query_as::<_, RoleAssignmentRow>(
            "SELECT id, role, holder_person_id, valid_from, valid_to, granted_by, granted_via, \
                    reason, created_at, revoked_at, revoked_by, revoked_reason \
               FROM role_assignments \
              WHERE ($1::text IS NULL OR role = $1) AND ($2 OR revoked_at IS NULL) \
              ORDER BY created_at DESC, id",
        )
        .bind(role)
        .bind(include_ended)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows)
    }

    /// The live assignment of `role` that `principal` holds now, if any
    /// (`epigraph_role_assignment_for`): subject-bound, so on an application
    /// connection it answers only about the session principal.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails. A failure is never mapped
    /// to "holds no role".
    #[instrument(skip(conn))]
    pub async fn live_for(
        conn: &mut sqlx::PgConnection,
        principal: Uuid,
        role: &str,
    ) -> Result<Option<Uuid>, DbError> {
        let id: Option<Uuid> =
            sqlx::query_scalar("SELECT public.epigraph_role_assignment_for($1, $2, now())")
                .bind(principal)
                .bind(role)
                .fetch_one(&mut *conn)
                .await?;
        Ok(id)
    }

    /// Whether `principal` holds a live assignment of ANY role whose catalog
    /// row `elevates`, now (operator ruling D2: the MCP manifest lists `sudo`
    /// only to such a holder). Subject-bound through 123's
    /// `epigraph_holds_role`, so on an application connection it answers only
    /// about the STAMPED principal (asked about anyone else, or unstamped:
    /// `false`). `instance_admins` is never consulted. This is a listing
    /// decision; the authority to elevate stays with migration 125's ticket
    /// definer, which re-checks this and more (a live passkey, a live family).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails. A failure is never mapped to
    /// "holds no role" here; the caller decides.
    #[instrument(skip(conn))]
    pub async fn holds_elevating_role(
        conn: &mut sqlx::PgConnection,
        principal: Uuid,
    ) -> Result<bool, DbError> {
        let held: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM public.platform_roles r \
                             WHERE r.elevates \
                               AND public.epigraph_holds_role($1, r.key, now()))",
        )
        .bind(principal)
        .fetch_one(&mut *conn)
        .await?;
        Ok(held)
    }

    /// Record one custodial act (`epigraph_record_custodial_act`): a
    /// `platform.custodial_act` audit row naming the assignment, refused
    /// (`CUS04`) unless `assignment` is a LIVE `role:platform-custodian`
    /// assignment held by `actor`. Call it in the SAME transaction as the act,
    /// so a refusal rolls the act back and the act never lands unrecorded.
    /// Returns the audit row's id.
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying `CUS04`, `22023` (an act outside
    /// [`CUSTODIAL_ACTS`]), or `42501` on a non-maintenance connection.
    #[instrument(skip(conn, details))]
    pub async fn record_custodial_act(
        conn: &mut sqlx::PgConnection,
        assignment: Uuid,
        actor: Uuid,
        act: &str,
        target_type: &str,
        target: Uuid,
        details: serde_json::Value,
    ) -> Result<Uuid, DbError> {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_record_custodial_act($1, $2, $3, $4, $5, $6)",
        )
        .bind(assignment)
        .bind(actor)
        .bind(act)
        .bind(target_type)
        .bind(target)
        .bind(details)
        .fetch_one(&mut *conn)
        .await?;
        Ok(id)
    }

    /// [`Self::record_custodial_act`] of a `claim.supersede` on a CONFIRMED
    /// `claim.custodial_supersede` act (migration 130): the recorder
    /// recomputes the act's args from the STORED successor (`details.new_id`,
    /// which must supersede `target`: its content's SHA-256 and its truth
    /// value) and from `details.reason` / `details.allow_owned`, and consumes
    /// the act; the `platform.custodial_act` row names it. Call it in the
    /// supersede's own transaction.
    ///
    /// # Errors
    /// [`Self::record_custodial_act`]'s, plus `ELV08` / `ELV09`.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(conn, details))]
    pub async fn record_custodial_act_on_act(
        conn: &mut sqlx::PgConnection,
        assignment: Uuid,
        actor: Uuid,
        act: &str,
        target_type: &str,
        target: Uuid,
        details: serde_json::Value,
        admin_act: Uuid,
    ) -> Result<Uuid, DbError> {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_record_custodial_act($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(assignment)
        .bind(actor)
        .bind(act)
        .bind(target_type)
        .bind(target)
        .bind(details)
        .bind(admin_act)
        .fetch_one(&mut *conn)
        .await?;
        Ok(id)
    }
}
