//! Repository for the `instance_admins` table — the D4 privatization authority.
//!
//! # Why nothing here takes a `Viewer`, written down rather than omitted
//!
//! `visibility_lint.rs` only inspects functions whose parameter list mentions
//! `Viewer`, so a repository that takes none exits its scope silently. That
//! silence must be a decision, not an oversight.
//!
//! These are **authority lookups over an authority table**, not corpus content
//! reads. A `Viewer` describes which claim/evidence/edge rows a principal may
//! see; it has no meaning for "is this agent an instance administrator". The
//! controls on this table are the ones migration 083 installs:
//!
//! * `instance_admins_self_or_definer` — an app connection reads its own row
//!   and nothing else;
//! * `REVOKE INSERT, UPDATE, DELETE … FROM epigraph_app`, plus INSERT and UPDATE
//!   policies whose only disjunct is `epigraph_bypass()`. That predicate reads
//!   `session_user`, which is `epigraph_app` on a request connection and is not
//!   changed by a `SECURITY DEFINER` frame, so the app role is denied by the
//!   REVOKE and denied again by the policy evaluating false. **DELETE is the one
//!   command whose second control is the absence of a policy**: 083 installs no
//!   DELETE policy at all, so under `FORCE` no role can delete a row.
//! * `epigraph_is_instance_admin(uuid)`, `SECURITY DEFINER` owned by
//!   `epigraph_maintenance`, which is how an app connection asks about its own
//!   authority without being able to read the roster.
//!
//! An earlier revision of this list said "the absence of any write policy —
//! default-denied twice over" for all three write commands. That named the wrong
//! second control, and the distinction is load-bearing in one direction: a future
//! author who believes absence is the control will read
//! `GRANT INSERT ON instance_admins TO epigraph_app` as harmless, when under the
//! real design the REVOKE is one of only two things standing in front of a
//! bypass predicate.
//!
//! [`InstanceAdminRepository::is_active`] therefore asks the function rather
//! than reading the table. Reading the table directly from the request pool
//! would return zero rows for every agent except the caller, and a caller that
//! read that as "not an admin" would deny an authorised operator — fail-closed,
//! but wrongly, and invisibly.
//!
//! # There is no write side any more (migration 123)
//!
//! Instance administration is `role:platform-custodian`, held by a registered
//! human through `role_assignments` ([`crate::repos::RoleAssignmentRepository`],
//! written by `epigraph-operator grant-role` / `end-role-assignment` on the
//! maintenance DSN). `instance_admins` is frozen for every role (a trigger
//! refuses any INSERT or edit but a `revoked_at` stamp), so the `grant` and
//! `revoke` this repository used to carry are removed: a call would only meet
//! `CUS05`. [`InstanceAdminRepository::list`] stays, read-compatible, for the
//! legacy rows; [`InstanceAdminRepository::is_active`] keeps its name and asks
//! the re-bodied `epigraph_is_instance_admin`, which answers from the role.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the `instance_admins` table.
#[derive(Debug, Clone, FromRow)]
pub struct InstanceAdminRow {
    pub agent_id: Uuid,
    pub granted_by: Option<Uuid>,
    pub granted_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub note: Option<String>,
}

/// Repository for instance-administrator grants.
pub struct InstanceAdminRepository;

/// The four facts FINAL-PLAN §6.6's check is a function of.
///
/// Deliberately NOT a `bool`. The middleware turns each field into a distinct
/// 403 reason, and collapsing them here would make an authorised operator's
/// refusal indistinguishable from an unauthorised one's — which is the outcome
/// `middleware/instance_authz.rs`'s header says the whole function exists to
/// prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivatizationAuthority {
    /// Condition 2: the caller holds `role:platform-custodian` now (since
    /// migration 123 `epigraph_is_instance_admin` answers from the role, not
    /// from the frozen `instance_admins` table).
    pub is_instance_admin: bool,
    /// The live custodian assignment that makes condition 2 true, so a
    /// custodial act can be recorded against it (`None` exactly when
    /// `is_instance_admin` is false).
    pub custodian_assignment_id: Option<Uuid>,
    /// `None` when the target group does not exist. Otherwise the value
    /// condition 3a's 24-hour maturity test is applied to.
    pub target_group_created_at: Option<DateTime<Utc>>,
    /// Live `role='admin'` memberships of the target group OTHER than the
    /// caller (condition 3b).
    pub other_live_admins: i64,
    /// The caller's own live `role='admin'` membership of the target group
    /// (condition 4).
    pub is_target_group_admin: bool,
}

impl InstanceAdminRepository {
    /// Is `agent_id` a live instance administrator?
    ///
    /// Answered through `public.epigraph_is_instance_admin(uuid)` — see the
    /// module docs for why this is not a table read. The function is
    /// `SECURITY DEFINER` owned by `epigraph_maintenance`.
    ///
    /// An agent with no grant, a revoked grant, or no row at all is `false`.
    /// There is no third state and no error path that returns `true`.
    ///
    /// # ⚠ `pool` MUST be a stamped or maintenance connection
    ///
    /// Migration 083 binds the function's subject inside its body: the answer is
    /// `false` unless `p_agent` is the session principal
    /// (`epigraph.principal_id`, which only [`crate::pool::ScopedPool`] sets) or
    /// `epigraph_bypass()` is true (a `session_user` that is a member of
    /// `epigraph_maintenance`, which includes any superuser). That is what stops
    /// the function being a roster oracle for anything holding an `epigraph_app`
    /// login — the SELECT policy narrows an app connection to its own row, and an
    /// unbound definer predicate would route around exactly that.
    ///
    /// The consequence for callers is concrete: on a BARE, UNSTAMPED `epigraph_app`
    /// pool this returns `false` for every agent, which denies an authorised
    /// operator — fail-closed, but wrongly. CI and every developer host connect
    /// as a superuser, so the bypass arm carries it there; under the posture plan
    /// §9.2 step 11d prescribes it does not. PR-18b owns the connection-shape
    /// decision for its caller `require_instance_admin_for_group`; the register
    /// carries this as an open obligation rather than leaving it to be discovered.
    ///
    /// `false` here means `false`, and that is enforced twice. Migration 083's
    /// body is wrapped in `COALESCE(…, false)` because the unstamped-non-bypass
    /// case is three-valued at the SQL level — the principal comparison is NULL
    /// against a NULL GUC, so a live admin evaluates `true AND NULL AND true`.
    /// The `Option<bool>` decode below is the second half: it means a database
    /// that predates that `COALESCE` yields `false` rather than a decode error,
    /// so this function cannot turn a documented denial into a 500.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails. A failure is
    /// propagated rather than mapped to `false`, so a caller cannot mistake an
    /// unreachable database for a definite negative. A NULL result is NOT such a
    /// failure and is mapped to `false`; see above.
    #[instrument(skip(pool))]
    pub async fn is_active(pool: &PgPool, agent_id: Uuid) -> Result<bool, DbError> {
        let row: (Option<bool>,) = sqlx::query_as("SELECT public.epigraph_is_instance_admin($1)")
            .bind(agent_id)
            .fetch_one(pool)
            .await?;
        Ok(row.0.unwrap_or(false))
    }

    /// Every fact FINAL-PLAN §6.6's four-condition check needs, in ONE
    /// statement on ONE connection.
    ///
    /// # Why this exists rather than four separate repository calls
    ///
    /// `middleware/instance_authz.rs` originally composed
    /// [`Self::is_active`], `GroupRepository::get_by_id`,
    /// `GroupMembershipRepository::count_live_admins_excluding` and
    /// `get_member_role`, all of which take a `&PgPool`. A route cannot supply
    /// one: `no_unscoped_pool.rs` bans `.db_pool` in `crates/epigraph-api/src`
    /// with an exact, monotone-decreasing register, and the only pools reachable
    /// from `AppState` that are NOT that one are hidden behind connection-
    /// yielding accessors (`read_as`, `maintenance_viewer`) by design. Widening
    /// those four to take a connection would either duplicate them as `*_conn`
    /// siblings — the drift shape `visibility_lint.rs::CONN_WITHOUT_VIEWER`'s own
    /// doc names — or pull four heavily-used functions into a lint register on a
    /// reason that has nothing to do with why they were widened.
    ///
    /// One purpose-built probe is smaller, and it is also more correct: the four
    /// facts are read at one instant rather than across four round trips, so the
    /// caller cannot authorise against a group that lost its second admin between
    /// the third call and the fourth.
    ///
    /// # Why it takes no `Viewer`, and what connection it needs
    ///
    /// This is an AUTHORIZATION probe about the CALLER'S OWN identity, not a
    /// corpus read. Filtering it by the caller's `Viewer` would make the answer
    /// depend on what that caller can currently see rather than on what is true —
    /// a caller who cannot see the target group's other admins would be told
    /// there are none and refused, which is a fail-closed wrong answer and
    /// indistinguishable from the real one. It is the same argument
    /// `epigraph_is_group_admin` embodies at the SQL level.
    ///
    /// So it must run on a connection that can see the whole roster: the
    /// **maintenance** connection. On a stamped app connection the two
    /// `group_memberships` sub-selects are narrowed by migration 077's policy and
    /// the counts under-report. `epigraph_is_instance_admin` works on either — it
    /// is `SECURITY DEFINER` and admits `p_agent = epigraph_principal_id() OR
    /// epigraph_bypass()` — which is exactly why the other three facts are the
    /// ones that decide the connection.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails. A failure is never
    /// mapped to an authorisation.
    #[instrument(skip(conn))]
    pub async fn privatization_authority(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
        target_group_id: Uuid,
    ) -> Result<PrivatizationAuthority, DbError> {
        let row: (Option<bool>, Option<DateTime<Utc>>, i64, bool, Option<Uuid>) = sqlx::query_as(
            r#"
            SELECT public.epigraph_is_instance_admin($1),
                   (SELECT g.created_at FROM public.groups g WHERE g.id = $2),
                   (SELECT count(*) FROM public.group_memberships m
                     WHERE m.group_id = $2 AND m.role = 'admin'
                       AND m.revoked_at IS NULL AND m.agent_id <> $1),
                   EXISTS (SELECT 1 FROM public.group_memberships m
                            WHERE m.group_id = $2 AND m.agent_id = $1
                              AND m.role = 'admin' AND m.revoked_at IS NULL),
                   public.epigraph_role_assignment_for($1, 'role:platform-custodian', now())
            "#,
        )
        .bind(agent_id)
        .bind(target_group_id)
        .fetch_one(&mut *conn)
        .await?;

        let is_instance_admin = row.0.unwrap_or(false);
        Ok(PrivatizationAuthority {
            is_instance_admin,
            // Read in the same statement as condition 2, so the two cannot
            // disagree about the instant; filtered to it so a caller never
            // records an act against an assignment condition 2 did not see.
            custodian_assignment_id: row.4.filter(|_| is_instance_admin),
            target_group_created_at: row.1,
            other_live_admins: row.2,
            is_target_group_admin: row.3,
        })
    }

    /// List grants, live ones only unless `include_revoked`.
    ///
    /// On an app-role connection `instance_admins_self_or_definer` filters this
    /// to the caller's own row, which is why the CLI runs it on the maintenance
    /// pool. That narrowing is the policy working, not a failure.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list(
        pool: &PgPool,
        include_revoked: bool,
    ) -> Result<Vec<InstanceAdminRow>, DbError> {
        let rows: Vec<InstanceAdminRow> = sqlx::query_as(
            r#"
            SELECT agent_id, granted_by, granted_at, revoked_at, note
            FROM instance_admins
            WHERE $1 OR revoked_at IS NULL
            ORDER BY granted_at DESC
            "#,
        )
        .bind(include_revoked)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }
}
