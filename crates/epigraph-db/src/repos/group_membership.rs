//! Repository for the `group_memberships` table

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the `group_memberships` table
#[derive(Debug, Clone, FromRow)]
pub struct MembershipRow {
    pub id: Uuid,
    pub group_id: Uuid,
    pub agent_id: Uuid,
    pub wrapped_key_share: Vec<u8>,
    pub epoch: i32,
    pub role: String,
    pub joined_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Outcome of [`GroupMembershipRepository::revoke_member_unless_last_admin`].
///
/// Three-valued because the route maps each case to a different HTTP status,
/// and the caller cannot recover the distinction from a row count alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// The membership was revoked.
    Revoked,
    /// The agent held no live membership in this group (404).
    NotAMember,
    /// The agent is the group's only live admin; revoking would leave the group
    /// permanently unadministrable (409).
    LastAdmin,
}

/// Repository for GroupMembership operations
pub struct GroupMembershipRepository;

impl GroupMembershipRepository {
    /// Add an agent to a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, wrapped_key_share))]
    pub async fn add_member(
        pool: &PgPool,
        group_id: Uuid,
        agent_id: Uuid,
        wrapped_key_share: &[u8],
        epoch: i32,
        role: &str,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(group_id)
        .bind(agent_id)
        .bind(wrapped_key_share)
        .bind(epoch)
        .bind(role)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Revoke a member's access by setting `revoked_at`.
    ///
    /// Returns the number of rows revoked — **0 means the agent was not a live
    /// member**, which the route turns into a 404. This previously discarded
    /// `rows_affected()` and returned `Ok(())` unconditionally, so removing a
    /// non-member was a silent HTTP 204 and told the caller nothing.
    ///
    /// **This function has no callers and is not the removal path.** PR-20's
    /// `group_key_epochs.status = 'rotating'` and `groups.reseal_required_at`
    /// writes live in [`Self::revoke_member_unless_last_admin`], which is what
    /// `DELETE /api/v1/groups/:id/members/:agent_id` actually calls. FINAL-PLAN
    /// PR-20's *Files* line names `remove_member`; measured on this tree, that
    /// name resolves here, to a function nothing invokes, so following it
    /// literally would have marked nothing on any real removal. The correction
    /// is recorded in `docs/tenancy/progress.json`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn remove_member(
        pool: &PgPool,
        group_id: Uuid,
        agent_id: Uuid,
    ) -> Result<u64, DbError> {
        let result = sqlx::query(
            r#"
            UPDATE group_memberships
            SET revoked_at = now()
            WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(group_id)
        .bind(agent_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Revoke a member, refusing to revoke the group's LAST live admin.
    ///
    /// **One statement, one snapshot.** The route used to do this as
    /// `get_member_role` -> `count_live_admins_excluding` -> `remove_member`,
    /// three round-trips on the pool with no transaction. That is check-then-act
    /// across three snapshots: two concurrent removals of admins A and B, when A
    /// and B are the only two admins, EACH see one other admin, both pass, and
    /// both revoke — leaving zero admins, which is precisely the outcome the
    /// guard exists to prevent and for which there is no break-glass path
    /// (`require_group_admin` is the only way in). "Both would have to pass a
    /// check against a roster that includes the other" was the reasoning error:
    /// they both do pass, *because* each sees the other.
    ///
    /// The `EXISTS` subquery is evaluated by the same `UPDATE` that writes, so
    /// the two serialise on the row locks the `UPDATE` takes: the loser of the
    /// race re-evaluates its subquery against the winner's committed state under
    /// READ COMMITTED and finds no other live admin.
    ///
    /// The follow-up read runs in the same transaction and only discriminates
    /// *why* zero rows changed.
    ///
    /// # PR-20: the removal MARKS the rotation obligation
    ///
    /// On the `Revoked` arm only, and in the same transaction, this now records
    /// FINAL-PLAN §6.7's obligation: `groups.reseal_required_at` is set and the
    /// group's current key epoch moves to `status = 'rotating'`. The removed
    /// member keeps a share that still decrypts everything sealed before the
    /// rotation, so revocation on its own discharges nothing, and an obligation
    /// nobody can see is one nobody services.
    ///
    /// It MARKS and does not enqueue. §6.7 is explicit that an automatic
    /// re-seal is deliberately not built: re-sealing needs the group key, which
    /// by §6.5.6 the server does not have, so a job scheduled here could only
    /// ever fail.
    ///
    /// Both writes are on the `Revoked` arm alone. The loser of the concurrent
    /// last-admin race sees `rows_affected() == 0` and returns `LastAdmin`; it
    /// revoked nobody and must mark nothing.
    ///
    /// `COALESCE(reseal_required_at, now())` rather than the plan's bare
    /// `now()`, and this is a deliberate documented deviation: the obligation
    /// dates from the FIRST unrotated removal. A bare `now()` restarts the
    /// clock on every subsequent removal, so a group with steady membership
    /// churn would never age past the seven days §6.7's gauge measures — the
    /// groups most in need of the alert would be exactly the ones excluded from
    /// it. Rotation does not clear the field either (see
    /// `GroupKeyEpochRepository::rotate_conn`); §6.7 point 3 gives that to the
    /// re-seal handler, when the last `claim_encryption` row has actually
    /// moved.
    ///
    /// Lock order across the three tables is `group_memberships`, then
    /// `groups`, then `group_key_epochs`. `GroupKeyEpochRepository::rotate_conn`
    /// takes the same two it needs in the same relative order — roster first,
    /// epoch row second — for exactly this reason: the reverse would let a
    /// rotation holding the epoch row wait on a removal holding the roster
    /// while the removal waited on the epoch row. Two concurrent removals
    /// serialise on the first table and cannot deadlock on the later two.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any statement fails.
    #[instrument(skip(pool))]
    pub async fn revoke_member_unless_last_admin(
        pool: &PgPool,
        group_id: Uuid,
        agent_id: Uuid,
    ) -> Result<RevokeOutcome, DbError> {
        let mut tx = pool.begin().await?;

        let result = sqlx::query(
            r#"
            UPDATE group_memberships
            SET revoked_at = now()
            WHERE group_id = $1
              AND agent_id = $2
              AND revoked_at IS NULL
              AND (
                    role <> 'admin'
                 OR EXISTS (
                        SELECT 1 FROM group_memberships m2
                        WHERE m2.group_id = $1
                          AND m2.agent_id <> $2
                          AND m2.role = 'admin'
                          AND m2.revoked_at IS NULL
                    )
              )
            "#,
        )
        .bind(group_id)
        .bind(agent_id)
        .execute(&mut *tx)
        .await?;

        let outcome = if result.rows_affected() > 0 {
            // FINAL-PLAN §6.7 point 2, in the transaction that did the
            // revoking. See this function's doc comment for why the timestamp
            // is COALESCEd and why nothing is enqueued.
            sqlx::query(
                r#"
                UPDATE groups
                SET reseal_required_at = COALESCE(reseal_required_at, now())
                WHERE id = $1
                "#,
            )
            .bind(group_id)
            .execute(&mut *tx)
            .await?;

            // The mark goes on the epoch row because `groups.status` cannot
            // hold it: `groups_status_check` admits only
            // active|suspended|deprovisioned, while
            // `group_key_epochs_status_check` admits active|rotating|retired.
            // The group stays usable — `GroupKeyEpochRepository::get_current_epoch`
            // treats `rotating` as current — so a removal records a debt
            // rather than causing an outage.
            sqlx::query(
                r#"
                UPDATE group_key_epochs
                SET status = 'rotating'
                WHERE group_id = $1 AND status = 'active'
                "#,
            )
            .bind(group_id)
            .execute(&mut *tx)
            .await?;

            RevokeOutcome::Revoked
        } else {
            // Zero rows: either no live membership at all, or the guard bit.
            let still_live: (bool,) = sqlx::query_as(
                r#"
                SELECT EXISTS (
                    SELECT 1 FROM group_memberships
                    WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL
                )
                "#,
            )
            .bind(group_id)
            .bind(agent_id)
            .fetch_one(&mut *tx)
            .await?;

            if still_live.0 {
                RevokeOutcome::LastAdmin
            } else {
                RevokeOutcome::NotAMember
            }
        };

        tx.commit().await?;
        Ok(outcome)
    }

    /// Count the group's live admins OTHER than `exclude_agent_id`.
    ///
    /// The last-admin guard on `DELETE /api/v1/groups/:id/members/:agent_id`
    /// does NOT use this: a separate count is a second snapshot, and two
    /// concurrent removals both pass it. That guard is
    /// [`Self::revoke_member_unless_last_admin`], which folds the count into the
    /// writing `UPDATE`. It was retained for PR-18's privatization approver
    /// check, which needs "≥ 2 live admins other than the plan author" on the
    /// target group as a read-only precondition — but PR-18's third slice folded
    /// that check into `InstanceAdminRepository::privatization_authority`, a
    /// single probe that answers all of FINAL-PLAN §6.6's conditions in one
    /// statement. **This function now has NO production caller**: what remains
    /// is its own regression coverage in
    /// `crates/epigraph-api/tests/group_lifecycle.rs`, which is what pins the
    /// "other than" semantics that `privatization_authority` restates.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count_live_admins_excluding(
        pool: &PgPool,
        group_id: Uuid,
        exclude_agent_id: Uuid,
    ) -> Result<i64, DbError> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT count(*) FROM group_memberships
            WHERE group_id = $1
              AND role = 'admin'
              AND revoked_at IS NULL
              AND agent_id <> $2
            "#,
        )
        .bind(group_id)
        .bind(exclude_agent_id)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Get active (non-revoked) members of a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_members(pool: &PgPool, group_id: Uuid) -> Result<Vec<MembershipRow>, DbError> {
        let rows: Vec<MembershipRow> = sqlx::query_as(
            r#"
            SELECT id, group_id, agent_id, wrapped_key_share, epoch, role, joined_at, revoked_at
            FROM group_memberships
            WHERE group_id = $1 AND revoked_at IS NULL
            ORDER BY joined_at ASC
            "#,
        )
        .bind(group_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Check whether an agent is an active member of a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn is_member(pool: &PgPool, group_id: Uuid, agent_id: Uuid) -> Result<bool, DbError> {
        let row: (bool,) = sqlx::query_as(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM group_memberships
                WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL
            )
            "#,
        )
        .bind(group_id)
        .bind(agent_id)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Get the role of an active member within a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_member_role(
        pool: &PgPool,
        group_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Option<String>, DbError> {
        let row: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT role FROM group_memberships
            WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL
            LIMIT 1
            "#,
        )
        .bind(group_id)
        .bind(agent_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| r.0))
    }

    /// [`Self::get_member_role`] over a borrowed connection.
    ///
    /// Exists for `POST /api/v1/groups/:id/rotate`, whose whole body runs on
    /// one `ScopedPool::begin_as` transaction: the handler must decide
    /// authorization on the SAME stamped connection that performs the rotation,
    /// and it must reach the raw application pool nowhere, because
    /// `crates/epigraph-db/tests/no_unscoped_pool.rs` holds
    /// `crates/epigraph-api/src/routes/groups.rs` at an exact site count with
    /// no headroom above [`HIGH_WATER`](no_unscoped_pool).
    ///
    /// A sibling rather than a signature change on `get_member_role`: making
    /// that function generic over `sqlx::PgExecutor` would move it into
    /// `visibility_lint.rs`'s `EXECUTOR_WITHOUT_VIEWER` register and rewrite
    /// two call sites this PR has no reason to touch.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(conn))]
    pub async fn get_member_role_conn(
        conn: &mut sqlx::PgConnection,
        group_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Option<String>, DbError> {
        let row: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT role FROM group_memberships
            WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL
            LIMIT 1
            "#,
        )
        .bind(group_id)
        .bind(agent_id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(|r| r.0))
    }

    /// Every live `(group_id, role)` pair for one agent.
    ///
    /// This is the single query behind `Viewer::resolve`
    /// (`crates/epigraph-db/src/visibility.rs`) and therefore sits on the hot
    /// path of every authenticated request once PR-07 attaches the extractor.
    /// It is served index-only by `idx_group_memberships_agent_live`
    /// (`migrations/060_group_tenancy_tables.sql:266-268`), whose columns are
    /// `(agent_id, group_id, role) WHERE revoked_at IS NULL` — exactly this
    /// predicate and exactly this projection, in that order.
    ///
    /// Rows are returned unordered. The partial unique index
    /// `group_memberships_one_live (group_id, agent_id) WHERE revoked_at IS
    /// NULL` (`migrations/060_group_tenancy_tables.sql:263-264`) guarantees at
    /// most one live row per `(group_id, agent_id)`, so a duplicate `group_id`
    /// is not reachable through the schema; `Viewer::resolve` still sorts and
    /// dedups defensively, because the bind it produces is fed to a `= ANY($V)`
    /// whose cost is proportional to the array length and nothing downstream
    /// should have to trust an index it cannot see.
    ///
    /// # Why this goes through `epigraph_live_memberships()` and not the table
    ///
    /// PR-17. This is the ONE statement in the system that provably runs with
    /// no tenancy GUC set, and it reads the table those GUCs are derived from.
    /// `Viewer::resolve` cannot use `ScopedPool::acquire_as` to stamp the
    /// connection first, because `acquire_as` takes the very `Viewer` this call
    /// is constructing — the dependency is circular by nature, not by oversight.
    ///
    /// Migration 077's `group_memberships_tenancy` keys its non-bypass arms on
    /// `epigraph_session_groups()` and `epigraph_principal_id()`, both of which
    /// are empty on an unstamped connection. Read directly, this query would
    /// therefore return ZERO rows for every principal once the app connects as a
    /// non-owner role; every viewer would resolve to `group_ids = []`; and the
    /// whole corpus would silently narrow to `visibility = 'public'` for its own
    /// owners. That is the sec-F1 defect, one layer ABOVE where the plan looks
    /// for it — it defeats RLS from above rather than from below, and it is
    /// fail-closed and invisible, indistinguishable from data loss.
    ///
    /// MEASURED on the throwaway at head 079, as `epigraph_app` with no GUCs:
    /// the direct read returns 0 rows and this call returns 1.
    ///
    /// `epigraph_live_memberships(uuid)` is `SECURITY DEFINER`, owned by
    /// `epigraph_maintenance`, `REVOKE`d from `PUBLIC` and granted only to
    /// `epigraph_app`. Inside its frame `current_user` is the owner, so
    /// `epigraph_definer_bypass()` is true and the policy's definer disjunct
    /// admits the scan. Its exposure is identical to this function's own: it was
    /// already callable with an arbitrary `agent_id` and already returned
    /// exactly `(group_id, role)`.
    ///
    /// The index note above still holds — the function body carries the same
    /// predicate and projection, so `idx_group_memberships_agent_live` serves it
    /// index-only exactly as before.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_live_for_agent(
        pool: &PgPool,
        agent_id: Uuid,
    ) -> Result<Vec<(Uuid, String)>, DbError> {
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT group_id, role FROM public.epigraph_live_memberships($1)")
                .bind(agent_id)
                .fetch_all(pool)
                .await?;

        Ok(rows)
    }
}
