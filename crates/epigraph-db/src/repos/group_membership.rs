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
    /// Deliberately does NOT set `group_key_epochs.status = 'rotating'` or
    /// `groups.reseal_required_at`. Revocation without a key rotation leaves the
    /// removed member able to decrypt anything they already hold; making the
    /// rotation obligation explicit is PR-20's job, and doing half of it here
    /// would look like the obligation was already discharged.
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
    /// writing `UPDATE`. This function survives for PR-18's privatization
    /// approver check, which needs "≥ 2 live admins other than the plan author"
    /// on the target group as a read-only precondition.
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
}
