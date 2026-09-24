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
    /// **The rows the decision reads are locked before the decision is made.**
    /// The route used to do this as
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
    /// Folding the count into the writing `UPDATE` is NECESSARY BUT NOT
    /// SUFFICIENT, and this doc comment used to claim otherwise — it said the
    /// two removals "serialise on the row locks the `UPDATE` takes". They do
    /// not. An `UPDATE` locks the row it WRITES, not the rows its `WHERE`
    /// clause READS. Removals of admins A and B write different rows, so they
    /// never block each other, and each one's `EXISTS` reads the other's row
    /// without locking it: both still see a second live admin, both proceed,
    /// and the group still ends with zero admins. One statement is one
    /// snapshot; it is just not a snapshot anyone else is excluded from.
    ///
    /// So the transaction OPENS by locking the group's ENTIRE live roster —
    /// `WHERE group_id = $1 AND revoked_at IS NULL ORDER BY agent_id
    /// FOR UPDATE`. That set contains every row the guard subsequently touches:
    /// the rows its `EXISTS` can match (the subquery only narrows the roster
    /// further, with `agent_id <> $2` and `role = 'admin'`) AND the target row
    /// the `UPDATE` writes. Any two concurrent removals in the same group
    /// therefore ask for the same rows before either decides, so the second
    /// cannot reach the guard until the first commits. When it unblocks, READ
    /// COMMITTED re-applies the lock statement's own qual to the newly
    /// committed row version: a just-revoked member drops out of the set rather
    /// than raising a serialization failure, and the guard `UPDATE` that
    /// follows takes a fresh statement snapshot that includes the winner's
    /// commit. The loser's `EXISTS` therefore finds no other live admin, and it
    /// refuses.
    ///
    /// The roster, not just the admin rows, is deliberate. Locking only the
    /// admins would be enough for the guard itself, but it would leave the
    /// target row of a non-admin removal outside the ordered lock set, to be
    /// picked up later by the `UPDATE`; see the lock-order section below for
    /// why every `group_memberships` row this transaction touches must be
    /// acquired by that one ordered statement.
    ///
    /// Locking ZERO rows means the group has no live member at all — so, a
    /// fortiori, no live admin. That is benign, and deliberately not an early
    /// return: the guard `UPDATE` then matches nothing, the follow-up read
    /// finds no live row either, and the caller gets `NotAMember`, which is the
    /// same answer it got before this lock existed.
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
    /// `groups`, then `group_key_epochs`, and the `FOR UPDATE` above does NOT
    /// change it: it is on `group_memberships`, the table this transaction
    /// already took first. That is why it was preferred to locking the
    /// `groups` row instead — taking one here FIRST would invert the order
    /// against `CommunityRepository::remove_member`, which holds the
    /// `group_memberships` roster while it writes `groups` for the SAME id (the
    /// community projection is id-preserving). Since batch F that function's
    /// definer (`epigraph_community_remove_member`, migration 106) and its
    /// `add_member` twin DO take a `groups` row lock, but only AFTER the same
    /// roster lock, so the order is unchanged. `GroupKeyEpochRepository::rotate_conn` takes the same
    /// two it needs in the same relative order — roster first, epoch row
    /// second — for exactly this reason: the reverse would let a rotation
    /// holding the epoch row wait on a removal holding the roster while the
    /// removal waited on the epoch row.
    ///
    /// WITHIN `group_memberships`, EVERY row this transaction locks is acquired
    /// by that one opening statement, and it selects the same rows in the same
    /// order as `rotate_conn`'s roster lock: same table, same predicate, same
    /// `ORDER BY` (the two literals differ only in line breaks). The
    /// guard `UPDATE`'s own row lock is not an additional acquisition: the
    /// target is already in the roster, so the `UPDATE` re-takes a lock the
    /// transaction holds. That is what makes the ordering argument true rather
    /// than merely plausible — a rotation and a removal on one group request
    /// the identical row set in the identical `agent_id` order, so they queue.
    /// Narrowing the lock statement (to admins only, say) would break this,
    /// because a non-admin target would then be acquired AFTER rows that sort
    /// above it. Two concurrent removals of DIFFERENT members of one group both
    /// still succeed; they serialise on the shared roster, and neither is
    /// refused.
    ///
    /// `FOR UPDATE` does not prevent an `INSERT`, so a concurrent `add_member`
    /// can still add an admin the lock set never saw. That direction is safe
    /// here — it can only make the guard's `EXISTS` true, i.e. permit a removal
    /// that leaves the group with the admin just added — and it is the same
    /// pre-existing check-then-act in `add_member` that `rotate_conn` names.
    /// This function does not close it and does not claim to.
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

        // THE ROWS THE GUARD READS AND WRITES, LOCKED BEFORE IT READS THEM.
        // The `UPDATE` below locks only the row it writes; this locks the whole
        // live roster, which contains both that row and every row its `EXISTS`
        // consults. The predicate and the `ORDER BY` are IDENTICAL to
        // `GroupKeyEpochRepository::rotate_conn`'s roster lock — same table,
        // same qual, same order — so the two functions request the same rows in
        // the same sequence. Keep them identical: this is the whole of the
        // ordering argument in the doc comment. See that comment for the READ
        // COMMITTED re-evaluation that makes the loser refuse, and for why zero
        // locked rows is benign.
        //
        // The binding exists only to feed the debug line below; the LOCK is the
        // point, not the rows. Do not delete the query along with the log.
        let locked_roster: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT agent_id
            FROM group_memberships
            WHERE group_id = $1
              AND revoked_at IS NULL
            ORDER BY agent_id
            FOR UPDATE
            "#,
        )
        .bind(group_id)
        .fetch_all(&mut *tx)
        .await?;

        tracing::debug!(
            locked_roster = locked_roster.len(),
            "last-admin guard: locked the group's live roster"
        );

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

    /// How many REVOKED membership rows `agent_id` holds, read through the
    /// policy's OWN-ROW arm.
    ///
    /// # The discriminator a provisioning mint must consult first
    ///
    /// Migration 077's `epigraph_ensure_personal_group` ended in `ON CONFLICT
    /// (group_id, agent_id, epoch) DO UPDATE SET revoked_at = NULL, role =
    /// 'admin'`: called for an agent that already held a revoked row in its
    /// personal group, it REVIVED that admin membership. So "this agent cannot
    /// see its personal group" did not on its own license a mint — "never
    /// provisioned" and "deliberately revoked" both look like that — and this
    /// count is what tells them apart: `0` means there is no revoked row. Since
    /// migration 105 the function refuses a revoked row itself; this read is
    /// how a caller learns WHY before it asks. (A live `reader` row is the other thing the same
    /// `DO UPDATE` would silently change; it is live, so the personal group is
    /// visible to a stamped caller and never reaches the mint branch at all.)
    ///
    /// # The connection MUST be stamped with `agent_id` as its principal
    ///
    /// Migration 077's `group_memberships_tenancy` `USING` carries the arm
    /// `agent_id = epigraph_principal_id()`, which admits an agent's own rows
    /// whatever their state and whatever the session's group set — including an
    /// EMPTY one, which is exactly what `ScopedPool::begin_as` stamps from the
    /// viewer `Viewer::resolve` returns for an agent with no live membership.
    /// MEASURED as `epigraph_app` (`rolbypassrls = false`) on a database
    /// migrated 001→head, for an agent whose only membership had been revoked:
    ///
    /// ```text
    /// unstamped                          own rows (any state) = 0   <- blind
    /// principal-only stamp, no groups    own rows (any state) = 1
    ///                                    own REVOKED rows     = 1
    /// principal-only stamp, OTHER agent  that agent's rows    = 0
    /// ```
    ///
    /// The consumer's end-to-end arm (revoke the ingest system agent's
    /// membership, call `store_workflow`, re-read `revoked_at`) is
    /// `scripts/e2e/probe-unit-e.sh`'s REVOKED arm.
    ///
    /// Unstamped it returns `0` for EVERY agent — wrong in exactly the direction
    /// that re-opens the revival — so it takes a connection, never a pool, and
    /// the caller owns the stamp.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn count_own_revoked_rows_conn(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
    ) -> Result<i64, DbError> {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM group_memberships \
              WHERE agent_id = $1 AND revoked_at IS NOT NULL",
        )
        .bind(agent_id)
        .fetch_one(&mut *conn)
        .await?;
        Ok(n)
    }

    /// The id of `agent_id`'s personal group (`did:epigraph:personal:<uuid>`) as
    /// THIS connection can see it — a pure read that never mints.
    ///
    /// `ClaimRepository::personal_group_of` is the read-first-then-mint twin;
    /// this is the half of it that cannot write. On a connection stamped from the
    /// agent's own viewer, `None` means the agent holds no LIVE membership of its
    /// personal group (`groups_tenancy` admits a group through `id =
    /// ANY(session_groups)`, or to its creator only while the roster admits them
    /// — migration 092). It does NOT mean the group does not exist: pair it with
    /// [`Self::count_own_rows_any_state_conn`] before treating `None` as "never
    /// provisioned".
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn visible_personal_group_conn(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
    ) -> Result<Option<Uuid>, DbError> {
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
        )
        .bind(agent_id)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(id)
    }

    /// Whether THIS connection's stamp may write rows owned by `group_id`:
    /// `group_id = ANY(epigraph_writable_groups())`, evaluated on the caller's
    /// own connection — a pure read that never mints.
    ///
    /// It is the exact question migration 077's `WITH CHECK (owner_group_id =
    /// ANY(epigraph_writable_groups()))` will ask of every row the caller then
    /// writes on the same connection, asked BEFORE the first write so a refusal
    /// can be reported with nothing written. It reads no table: the answer comes
    /// from the `epigraph.writable_group_ids` GUC the stamp set (migration 067),
    /// so a live `reader` membership answers `false`, and an UNSTAMPED
    /// connection answers `false` for every group (the function is `{}` without
    /// the GUC) — it fails closed.
    ///
    /// It deliberately takes a connection and not a `Viewer`: a `Viewer`'s
    /// `writable_groups()` is the set a stamp was COMPUTED from, while this asks
    /// the set the connection actually CARRIES, which is what the `WITH CHECK`
    /// evaluates.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn session_can_write_group_conn(
        conn: &mut sqlx::PgConnection,
        group_id: Uuid,
    ) -> Result<bool, DbError> {
        let writable: bool =
            sqlx::query_scalar("SELECT $1 = ANY(public.epigraph_writable_groups()::uuid[])")
                .bind(group_id)
                .fetch_one(&mut *conn)
                .await?;
        Ok(writable)
    }
}
