//! Repository for the `group_key_epochs` table

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use std::collections::BTreeSet;
use tracing::instrument;
use uuid::Uuid;

/// A row from the `group_key_epochs` table
#[derive(Debug, Clone, FromRow)]
pub struct KeyEpochRow {
    pub id: Uuid,
    pub group_id: Uuid,
    pub epoch: i32,
    pub wrapped_key: Option<Vec<u8>>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

/// Outcome of [`GroupKeyEpochRepository::rotate_conn`].
///
/// Multi-valued for the same reason as
/// [`crate::repos::group_membership::RevokeOutcome`]: the route maps each
/// refusal to a different HTTP status and a different operator instruction, and
/// none of them is recoverable from a row count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateOutcome {
    /// Epoch N was retired and epoch N+1 created, with every live member
    /// re-wrapped, in one transaction.
    Rotated {
        previous_epoch: i32,
        new_epoch: i32,
        members_rewrapped: usize,
    },
    /// The group has no `active` or `rotating` epoch to retire. Either the id
    /// names no group, or the group is broken — `GroupRepository::create_with_admin`
    /// writes epoch 0 in the same transaction as the group row, so this is not
    /// reachable through the normal path.
    NoCurrentEpoch,
    /// FINAL-PLAN §6.7's gate: the retiring epoch's key is not recoverable, so
    /// rotating would strand every `claim_encryption` row bound to it behind a
    /// key nobody can ever produce again. Recoverable means the epoch row
    /// carries a `wrapped_key`, or the group carries a
    /// `properties->>'kms_key_ref'`.
    RetiringKeyUnrecoverable,
    /// The submitted shares do not cover exactly the live roster the
    /// transaction locked. `missing` are live members with no submitted share;
    /// `unknown` are submitted shares naming an agent who is not a live member.
    RosterMismatch {
        missing: Vec<Uuid>,
        unknown: Vec<Uuid>,
    },
    /// The submission names the same agent more than once.
    ///
    /// A separate refusal rather than a silent collapse: the set-difference
    /// roster check deduplicates by construction, so `[A, A, B]` against a live
    /// roster of `{A, B}` would pass it, the last share written for `A` would
    /// silently win over the first, and the reported re-wrap count would exceed
    /// the roster. Two contradictory shares for one member is the same class of
    /// ambiguity the roster contract exists to refuse.
    DuplicateShares { agent_ids: Vec<Uuid> },
}

/// Repository for GroupKeyEpoch operations
pub struct GroupKeyEpochRepository;

impl GroupKeyEpochRepository {
    /// Create a new key epoch for a group.
    ///
    /// Thin wrapper over [`Self::create_epoch_conn`] for callers that are not
    /// already inside a transaction.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, wrapped_key))]
    pub async fn create_epoch(
        pool: &PgPool,
        group_id: Uuid,
        epoch: i32,
        wrapped_key: Option<&[u8]>,
        status: &str,
    ) -> Result<Uuid, DbError> {
        let mut conn = pool.acquire().await?;
        Self::create_epoch_conn(&mut conn, group_id, epoch, wrapped_key, status).await
    }

    /// `create_epoch` over a borrowed connection, for callers already inside a
    /// transaction.
    ///
    /// `GroupRepository::create_with_admin` inlined an equivalent INSERT that
    /// additionally pinned `status = 'active'`, which left this function with
    /// zero callers workspace-wide and two statements free to drift apart —
    /// exactly the pair migration 060's ROTATION CONTRACT comment addresses by
    /// name. `status` is therefore an explicit parameter rather than relying on
    /// the column DEFAULT: an epoch row's status is the rotation state machine,
    /// and a caller must say which state it is writing.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(conn, wrapped_key))]
    pub async fn create_epoch_conn(
        conn: &mut sqlx::PgConnection,
        group_id: Uuid,
        epoch: i32,
        wrapped_key: Option<&[u8]>,
        status: &str,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO group_key_epochs (group_id, epoch, wrapped_key, status)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
        )
        .bind(group_id)
        .bind(epoch)
        .bind(wrapped_key)
        .bind(status)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.0)
    }

    /// The group's CURRENT key epoch: the one new content is sealed under and
    /// new members are pinned to.
    ///
    /// # Why this is not `get_active_epoch`, and why the predicate is wider
    ///
    /// PR-20 makes member removal set the current epoch's `status = 'rotating'`
    /// (FINAL-PLAN §6.7 point 2) to record that a re-key is owed. Under the
    /// former `WHERE status = 'active'` predicate that single UPDATE took the
    /// group's epoch lookup to `None`, which made
    /// `POST /groups/:id/members` answer 409, `POST /claims` answer 400 for any
    /// claim owned by the group, and `GET /groups/:id` report a null
    /// `current_epoch` — until an operator got round to rotating. §6.7's own
    /// gauge counts groups whose obligation is **more than seven days old**,
    /// which presupposes the obligation can sit unmet; a group that is bricked
    /// for writes in the meantime is not a deferred obligation, it is an
    /// outage, and nothing in the plan asks removal to cause one.
    ///
    /// So `'rotating'` is a MARK on the still-usable current epoch, not a
    /// removal of it, and the function was renamed rather than quietly widened:
    /// a function called `get_active_epoch` that returns a row whose status is
    /// not `active` is a name that lies, and every lint in this crate exists
    /// because a name lied.
    ///
    /// `ORDER BY (status = 'active') DESC, epoch DESC` puts the preference in
    /// the statement rather than in a reasoning step. Only one non-retired row
    /// per group is reachable — `group_key_epochs_one_active` admits one
    /// `active`, and only [`Self::rotate_conn`] and the removal path move a row
    /// between the two live states, each retiring what it supersedes — but the
    /// ordering makes the answer deterministic without relying on that.
    ///
    /// # What the wider predicate costs, stated so it is not read as free
    ///
    /// Treating `rotating` as current means content written while the mark is
    /// outstanding is sealed under the SAME epoch key a removed member may
    /// still hold, and a member added during that window is pinned to it too.
    /// The exposure §6.7 discloses therefore extends forward in time, not only
    /// backward over what was already sealed. That is the deliberate trade for
    /// not turning every removal into a write outage, and it is why
    /// `epigraph_groups_reseal_required` is an ALERT with an age clause rather
    /// than a report: the window is meant to be short.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_current_epoch(
        pool: &PgPool,
        group_id: Uuid,
    ) -> Result<Option<KeyEpochRow>, DbError> {
        let row: Option<KeyEpochRow> = sqlx::query_as(
            r#"
            SELECT id, group_id, epoch, wrapped_key, status, created_at, retired_at
            FROM group_key_epochs
            WHERE group_id = $1 AND status IN ('active', 'rotating')
            ORDER BY (status = 'active') DESC, epoch DESC
            LIMIT 1
            "#,
        )
        .bind(group_id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Retire epoch N, create epoch N+1 and re-wrap every live member's share —
    /// in ONE transaction, gated on the retiring epoch's key being recoverable.
    ///
    /// This is FINAL-PLAN PR-20's `rotate_tx`. It takes a borrowed connection
    /// rather than a pool so the caller can supply a `ScopedPool::begin_as`
    /// transaction: the three tables written here (`group_key_epochs`,
    /// `group_memberships`, and `groups` indirectly through the removal path)
    /// all carry FORCEd RLS policies from migrations 077/079 that key on the
    /// CONNECTION's tenancy GUCs, so an unstamped connection would write
    /// nothing from §9.2 step 11d onward.
    ///
    /// The plan spells the name `rotate_tx`; it is spelled `rotate_conn` here
    /// because `crates/epigraph-db/tests/visibility_lint.rs` selects functions
    /// to lint on `name.ends_with("_conn") && params.contains("PgConnection")`.
    /// Under the plan's spelling this function — which is viewer-less and reads
    /// two tables — was invisible to that assertion, and the exact-set equality
    /// on `CONN_WITHOUT_VIEWER` would have kept silently passing while no
    /// longer covering the repo's viewer-less connection reads. The name is the
    /// thing the lint keys on, so the name is what had to change. Recorded in
    /// `docs/tenancy/progress.json` under `plan_corrections`.
    ///
    /// # The gate, and why it is not advisory
    ///
    /// Migration 060 keeps retired epochs and their `claim_encryption` rows,
    /// which stay bound to epoch N by `claim_encryption_epoch_fkey`. If the key
    /// for epoch N is not recoverable at the moment N is retired, every claim
    /// sealed under it is ciphertext nobody can ever read again — an
    /// irreversible data loss caused by a routine-looking operation. So the
    /// rotation refuses unless the RETIRING epoch row carries a `wrapped_key`,
    /// or the group carries a `properties->>'kms_key_ref'` naming an external
    /// escrow (FINAL-PLAN §6.5.6). The `groups` read happens inside this
    /// transaction so the gate cannot be satisfied by a value that changed
    /// afterwards.
    ///
    /// **The gate takes no key material from the caller, and an earlier
    /// revision of this function did.** It accepted a `retiring_wrapped_key`
    /// that was `COALESCE`d onto the retired row, on the argument that the
    /// first disjunct would otherwise be unreachable for a group that had never
    /// escrowed anything. That argument is answered by FINAL-PLAN §5.4, which
    /// says `group_key_epochs.wrapped_key` stays NULL under both production
    /// custody models by design and names `properties->>'kms_key_ref'` as the
    /// production satisfier. A server-side deposit path was also unbudgeted —
    /// §6.5.7's interface row gives this route no body beyond the shares — and
    /// the server can verify nothing about a blob purporting to BE the outgoing
    /// group key, so an arbitrary value would have satisfied the one gate that
    /// stands between a routine operation and permanent unreadability. The
    /// field was withdrawn rather than validated: there is no in-tree
    /// definition of an escrowed epoch key's shape, so any check would have
    /// pinned an invented wire format. The incoming epoch N+1 is likewise
    /// created with no `wrapped_key` at all.
    ///
    /// # The roster contract
    ///
    /// `shares` must cover EXACTLY the live roster this transaction locked:
    /// every live member gets a new share, and no share may name a non-member.
    /// This is what discharges the enforceable half of the deferred obligation
    /// `D-PR20-A` — an epoch advance is accompanied by a re-wrapped share for
    /// every live member, in the same transaction, enforced rather than
    /// conventional. The UNENFORCEABLE half stays deferred and is stated here
    /// so it is not mistaken for closed: the server holds no group key material
    /// (§6.5.6) and `group_key_epochs` carries no column tying an epoch to a
    /// base-key generation, so nothing here can verify that the submitted
    /// shares wrap a FRESH base key rather than the outgoing one. The wrap
    /// AAD's epoch component binds the wrap message; it is not a substitute.
    ///
    /// The roster is read `FOR UPDATE`, which closes the concurrent-revocation
    /// race. It does NOT close a concurrent `add_member`: row locks do not
    /// prevent an INSERT, so a member added after this snapshot lands at epoch
    /// N and is not re-wrapped here. That is the pre-existing check-then-act in
    /// `add_member`, not one this function introduces, and the guarantee is
    /// therefore stated over the roster the transaction saw.
    ///
    /// The group creator's row is included, and that is deliberate:
    /// `GroupRepository::create_with_admin` writes their `wrapped_key_share`
    /// as `''::bytea` because they generated the base key and had nothing to
    /// wrap. At epoch N+1 there IS something to wrap — a key they may not have
    /// minted — so rotation normalises that row to a real share rather than
    /// carrying the empty one forward.
    ///
    /// # `reseal_required_at` is deliberately NOT cleared
    ///
    /// Rotation gates future ciphertext only; the claims sealed under epoch N
    /// are still sealed under epoch N. §6.7 point 3 gives the clearing to
    /// `PrivatizationResealHandler`, when the last `claim_encryption` row has
    /// actually moved. Clearing it here would report an obligation as
    /// discharged that has not been.
    ///
    /// # Errors
    /// * `DbError::InvalidData` if the epoch counter would overflow `i32`.
    /// * `DbError::QueryFailed` if any statement fails. The caller owns the
    ///   transaction and must roll back — a partial rotation is exactly the
    ///   state that leaves zero or two active epochs.
    #[instrument(skip(conn, shares))]
    pub async fn rotate_conn(
        conn: &mut sqlx::PgConnection,
        group_id: Uuid,
        shares: &[(Uuid, Vec<u8>)],
    ) -> Result<RotateOutcome, DbError> {
        // THE LIVE ROSTER IS LOCKED FIRST, and the order is load-bearing.
        // `GroupMembershipRepository::revoke_member_unless_last_admin` locks
        // `group_memberships` and then `group_key_epochs`; taking them the
        // other way round here would let a rotation holding the epoch row wait
        // on a removal holding the roster while that removal waited on the
        // epoch row.
        let live: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT agent_id
            FROM group_memberships
            WHERE group_id = $1 AND revoked_at IS NULL
            ORDER BY agent_id
            FOR UPDATE
            "#,
        )
        .bind(group_id)
        .fetch_all(&mut *conn)
        .await?;

        // The epoch being retired, locked for the life of the transaction.
        let current: Option<(Uuid, i32, Option<Vec<u8>>)> = sqlx::query_as(
            r#"
            SELECT id, epoch, wrapped_key
            FROM group_key_epochs
            WHERE group_id = $1 AND status IN ('active', 'rotating')
            ORDER BY (status = 'active') DESC, epoch DESC
            LIMIT 1
            FOR UPDATE
            "#,
        )
        .bind(group_id)
        .fetch_optional(&mut *conn)
        .await?;

        let Some((current_id, current_epoch, current_wrapped_key)) = current else {
            return Ok(RotateOutcome::NoCurrentEpoch);
        };

        // THE GATE. Read in this transaction, not by the caller beforehand.
        if current_wrapped_key.is_none() {
            let kms_key_ref: Option<Option<String>> = sqlx::query_scalar(
                r#"SELECT properties->>'kms_key_ref' FROM groups WHERE id = $1"#,
            )
            .bind(group_id)
            .fetch_optional(&mut *conn)
            .await?;

            if kms_key_ref.flatten().is_none() {
                return Ok(RotateOutcome::RetiringKeyUnrecoverable);
            }
        }

        let new_epoch = current_epoch
            .checked_add(1)
            .ok_or_else(|| DbError::InvalidData {
                reason: "group key epoch counter would overflow i32; the group must be \
                         re-provisioned rather than rotated"
                    .to_string(),
            })?;

        let live_set: BTreeSet<Uuid> = live.into_iter().map(|r| r.0).collect();
        let offered: BTreeSet<Uuid> = shares.iter().map(|(agent_id, _)| *agent_id).collect();

        // Duplicates are refused BEFORE the set-difference, because the set is
        // what hides them: collapsing `[A, A, B]` to `{A, B}` makes a
        // contradictory submission indistinguishable from a well-formed one.
        if offered.len() != shares.len() {
            let mut seen: BTreeSet<Uuid> = BTreeSet::new();
            let mut agent_ids: BTreeSet<Uuid> = BTreeSet::new();
            for (agent_id, _) in shares {
                if !seen.insert(*agent_id) {
                    agent_ids.insert(*agent_id);
                }
            }
            return Ok(RotateOutcome::DuplicateShares {
                agent_ids: agent_ids.into_iter().collect(),
            });
        }

        let missing: Vec<Uuid> = live_set.difference(&offered).copied().collect();
        let unknown: Vec<Uuid> = offered.difference(&live_set).copied().collect();
        if !missing.is_empty() || !unknown.is_empty() {
            return Ok(RotateOutcome::RosterMismatch { missing, unknown });
        }

        // RETIRE FIRST. `group_key_epochs_one_active` is a partial unique index
        // on (group_id) WHERE status = 'active', so inserting N+1 before
        // retiring N is a 23505 — migration 060 names this pair in its ROTATION
        // CONTRACT comment.
        sqlx::query(
            r#"
            UPDATE group_key_epochs
            SET status = 'retired',
                retired_at = now()
            WHERE id = $1
            "#,
        )
        .bind(current_id)
        .execute(&mut *conn)
        .await?;

        Self::create_epoch_conn(conn, group_id, new_epoch, None, "active").await?;

        // Re-wrap in place. `group_memberships_one_live` is unique on
        // (group_id, agent_id) WHERE revoked_at IS NULL, so a second live row
        // per member is not insertable; the live row is UPDATEd instead.
        let mut members_rewrapped = 0usize;
        for (agent_id, share) in shares {
            let updated = sqlx::query(
                r#"
                UPDATE group_memberships
                SET wrapped_key_share = $3, epoch = $4
                WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL
                "#,
            )
            .bind(group_id)
            .bind(agent_id)
            .bind(share.as_slice())
            .bind(new_epoch)
            .execute(&mut *conn)
            .await?;
            members_rewrapped += updated.rows_affected() as usize;
        }

        // THE ROSTER PROPERTY IS ENFORCED AGAINST THE WRITE, NOT ONLY THE READ.
        // The set-difference above checks the submission against the roster the
        // SELECT saw; this checks that the UPDATEs actually landed. The retire
        // statement fails closed by accident — a no-op there makes
        // `create_epoch_conn` insert a second `active` row and
        // `group_key_epochs_one_active` raise 23505 — but the re-wrap loop has
        // no such backstop, and a loop that affected zero rows would otherwise
        // report `Rotated`, commit, and leave epoch N retired with every live
        // member still holding a share for it. `SELECT ... FOR UPDATE` on the
        // identical predicate makes the two counts agree today; migrations
        // 077/079 apply FORCEd policies to `group_memberships` whose UPDATE
        // `USING` clause need not match the SELECT one, and from §9.2 step 11d
        // a divergence there would convert a rotation into a group-wide strand
        // with an HTTP 200. Refuse rather than report: the caller owns the
        // transaction and rolls back.
        if members_rewrapped != shares.len() {
            return Err(DbError::InvalidData {
                reason: format!(
                    "rotation re-wrapped {members_rewrapped} of {} live memberships; refusing to \
                     commit an epoch advance that leaves a member on the retired epoch",
                    shares.len()
                ),
            });
        }

        Ok(RotateOutcome::Rotated {
            previous_epoch: current_epoch,
            new_epoch,
            members_rewrapped,
        })
    }

    /// Retire a specific epoch for a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn retire_epoch(pool: &PgPool, group_id: Uuid, epoch: i32) -> Result<(), DbError> {
        sqlx::query(
            r#"
            UPDATE group_key_epochs
            SET status = 'retired', retired_at = now()
            WHERE group_id = $1 AND epoch = $2
            "#,
        )
        .bind(group_id)
        .bind(epoch)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get a specific epoch by group and epoch number
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_group_and_epoch(
        pool: &PgPool,
        group_id: Uuid,
        epoch: i32,
    ) -> Result<Option<KeyEpochRow>, DbError> {
        let row: Option<KeyEpochRow> = sqlx::query_as(
            r#"
            SELECT id, group_id, epoch, wrapped_key, status, created_at, retired_at
            FROM group_key_epochs
            WHERE group_id = $1 AND epoch = $2
            "#,
        )
        .bind(group_id)
        .bind(epoch)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }
}
