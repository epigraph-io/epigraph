//! Repository for a registered human's passkeys and their enrollment tickets
//! (migration 124): the maintenance half, which the operator CLI calls.
//!
//! # Thin wrappers over 124's definers
//!
//! Every write goes through a migration-124 definer, never a raw statement
//! here: `epigraph_create_passkey_enrollment` opens a ticket and
//! `epigraph_revoke_passkey` revokes a passkey, and the tables' own triggers
//! enforce the rules (ELV01 a passkey belongs only to a registered human that
//! is no other human's agent, ELV03 append-only, ELV04 a ticket that is not
//! live) and write the `platform.passkey_*` audit rows. A caller of this
//! module cannot get a rule wrong: it can only be refused by one.
//!
//! # Connections
//!
//! Every function here is a MAINTENANCE act: 124 grants the two definers to
//! the maintenance role only, and its row policies show an application
//! connection no row of either table. The ceremony's three app-callable
//! definers (the reader, the challenge store, the completion) belong to the
//! API that runs the ceremony, not to this module.
//!
//! # Why nothing here takes a `Viewer`
//!
//! These are authentication records about a principal, not corpus rows; a
//! viewer filter has nothing to narrow (`visibility_lint.rs` registers each
//! function with its reason).

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use tracing::instrument;
use uuid::Uuid;

/// A row of `passkey_enrollments` (its ceremony state omitted).
#[derive(Debug, Clone, FromRow)]
pub struct PasskeyEnrollmentRow {
    pub id: Uuid,
    pub person_agent_id: Uuid,
    pub reason: String,
    pub label: Option<String>,
    pub created_via: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub authenticator_id: Option<Uuid>,
}

/// A row of `person_authenticators` (its serialized credential omitted).
#[derive(Debug, Clone, FromRow)]
pub struct PasskeyRow {
    pub id: Uuid,
    pub person_agent_id: Uuid,
    pub credential_id: Vec<u8>,
    pub aaguid: Uuid,
    pub attestation_format: String,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub label: Option<String>,
    pub enrollment_id: Uuid,
    pub sign_count: i64,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
    pub revoked_reason: Option<String>,
}

const PASSKEY_COLUMNS: &str = "id, person_agent_id, credential_id, aaguid, attestation_format, \
     user_verified, backup_eligible, label, enrollment_id, sign_count, created_at, \
     last_used_at, revoked_at, revoked_by, revoked_reason";

/// Repository for passkeys and their enrollment tickets.
pub struct PasskeyRepository;

impl PasskeyRepository {
    /// Open an enrollment ticket for `person` (a registered human), live for
    /// 15 minutes, through `epigraph_create_passkey_enrollment`. Returns its
    /// id; the ceremony path is `/elevate/enroll/<id>`.
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying the guard's SQLSTATE (`ELV01`), `22004`
    /// for an empty reason, or `42501` on a non-maintenance connection.
    #[instrument(skip(conn, reason, label))]
    pub async fn create_enrollment(
        conn: &mut sqlx::PgConnection,
        person: Uuid,
        reason: &str,
        label: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let id: Uuid =
            sqlx::query_scalar("SELECT public.epigraph_create_passkey_enrollment($1, $2, $3)")
                .bind(person)
                .bind(reason)
                .bind(label)
                .fetch_one(&mut *conn)
                .await?;
        Ok(id)
    }

    /// One enrollment ticket by id (a maintenance read; an application
    /// connection sees none).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn get_enrollment(
        conn: &mut sqlx::PgConnection,
        enrollment: Uuid,
    ) -> Result<Option<PasskeyEnrollmentRow>, DbError> {
        let row = sqlx::query_as::<_, PasskeyEnrollmentRow>(
            "SELECT id, person_agent_id, reason, label, created_via, created_by, created_at, \
                    expires_at, consumed_at, authenticator_id \
               FROM passkey_enrollments WHERE id = $1",
        )
        .bind(enrollment)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row)
    }

    /// Revoke a passkey now (`epigraph_revoke_passkey`). `false` when it was
    /// already revoked or does not exist: a revoke is never repeated.
    ///
    /// # Errors
    /// `DbError::QueryFailed`, including `42501` on a non-maintenance
    /// connection.
    #[instrument(skip(conn, reason))]
    pub async fn revoke(
        conn: &mut sqlx::PgConnection,
        passkey: Uuid,
        reason: &str,
    ) -> Result<bool, DbError> {
        let revoked: bool = sqlx::query_scalar("SELECT public.epigraph_revoke_passkey($1, $2)")
            .bind(passkey)
            .bind(reason)
            .fetch_one(&mut *conn)
            .await?;
        Ok(revoked)
    }

    /// One passkey by id (a maintenance read).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn get(
        conn: &mut sqlx::PgConnection,
        passkey: Uuid,
    ) -> Result<Option<PasskeyRow>, DbError> {
        let row = sqlx::query_as::<_, PasskeyRow>(&format!(
            "SELECT {PASSKEY_COLUMNS} FROM person_authenticators WHERE id = $1"
        ))
        .bind(passkey)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row)
    }

    /// Every passkey (of `person`, when given), live ones only unless
    /// `include_revoked`, newest first (a maintenance read).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn list(
        conn: &mut sqlx::PgConnection,
        person: Option<Uuid>,
        include_revoked: bool,
    ) -> Result<Vec<PasskeyRow>, DbError> {
        let rows = sqlx::query_as::<_, PasskeyRow>(&format!(
            "SELECT {PASSKEY_COLUMNS} FROM person_authenticators \
              WHERE ($1::uuid IS NULL OR person_agent_id = $1) AND ($2 OR revoked_at IS NULL) \
              ORDER BY created_at DESC, id"
        ))
        .bind(person)
        .bind(include_revoked)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows)
    }
}
