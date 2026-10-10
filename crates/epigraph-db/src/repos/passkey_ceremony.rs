//! The passkey enrollment ceremony's database half (migration 124): the three
//! definers the application role may EXECUTE, each keyed by the enrollment id.
//!
//! # Why this is not `PasskeyRepository`
//!
//! `PasskeyRepository` is the MAINTENANCE half (open a ticket, revoke, list),
//! and `locked_decisions.rs` bans its call shapes and its reads from the
//! request-path crates. This type is the half the unauthenticated enrollment
//! page runs on the request DSN, and its names must not collide with those
//! banned needles (a substring match), so it is a separate type.
//!
//! # Connections
//!
//! An UNSTAMPED application connection: the enrollment page is
//! unauthenticated by design (the enrollment id and the authenticator are its
//! credentials), so there is no principal to stamp, and the definers need
//! none. Every rule (ELV01 a registered human that is no other human's agent,
//! ELV03 append-only, ELV04 a live, started enrollment, user verification) is
//! the tables' and holds whatever this module passes.
//!
//! # Why nothing here takes a `Viewer`
//!
//! Authentication records about a principal, not corpus rows: a viewer filter
//! has nothing to narrow (`visibility_lint.rs` registers each function).

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use tracing::instrument;
use uuid::Uuid;

/// What the ceremony page may know of ONE live enrollment.
#[derive(Debug, Clone, FromRow)]
pub struct CeremonyEnrollment {
    /// The registered human the passkey will belong to.
    pub person_agent_id: Uuid,
    /// Why the operator opened it.
    pub reason: String,
    /// The name the passkey will carry.
    pub label: Option<String>,
    /// When it stops being live.
    pub expires_at: DateTime<Utc>,
    /// The WebAuthn library's state for the ceremony in flight, once started.
    pub challenge_state: Option<serde_json::Value>,
}

/// A passkey a verified ceremony registered: the completion definer's
/// arguments.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedPasskey<'a> {
    /// The credential id.
    pub credential_id: &'a [u8],
    /// The library's serialized credential.
    pub passkey: &'a serde_json::Value,
    /// The attested authenticator model (nil for `none`).
    pub aaguid: Uuid,
    /// The attestation statement format.
    pub attestation_format: &'a str,
    /// Whether the authenticator verified its user.
    pub user_verified: bool,
    /// Whether the credential may be synced.
    pub backup_eligible: bool,
    /// The authenticator's raw registration response (the
    /// `PublicKeyCredential` JSON the credential was verified from), kept so
    /// the offline verifier can run the registration again (migration 160).
    pub registration: &'a serde_json::Value,
}

/// The ceremony half of migration 124's definers.
pub struct PasskeyCeremony;

impl PasskeyCeremony {
    /// The live enrollment `enrollment` (unconsumed, unexpired), through
    /// `epigraph_enrollment_for_ceremony`; `None` for an unknown, expired or
    /// used one. It enumerates nothing.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the call fails.
    #[instrument(skip(conn))]
    pub async fn live_enrollment(
        conn: &mut sqlx::PgConnection,
        enrollment: Uuid,
    ) -> Result<Option<CeremonyEnrollment>, DbError> {
        let row = sqlx::query_as::<_, CeremonyEnrollment>(
            "SELECT person_agent_id, reason, label, expires_at, challenge_state \
               FROM public.epigraph_enrollment_for_ceremony($1)",
        )
        .bind(enrollment)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row)
    }

    /// Store the library's registration state on `enrollment`
    /// (`epigraph_set_passkey_enrollment_challenge`; a restarted ceremony
    /// overwrites it).
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying `ELV04` when the enrollment is not
    /// live.
    #[instrument(skip(conn, state))]
    pub async fn store_challenge(
        conn: &mut sqlx::PgConnection,
        enrollment: Uuid,
        state: &serde_json::Value,
    ) -> Result<(), DbError> {
        sqlx::query("SELECT public.epigraph_set_passkey_enrollment_challenge($1, $2)")
            .bind(enrollment)
            .bind(state)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    /// Record the passkey a verified ceremony registered, with the
    /// registration response it was verified from, consuming `enrollment`
    /// (migration 160's eight-argument `epigraph_complete_passkey_enrollment`,
    /// which writes `platform.passkey_registered`). Returns the passkey's id.
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying `ELV04` (not live, or no ceremony
    /// started), `ELV01` (the subject is no longer eligible) or `ELV03`;
    /// `DbError::DuplicateKey` for a credential already registered.
    #[instrument(skip(conn, passkey))]
    pub async fn complete(
        conn: &mut sqlx::PgConnection,
        enrollment: Uuid,
        passkey: VerifiedPasskey<'_>,
    ) -> Result<Uuid, DbError> {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_complete_passkey_enrollment($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(enrollment)
        .bind(passkey.credential_id)
        .bind(passkey.passkey)
        .bind(passkey.aaguid)
        .bind(passkey.attestation_format)
        .bind(passkey.user_verified)
        .bind(passkey.backup_eligible)
        .bind(passkey.registration)
        .fetch_one(&mut *conn)
        .await?;
        Ok(id)
    }
}
