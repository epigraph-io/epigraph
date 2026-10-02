//! The elevation ceremony's database half (migration 125): the definers the
//! application role may EXECUTE, nothing else.
//!
//! # Two kinds of connection
//!
//! * **Principal-bound** calls ([`ElevationCeremony::create_ticket`],
//!   [`ElevationCeremony::end`]) run on a connection STAMPED with the
//!   requester's viewer: the definer reads `epigraph_principal_id()` and never
//!   takes a person as an argument, so a caller cannot ask for someone else's
//!   ticket or end someone else's session.
//! * **Ticket-keyed** calls ([`ElevationCeremony::live_ticket`],
//!   [`ElevationCeremony::passkeys`], [`ElevationCeremony::store_challenge`],
//!   [`ElevationCeremony::confirm`]) run on an UNSTAMPED application
//!   connection: the ceremony page is unauthenticated by design (the ticket id
//!   in its URL and the authenticator are its credentials).
//!
//! # Why the SQL lives here
//!
//! `locked_decisions.rs` bans `FROM elevation_*` and the two unbound readers on
//! the request-path crates; every call below is one app-callable definer, and
//! every rule (ELV02 who may elevate, ELV03 append-only, ELV05 the counter,
//! ELV06 a live ticket, one live session per family) is the tables' and holds
//! whatever this module passes. No function takes a `Viewer`: these are
//! authentication records about a principal, not corpus rows
//! (`visibility_lint.rs` registers each one).

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use tracing::instrument;
use uuid::Uuid;

/// What the ceremony page may know of ONE live ticket (unasserted,
/// unexpired). No secret.
#[derive(Debug, Clone, FromRow)]
pub struct CeremonyTicket {
    /// The person the elevation would be for.
    pub person_agent_id: Uuid,
    /// The client the ticket was asked on.
    pub client_id: Uuid,
    /// That client's name.
    pub client_name: String,
    /// The refresh family the elevation would bind.
    pub family_id: Uuid,
    /// `grant` or `connector`.
    pub mode: String,
    /// Why it was asked for.
    pub reason: String,
    /// When it stops being live.
    pub expires_at: DateTime<Utc>,
    /// The WebAuthn library's state for the ceremony in flight, once started.
    pub challenge_state: Option<serde_json::Value>,
}

/// One live passkey of the ticket's person, as the ceremony needs it.
#[derive(Debug, Clone, FromRow)]
pub struct TicketPasskey {
    /// The passkey's row id.
    pub authenticator_id: Uuid,
    /// The credential id.
    pub credential_id: Vec<u8>,
    /// The library's serialized credential.
    pub passkey: serde_json::Value,
    /// The stored signature counter.
    pub sign_count: i64,
    /// Whether it was registered backup-eligible.
    pub backup_eligible: bool,
    /// Its attestation statement format.
    pub attestation_format: String,
}

/// `epigraph_confirm_elevation`'s answer.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct Confirmation {
    /// `confirmed` or `refused`.
    pub outcome: String,
    /// The session a confirmation opened.
    pub session_id: Option<Uuid>,
    /// When that session expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// Why a refusal: `credential_unknown`, `person_mismatch`,
    /// `credential_revoked`, `counter_regressed`, `backup_eligibility_changed`,
    /// `no_live_assignment`, `family_revoked`.
    pub refusal: Option<String>,
    /// `ELV05` for a counter regression, else `ELV02`, on a refusal.
    pub code: Option<String>,
}

/// An assertion the ceremony hands the confirm definer.
#[derive(Debug, Clone, Copy)]
pub struct AssertedCredential<'a> {
    /// The credential id the assertion named.
    pub credential_id: &'a [u8],
    /// The signature counter it asserted.
    pub counter: i64,
    /// The backup-eligible flag it asserted.
    pub backup_eligible: bool,
    /// The evidence to keep (challenge and client response, verbatim).
    pub evidence: &'a serde_json::Value,
}

/// How the elevation a ticket opens is reached afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketMode {
    /// A CLI or console redeems the confirmed ticket ONCE at the token
    /// endpoint (`urn:epigraph:grant:elevate`) with the secret it was shown
    /// at creation; the database keeps only its SHA-256.
    Grant {
        /// SHA-256 of the redeem secret.
        redeem_hash: [u8; 32],
    },
    /// The family's own later requests resolve the elevation (MCP `sudo`).
    Connector,
}

impl TicketMode {
    fn sql(&self) -> &'static str {
        match self {
            Self::Grant { .. } => "grant",
            Self::Connector => "connector",
        }
    }

    fn redeem_hash(&self) -> Option<&[u8]> {
        match self {
            Self::Grant { redeem_hash } => Some(redeem_hash.as_slice()),
            Self::Connector => None,
        }
    }
}

/// Why a session is ended on request (migration 125's caller-allowed reasons;
/// the end triggers and the lazy expiry record their own).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// MCP `unsudo`.
    Unsudo,
    /// `POST /api/v1/elevation/end`.
    Ended,
}

impl EndReason {
    fn sql(self) -> &'static str {
        match self {
            Self::Unsudo => "unsudo",
            Self::Ended => "ended",
        }
    }
}

/// The ceremony half of migration 125's definers.
pub struct ElevationCeremony;

impl ElevationCeremony {
    /// Open a ticket for the connection's STAMPED principal on `client` /
    /// `family`, live 5 minutes (`epigraph_create_elevation_ticket`). Returns
    /// the ticket id; the ceremony page is `/elevate/<id>`.
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying `ELV02` (the principal may not elevate:
    /// no live assignment of an elevating role, no live passkey, the family is
    /// not a live family of its own human client, or it is unstamped), `ELV06`
    /// (the family is already elevated) or `22004` (no reason).
    #[instrument(skip(conn, reason, mode))]
    pub async fn create_ticket(
        conn: &mut sqlx::PgConnection,
        client: Uuid,
        family: Uuid,
        reason: &str,
        mode: TicketMode,
    ) -> Result<Uuid, DbError> {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_create_elevation_ticket($1, $2, $3, $4, $5)",
        )
        .bind(client)
        .bind(family)
        .bind(mode.sql())
        .bind(reason)
        .bind(mode.redeem_hash())
        .fetch_one(&mut *conn)
        .await?;
        Ok(id)
    }

    /// The live ticket `ticket` (`epigraph_ticket_for_ceremony`); `None` for an
    /// unknown, asserted or expired one. It enumerates nothing.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the call fails.
    #[instrument(skip(conn))]
    pub async fn live_ticket(
        conn: &mut sqlx::PgConnection,
        ticket: Uuid,
    ) -> Result<Option<CeremonyTicket>, DbError> {
        let row = sqlx::query_as::<_, CeremonyTicket>(
            "SELECT person_agent_id, client_id, client_name, family_id, mode, reason, \
                    expires_at, challenge_state \
               FROM public.epigraph_ticket_for_ceremony($1)",
        )
        .bind(ticket)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row)
    }

    /// The TICKET person's live passkeys while the ticket is live
    /// (`epigraph_passkeys_for_ticket`); never anyone else's.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the call fails.
    #[instrument(skip(conn))]
    pub async fn passkeys(
        conn: &mut sqlx::PgConnection,
        ticket: Uuid,
    ) -> Result<Vec<TicketPasskey>, DbError> {
        let rows = sqlx::query_as::<_, TicketPasskey>(
            "SELECT authenticator_id, credential_id, passkey, sign_count, backup_eligible, \
                    attestation_format \
               FROM public.epigraph_passkeys_for_ticket($1)",
        )
        .bind(ticket)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows)
    }

    /// Store the library's authentication state on `ticket`
    /// (`epigraph_set_elevation_ticket_challenge`; a restarted ceremony
    /// overwrites it).
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying `ELV06` when the ticket is not live.
    #[instrument(skip(conn, state))]
    pub async fn store_challenge(
        conn: &mut sqlx::PgConnection,
        ticket: Uuid,
        state: &serde_json::Value,
    ) -> Result<(), DbError> {
        sqlx::query("SELECT public.epigraph_set_elevation_ticket_challenge($1, $2)")
            .bind(ticket)
            .bind(state)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    /// Record an assertion over `ticket` (`epigraph_confirm_elevation`): a
    /// session and `platform.elevated`, or a RETURNED refusal with its
    /// `platform.` rows (the ticket is then burned).
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying `ELV06` when the ticket is not live and
    /// started, or its family is already elevated.
    #[instrument(skip(conn, asserted))]
    pub async fn confirm(
        conn: &mut sqlx::PgConnection,
        ticket: Uuid,
        asserted: AssertedCredential<'_>,
    ) -> Result<Confirmation, DbError> {
        let row = sqlx::query_as::<_, Confirmation>(
            "SELECT outcome, session_id, expires_at, refusal, code \
               FROM public.epigraph_confirm_elevation($1, $2, $3, $4, $5)",
        )
        .bind(ticket)
        .bind(asserted.credential_id)
        .bind(asserted.counter)
        .bind(asserted.backup_eligible)
        .bind(asserted.evidence)
        .fetch_one(&mut *conn)
        .await?;
        Ok(row)
    }

    /// End the stamped principal's session `session` now
    /// (`epigraph_end_elevation`). `false` when there was nothing to end
    /// (unknown, someone else's, or already ended): the answer is no oracle.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the call fails.
    #[instrument(skip(conn))]
    pub async fn end(
        conn: &mut sqlx::PgConnection,
        session: Uuid,
        reason: EndReason,
    ) -> Result<bool, DbError> {
        let ended: bool = sqlx::query_scalar("SELECT public.epigraph_end_elevation($1, $2)")
            .bind(session)
            .bind(reason.sql())
            .fetch_one(&mut *conn)
            .await?;
        Ok(ended)
    }
}
