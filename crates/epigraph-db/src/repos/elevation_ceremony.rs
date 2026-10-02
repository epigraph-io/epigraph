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
//! * **Ticket-keyed** calls (the ceremony page's, added with it) run on an
//!   UNSTAMPED application connection: the page is unauthenticated by design
//!   (the ticket id in its URL and the authenticator are its credentials).
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
use tracing::instrument;
use uuid::Uuid;

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
