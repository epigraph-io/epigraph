//! Proposing and confirming admin acts: the request path's half of
//! migration 130 (and 131's reader). Only the app-callable definers, nothing
//! else.
//!
//! # Three kinds of connection
//!
//! * **Elevated, principal-bound**: [`AdminActCeremony::propose`] runs on a
//!   connection STAMPED with the proposer's ELEVATED viewer, inside a
//!   writable transaction ([`crate::ScopedPool::propose_admin_act`] is the one
//!   caller). `epigraph_propose_admin_act` refuses an unelevated connection
//!   (ELV07) and takes the proposer, the elevation and the assignment from the
//!   stamped session, never from an argument.
//! * **Principal-bound**: [`AdminActCeremony::list_mine`] runs on a connection
//!   stamped with the requester's viewer (elevated or not): 131's
//!   `epigraph_admin_acts_of_principal` lists only the stamped principal's own
//!   acts.
//! * **Act-keyed**: [`AdminActCeremony::live_act`],
//!   [`AdminActCeremony::passkeys`], [`AdminActCeremony::store_challenge`] and
//!   [`AdminActCeremony::confirm`] run on an UNSTAMPED application connection:
//!   the confirmation page is unauthenticated by design (the act id in its URL
//!   and the proposer's passkey are its credentials), as the elevation page is.
//!
//! # Why the SQL lives here
//!
//! `locked_decisions.rs` bans raw reads and writes of the act table, the
//! consumer and the passkey oracle on the request-path crates; every call
//! below is one app-callable definer, and every rule (ELV07 who may propose,
//! the canonical args and their digest, ELV02 only the proposer's live
//! passkey confirms, ELV05 the counter, ELV08 a live act) is the table's and
//! holds whatever this module passes. No function takes a `Viewer`: an act is
//! an authority record about a principal, not a corpus row
//! (`visibility_lint.rs` registers each one).

use crate::errors::DbError;
use crate::repos::elevation_ceremony::{AssertedCredential, TicketPasskey};
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use tracing::instrument;
use uuid::Uuid;

/// What the confirmation page may know of ONE live act (unasserted,
/// unexpired): `epigraph_act_for_ceremony`.
#[derive(Debug, Clone, FromRow)]
pub struct CeremonyAct {
    /// The act's kind (`role.grant`, `role.end`, `claim.custodial_supersede`,
    /// `passkey.register`).
    pub kind: String,
    /// Its args, in canonical form, as stored.
    pub args: serde_json::Value,
    /// SHA-256 of the canonical args.
    pub args_digest: Vec<u8>,
    /// Why it was proposed.
    pub reason: String,
    /// Who proposed it (the only person whose passkey confirms it).
    pub proposed_by: Uuid,
    /// When.
    pub proposed_at: DateTime<Utc>,
    /// When it stops being live.
    pub expires_at: DateTime<Utc>,
    /// The ceremony state, once a confirmation was started.
    pub challenge_state: Option<serde_json::Value>,
}

/// One act as its proposer lists it (131's reader): no ceremony state,
/// evidence, consuming login or result.
#[derive(Debug, Clone, FromRow, serde::Serialize)]
pub struct ProposedAct {
    /// The act.
    pub id: Uuid,
    /// Its kind.
    pub kind: String,
    /// Its canonical args.
    pub args: serde_json::Value,
    /// SHA-256 of the canonical args.
    #[serde(serialize_with = "hex_bytes")]
    pub args_digest: Vec<u8>,
    /// What the args name: `agent`, `role_assignment` or `claim`.
    pub target_type: String,
    /// Its id.
    pub target_id: Uuid,
    /// Why it was proposed.
    pub reason: String,
    /// The elevation it was proposed under.
    pub elevation_id: Uuid,
    /// When.
    pub proposed_at: DateTime<Utc>,
    /// When an unconfirmed act stops being confirmable, and a confirmed one
    /// executable.
    pub expires_at: DateTime<Utc>,
    /// When the passkey answered, if it has.
    pub asserted_at: Option<DateTime<Utc>>,
    /// `confirmed` or `refused`, once asserted.
    pub outcome: Option<String>,
    /// Why a refusal.
    pub refusal: Option<String>,
    /// When the maintenance CLI executed it, if it has.
    pub consumed_at: Option<DateTime<Utc>>,
}

fn hex_bytes<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(bytes))
}

/// A confirm definer's answer for an act.
#[derive(Debug, Clone, FromRow)]
pub struct ActConfirmation {
    /// `confirmed` or `refused`.
    pub outcome: String,
    /// Why a refusal: `credential_unknown`, `person_mismatch`,
    /// `credential_revoked`, `counter_regressed`, `backup_eligibility_changed`,
    /// `no_live_assignment`.
    pub refusal: Option<String>,
    /// `ELV05` for a counter regression, else `ELV02`, on a refusal.
    pub code: Option<String>,
}

/// Repository for the request path's admin-act definers.
pub struct AdminActCeremony;

impl AdminActCeremony {
    /// Propose an act as the connection's STAMPED, ELEVATED principal
    /// (`epigraph_propose_admin_act`): the act id. The connection must be
    /// inside a writable transaction stamped with an elevated viewer
    /// ([`crate::ScopedPool::propose_admin_act`]).
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying `ELV07` (the connection is not
    /// elevated), `22023` (args the kind does not take, or a
    /// `passkey.register` act for someone else) or `22004` (no reason).
    #[instrument(skip(conn, args, reason, jti))]
    pub async fn propose(
        conn: &mut sqlx::PgConnection,
        kind: &str,
        args: &serde_json::Value,
        reason: &str,
        jti: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let id: Uuid =
            sqlx::query_scalar("SELECT public.epigraph_propose_admin_act($1, $2, $3, $4)")
                .bind(kind)
                .bind(args)
                .bind(reason)
                .bind(jti)
                .fetch_one(&mut *conn)
                .await?;
        Ok(id)
    }

    /// The STAMPED principal's own acts, newest first, at most `limit`
    /// (clamped by the definer to 1..=200; `None` reads 50).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn list_mine(
        conn: &mut sqlx::PgConnection,
        limit: Option<i32>,
    ) -> Result<Vec<ProposedAct>, DbError> {
        let rows = sqlx::query_as::<_, ProposedAct>(
            "SELECT id, kind, args, args_digest, target_type, target_id, reason, elevation_id, \
                    proposed_at, expires_at, asserted_at, outcome, refusal, consumed_at \
               FROM public.epigraph_admin_acts_of_principal($1)",
        )
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows)
    }

    /// One LIVE act by id, for the confirmation page; `None` when it is
    /// unknown, asserted or expired.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn live_act(
        conn: &mut sqlx::PgConnection,
        act: Uuid,
    ) -> Result<Option<CeremonyAct>, DbError> {
        let row = sqlx::query_as::<_, CeremonyAct>(
            "SELECT kind, args, args_digest, reason, proposed_by, proposed_at, expires_at, \
                    challenge_state \
               FROM public.epigraph_act_for_ceremony($1)",
        )
        .bind(act)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row)
    }

    /// The PROPOSER's live passkeys, only while the act is live.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn passkeys(
        conn: &mut sqlx::PgConnection,
        act: Uuid,
    ) -> Result<Vec<TicketPasskey>, DbError> {
        let rows = sqlx::query_as::<_, TicketPasskey>(
            "SELECT authenticator_id, credential_id, passkey, sign_count, backup_eligible, \
                    attestation_format \
               FROM public.epigraph_passkeys_for_act($1)",
        )
        .bind(act)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows)
    }

    /// Store the confirmation ceremony's state for a live act (a restart
    /// overwrites it).
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying `ELV08` (no such act), or the table's
    /// guard's refusal of a non-live act.
    #[instrument(skip(conn, state))]
    pub async fn store_challenge(
        conn: &mut sqlx::PgConnection,
        act: Uuid,
        state: &serde_json::Value,
    ) -> Result<(), DbError> {
        sqlx::query("SELECT public.epigraph_set_admin_act_challenge($1, $2)")
            .bind(act)
            .bind(state)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    /// Record an assertion over a live, started act: confirmed, or an
    /// audited refusal RETURNED (never raised).
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying `ELV08` (the act is not live and
    /// started).
    #[instrument(skip(conn, asserted))]
    pub async fn confirm(
        conn: &mut sqlx::PgConnection,
        act: Uuid,
        asserted: AssertedCredential<'_>,
    ) -> Result<ActConfirmation, DbError> {
        let row = sqlx::query_as::<_, ActConfirmation>(
            "SELECT outcome, refusal, code \
               FROM public.epigraph_confirm_admin_act($1, $2, $3, $4, $5)",
        )
        .bind(act)
        .bind(asserted.credential_id)
        .bind(asserted.counter)
        .bind(asserted.backup_eligible)
        .bind(asserted.evidence)
        .fetch_one(&mut *conn)
        .await?;
        Ok(row)
    }
}
