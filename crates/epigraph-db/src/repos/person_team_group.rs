//! Person-facing keyless team groups and their consented invitations
//! (migration 263, backlog ee9e05b4).
//!
//! Six calls, each one definer, each on the caller's STAMPED connection
//! (`ScopedPool::begin_as` / `AppState::write_as`): the definers read the
//! caller from the session (`epigraph_principal_id()`), never from an
//! argument, and make every authority decision themselves, so the REST
//! routes and the MCP tools that call this module cannot disagree.
//!
//! * [`PersonTeamGroupRepository::create_conn`]: a Person creates a keyless
//!   team group and becomes its one admin.
//! * [`PersonTeamGroupRepository::invite_conn`]: a live admin invites another
//!   Person; no membership is written.
//! * [`PersonTeamGroupRepository::accept_conn`] /
//!   [`PersonTeamGroupRepository::decline_conn`]: only the invitee answers;
//!   accepting is what makes the membership live.
//! * [`PersonTeamGroupRepository::my_groups_conn`] /
//!   [`PersonTeamGroupRepository::my_invitations_conn`]: the caller's live
//!   memberships and the invitations waiting for them.
//!
//! Every designed refusal carries a `TGPnn:` code and is returned by
//! `map_refusal` as [`DbError::Refused`] of its kind (TGP01/02 authority,
//! TGP03/09 input, TGP04-07 state) with the database's own words, or as
//! [`DbError::NotFound`] (TGP08: a group or invitation the caller may not
//! see answers exactly as a missing one).

use crate::errors::{DbError, RefusalKind};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// The membership roles an invitation may carry (`group_invitations_role_check`).
pub const INVITATION_ROLES: &[&str] = &["reader", "writer", "admin"];

/// One of the caller's live memberships ([`PersonTeamGroupRepository::my_groups_conn`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyGroup {
    pub group_id: Uuid,
    pub display_name: Option<String>,
    /// `personal`, `team`, `community`, `world` or `seed`.
    pub kind: String,
    /// `active`, `suspended` or `deprovisioned`.
    pub status: String,
    /// The caller's highest live role in it.
    pub role: String,
    pub created_by: Option<Uuid>,
    /// `true` for an active keyless team group these verbs manage: the kind an
    /// admin can invite into.
    pub invitable: bool,
}

/// A pending invitation addressed to the caller
/// ([`PersonTeamGroupRepository::my_invitations_conn`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyInvitation {
    pub invitation_id: Uuid,
    pub group_id: Uuid,
    pub display_name: Option<String>,
    pub role: String,
    pub invited_by: Uuid,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// What an accepted invitation wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedInvitation {
    pub group_id: Uuid,
    /// The new live membership row.
    pub membership_id: Uuid,
    pub role: String,
}

/// Map a migration-263 refusal to a designed refusal (or, for TGP08, to a
/// not-found naming `entity` / `id`); anything else to the ordinary
/// conversion.
fn map_refusal(e: sqlx::Error, entity: &str, id: Uuid) -> DbError {
    if let sqlx::Error::Database(db) = &e {
        let message = db.message().to_string();
        let kind = match db.code().as_deref() {
            Some("TGP08") => {
                return DbError::NotFound {
                    entity: entity.to_string(),
                    id,
                }
            }
            Some("TGP01" | "TGP02") => Some(RefusalKind::Authority),
            Some("TGP03" | "TGP09") => Some(RefusalKind::Input),
            Some("TGP04" | "TGP05" | "TGP06" | "TGP07") => Some(RefusalKind::State),
            _ => None,
        };
        if let Some(kind) = kind {
            return DbError::Refused { kind, message };
        }
    }
    DbError::from(e)
}

/// The repository for migration 263's definers.
pub struct PersonTeamGroupRepository;

impl PersonTeamGroupRepository {
    /// Create a keyless team group named `name`; the caller becomes its one
    /// admin. Returns the group id.
    ///
    /// # Errors
    /// `Refused` (authority) when the caller is not a Person signed in as
    /// themselves; (input) for a blank or over-long name or reason; (state)
    /// when the caller already has an active team group of that name.
    pub async fn create_conn(
        conn: &mut sqlx::PgConnection,
        name: &str,
        reason: Option<&str>,
    ) -> Result<Uuid, DbError> {
        sqlx::query_scalar("SELECT public.epigraph_person_create_team_group($1, $2)")
            .bind(name)
            .bind(reason)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| map_refusal(e, "group", Uuid::nil()))
    }

    /// Invite `invitee` into `group` at `role`. Returns the invitation id. No
    /// membership is written.
    ///
    /// # Errors
    /// `NotFound` when the caller holds no live membership of `group` (as for
    /// a missing group); `Refused` (authority) when the caller is not a
    /// Person or not an admin of it; (input) for an invitee that is not a
    /// Person, the caller itself, or a bad role or reason; (state) for an
    /// invitee already a member or already invited, or a group that is not
    /// an active keyless team group.
    pub async fn invite_conn(
        conn: &mut sqlx::PgConnection,
        group: Uuid,
        invitee: Uuid,
        role: &str,
        reason: Option<&str>,
    ) -> Result<Uuid, DbError> {
        sqlx::query_scalar("SELECT public.epigraph_invite_to_team_group($1, $2, $3, $4)")
            .bind(group)
            .bind(invitee)
            .bind(role)
            .bind(reason)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| map_refusal(e, "group", group))
    }

    /// Accept `invitation` as its invitee: the membership goes live now.
    ///
    /// # Errors
    /// `NotFound` for an invitation not addressed to the caller; `Refused`
    /// (authority) when the caller is not a Person signed in as themselves;
    /// (state) when it was already answered, has lapsed, or the caller is
    /// already a member.
    pub async fn accept_conn(
        conn: &mut sqlx::PgConnection,
        invitation: Uuid,
    ) -> Result<AcceptedInvitation, DbError> {
        let (group_id, membership_id, role): (Uuid, Uuid, String) = sqlx::query_as(
            "SELECT out_group_id, out_membership_id, out_role \
               FROM public.epigraph_accept_group_invitation($1)",
        )
        .bind(invitation)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| map_refusal(e, "invitation", invitation))?;
        Ok(AcceptedInvitation {
            group_id,
            membership_id,
            role,
        })
    }

    /// Decline `invitation` as its invitee. Returns its group id.
    ///
    /// # Errors
    /// `NotFound` for an invitation not addressed to the caller; `Refused`
    /// (state) when it was already answered.
    pub async fn decline_conn(
        conn: &mut sqlx::PgConnection,
        invitation: Uuid,
    ) -> Result<Uuid, DbError> {
        sqlx::query_scalar("SELECT public.epigraph_decline_group_invitation($1)")
            .bind(invitation)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| map_refusal(e, "invitation", invitation))
    }

    /// The caller's live memberships, one per group at its highest role.
    ///
    /// # Errors
    /// The read failed.
    pub async fn my_groups_conn(conn: &mut sqlx::PgConnection) -> Result<Vec<MyGroup>, DbError> {
        type Row = (
            Uuid,
            Option<String>,
            String,
            String,
            String,
            Option<Uuid>,
            bool,
        );
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT group_id, display_name, kind, status, role, created_by, invitable \
               FROM public.epigraph_my_groups()",
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| map_refusal(e, "group", Uuid::nil()))?;
        Ok(rows
            .into_iter()
            .map(
                |(group_id, display_name, kind, status, role, created_by, invitable)| MyGroup {
                    group_id,
                    display_name,
                    kind,
                    status,
                    role,
                    created_by,
                    invitable,
                },
            )
            .collect())
    }

    /// The invitations still pending that name the caller, oldest first.
    ///
    /// # Errors
    /// The read failed.
    pub async fn my_invitations_conn(
        conn: &mut sqlx::PgConnection,
    ) -> Result<Vec<MyInvitation>, DbError> {
        type Row = (
            Uuid,
            Uuid,
            Option<String>,
            String,
            Uuid,
            Option<String>,
            DateTime<Utc>,
        );
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT invitation_id, group_id, display_name, role, invited_by, reason, created_at \
               FROM public.epigraph_my_group_invitations()",
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| map_refusal(e, "invitation", Uuid::nil()))?;
        Ok(rows
            .into_iter()
            .map(
                |(invitation_id, group_id, display_name, role, invited_by, reason, created_at)| {
                    MyInvitation {
                        invitation_id,
                        group_id,
                        display_name,
                        role,
                        invited_by,
                        reason,
                        created_at,
                    }
                },
            )
            .collect())
    }
}
