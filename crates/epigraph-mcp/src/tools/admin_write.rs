//! The audited admin path for `claims:admin` cross-group claim writes over MCP
//! (batch H-b, D2; migration 111).
//!
//! # When a write takes it
//!
//! Exactly when BOTH hold:
//!
//! 1. the request carries a token with `claims:admin` — the only grant in
//!    [`crate::tools::claims::require_owner_or_admin`] that brings no write
//!    authority of its own; and
//! 2. the claim's owning group is NOT in the caller's own writable set, so the
//!    caller's own stamp (D1) could not write the row.
//!
//! Every other write — an author, an operator, an admin writing into a group it
//! IS a writer of — stays on the caller's own stamp. The admin path never lends
//! anyone's stamp: the transaction it runs on is stamped from the ADMIN's own
//! viewer (`epigraph.principal_id` = the admin), and the SECURITY DEFINER it
//! calls is what carries the write across the group boundary, writing the
//! `security_events` audit row (`claims.admin_write`) in the same statement.
//!
//! # (a) The grant is re-checked from the token, server-side, twice
//!
//! [`admin_patch`] refuses unless the validated `AuthContext` itself carries
//! `claims:admin` — never a flag a caller passes. The definer then re-checks
//! the token's client record (`oauth_clients.id = sub`: active, `claims:admin`
//! granted, bound to the session principal), so a client suspended or
//! de-scoped after its token was minted loses the path at once. A context with
//! no real client behind it — the `--allow-unauthenticated-http` listener's
//! injected context has a nil `client_id` — therefore cannot use it.
//!
//! The HTTP twin is `epigraph-api/src/routes/claims.rs::update_labels`, which
//! routes the same way and calls the same repository function.

use epigraph_db::{AdminClaimAction, AdminClaimWrite, AdminToken, ClaimRepository};

use crate::errors::{internal_error, invalid_params, McpError};

/// Whether this write must take the audited admin path; see the module doc.
#[must_use]
pub(crate) fn takes_admin_path(
    auth: Option<&epigraph_auth::AuthContext>,
    caller_viewer: &epigraph_db::visibility::Viewer,
    owner_group: uuid::Uuid,
) -> bool {
    auth.is_some_and(|a| a.has_scope("claims:admin"))
        && !caller_viewer.writable_groups().contains(&owner_group)
}

/// The owning group of `claim_id`, read through the caller's viewer on the
/// caller's stamped transaction. A claim the caller cannot read is "not found",
/// exactly as on the ordinary path: the admin path reaches only claims the
/// admin can see.
pub(crate) async fn owner_group_of(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: uuid::Uuid,
) -> Result<uuid::Uuid, McpError> {
    ClaimRepository::write_target_of(&mut *conn, viewer, claim_id)
        .await
        .map_err(internal_error)?
        .map(|(_, group)| group)
        .ok_or_else(|| invalid_params(format!("claim {claim_id} not found")))
}

/// Run the audited admin write on `conn`, which must be the ADMIN's own
/// stamped transaction.
///
/// # Errors
/// * invalid-params when the request's token does not carry `claims:admin`
///   (this is re-checked here, not trusted from the router);
/// * invalid-params naming the refusal when migration 111's function refuses
///   the admin (no live `claims:admin` grant on the token's client record, or
///   no principal) or finds no claim; nothing is written in either case;
/// * the label-validation error for an unexpanded shell label.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn admin_patch(
    conn: &mut sqlx::PgConnection,
    auth: Option<&epigraph_auth::AuthContext>,
    claim_id: uuid::Uuid,
    action: AdminClaimAction,
    add_labels: &[String],
    remove_labels: &[String],
    properties: Option<&serde_json::Value>,
    trace_id: Option<uuid::Uuid>,
) -> Result<AdminClaimWrite, McpError> {
    let Some(auth) = auth.filter(|a| a.has_scope("claims:admin")) else {
        return Err(invalid_params(
            "the audited admin path requires a token carrying claims:admin; nothing was written",
        ));
    };
    ClaimRepository::admin_patch_claim_conn(
        conn,
        AdminToken {
            client_id: auth.client_id,
            jti: auth.jti,
        },
        claim_id,
        action,
        add_labels,
        remove_labels,
        properties,
        trace_id,
    )
    .await
    .map_err(|e| {
        let code = match &e {
            epigraph_db::DbError::QueryFailed { source } => source
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .map(|c| c.to_string()),
            _ => None,
        };
        match code.as_deref() {
            Some("42501") => invalid_params(format!(
                "claim {claim_id}: the audited admin path refused this token ({e}). The \
                 claim is owned by a group you cannot write, and only a live claims:admin \
                 grant on the token's own client record may write it. Nothing was written."
            )),
            Some("P0002") => invalid_params(format!("claim {claim_id} not found")),
            _ => crate::errors::db_caller_error(e),
        }
    })
}
