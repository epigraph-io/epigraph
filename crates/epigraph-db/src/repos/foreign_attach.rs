//! Writes by a NON-OWNER onto a public claim (migration 114).
//!
//! An agent may attach evidence, a DS mass function or a reasoning trace to a
//! PUBLIC claim whose owning group it cannot write (in production, almost every
//! claim is owned by the memberless world group). Migration 114 splits what
//! such a write touches into two kinds:
//!
//! * **Per-writer rows** — `evidence`, `mass_functions`, `reasoning_traces`.
//!   The `<table>_attach_writer` trigger owns them by the WRITER's group
//!   (`writer_owned = true`) with no change on the Rust side: the ordinary
//!   INSERT lands.
//! * **Per-claim aggregates** — the `claim_frames` assignment and the DS cache
//!   columns on the `claims` row. These stay owned by the CLAIM's group, so a
//!   non-owner reaches them only through migration 114's audited
//!   `SECURITY DEFINER` functions (`epigraph_foreign_*`). They never write
//!   `truth_value`, `labels` or `content`.
//!
//! This module holds the one predicate that decides which path an aggregate
//! write takes, so every caller asks the same question. It is TRUE only when
//! the session is not privileged (superuser, BYPASSRLS, a maintenance member),
//! carries a principal (an UNSTAMPED session has no writer to attribute the
//! write to, so it keeps the pre-114 answer: 077's refusal), can READ the claim (the read is the session's own, RLS-filtered), the claim
//! is `public`, and its owning group is not in the session's writable set. In
//! every other case — the owner, an admin writing its own group, a maintenance
//! session, a claim the session cannot see, a private claim — the caller's
//! statement is exactly the one it always ran, and fails or succeeds as it
//! always did.

use sqlx::PgConnection;
use uuid::Uuid;

use crate::errors::DbError;

/// The predicate, as a SQL boolean expression over the claim id placeholder
/// `{claim}` (substituted with the caller's `$n`).
///
/// `epigraph_session_is_privileged_writer()` is migration 114's; it is the
/// same test the `<table>_attach_writer` trigger applies, so a row the trigger
/// leaves to the claim's owner is never sent down the definer path, and vice
/// versa.
pub(crate) const FOREIGN_PUBLIC_CLAIM: &str =
    "(NOT public.epigraph_session_is_privileged_writer() \
     AND public.epigraph_principal_id() IS NOT NULL \
     AND EXISTS (SELECT 1 FROM public.claims fc \
                  WHERE fc.id = {claim} AND fc.visibility = 'public' \
                    AND NOT (fc.owner_group_id = ANY (public.epigraph_writable_groups()))))";

/// [`FOREIGN_PUBLIC_CLAIM`] with its placeholder bound to `param` (e.g. `"$1"`).
pub(crate) fn foreign_public_claim(param: &str) -> String {
    FOREIGN_PUBLIC_CLAIM.replace("{claim}", param)
}

/// Whether this session would attach to `claim_id` as a non-owner: see the
/// module doc. Read on the caller's (stamped) connection, so "can read" is the
/// session's own RLS answer.
///
/// # Errors
/// Returns `DbError::QueryFailed` if the query fails.
pub async fn is_foreign_public_claim(
    conn: &mut PgConnection,
    claim_id: Uuid,
) -> Result<bool, DbError> {
    let sql = format!("SELECT {}", foreign_public_claim("$1"));
    let foreign: bool = sqlx::query_scalar(&sql)
        .bind(claim_id)
        .fetch_one(conn)
        .await?;
    Ok(foreign)
}
