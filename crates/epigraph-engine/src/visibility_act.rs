//! The two audited widening acts of migration 206 (re-stated by 215),
//! `publicize_claims` and `share_claims_with_team`, with the moved claims'
//! cached belief refolded for their new audience in the same transaction
//! (backlog 31285392; spec `docs/tenancy/share-with-team.md` section 4.6,
//! "The DS cache").
//!
//! # Why the act is not done when the definer returns
//!
//! A claim's cached belief (`claims.belief`, `plausibility`, `pignistic_prob`,
//! `mass_on_empty`, `mass_on_missing`, `classification`) is read by everyone
//! who can read the claim, so it may fold a BBA only when every source of that
//! BBA is at least as widely readable as the claim
//! ([`crate::derivation_scope::retain_for_cache`]). Both acts widen the
//! claim's audience: publicize to every reader, share from the home group to
//! a team. A value folded under the OLD tenancy can include a BBA citing
//! evidence that stays behind (a pinned row, migration 110) or an edge-factor
//! BBA from a source the new audience cannot read, and serving it leaks the
//! direction and weight of that source through the number.
//!
//! The fold runs in Rust, so the definer cannot do it (migration 114 records
//! why a definer takes cache values from its caller). These functions are the
//! ONE entry point both transports call (MCP `tools::visibility`, REST
//! `routes::claim_visibility`): the definer, then, for every moved claim,
//! [`edge_factor::recompute_widened_claim_cached_belief`], whose fold of the
//! cache-owner frame admits only what the moved claim's new audience may
//! read. When the owner frame has inputs and none of them is admissible, the
//! cache is vacated (the full-ignorance value) even if ANOTHER frame of the
//! claim still has an admissible input: the cached value is the owner frame's
//! old fold, and the act has just widened who is served it. (An ordinary
//! recompute vacates only when no frame has an admissible input.) The caller
//! commits after both, so the act and the refold commit together or not at
//! all.
//!
//! # Fail closed when the session cannot write the moved claim
//!
//! The refold writes `claims` on the caller's stamped session, under row
//! security. A share admits a target team the caller writes only through its
//! live human (the operator arm, `epigraph_writable_teams` `via = 'operator'`), and the
//! caller's own stamp does not carry that team. After the move the session
//! then cannot read or write the claim, the refold would silently match
//! nothing, and the stale value would be served to the team. Every moved claim
//! must therefore be in the session's writable groups; if one is not, the act
//! is refused ([`RefusalKind::Authority`]) and, because the caller then drops
//! the transaction, nothing is changed. A member of the team (the human
//! itself) can make the same call.
//!
//! # What is not refolded here (residuals)
//!
//! * A claim with no cache-owner frame (only ingest template rows, or a
//!   non-procedural compound) is left as `recompute_claim_cached_belief` leaves
//!   it: unchanged.
//! * A claim whose owner frame has only inadmissible rows while ANOTHER frame
//!   still has an admissible one is vacated, not refolded from that other
//!   frame: the cache owner rule still picks the owner frame, and the act
//!   does not change it.
//! * `claims.truth_value`, which some writers set from a fold, is not
//!   recomputed.
//! * Claims moved by 206 before this ran keep the value folded then.

use epigraph_db::errors::RefusalKind;
use epigraph_db::{ClaimRepository, DbError, VisibilityActOutcome};
use uuid::Uuid;

use crate::edge_factor;

/// Why [`publicize_claims`] or [`share_claims_with_team`] did not complete.
#[derive(Debug, thiserror::Error)]
pub enum VisibilityActError {
    /// The definer refused or failed, or the session cannot write a moved
    /// claim (a [`DbError::Refused`]). Map it as the transport maps any
    /// visibility refusal.
    #[error(transparent)]
    Db(#[from] DbError),
    /// The refold of a moved claim's cached belief failed. The act must not
    /// commit.
    #[error("cached belief recompute after the act: {0}")]
    Cache(String),
}

/// `publicize_claims` (migration 215 section 4), then the refold of every
/// claim it publicized. See the module doc.
///
/// # Errors
/// [`VisibilityActError::Db`] for every refusal of the act (nothing changed),
/// [`VisibilityActError::Cache`] when a refold fails. On either, the caller
/// must drop the transaction.
pub async fn publicize_claims(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_ids: &[Uuid],
    reason: &str,
) -> Result<Vec<VisibilityActOutcome>, VisibilityActError> {
    let outcomes = ClaimRepository::publicize_conn(&mut *conn, claim_ids, reason).await?;
    refold_moved(
        &mut *conn,
        viewer,
        "publicize_claims",
        &outcomes,
        "publicized",
    )
    .await?;
    Ok(outcomes)
}

/// `share_claims_with_team` (migration 215 section 5), then the refold of
/// every claim it shared. See the module doc.
///
/// # Errors
/// As [`publicize_claims`].
pub async fn share_claims_with_team(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_ids: &[Uuid],
    group_id: Uuid,
    reason: &str,
) -> Result<Vec<VisibilityActOutcome>, VisibilityActError> {
    let outcomes =
        ClaimRepository::share_with_team_conn(&mut *conn, claim_ids, group_id, reason).await?;
    refold_moved(
        &mut *conn,
        viewer,
        "share_claims_with_team",
        &outcomes,
        "shared",
    )
    .await?;
    Ok(outcomes)
}

/// Refold the cached belief of every claim the act reported `moved_outcome`
/// for, refusing first if the session cannot write one of them.
async fn refold_moved(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    act: &str,
    outcomes: &[VisibilityActOutcome],
    moved_outcome: &str,
) -> Result<(), VisibilityActError> {
    let moved: Vec<Uuid> = outcomes
        .iter()
        .filter(|o| o.outcome == moved_outcome)
        .map(|o| o.claim_id)
        .collect();
    if moved.is_empty() {
        return Ok(());
    }
    let unwritable = ClaimRepository::claims_not_writable_on_session(&mut *conn, &moved).await?;
    if !unwritable.is_empty() {
        let ids = unwritable
            .iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(DbError::Refused {
            kind: RefusalKind::Authority,
            message: format!(
                "{act}: refused, and nothing was changed: this session does not itself write \
                 the group that would own {ids}, so their cached belief cannot be recomputed \
                 for the new audience. Make the call as a member who writes that group."
            ),
        }
        .into());
    }
    for claim_id in moved {
        edge_factor::recompute_widened_claim_cached_belief(&mut *conn, viewer, claim_id)
            .await
            .map_err(VisibilityActError::Cache)?;
    }
    Ok(())
}
