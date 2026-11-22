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
//! read. The owner is the frame the cache records, kept through the act and
//! not re-elected. When the owner frame has inputs and none of them is
//! admissible, the cache is vacated (the full-ignorance value) even if ANOTHER
//! frame of the claim still has an admissible input: the cached value is the
//! owner frame's old fold, and the act has just widened who is served it. (An
//! ordinary recompute vacates only when no frame has an admissible input, and
//! its owner rule puts a frame with an admissible input first.) The caller
//! commits after both, so the act and the refold commit together or not at
//! all.
//!
//! # `truth_value`
//!
//! Several writers persist `claims.truth_value` as a copy of the fold they
//! just cached (`submit_claim`, `update_with_evidence`), and a later recompute
//! of the cache leaves that copy as it was. So `truth_value` can carry the
//! same inadmissible BBA as the old cache, and readers that order or filter
//! on it (recall's fallback among them) would serve its influence to the new
//! audience (backlog 0d9dfd24). Whenever the refold writes the cache, the act
//! therefore sets `truth_value` to the refolded BetP in the same transaction
//! (`ClaimRepository::mirror_refolded_cache_into_truth_conn`, which states
//! the claims it leaves alone). A copy is not told apart from an authored
//! value: an authored confidence (`memorize`) is replaced by the admissible
//! fold, which still contains the author's own seed BBA. Workflow, step and
//! procedural claims are written too: `report_workflow_outcome` persists the
//! same fold copy, and an outcome track kept without a BBA (the REST outcome
//! route) is derived from reports the new audience may not read. Only a
//! value at the deprecation marker (0.05) is kept, current or not: it is a
//! retirement or a step's soft delete, not a fold, and carries no input.
//!
//! # Scoped beliefs
//!
//! Migration 215 deletes a moved claim's `ds_combined_beliefs` and
//! `ds_bayesian_divergence` rows as folded for the old audience. The act then
//! writes the claim's `ds_combined_beliefs` rows afresh, at the keys it had
//! before the act and for the new audience
//! ([`crate::scoped_belief::refresh_scoped_beliefs`]: `global` and
//! `perspective` scopes, each best-effort under its own savepoint as the REST
//! route writes them), so a scoped read right after the act finds a value
//! (backlog 4d8df0cf). A key with nothing admissible left gets no row.
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
//!   frame: the act keeps the recorded owner
//!   (`MassFunctionRepository::cache_owner_frame_keeping_recorded`). The
//!   claim's next ordinary recompute hands the cache to that other frame
//!   (the admissible-first owner rule, backlog 8d720490 (1)).
//! * `claims.truth_value` follows the refold only where the cache was
//!   written. A claim the refold leaves unchanged (the first item: a
//!   template-only claim, a non-procedural compound) keeps its `truth_value`,
//!   which can still carry an input the new audience cannot read (a value a
//!   propagation wrote); there is no admissible fold to replace it with here.
//!   A claim at the deprecation marker keeps it (see "`truth_value`").
//! * Claims moved by 206 before this ran keep the value folded then.
//! * A `community` scoped row is not written afresh: its fold reads the
//!   community's members and mass override on the raw pool. It stays absent
//!   until the next computation that stores it.
//! * `ds_bayesian_divergence` rows are not written afresh. Their posterior is
//!   the claim's Beta track (`claims.beta_alpha` / `beta_beta`), which moves
//!   with the claim unchanged and was accumulated from every BBA the old
//!   audience could read. That track is itself an open leak this act does not
//!   close: the claim's next live evidence write returns its posterior to the
//!   writer and records a divergence row from it, both served to the new
//!   audience. Recomputing the row here would only serve it sooner.

use std::collections::HashMap;

use epigraph_db::errors::RefusalKind;
use epigraph_db::{ClaimRepository, DbError, ScopedBeliefRepository, VisibilityActOutcome};
use uuid::Uuid;

use crate::edge_factor;
use crate::scoped_belief::{self, ScopeKey};

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
    let scoped = scoped_keys(&mut *conn, viewer, claim_ids).await?;
    let outcomes = ClaimRepository::publicize_conn(&mut *conn, claim_ids, reason).await?;
    refold_moved(
        &mut *conn,
        viewer,
        "publicize_claims",
        &outcomes,
        "publicized",
        &scoped,
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
    let scoped = scoped_keys(&mut *conn, viewer, claim_ids).await?;
    let outcomes =
        ClaimRepository::share_with_team_conn(&mut *conn, claim_ids, group_id, reason).await?;
    refold_moved(
        &mut *conn,
        viewer,
        "share_claims_with_team",
        &outcomes,
        "shared",
        &scoped,
    )
    .await?;
    Ok(outcomes)
}

/// The `ds_combined_beliefs` keys of each of `claim_ids` the caller reads,
/// before the act deletes them (migration 215), so that [`refold_moved`]
/// writes the same keys afresh for the new audience.
async fn scoped_keys(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<ScopeKey>>, VisibilityActError> {
    let mut keys: HashMap<Uuid, Vec<ScopeKey>> = HashMap::new();
    for &claim_id in claim_ids {
        if keys.contains_key(&claim_id) {
            continue;
        }
        let mut rows: Vec<ScopeKey> =
            ScopedBeliefRepository::list_for_claim(&mut *conn, viewer, claim_id)
                .await?
                .into_iter()
                .map(|r| (r.frame_id, r.scope_type, r.scope_id))
                .collect();
        rows.sort();
        rows.dedup();
        keys.insert(claim_id, rows);
    }
    Ok(keys)
}

/// Refold the cached belief of every claim the act reported `moved_outcome`
/// for, refusing first if the session cannot write one of them, then write
/// its scoped rows afresh at the keys it had before the act (`scoped`).
async fn refold_moved(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    act: &str,
    outcomes: &[VisibilityActOutcome],
    moved_outcome: &str,
    scoped: &HashMap<Uuid, Vec<ScopeKey>>,
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
        let written =
            edge_factor::recompute_widened_claim_cached_belief(&mut *conn, viewer, claim_id)
                .await
                .map_err(VisibilityActError::Cache)?;
        // `truth_value` may be a copy of the cache as folded for the OLD
        // audience (see the module doc, "truth_value"): replace it with the
        // refolded value, which is admissible by construction.
        if written {
            ClaimRepository::mirror_refolded_cache_into_truth_conn(&mut *conn, viewer, claim_id)
                .await?;
        }
        // The scoped rows the definer deleted as stale, folded for the new
        // audience (see the module doc, "Scoped beliefs").
        if let Some(keys) = scoped.get(&claim_id).filter(|k| !k.is_empty()) {
            let report = scoped_belief::refresh_scoped_beliefs(&mut *conn, viewer, claim_id, keys)
                .await
                .map_err(VisibilityActError::Cache)?;
            tracing::debug!(%claim_id, ?report, "{act}: scoped beliefs recomputed");
        }
    }
    Ok(())
}
