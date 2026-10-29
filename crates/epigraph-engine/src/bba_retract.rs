//! The claim's cached belief after ONE BBA is retracted (operator rulings
//! R-79 and R-80, migration 184), or un-retracted (ruling R-103). Shared by
//! `POST /api/v1/mass-functions/:id/retract` and `.../unretract` and MCP
//! `retract_bba` and `unretract_bba`, so both transports leave the same cache.
//!
//! A retracted BBA is excluded from every fold, and the served cache
//! (`claims.belief`, `plausibility`, `pignistic_prob`, `classification`) is a
//! fold. After a retraction the cache is therefore refolded from the BBAs that
//! remain ([`edge_factor::recompute_claim_cached_belief`], the per-request
//! refresh `routes::assess` uses). When NO BBA remains to fold, that refresh
//! writes nothing (it never makes a cache emptier than it was), which would
//! leave the claim serving the retracted BBA's fold. Ruling R-80 gives such a
//! claim an explicit VACUOUS cache (Bel 0, Pl 1, BetP 0.5, `not_enough_info`
//! on `binary_truth`), never a NULL one, and so does this module, through
//! [`edge_factor::vacate_atom_cache`]'s write and refusal ladder (a compound,
//! a procedural or rule claim, a non-current claim, or one with atom input
//! left is never vacated).
//!
//! **Which claims are vacated.** Only one whose cache-owning input DISAPPEARED
//! with this retraction and that HAD a cache: [`RetractCacheBefore`] reads,
//! before the retraction and in the same transaction, whether the claim had a
//! cache-owner frame
//! ([`epigraph_db::MassFunctionRepository::cache_owner_frame_for_claim`]: a
//! live combine input that is not an ingest template row, on a claim that is
//! not a frozen compound) and a non-NULL cache on a non-compound
//! ([`epigraph_db::repos::compound_valuation::atom_cache_batch`]); the vacate
//! runs only when both held and no owner is left after. A claim whose only
//! rows are templates, or a compound, had no owner before and is left as it
//! was; a claim with no cache is not given one (as R-80's recompute vacate
//! reads it: a vacuous value appearing would tell other readers a BBA
//! existed).
//!
//! **Viewer.** As every legacy cache writer, the fold and the vacate read what
//! the caller can see and offer the result to the one global cache under the
//! migration-114 non-owner rule (`written` / `vacated` says whether the cache
//! took it). On an application session, `edges` row security can hide a
//! compound's decomposition so that it reads as a standalone claim (the
//! `claim_role` module doc); such a compound whose own last BBA is retracted
//! could be vacated. That is the caveat `recompute_atom_cache_with` documents
//! for every per-request site (PR-5b1).
//!
//! **PR-5b1.** This site is a lifecycle act that removes evidence:
//! `edge_factor::CacheWriteCause::EvidenceRemoved` (ruling O24) names "a
//! retraction". When PR-5b1 wires the per-request sites to the single
//! atom-cache writer, this function is one of them.

use uuid::Uuid;

use crate::edge_factor;
use epigraph_db::MassFunctionRepository;

/// Whether a BBA's claim had a cache-owner frame BEFORE the BBA was
/// retracted, read by [`RetractCacheBefore::read`], the only way to build
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetractCacheBefore {
    claim_id: Uuid,
    had_owner: bool,
    had_cache: bool,
}

impl RetractCacheBefore {
    /// Read, on the transaction that will retract `mass_function_id` and
    /// before it does, whether the BBA's claim has a cache-owner frame and a
    /// (non-compound) cache as `viewer` sees them. `None` when the viewer
    /// cannot read the BBA (the retraction then answers "not found", writing
    /// nothing).
    ///
    /// # Errors
    /// A database read.
    pub async fn read(
        conn: &mut sqlx::PgConnection,
        viewer: &epigraph_db::visibility::Viewer,
        mass_function_id: Uuid,
    ) -> Result<Option<Self>, String> {
        let Some(row) = MassFunctionRepository::get_by_id(&mut *conn, viewer, mass_function_id)
            .await
            .map_err(|e| format!("get_by_id: {e}"))?
        else {
            return Ok(None);
        };
        let owner =
            MassFunctionRepository::cache_owner_frame_for_claim(&mut *conn, viewer, row.claim_id)
                .await
                .map_err(|e| format!("cache_owner_frame_for_claim: {e}"))?;
        let had_cache = epigraph_db::repos::compound_valuation::atom_cache_batch(
            &mut *conn,
            viewer,
            &[row.claim_id],
        )
        .await
        .map_err(|e| format!("atom_cache_batch: {e}"))?
        .contains_key(&row.claim_id);
        Ok(Some(Self {
            claim_id: row.claim_id,
            had_owner: owner.is_some(),
            had_cache,
        }))
    }
}

/// What [`refresh_cache_after_retract`] did to the claim's cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetractCacheOutcome {
    /// The cache was refolded from the BBAs that remain.
    pub recomputed: bool,
    /// No BBA remained to fold, and the cache took the explicit vacuous
    /// value (ruling R-80).
    pub vacated: bool,
}

/// Refresh `claim_id`'s cached belief after a FIRST retraction of one of its
/// BBAs, on the retracting transaction. See the module doc.
///
/// # Errors
/// A database read or write, or a fold that fails.
pub async fn refresh_cache_after_retract(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    before: Option<RetractCacheBefore>,
) -> Result<RetractCacheOutcome, String> {
    if edge_factor::recompute_claim_cached_belief(&mut *conn, viewer, claim_id).await? {
        return Ok(RetractCacheOutcome {
            recomputed: true,
            vacated: false,
        });
    }
    let lost_owner = before.is_some_and(|b| b.claim_id == claim_id && b.had_owner && b.had_cache);
    if !lost_owner {
        return Ok(RetractCacheOutcome::default());
    }
    let owner_after =
        MassFunctionRepository::cache_owner_frame_for_claim(&mut *conn, viewer, claim_id)
            .await
            .map_err(|e| format!("cache_owner_frame_for_claim: {e}"))?;
    if owner_after.is_some() {
        // A live input remains; the refold was not taken by the cache
        // (migration 114's non-owner rule). Nothing to vacate.
        return Ok(RetractCacheOutcome::default());
    }
    let outcome = edge_factor::vacate_atom_cache(
        &mut *conn,
        viewer,
        claim_id,
        crate::atom_items::CompoundSourceEdges::current(),
    )
    .await?;
    let vacated = matches!(
        outcome,
        edge_factor::VacateOutcome::Vacated { written: true }
    );
    if vacated {
        tracing::warn!(
            target: "epigraph::atom_cache::vacate",
            claim = %claim_id,
            "BBA retraction vacate: the claim's last cache-owning BBA was retracted; \
             explicit vacuous cache (ruling R-80)"
        );
    }
    Ok(RetractCacheOutcome {
        recomputed: false,
        vacated,
    })
}

/// Refresh `claim_id`'s cached belief after one of its BBAs was UN-retracted
/// (operator ruling R-103), on the un-retracting transaction: the BBA folds
/// again, so the cache is refolded from the live BBAs, the un-retracted one
/// included ([`edge_factor::recompute_claim_cached_belief`], as after a
/// retraction). A claim whose cache a retraction had vacated (ruling R-80)
/// regains a cache-owning input here, so the refold replaces the vacuous
/// value. Returns whether the cache was written.
///
/// # Errors
/// A database read or write, or a fold that fails.
pub async fn refresh_cache_after_unretract(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
) -> Result<bool, String> {
    edge_factor::recompute_claim_cached_belief(&mut *conn, viewer, claim_id).await
}
