//! Belief folded only from BBAs whose sources the audience may see (operator
//! ruling R-22, backlog fef24216, generalised by the security review).
//!
//! A claim's cached belief (`claims.belief`, `plausibility`, `pignistic_prob`,
//! ...) and every stored belief derived from it are read by everyone who can
//! read the claim, so they fold only the BBAs whose every source is at least
//! as widely readable as the claim: for a public claim, public sources; for a
//! group claim, public sources or the group's own. An edge-factor BBA carrying
//! a group-private source claim's belief through a group-private edge, or a
//! BBA citing evidence narrowed to a private group, never enters a wider
//! audience's cache. A belief computed on read for one viewer folds the BBAs
//! whose sources THAT viewer can see, so a member of the source's group still
//! gets the full belief through its own reads. See
//! `epigraph_db::repos::derivation_scope` for the admissibility reads and why
//! they are written inclusively.

use epigraph_db::repos::derivation_scope::DerivationScopeRepository;
use epigraph_db::{DbError, MassFunctionRow};

/// The rows that may enter their claim's CACHED belief (and anything stored
/// from the same fold): those whose every derivation source is at least as
/// widely readable as the claim. Order is kept.
///
/// # Errors
/// `DbError` if the read fails.
pub async fn retain_for_cache(
    conn: &mut sqlx::PgConnection,
    rows: Vec<MassFunctionRow>,
) -> Result<Vec<MassFunctionRow>, DbError> {
    if rows.is_empty() {
        return Ok(rows);
    }
    let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.id).collect();
    let admissible = DerivationScopeRepository::cache_admissible(&mut *conn, &ids).await?;
    Ok(rows
        .into_iter()
        .filter(|r| admissible.contains(&r.id))
        .collect())
}

/// The rows `viewer` may see a belief folded from: those whose every
/// derivation source it can read. Order is kept.
///
/// # Errors
/// `DbError` if the read fails.
pub async fn retain_for_viewer<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    viewer: &epigraph_db::visibility::Viewer,
    rows: Vec<MassFunctionRow>,
) -> Result<Vec<MassFunctionRow>, DbError> {
    if rows.is_empty() {
        return Ok(rows);
    }
    let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.id).collect();
    let admissible = DerivationScopeRepository::viewer_derived(executor, viewer, &ids).await?;
    Ok(rows
        .into_iter()
        .filter(|r| admissible.contains(&r.id))
        .collect())
}

/// Whether a recompute of `claim_id` must VACATE its cache (ruling R-80): the
/// claim has a cached belief, it has combine inputs `viewer` can see (on any
/// frame, as the cache owner rule counts them), and NOT ONE of them may enter
/// the cache. The cached value was then folded from sources narrower than the
/// claim (a source narrowed after the fact, or a cache written before R-22),
/// and keeping it serves their direction and weight to every reader.
///
/// A claim with an admissible input on any frame is not vacated, and neither
/// is a claim with no cache: a vacuous value written where there was none
/// would tell its readers that an unseen BBA exists. Nor is a compound, whose
/// cache is not a fold of its own BBAs (the cache owner rule never refolds
/// one either).
///
/// # Errors
/// `DbError` if a read fails.
pub async fn must_vacate_cache(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: uuid::Uuid,
) -> Result<bool, DbError> {
    let inputs =
        DerivationScopeRepository::combine_input_ids_for_claim(&mut *conn, viewer, claim_id)
            .await?;
    if inputs.is_empty() {
        return Ok(false);
    }
    if !DerivationScopeRepository::cache_admissible(&mut *conn, &inputs)
        .await?
        .is_empty()
    {
        return Ok(false);
    }
    DerivationScopeRepository::claim_has_fold_cache(&mut *conn, viewer, claim_id).await
}
