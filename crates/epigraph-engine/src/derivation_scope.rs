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
pub async fn retain_for_viewer(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    rows: Vec<MassFunctionRow>,
) -> Result<Vec<MassFunctionRow>, DbError> {
    if rows.is_empty() {
        return Ok(rows);
    }
    let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.id).collect();
    let admissible = DerivationScopeRepository::viewer_derived(&mut *conn, viewer, &ids).await?;
    Ok(rows
        .into_iter()
        .filter(|r| admissible.contains(&r.id))
        .collect())
}
