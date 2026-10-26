//! Belief folded only from BBAs whose sources the audience may see (operator
//! ruling R-22, backlog fef24216).
//!
//! A public claim's cached belief (`claims.belief`, `plausibility`,
//! `pignistic_prob`, ...) and every stored belief derived from it are read by
//! everyone, so they fold only the claim's PUBLIC-DERIVED BBAs: an edge-factor
//! BBA carrying a group-private source claim's belief through a group-private
//! edge, or a BBA citing evidence narrowed to a private group, never enters
//! them. A belief computed on read for one viewer folds the BBAs whose sources
//! THAT viewer can see, so a member of the group still gets the full belief
//! through its own reads. See `epigraph_db::repos::derivation_scope` for the
//! admissibility read and why it is written inclusively.
//!
//! Non-public claims are left as they were: their cache is read only by those
//! who can read the claim.

use epigraph_db::repos::derivation_scope::DerivationScopeRepository;
use epigraph_db::{DbError, MassFunctionRow};

/// The rows of `claim_id` that may enter its CACHED belief (and anything
/// stored from the same fold): all of them for a claim that is not public,
/// only the public-derived ones for a public claim. Order is kept.
///
/// # Errors
/// `DbError` if a read fails.
pub async fn retain_for_cache(
    conn: &mut sqlx::PgConnection,
    claim_id: uuid::Uuid,
    rows: Vec<MassFunctionRow>,
) -> Result<Vec<MassFunctionRow>, DbError> {
    if rows.is_empty() || !DerivationScopeRepository::claim_is_public(&mut *conn, claim_id).await? {
        return Ok(rows);
    }
    let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.id).collect();
    let admissible = DerivationScopeRepository::public_derived(&mut *conn, &ids).await?;
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
