//! Which stored BBAs a belief may be computed from, by where the BBAs CAME
//! FROM (operator ruling R-22, backlog fef24216).
//!
//! A `mass_functions` row inherits its CLAIM's tenancy (migration 070 arm (c),
//! or migration 114's public writer-owned row), so every row on a public claim
//! is itself public. Visibility of the row therefore says nothing about the
//! evidence it was derived from:
//!
//! * an edge-factor row (`combination_method = 'edge_factor'`, keyed by the
//!   edge id in `perspective_id`) carries the belief of the edge's SOURCE
//!   claim, which may be group-private, through an edge that may be
//!   group-private;
//! * an evidence-derived row (`evidence_id`) may cite an evidence row narrowed
//!   to a private group (`epigraph-operator hide-evidence`, migration 110).
//!
//! A Bel/Pl folded from such a row leaks the existence, direction and weight
//! of the restricted evidence even when nothing restricted is displayed. The
//! reads here decide ADMISSIBILITY by derivation, and they are written as
//! "include iff the source is visible" (an `EXISTS` over the visible source),
//! never "exclude iff a private source exists": row security hides private
//! rows from some sessions, so only the inclusive form gives the same answer
//! on a maintenance connection and on an application session.
//!
//! A consequence, recorded: an edge-factor row whose edge (or source claim) no
//! longer exists is not admissible either, since nothing visible vouches for
//! it.

use std::collections::HashSet;

use uuid::Uuid;

use crate::errors::DbError;
use crate::visibility::Viewer;

/// The admissibility predicate for a PUBLIC audience: the row itself, the
/// evidence `e` it cites and, for an edge-factor row, the edge `ed` and the
/// edge's source claim `s` must all be public. [`DerivationScopeRepository::
/// viewer_derived`] spells the same statement with the viewer's markers.
const PUBLIC_DERIVED_SQL: &str = "SELECT mf.id FROM mass_functions mf \
     WHERE mf.id = ANY($1) AND mf.visibility = 'public' \
       AND (mf.evidence_id IS NULL \
            OR EXISTS (SELECT 1 FROM evidence e \
                        WHERE e.id = mf.evidence_id AND e.visibility = 'public')) \
       AND (mf.combination_method IS DISTINCT FROM 'edge_factor' \
            OR mf.perspective_id IS NULL \
            OR EXISTS (SELECT 1 FROM edges ed \
                        WHERE ed.id = mf.perspective_id AND ed.visibility = 'public' \
                          AND EXISTS (SELECT 1 FROM claims s \
                                       WHERE s.id = ed.source_id \
                                         AND s.visibility = 'public')))";

/// Repository for derivation-scoped belief reads.
pub struct DerivationScopeRepository;

impl DerivationScopeRepository {
    /// Is `claim_id` a public claim? `false` for a claim this session cannot
    /// see or that does not exist (a public claim is visible to every
    /// session).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn claim_is_public<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        claim_id: Uuid,
    ) -> Result<bool, DbError> {
        let public: Option<bool> =
            sqlx::query_scalar("SELECT c.visibility = 'public' FROM claims c WHERE c.id = $1")
                .bind(claim_id)
                .fetch_optional(executor)
                .await?;
        Ok(public.unwrap_or(false))
    }

    /// Of the `mass_functions` rows `row_ids`, those whose every derivation
    /// source is PUBLIC: the row itself, the evidence it cites, and for an
    /// edge-factor row the edge and the edge's source claim. These, and only
    /// these, may enter a public claim's cached or served-to-everyone belief.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn public_derived<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        row_ids: &[Uuid],
    ) -> Result<HashSet<Uuid>, DbError> {
        if row_ids.is_empty() {
            return Ok(HashSet::new());
        }
        let ids: Vec<Uuid> = sqlx::query_scalar(PUBLIC_DERIVED_SQL)
            .bind(row_ids)
            .fetch_all(executor)
            .await?;
        Ok(ids.into_iter().collect())
    }

    /// Of the `mass_functions` rows `row_ids`, those whose every derivation
    /// source `viewer` can read (the same sources as [`Self::public_derived`],
    /// under the viewer's predicates; `edges` under the co-ownership
    /// intersection). A group member gets the rows derived from its group's
    /// private sources; a reader outside the group does not. A bypass viewer
    /// admits every row it is given.
    ///
    /// The session's own row security applies on top of the predicate, so
    /// on an UNSTAMPED application session a private source is invisible and
    /// its rows are not admitted for anyone, which is what that session can
    /// show.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn viewer_derived<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        row_ids: &[Uuid],
    ) -> Result<HashSet<Uuid>, DbError> {
        if row_ids.is_empty() {
            return Ok(HashSet::new());
        }
        let sql = viewer.splice(
            "SELECT mf.id FROM mass_functions mf \
             WHERE mf.id = ANY($1) /* {VISIBILITY:mf} */ \
               AND (mf.evidence_id IS NULL \
                    OR EXISTS (SELECT 1 FROM evidence e \
                                WHERE e.id = mf.evidence_id /* {VISIBILITY:e} */)) \
               AND (mf.combination_method IS DISTINCT FROM 'edge_factor' \
                    OR mf.perspective_id IS NULL \
                    OR EXISTS (SELECT 1 FROM edges ed \
                                WHERE ed.id = mf.perspective_id /* {EDGE_VISIBILITY:ed} */ \
                                  AND EXISTS (SELECT 1 FROM claims s \
                                               WHERE s.id = ed.source_id \
                                                 /* {VISIBILITY:s} */)))",
            2,
        );
        let mut q = sqlx::query_scalar(&sql).bind(row_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let ids: Vec<Uuid> = q.fetch_all(executor).await?;
        Ok(ids.into_iter().collect())
    }
}
