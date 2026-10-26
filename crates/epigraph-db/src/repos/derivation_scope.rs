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
//! same holds one level down: a GROUP claim's cache is read by every member of
//! its group, so a BBA derived from ANOTHER group's private source leaks that
//! source to them (the security review's generalisation of R-22: a BBA enters
//! a claim's cached belief only if every source is at least as widely readable
//! as the claim). The reads here decide ADMISSIBILITY by derivation, and they
//! are written as
//! "include iff the source is visible" (an `EXISTS` over the visible source),
//! never "exclude iff a private source exists": row security hides private
//! rows from some sessions, so only the inclusive form gives the same answer
//! on a maintenance connection and on an application session.
//!
//! A consequence, recorded: an edge-factor row whose edge (or source claim) no
//! longer exists is not admissible either, since nothing visible vouches for
//! it.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::errors::DbError;
use crate::visibility::Viewer;

/// A source `x` is at least as widely readable as the claim `c` when it is
/// public, or when the claim is not public and the source belongs to the
/// claim's own owner group (an edge only as a single-owner edge: a co-owned
/// edge is readable by the members of BOTH groups, fewer than the claim's).
const CACHE_ADMISSIBLE_SQL: &str = "SELECT mf.id FROM mass_functions mf \
       JOIN claims c ON c.id = mf.claim_id \
     WHERE mf.id = ANY($1) \
       AND (mf.visibility = 'public' \
            OR (c.visibility <> 'public' AND mf.owner_group_id = c.owner_group_id)) \
       AND (mf.evidence_id IS NULL \
            OR EXISTS (SELECT 1 FROM evidence e \
                        WHERE e.id = mf.evidence_id \
                          AND (e.visibility = 'public' \
                               OR (c.visibility <> 'public' \
                                   AND e.owner_group_id = c.owner_group_id)))) \
       AND (mf.combination_method IS DISTINCT FROM 'edge_factor' \
            OR mf.perspective_id IS NULL \
            OR EXISTS (SELECT 1 FROM edges ed \
                        WHERE ed.id = mf.perspective_id \
                          AND (ed.visibility = 'public' \
                               OR (c.visibility <> 'public' \
                                   AND ed.owner_group_id = c.owner_group_id \
                                   AND ed.co_owner_group_id IS NULL)) \
                          AND EXISTS (SELECT 1 FROM claims s \
                                       WHERE s.id = ed.source_id \
                                         AND (s.visibility = 'public' \
                                              OR (c.visibility <> 'public' \
                                                  AND s.owner_group_id = c.owner_group_id)))))";

/// Repository for derivation-scoped belief reads.
pub struct DerivationScopeRepository;

impl DerivationScopeRepository {
    /// Of the `mass_functions` rows `row_ids`, those that may enter THEIR
    /// claim's cached belief (and anything stored from the same fold): every
    /// derivation source (the row itself, the evidence it cites and, for an
    /// edge-factor row, the edge and the edge's source claim) is at least as
    /// widely readable as the claim. For a public claim that is "public"; for
    /// a group claim, "public, or owned by the claim's own group".
    ///
    /// A row whose claim this session cannot see is not admitted (no session
    /// that cannot see a claim folds its rows).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn cache_admissible<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        row_ids: &[Uuid],
    ) -> Result<HashSet<Uuid>, DbError> {
        if row_ids.is_empty() {
            return Ok(HashSet::new());
        }
        let ids: Vec<Uuid> = sqlx::query_scalar(CACHE_ADMISSIBLE_SQL)
            .bind(row_ids)
            .fetch_all(executor)
            .await?;
        Ok(ids.into_iter().collect())
    }

    /// The tenancy (`is public`, owner group) of each claim among `ids` that
    /// `viewer` can read; an id that is no claim, or one the viewer cannot
    /// read, is absent.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn claim_tenancy_among<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        ids: &[Uuid],
    ) -> Result<HashMap<Uuid, (bool, Uuid)>, DbError> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let sql = viewer.splice(
            "SELECT c.id, c.visibility = 'public', c.owner_group_id FROM claims c \
             WHERE c.id = ANY($1) /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid, bool, Uuid)>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor)
            .await?
            .into_iter()
            .map(|(id, public, owner)| (id, (public, owner)))
            .collect())
    }

    /// Of the `mass_functions` rows `row_ids`, those whose every derivation
    /// source `viewer` can read (the same sources as [`Self::cache_admissible`],
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
