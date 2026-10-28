//! The reads a compound's per-viewer derivation needs beyond its leaves' AEF
//! rows (atom-level belief program, SPEC §3.3 Legacy leaves, §3.6 `not_all`,
//! §7.1 readiness, §8 T1).
//!
//! * [`atom_cache_batch`]: the kept cache of a leaf that has no AEF input, so
//!   it can be read as one `legacy:<atom>` pseudo-item. A **compound** never
//!   has a leaf cache here, even when a viewer sees it as a leaf because its
//!   whole decomposition is hidden from that viewer: its frozen cache is
//!   compound belief, and folding it into a conjunction would put compound
//!   belief back into the atom layer.
//! * [`compound_own_rows`]: a compound's own stored rows, the carrier of its
//!   `not_all` valuation (refutation of the compound as a whole), each with
//!   the claims whose `attributed_v1` rows carried its refutation onward.
//! * [`refuting_edges_into`]: live `contradicts` / `refutes` edges into the
//!   requested claims, as the viewer sees them.
//!
//! Every read is spliced for the viewer: a derived value served to viewer V
//! uses only the claims, edges and rows V can read.

use std::collections::HashMap;

use tracing::instrument;
use uuid::Uuid;

use super::atom_axiom::AtomInputRow;
use super::claim_role::is_compound_sql;
use super::edge::EDGE_IN_FORCE;
use super::mass_function::{
    cached_combination_predicate, ingest_template_predicate, not_retracted_predicate,
};
use crate::errors::DbError;
use crate::visibility::Viewer;

/// A non-compound claim's kept belief cache (both `belief` and
/// `plausibility` set, the pair a DS write sets together).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AtomCache {
    /// `claims.belief`.
    pub belief: f64,
    /// `claims.plausibility`.
    pub plausibility: f64,
    /// `claims.pignistic_prob`, which a BP apply may have written apart from
    /// the interval.
    pub pignistic_prob: Option<f64>,
    /// `claims.mass_on_missing`: the open-world mass left in the fold.
    pub mass_on_missing: Option<f64>,
}

/// The kept cache of each requested claim the viewer can read that is not a
/// compound ([`super::claim_role::IS_COMPOUND_SQL`]) and has both `belief`
/// and `plausibility` set. Any other id is absent.
///
/// # Errors
/// Returns [`DbError::QueryFailed`] if the query fails.
#[instrument(skip(executor, viewer, ids), fields(n = ids.len()))]
pub async fn atom_cache_batch<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    viewer: &Viewer,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, AtomCache>, DbError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = viewer.splice(
        &[
            "SELECT c.id, c.belief, c.plausibility, c.pignistic_prob, c.mass_on_missing \
               FROM claims c \
              WHERE c.id = ANY($1) \
                AND c.belief IS NOT NULL \
                AND c.plausibility IS NOT NULL \
                AND NOT ",
            &is_compound_sql("c"),
            " /* {VISIBILITY:c} */",
        ]
        .concat(),
        2,
    );
    let mut q = sqlx::query_as::<_, (Uuid, f64, f64, Option<f64>, Option<f64>)>(&sql).bind(ids);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    Ok(q.fetch_all(executor)
        .await?
        .into_iter()
        .map(
            |(id, belief, plausibility, pignistic_prob, mass_on_missing)| {
                (
                    id,
                    AtomCache {
                        belief,
                        plausibility,
                        pignistic_prob,
                        mass_on_missing,
                    },
                )
            },
        )
        .collect())
}

/// One of a compound's own stored rows, with what the engine needs to read
/// it as refutation of the whole.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CompoundOwnRow {
    /// The row, in the shape the atom fold's reader takes (its edge fields
    /// are empty: an edge-factor row on a compound is never refutation of the
    /// compound, and the engine drops it by class).
    #[sqlx(flatten)]
    pub input: AtomInputRow,
    /// The claims carrying an `attributed_v1` row that cites this one
    /// (`perspective_id` is this row's id, perspective or evidence: readiness
    /// P3) with refutation mass, as the viewer sees them. `attributed_v1`
    /// rows are written on `binary_truth` (SPEC §5.3), so refutation mass is
    /// mass on `"1"` (FALSE). The engine counts a citation only when its
    /// claim is one of the compound's visible leaves: only then has this
    /// row's refutation moved onto the atoms the compound's conjunction reads.
    pub refuting_citers: Vec<Uuid>,
}

/// The own rows of each requested claim, as `viewer` sees them, on every
/// 2-hypothesis frame plus `claim_validity`, minus cached combinations and
/// ingest template rows, ordered by claim, then `created_at`, then id.
///
/// The caller passes compounds; the classes that are not evidence about the
/// claim (edge-factor, seed, propagated, `auto_cdst`) are the engine's to drop,
/// and so is the side of a hypothesis' promotion it does not read
/// (`hypothesis_promoted` is the claim's real flag, as the atom reader's).
///
/// # Errors
/// Returns [`DbError::QueryFailed`] if the query fails.
#[instrument(skip(executor, viewer, ids), fields(n = ids.len()))]
pub async fn compound_own_rows<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    viewer: &Viewer,
    ids: &[Uuid],
    claim_validity_frame_id: Uuid,
) -> Result<Vec<CompoundOwnRow>, DbError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = viewer.splice(
        &format!(
            r#"
            SELECT mf.id, mf.claim_id, mf.frame_id, mf.source_agent_id, mf.perspective_id,
                   mf.masses, mf.conflict_k, mf.combination_method, mf.source_strength,
                   mf.evidence_type, mf.locality_tag, mf.evidence_id, mf.created_at,
                   f.name AS frame_name,
                   f.hypotheses AS frame_hypotheses,
                   cf.hypothesis_index,
                   COALESCE(c.properties->>'hypothesis_status' = 'promoted', false)
                       AS hypothesis_promoted,
                   NULL::text AS edge_relationship,
                   NULL::uuid AS edge_source_id,
                   false AS edge_source_is_compound,
                   EXISTS (SELECT 1 FROM perspectives p
                            WHERE p.id = mf.perspective_id
                              AND p.perspective_type = 'evidence'
                              /* {{VISIBILITY:p}} */) AS perspective_is_evidence,
                   ARRAY(SELECT DISTINCT ar.claim_id FROM mass_functions ar
                          WHERE ar.combination_method = 'attributed_v1'
                            AND ar.perspective_id IN (mf.id, mf.perspective_id, mf.evidence_id)
                            AND COALESCE((ar.masses->>'1')::float8, 0) > 0
                            AND ar.retracted_at IS NULL
                            /* {{VISIBILITY:ar}} */) AS refuting_citers
            FROM mass_functions mf
            JOIN frames f ON f.id = mf.frame_id
            JOIN claims c ON c.id = mf.claim_id
            LEFT JOIN claim_frames cf
                   ON cf.claim_id = mf.claim_id AND cf.frame_id = mf.frame_id
                  /* {{VISIBILITY:cf}} */
            WHERE mf.claim_id = ANY($1)
              AND (array_length(f.hypotheses, 1) = 2 OR f.id = $2)
              AND NOT {cached}
              AND NOT {template}
              AND {not_retracted}
              /* {{VISIBILITY:mf}} */ /* {{VISIBILITY:f}} */ /* {{VISIBILITY:c}} */
            ORDER BY mf.claim_id, mf.created_at, mf.id
            "#,
            cached = cached_combination_predicate("mf."),
            template = ingest_template_predicate("mf.", "f."),
            not_retracted = not_retracted_predicate("mf."),
        ),
        3,
    );
    let mut q = sqlx::query_as::<_, CompoundOwnRow>(&sql)
        .bind(ids)
        .bind(claim_validity_frame_id);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    Ok(q.fetch_all(executor).await?)
}

/// A live refuting edge between two claims.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct RefutingEdge {
    /// The edge.
    pub id: Uuid,
    /// The refuting claim.
    pub source_id: Uuid,
    /// The refuted claim.
    pub target_id: Uuid,
    /// `contradicts` or `refutes`, lower-cased.
    pub relationship: String,
}

/// Every in-force `contradicts` / `refutes` edge (matched in any case) from a
/// current claim into one of `target_ids`, as `viewer` sees it: the edge and
/// its source claim must both be visible. Ordered by edge id.
///
/// # Errors
/// Returns [`DbError::QueryFailed`] if the query fails.
#[instrument(skip(executor, viewer, target_ids), fields(n = target_ids.len()))]
pub async fn refuting_edges_into<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    viewer: &Viewer,
    target_ids: &[Uuid],
) -> Result<Vec<RefutingEdge>, DbError> {
    if target_ids.is_empty() {
        return Ok(Vec::new());
    }
    // `concat`, not `format!`: the markers stay plain literals, as the marker
    // scanners in `tests/visibility_lint.rs` read them.
    let sql = viewer.splice(
        &[
            "SELECT e.id, e.source_id, e.target_id, lower(e.relationship) AS relationship \
               FROM edges e \
               JOIN claims s ON s.id = e.source_id \
              WHERE e.target_id = ANY($1) \
                AND e.source_type = 'claim' \
                AND e.target_type = 'claim' \
                AND lower(e.relationship) IN ('contradicts', 'refutes') \
                AND ",
            EDGE_IN_FORCE,
            " AND COALESCE(s.is_current, true) \
                /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:s} */ \
              ORDER BY e.id",
        ]
        .concat(),
        2,
    );
    let mut q = sqlx::query_as::<_, RefutingEdge>(&sql).bind(target_ids);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    Ok(q.fetch_all(executor).await?)
}
