//! The rows an atom's evidence fold (AEF) may read (atom-level belief program,
//! SPEC §3.3, §3.4, §6.3, §11.4).
//!
//! [`atom_input_rows`] is the ONE read of an atom's fold input. It returns
//! every visible BBA row of the requested claims that the fold could take,
//! with the context the engine needs to coarsen, discount, key and classify
//! it (`epigraph_engine::atom_items` does that). It already excludes, with
//! the one spellings of each predicate:
//!
//! * rows on a frame that is neither 2-hypothesis nor `claim_validity`;
//! * cached combination rows
//!   ([`super::mass_function::cached_combination_predicate`]);
//! * ingest template rows ([`super::mass_function::ingest_template_predicate`]);
//! * `edge_factor` rows whose edge the viewer cannot see (or that no longer
//!   exists). The edge is read through the viewer's `EDGE_VISIBILITY` splice
//!   (SPEC §6.3), so for such a row the viewer cannot tell whether its source
//!   is a compound or which way its relationship points. Reading it as an
//!   atom-source row would keep a compound's mass two-sided, and keep it
//!   under `excluded`; it is not evidence this viewer can read, so it is not
//!   in this viewer's fold;
//! * every row of a **compound** ([`super::claim_role::is_compound_sql`]):
//!   its belief is a query over its leaves, never a fold of its own rows. The
//!   role test carries no splice (role is structure, as the
//!   [`claim_role`](super::claim_role) module doc states). On a connection
//!   that bypasses row security (the maintenance pool and session, where the
//!   bulk writers run) a viewer who cannot see a compound's decomposition
//!   therefore still never folds its rows. **On an application session it
//!   can:** `edges` is FORCE ROW LEVEL SECURITY, so a session that can read
//!   none of a compound's in-force decomposition edges finds no compound and
//!   reads that compound's rows as an atom's (the gap the `claim_role` doc
//!   records; pinned by `atom_fold.rs::on_an_app_session_row_security_hides_a_compound_from_the_fold`).
//!   Per-request callers must close it before they fold (PR-5b1: fail closed,
//!   or a definer-rights role read under a ruling).
//!
//! The mode filters (`Display` / `Pure`), the seed rule and the
//! hypothesis-promotion rule are the engine's, over these rows.

use tracing::instrument;
use uuid::Uuid;

use super::claim_role::is_compound_sql;
use super::mass_function::{
    cached_combination_predicate, ingest_template_predicate, not_retracted_predicate,
    MassFunctionRow,
};
use crate::errors::DbError;
use crate::visibility::Viewer;

/// One candidate AEF input row, with what the fold needs to read it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AtomInputRow {
    /// The stored BBA.
    #[sqlx(flatten)]
    pub row: MassFunctionRow,
    /// The frame's name.
    pub frame_name: String,
    /// The frame's ordered hypotheses.
    pub frame_hypotheses: Vec<String>,
    /// The claim's `claim_frames.hypothesis_index` on this frame, if any.
    pub hypothesis_index: Option<i32>,
    /// `claims.properties->>'hypothesis_status' = 'promoted'`.
    pub hypothesis_promoted: bool,
    /// For an `edge_factor` row: the edge's relationship. Always `Some` on
    /// such a row (a row whose edge the viewer cannot see is not returned).
    pub edge_relationship: Option<String>,
    /// For an `edge_factor` row: the edge's source claim.
    pub edge_source_id: Option<Uuid>,
    /// For an `edge_factor` row: whether the edge's source claim is a
    /// compound ([`super::claim_role::IS_COMPOUND_SQL`]); `false` on every
    /// other row.
    pub edge_source_is_compound: bool,
    /// The row's `perspective_id` names an evidence perspective
    /// (`perspective_type = 'evidence'`, which shares its evidence row's id),
    /// so the row cites that evidence row even when `evidence_id` is NULL.
    pub perspective_is_evidence: bool,
}

/// The candidate AEF input rows of each requested claim, as `viewer` sees
/// them (see the module doc for what is already excluded), ordered by claim,
/// then `created_at`, then row id.
///
/// `claim_validity_frame_id` is the canonical `claim_validity` frame, the one
/// frame with more than two hypotheses the fold reads.
///
/// # Errors
/// Returns [`DbError::QueryFailed`] if the query fails.
#[instrument(skip(executor, viewer, ids), fields(n = ids.len()))]
pub async fn atom_input_rows<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    viewer: &Viewer,
    ids: &[Uuid],
    claim_validity_frame_id: Uuid,
) -> Result<Vec<AtomInputRow>, DbError> {
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
                   ae.relationship AS edge_relationship,
                   ae.source_id AS edge_source_id,
                   COALESCE(ae.source_is_compound, false) AS edge_source_is_compound,
                   EXISTS (SELECT 1 FROM perspectives p
                            WHERE p.id = mf.perspective_id
                              AND p.perspective_type = 'evidence'
                              /* {{VISIBILITY:p}} */) AS perspective_is_evidence
            FROM mass_functions mf
            JOIN frames f ON f.id = mf.frame_id
            JOIN claims c ON c.id = mf.claim_id
            LEFT JOIN claim_frames cf
                   ON cf.claim_id = mf.claim_id AND cf.frame_id = mf.frame_id
                  /* {{VISIBILITY:cf}} */
            LEFT JOIN LATERAL (
                SELECT e.relationship,
                       e.source_id,
                       (e.source_type = 'claim'
                        AND EXISTS (SELECT 1 FROM claims aa_src
                                     WHERE aa_src.id = e.source_id
                                       AND {src_compound})) AS source_is_compound
                  FROM edges e
                 WHERE mf.combination_method = 'edge_factor'
                   AND e.id = mf.perspective_id
                   /* {{EDGE_VISIBILITY:e}} */
            ) ae ON true
            WHERE mf.claim_id = ANY($1)
              AND (array_length(f.hypotheses, 1) = 2 OR f.id = $2)
              AND NOT {cached}
              AND NOT {template}
              AND {not_retracted}
              AND NOT {claim_compound}
              AND (mf.combination_method IS DISTINCT FROM 'edge_factor'
                   OR ae.relationship IS NOT NULL)
              /* {{VISIBILITY:mf}} */ /* {{VISIBILITY:f}} */ /* {{VISIBILITY:c}} */
            ORDER BY mf.claim_id, mf.created_at, mf.id
            "#,
            src_compound = is_compound_sql("aa_src"),
            cached = cached_combination_predicate("mf."),
            template = ingest_template_predicate("mf.", "f."),
            not_retracted = not_retracted_predicate("mf."),
            claim_compound = is_compound_sql("c"),
        ),
        3,
    );
    let mut q = sqlx::query_as::<_, AtomInputRow>(&sql)
        .bind(ids)
        .bind(claim_validity_frame_id);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    Ok(q.fetch_all(executor).await?)
}
