//! The edge and BBA selections of the supersede belief fixes (supersede SPEC
//! §11 K3, K10(2), K12(b)), shared by the fixes and by the read-only dry-run
//! delta that measures them (K0, X-3), so the measurement and the fix cannot
//! select different rows.
//!
//! * [`RETIRED_SOURCE_EDGE_BBAS_SQL`]: the live edge-keyed BBAs that a
//!   retired claim's outgoing edges froze onto current claims. The supersede
//!   cascade invalidates them for the claim it just retired
//!   (`retraction_cascade::cascade_after_supersede`); the delta reads them for
//!   every retired claim (the retroactive sweep K10(3), which nothing applies:
//!   operator decision OD-10).
//!
//! Every statement here is a READ. The write half lives in the repo layer
//! (`MassFunctionRepository::delete_for_perspective`) and in the cascade that
//! sequences it.

use uuid::Uuid;

/// Live BBAs keyed on an edge whose SOURCE is a retired claim, held by a
/// current claim. `$1` (`uuid[]`): the retired sources to read, or NULL for
/// every retired claim.
///
/// * Only `perspective_type = 'edge'` perspectives: a BBA is edge-keyed when
///   its perspective is the edge's own (`PerspectiveRepository::ensure_edge_perspective`).
/// * Retracted rows are never selected (SPEC §4, "retracted BBAs"; ruling
///   R-79): an invalidation skips them, so they are kept.
/// * The edge's own in-force state is NOT a predicate: a BBA keyed on a
///   withdrawn edge from a retired claim is as stale as one on an edge in
///   force. It is returned so a report can tell the two apart.
pub const RETIRED_SOURCE_EDGE_BBAS_SQL: &str = r#"-- VISIBILITY-EXEMPT: maintenance read; the supersede cascade and the dry-run delta run on the privileged connection.
SELECT mf.id, mf.claim_id, e.id, e.source_id, lower(e.relationship),
       (e.valid_to IS NULL OR e.valid_to > now())
  FROM mass_functions mf
  JOIN perspectives p ON p.id = mf.perspective_id AND p.perspective_type = 'edge'
  JOIN edges e ON e.id = p.id
  JOIN claims s ON s.id = e.source_id
  JOIN claims h ON h.id = mf.claim_id
 WHERE e.source_type = 'claim'
   AND NOT COALESCE(s.is_current, true)
   AND COALESCE(h.is_current, true)
   AND mf.retracted_at IS NULL
   AND ($1::uuid[] IS NULL OR e.source_id = ANY($1::uuid[]))
 ORDER BY e.id, mf.claim_id, mf.id"#;

/// One row of [`RETIRED_SOURCE_EDGE_BBAS_SQL`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EdgeKeyedBba {
    pub mass_function_id: Uuid,
    /// The current claim holding the row.
    pub holder_id: Uuid,
    pub edge_id: Uuid,
    pub source_id: Uuid,
    /// Lower-cased.
    pub relationship: String,
    pub edge_in_force: bool,
}

type EdgeKeyedRow = (Uuid, Uuid, Uuid, Uuid, String, bool);

fn edge_keyed(rows: Vec<EdgeKeyedRow>) -> Vec<EdgeKeyedBba> {
    rows.into_iter()
        .map(
            |(mass_function_id, holder_id, edge_id, source_id, relationship, edge_in_force)| {
                EdgeKeyedBba {
                    mass_function_id,
                    holder_id,
                    edge_id,
                    source_id,
                    relationship,
                    edge_in_force,
                }
            },
        )
        .collect()
}

/// [`RETIRED_SOURCE_EDGE_BBAS_SQL`] for `sources`, or for every retired claim
/// when `None`.
///
/// # Errors
/// The query's error.
pub async fn retired_source_edge_bbas(
    conn: &mut sqlx::PgConnection,
    sources: Option<&[Uuid]>,
) -> Result<Vec<EdgeKeyedBba>, sqlx::Error> {
    let rows: Vec<EdgeKeyedRow> = sqlx::query_as(RETIRED_SOURCE_EDGE_BBAS_SQL)
        .bind(sources.map(<[Uuid]>::to_vec))
        .fetch_all(&mut *conn)
        .await?;
    Ok(edge_keyed(rows))
}
