//! The edge-factor selections of the `backfill_factors` binary, in the library
//! so the tests in `crates/epigraph-cli/tests/` can run the exact SQL the
//! binary runs.

/// Edge-phase eligibility: factorless target claim, claim-to-claim edge with
/// epistemic relationship. Uses `signer_id` when present, otherwise falls back
/// to the source claim's `agent_id` (always populated) — the edge factor is
/// attributable to the source claim's author since they're asserting the
/// support/contradiction via the edge.
pub const EDGE_QUERY: &str = r#"
SELECT e.id, COALESCE(e.signer_id, src.agent_id) AS agent_id,
       e.source_id, e.target_id, e.relationship
FROM edges e
JOIN claims tgt ON tgt.id = e.target_id
JOIN claims src ON src.id = e.source_id
WHERE tgt.is_current AND src.is_current
  AND e.source_type = 'claim' AND e.target_type = 'claim'
  AND LOWER(e.relationship) IN (
    'supports','corroborates','contradicts','refutes','refines','undercuts','rebuts',
    'elaborates','specializes','generalizes','supersedes','informs','frame_validates'
  )
  AND NOT EXISTS (SELECT 1 FROM mass_functions mf WHERE mf.claim_id = tgt.id)
ORDER BY e.target_id, e.created_at
LIMIT $1 OFFSET $2
"#;

use sqlx::PgPool;
use uuid::Uuid;

/// One already-wired edge factor the rewire phase rewrites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewireEdge {
    pub edge_id: Uuid,
    /// The `source_agent_id` the stored row is keyed on.
    pub agent_id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub relationship: String,
    /// The frame the stored row lives on.
    pub frame_id: Uuid,
}

/// Paging and safety switches for [`run_rewire_phase`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RewireOptions {
    /// At most this many edges (0 = unlimited).
    pub limit: usize,
    pub offset: usize,
    /// Select and report; write nothing.
    pub dry_run: bool,
    /// Only rows last written before this instant.
    pub written_before: Option<chrono::DateTime<chrono::Utc>>,
}

/// What [`run_rewire_phase`] did, one counter per outcome.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RewireSummary {
    pub eligible: usize,
    pub rewired: usize,
    pub removed_vacuous: usize,
    pub removed_source_factorless: usize,
    pub skipped_non_epistemic: usize,
    pub failed: usize,
}

/// STUB (red commit): selects nothing.
///
/// # Errors
/// The query's error.
pub async fn select_rewire_edges(
    _pool: &PgPool,
    _opts: &RewireOptions,
) -> Result<Vec<RewireEdge>, sqlx::Error> {
    Ok(Vec::new())
}

/// STUB (red commit): rewrites nothing.
///
/// # Errors
/// The selection's error.
pub async fn run_rewire_phase(
    _pool: &PgPool,
    _viewer: &epigraph_db::visibility::Viewer,
    _opts: &RewireOptions,
) -> Result<RewireSummary, sqlx::Error> {
    Ok(RewireSummary::default())
}
