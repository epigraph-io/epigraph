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
