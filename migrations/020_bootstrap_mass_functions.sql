-- Migration 020: Bootstrap mass functions from existing truth values
--
-- Generate initial BBAs for claims that belong to frames.
-- Uses a conservative conversion: m({supported}) = truth_value * 0.7,
-- with the remaining mass on Θ (total ignorance).
--
-- Evidence:
-- - dekg-planning-doc.md §4: "Bayesian-to-DS migration" requires initial BBAs
-- - Claims already have truth_value from Bayesian propagation
--
-- Reasoning:
-- - 0.7 scaling factor prevents overconfidence in bootstrapped data
-- - This is a one-time bootstrap; real evidence will override
-- - Only claims IN a frame get mass functions (others stay Bayesian-only)
-- - source_agent_id = NULL marks these as system-generated
-- - combination_method = 'bootstrap' for audit trail

INSERT INTO mass_functions (claim_id, frame_id, masses, conflict_k, combination_method)
SELECT
    cf.claim_id,
    cf.frame_id,
    -- Build JSONB: key "0" = supported hypothesis, key = full set = remaining
    jsonb_build_object(
        COALESCE(cf.hypothesis_index::text, '0'),
        ROUND((c.truth_value * 0.7)::numeric, 6),
        -- Full set key: "0,1" for binary, "0,1,2" for ternary, etc.
        (
            SELECT string_agg(idx::text, ',' ORDER BY idx)
            FROM generate_series(0, array_length(f.hypotheses, 1) - 1) AS idx
        ),
        ROUND((1.0 - c.truth_value * 0.7)::numeric, 6)
    ),
    0.0,  -- no conflict for bootstrapped functions
    'bootstrap'
FROM claim_frames cf
JOIN claims c ON c.id = cf.claim_id
JOIN frames f ON f.id = cf.frame_id
WHERE c.truth_value IS NOT NULL
  AND c.truth_value > 0.0
  -- Skip claims that already have mass functions
  AND NOT EXISTS (
      SELECT 1 FROM mass_functions mf
      WHERE mf.claim_id = cf.claim_id AND mf.frame_id = cf.frame_id
  );
