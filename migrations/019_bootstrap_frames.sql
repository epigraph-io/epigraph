-- Migration 019: Bootstrap paper frames + topic clusters from existing data
--
-- Creates frames for existing claims:
-- 1. Paper frames: claims from the same paper share a binary frame
-- 2. Topic frames: claims with common labels share ternary frames
-- 3. Backfills belief/plausibility from truth_value with initial ignorance gap
--
-- Evidence:
-- - Existing claims have properties->>'source_paper_title' and labels[]
-- - DS theory requires frame membership for mass function assignment
--
-- Reasoning:
-- - Paper frames use binary ["supported", "unsupported"] — papers either support or don't
-- - Topic frames use ternary ["true", "false", "indeterminate"] — richer for topic debate
-- - Backfill mapping: Bel = truth_value * 0.8, Pl = min(1.0, truth_value + 0.15)
--   This preserves ordering while introducing an initial ignorance gap

-- 1. Create frames for each paper source
INSERT INTO frames (id, name, description, hypotheses)
SELECT DISTINCT
    gen_random_uuid(),
    'paper:' || (c.properties->>'source_paper_title'),
    'Claims sourced from paper: ' || (c.properties->>'source_paper_title'),
    ARRAY['supported', 'unsupported']
FROM claims c
WHERE c.properties->>'source_paper_title' IS NOT NULL
ON CONFLICT (name) DO NOTHING;

-- 2. Link claims to their paper frames
INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index)
SELECT c.id, f.id, 0  -- hypothesis_index 0 = "supported"
FROM claims c
JOIN frames f ON f.name = 'paper:' || (c.properties->>'source_paper_title')
WHERE c.properties->>'source_paper_title' IS NOT NULL
ON CONFLICT DO NOTHING;

-- 3. Create topic cluster frames from claim labels
INSERT INTO frames (id, name, description, hypotheses)
SELECT DISTINCT
    gen_random_uuid(),
    'topic:' || unnest_label,
    'Topic cluster: ' || unnest_label,
    ARRAY['true', 'false', 'indeterminate']
FROM (
    SELECT DISTINCT unnest(labels) AS unnest_label
    FROM claims
    WHERE array_length(labels, 1) > 0
) sub
ON CONFLICT (name) DO NOTHING;

-- 4. Link claims to topic frames
INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index)
SELECT c.id, f.id, 0  -- hypothesis_index 0 = "true"
FROM claims c
CROSS JOIN LATERAL unnest(c.labels) AS label
JOIN frames f ON f.name = 'topic:' || label
ON CONFLICT DO NOTHING;

-- 5. Backfill belief/plausibility from existing truth_value
-- Initial mapping: Bel = truth_value * 0.8, Pl = min(1.0, truth_value + 0.15)
-- This preserves ordering while introducing initial ignorance gap
UPDATE claims SET
    belief = GREATEST(0.0, truth_value * 0.8),
    plausibility = LEAST(1.0, truth_value + 0.15)
WHERE belief IS NULL;
