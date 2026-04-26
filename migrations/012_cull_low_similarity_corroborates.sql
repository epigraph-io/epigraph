-- 103_cull_low_similarity_corroborates.sql
--
-- Remove CORROBORATES edges with similarity < 0.80 and their factors.
--
-- Evidence: sampling 12 edges in the 0.75–0.80 bucket showed ~40–50% false
-- positive rate — different anatomical structures, opposite binding sites,
-- different vessel segments — matched on topical vocabulary, not shared facts.
-- The existing claim in the graph (claim about cross-source threshold needing
-- raising) noted true corroboration clusters above 0.85; 0.80 is the
-- conservative cut here pending LLM assessment of the 0.80–0.95 range.
--
-- Scope: 24,416 edges, all from paraphrase-probe method (other methods were
-- already filtered to 0.85+ at ingestion time).

BEGIN;

-- Collect the edge IDs to delete once, reuse in subsequent statements.
CREATE TEMP TABLE edges_to_cull AS
SELECT id FROM edges
WHERE relationship = 'CORROBORATES'
  AND (properties->>'similarity')::float < 0.80;

-- 1. Remove bp_messages for affected factors (no FK cascade, explicit delete).
DELETE FROM bp_messages
WHERE factor_id IN (
    SELECT f.id FROM factors f
    WHERE f.properties->>'source_edge_id' IN (
        SELECT id::text FROM edges_to_cull
    )
);

-- 2. Remove the factors themselves.
DELETE FROM factors
WHERE properties->>'source_edge_id' IN (
    SELECT id::text FROM edges_to_cull
);

-- 3. Delete the edges.
DELETE FROM edges WHERE id IN (SELECT id FROM edges_to_cull);

DROP TABLE edges_to_cull;

COMMIT;
