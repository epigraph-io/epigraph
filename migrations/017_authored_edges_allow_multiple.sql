-- AUTHORED verb-edge accumulation per architecture doc
-- (docs/architecture/noun-claims-and-verb-edges.md §"Cause 1"):
--
--   "The auto-emitted AUTHORED verb-edge on each submission is preserved —
--    each submission is a distinct verb-event even when the noun-claim
--    already exists."
--
-- The original idx_edges_unique_triple (defined in 001_initial_schema.sql)
-- prevented AUTHORED accumulation: a second AUTHORED edge for the same
-- (agent, claim) tripped
-- the unique violation, and the API handler at routes/claims.rs:565 silently
-- swallowed it via `let _ = ...`. The architecture doc's "verb-event"
-- semantics was aspirational and never realized in the schema.
--
-- This migration replaces the constraint with a partial unique index that
-- excludes AUTHORED, so AUTHORED edges accumulate one-per-submission while
-- every other relationship type continues to enforce triple-uniqueness. No
-- in-tree code uses ON CONFLICT (source_id, target_id, relationship), so the
-- behavior change is contained to AUTHORED accumulation.

DROP INDEX IF EXISTS idx_edges_unique_triple;

CREATE UNIQUE INDEX idx_edges_unique_triple_non_authored
  ON edges (source_id, target_id, relationship)
  WHERE relationship != 'AUTHORED';
