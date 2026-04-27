-- Migration 100: multi-dimensional conflict surfacing (additive, forward-only).
--
-- Evidence:
-- - docs/superpowers/specs/2026-04-18-multi-dimensional-conflict-surfacing-design.md
-- - edges.relationship is already VARCHAR(100) (migration 006) so the three
--   new edge-type strings ('method_diverges', 'scope_diverges', 'temporal_drift')
--   need no schema change — only new columns land here.
--
-- Reasoning:
-- - dimension_score is nullable because contradicts edges don't require it
--   (K lives on mass_functions.conflict_k, the source of truth for K).
-- - evidence.scope is JSONB so new dimension keys can be added without
--   migration churn; shape: {population?: str, condition?: str,
--   geography?: str, era?: str}.

ALTER TABLE edges ADD COLUMN dimension_score DOUBLE PRECISION
  CHECK (dimension_score IS NULL OR (dimension_score >= 0 AND dimension_score <= 1));

ALTER TABLE evidence ADD COLUMN scope JSONB;

CREATE INDEX IF NOT EXISTS idx_edges_relationship_new
  ON edges(relationship)
  WHERE relationship IN ('method_diverges', 'scope_diverges', 'temporal_drift');
