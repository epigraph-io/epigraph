-- Migration 033: workflows.truth_value column for deprecation filtering.
--
-- The hierarchical `workflows` table (added in 020) had no truth_value.
-- `deprecate_workflow` (both MCP and API) only updated the matching row
-- in `claims` — which is the FLAT representation — so deprecating a
-- hierarchical workflow had no visible effect on
-- `find_workflow_hierarchical`, which reads from `workflows`.
--
-- This migration adds `truth_value` to `workflows` and a partial index
-- to keep deprecation filters cheap. The default 1.0 preserves all
-- existing rows as "live" — no backfill required. The cascade write
-- (deprecate_workflow → UPDATE workflows.truth_value) is added in the
-- accompanying Rust changes.

ALTER TABLE workflows
    ADD COLUMN truth_value DOUBLE PRECISION NOT NULL DEFAULT 1.0;

-- Partial index: only deprecated rows. Live rows (truth_value = 1.0)
-- dominate the table; we only need fast lookup for the deprecation
-- filter `truth_value < $min_truth`, which is rare.
CREATE INDEX workflows_truth_value_low_idx
    ON workflows (truth_value)
    WHERE truth_value < 1.0;
