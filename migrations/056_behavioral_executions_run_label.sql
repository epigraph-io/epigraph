-- 056_behavioral_executions_run_label.sql
--
-- Add an optional run/variant label to behavioral_executions so a parameter
-- sweep (N runs of one workflow with different parameter sets) produces rows
-- that are machine-distinguishable, rather than tellable apart only by the
-- free-text goal_text / step_beliefs. Surfaced by get_workflow_executions and
-- set by report_hierarchical_outcome's optional run_label field (issue #353).
--
-- Nullable and additive: existing rows and every non-sweep caller leave it NULL,
-- so behaviour is unchanged when no label is supplied.

ALTER TABLE behavioral_executions
    ADD COLUMN IF NOT EXISTS run_label TEXT;

-- Partial index: sweep queries filter to the labelled rows only.
CREATE INDEX IF NOT EXISTS idx_behavioral_executions_run_label
    ON behavioral_executions (workflow_id, run_label)
    WHERE run_label IS NOT NULL;
