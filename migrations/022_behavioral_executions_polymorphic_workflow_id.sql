-- Migration 022: behavioral_executions.workflow_id is now polymorphic (#34).
--
-- Hierarchical workflows (introduced in migration 020) have their root id in
-- the `workflows` table, not `claims`. The existing FK from
-- behavioral_executions.workflow_id to claims(id) makes it impossible to
-- record per-step execution rows for hierarchical workflows: every insert
-- fails the FK check and is silently dropped at the application layer.
--
-- Drop the FK so workflow_id can reference either claims.id (legacy flat)
-- or workflows.id (hierarchical). The column stays as plain uuid; callers
-- are responsible for ensuring it points at a real row in one of the two
-- tables. A future cleanup may introduce a discriminator column or split
-- this table into two; for now, the polymorphic interpretation is documented
-- below.

ALTER TABLE behavioral_executions
    DROP CONSTRAINT IF EXISTS behavioral_executions_workflow_id_fkey;

COMMENT ON COLUMN behavioral_executions.workflow_id IS
    'Polymorphic root identifier. References claims.id for legacy flat-JSON
    workflows, or workflows.id for hierarchical workflows. The originating
    handler determines which table is the target.';
