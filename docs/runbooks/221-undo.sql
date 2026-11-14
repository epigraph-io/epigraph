-- ===================================================================
-- 221-undo.sql: take migration 221 (`workflow_outcome_reports`, one row per
-- hierarchical outcome report) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- READ FIRST: ROLL THE BINARIES BACK BEFORE THIS RUNS. A 221 binary reads and
-- writes the table on every hierarchical outcome report (MCP
-- `report_hierarchical_outcome`, the hierarchical branch of
-- `report_workflow_outcome`, `POST /api/v1/workflows/hierarchical/:id/outcome`).
-- A unit left serving after this undo
-- answers every such call with an error (42P01). A pre-221 binary never
-- touches it.
--
-- WHAT IT DOES: drops the table, with its policies and indexes.
--
-- WHAT IT LOSES AND LEAVES:
--   * every stored `outcome_details` and every idempotency key is LOST with the
--     table. Export first if they matter:
--       COPY (SELECT * FROM public.workflow_outcome_reports) TO STDOUT CSV HEADER;
--   * the `workflows.metadata` counters and every `behavioral_executions` row
--     those reports wrote, as they stand;
--   * 221's `_sqlx_migrations` row. Re-introducing the table is a NEW
--     migration, never a re-run of 221.
-- Idempotent: a second run changes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TABLE IF EXISTS public.workflow_outcome_reports;

COMMIT;
