-- ===================================================================
-- 237-undo.sql: take migration 237 (a `workflows` UPDATE is owner-scoped,
-- the outcome counters move through two definers, and the recorded submitter
-- is write-once) back out, in ONE transaction, on the migration (superuser)
-- DSN.
--
-- ROLL THE BINARY BACK FIRST. A binary built with 237 moves every
-- hierarchical outcome report's counters through
-- `epigraph_workflow_outcome_lock` and `epigraph_workflow_record_outcome`;
-- with them dropped, every report (REST and MCP) fails 42883. A binary built
-- without 237 needs neither, and works below 237 as before.
--
-- WHAT IT DOES:
--   * drops `workflows_submitter_immutable` and its function
--     `epigraph_workflows_submitter_guard()` (section 5);
--   * drops the RESTRICTIVE policy `workflows_update_owner` (section 4).
--     183's `workflows_update`, `workflows_read`, `workflows_insert`,
--     `workflows_delete_owner` and `workflows_elevated_no_*` are not touched;
--   * drops the two outcome definers (section 2).
--
-- WHAT IT LEAVES:
--   * every `workflows` row as it stands, counters included;
--   * 237's `_sqlx_migrations` row. Re-introducing the rule is a NEW
--     migration, never a re-run of 237.
--
-- WHAT COMES BACK: any application-role session can again UPDATE a public
-- workflow row (its truth_value, metadata and goal_embedding), and a reader
-- can UPDATE a group row, by a direct statement; a writer can again re-name a
-- row's recorded submitter.
--
-- Idempotent: a second run changes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS workflows_submitter_immutable ON public.workflows;
DROP FUNCTION IF EXISTS public.epigraph_workflows_submitter_guard();

DROP POLICY IF EXISTS workflows_update_owner ON public.workflows;

DROP FUNCTION IF EXISTS public.epigraph_workflow_record_outcome(uuid, boolean, double precision);
DROP FUNCTION IF EXISTS public.epigraph_workflow_outcome_lock(uuid);

COMMIT;
