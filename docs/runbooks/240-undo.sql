-- ===================================================================
-- 240-undo.sql: take migration 240 (`behavioral_executions` carries its
-- workflow's tenancy under FORCEd row security; backlog 88cf603b) back out,
-- in ONE transaction, on the migration (superuser or maintenance) DSN.
--
-- ROLL THE BINARY BACK FIRST. A binary built with 240 lists
-- `behavioral_executions` in `FORCE_PROTECTED_SET` and refuses to serve where
-- the table exists un-FORCEd; it requires 240's three triggers only while one
-- of 240's functions exists, and this file drops all three functions.
--
-- WHAT IT DOES:
--   * drops the three tenancy triggers (the INSERT stamp on
--     `behavioral_executions`, the follow triggers on `workflows` and
--     `claims`), the owner guard, and the three functions;
--   * drops every policy 240 created, then NO FORCE and DISABLE row security;
--   * drops the index, the three constraints and both columns;
--   * restores 069's `tenancy_exempt` row, verbatim.
--
-- WHAT IT LEAVES:
--   * every run row, with its tenancy columns gone: the table is readable to
--     every application session again, the posture it had before 240 (the
--     readers' own parent filters still gate the first-party reads);
--   * 240's `_sqlx_migrations` row. Re-introducing the posture is a NEW
--     migration, never a re-run of 240;
--   * `behavioral_executions` in `docs/runbooks/079-undo.sql`'s list:
--     `NO FORCE` on a table that is not FORCEd is a no-op.
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS claims_behavioral_executions_inherit_tenancy ON public.claims;
DROP TRIGGER IF EXISTS workflows_behavioral_executions_inherit_tenancy ON public.workflows;
DROP TRIGGER IF EXISTS behavioral_executions_inherit_tenancy ON public.behavioral_executions;
DROP TRIGGER IF EXISTS behavioral_executions_owner_immutable ON public.behavioral_executions;

DROP FUNCTION IF EXISTS public.epigraph_claim_behavioral_executions_follow();
DROP FUNCTION IF EXISTS public.epigraph_workflow_behavioral_executions_follow();
DROP FUNCTION IF EXISTS public.epigraph_behavioral_execution_inherit_tenancy();

DROP POLICY IF EXISTS behavioral_executions_read ON public.behavioral_executions;
DROP POLICY IF EXISTS behavioral_executions_insert ON public.behavioral_executions;
DROP POLICY IF EXISTS behavioral_executions_maintenance_update ON public.behavioral_executions;
DROP POLICY IF EXISTS behavioral_executions_delete_owner ON public.behavioral_executions;
DROP POLICY IF EXISTS behavioral_executions_elevated_no_insert ON public.behavioral_executions;
DROP POLICY IF EXISTS behavioral_executions_elevated_no_update ON public.behavioral_executions;
DROP POLICY IF EXISTS behavioral_executions_elevated_no_delete ON public.behavioral_executions;

ALTER TABLE public.behavioral_executions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.behavioral_executions DISABLE ROW LEVEL SECURITY;

DROP INDEX IF EXISTS public.behavioral_executions_group_owner_idx;
ALTER TABLE public.behavioral_executions
    DROP CONSTRAINT IF EXISTS behavioral_executions_group_needs_real_group,
    DROP CONSTRAINT IF EXISTS behavioral_executions_owner_group_fkey,
    DROP CONSTRAINT IF EXISTS behavioral_executions_visibility_check,
    DROP COLUMN IF EXISTS owner_group_id,
    DROP COLUMN IF EXISTS visibility;

INSERT INTO public.tenancy_exempt (table_name, reason, residual, reviewed_by) VALUES
 ('behavioral_executions',
  'Generator B hit via behavioral_executions_step_claim_id (nullable). '
  'Workflow telemetry, not claim content.',
  'goal_text and goal_embedding vector(1536) are workflow-goal text; a private '
  'workflow step''s goal is disclosed. Low value, ledgered.',
  'PENDING')
ON CONFLICT (table_name) DO NOTHING;

COMMIT;
