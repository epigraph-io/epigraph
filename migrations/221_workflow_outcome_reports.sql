-- 221_workflow_outcome_reports.sql
-- One row per hierarchical outcome report (backlog 9928b61f).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- `report_hierarchical_outcome` (MCP tool and
-- `POST /api/v1/workflows/hierarchical/:id/outcome`) moves the rolling
-- counters on `workflows.metadata` and writes one `behavioral_executions` row
-- per step. Two defects remained:
--   * a RETRY of a report whose answer was lost (a timeout, a dropped
--     connection) counted the run twice: nothing identified a report, so the
--     second call was indistinguishable from a second run;
--   * `outcome_details`, a required argument on both transports, was
--     accepted and dropped: no column held it.
--
-- ===================================================================
-- 2. WHAT THIS FILE ADDS
-- ===================================================================
--
-- `public.workflow_outcome_reports`, one row per report, written on the same
-- caller-stamped transaction as the counters and the step rows (all or
-- nothing):
--   workflow_id      the hierarchical workflow (FK; a report row goes with its
--                    workflow row)
--   reporter_id      the reporting principal, as the server resolved it
--                    (NULL only for a principal-less session)
--   idempotency_key  the caller's optional key. UNIQUE per (workflow,
--                    reporter, key), NULLS NOT DISTINCT so a principal-less
--                    session's keys are unique too. A report that repeats a
--                    key writes nothing and is answered with the stored
--                    result.
--   success, quality, run_label, outcome_details   what the report said
--   result           the report's transport-neutral result (counters after
--                    it, its variance, step rows written, unresolved step
--                    indices), which a replay answers with
--
-- Keys are scoped to the reporter, not only the workflow: two reporters that
-- happen to choose the same key name two reports, and one reporter can never
-- receive another's result by guessing its key.
--
-- ===================================================================
-- 3. TENANCY: INHERITED FROM THE WORKFLOW ROW
-- ===================================================================
--
-- A report belongs to its workflow, which carries its plan's tenancy and
-- FORCEd row security since migration 183. The row has no tenancy columns
-- of its own; its policies admit it exactly when the session reads its
-- `workflows` row (the `EXISTS` below is itself filtered by
-- `workflows_read`), so a report on a group-private plan, and its
-- `outcome_details`, are read only by sessions that read that plan. A
-- bypassing session (maintenance) reads every row, as it reads every
-- workflow.
--
-- The application role gets SELECT and INSERT only: a report is never
-- edited or deleted by the request path (no UPDATE or DELETE policy either).
-- An elevated session writes none (126's census: refusal-only, the same
-- three policies as `workflows`, class T-PLAN).
--
-- No claim_id column and no FK to claims, so tenancy_coverage.rs's generators
-- do not reach this table.
--
-- Undo: docs/runbooks/221-undo.sql (drops the table and every report in it;
-- roll the binaries back first).
SET LOCAL lock_timeout = '3s';

CREATE TABLE public.workflow_outcome_reports (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id      uuid NOT NULL REFERENCES public.workflows(id) ON DELETE CASCADE,
    reporter_id      uuid,
    idempotency_key  text CHECK (idempotency_key IS NULL
                                 OR length(idempotency_key) BETWEEN 1 AND 200),
    success          boolean NOT NULL,
    quality          double precision CHECK (quality IS NULL OR quality BETWEEN 0 AND 1),
    run_label        text,
    outcome_details  text NOT NULL DEFAULT ''
                          CHECK (octet_length(outcome_details) <= 65536),
    result           jsonb NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);
-- Partial: unkeyed reports (idempotency_key NULL) are never unique-checked.
-- NULLS NOT DISTINCT makes a NULL reporter_id compare equal to itself.
CREATE UNIQUE INDEX workflow_outcome_reports_idempotency
    ON public.workflow_outcome_reports (workflow_id, reporter_id, idempotency_key)
    NULLS NOT DISTINCT
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX workflow_outcome_reports_workflow_idx
    ON public.workflow_outcome_reports (workflow_id, created_at DESC);

ALTER TABLE public.workflow_outcome_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workflow_outcome_reports FORCE ROW LEVEL SECURITY;

CREATE POLICY workflow_outcome_reports_read ON public.workflow_outcome_reports
    FOR SELECT TO PUBLIC
    USING (EXISTS (SELECT 1 FROM public.workflows w
                    WHERE w.id = workflow_outcome_reports.workflow_id));
CREATE POLICY workflow_outcome_reports_insert ON public.workflow_outcome_reports
    FOR INSERT TO PUBLIC
    WITH CHECK (EXISTS (SELECT 1 FROM public.workflows w
                         WHERE w.id = workflow_outcome_reports.workflow_id));

-- 126's census, refusal-only (class T-PLAN), as `workflows` (183 section 6).
CREATE POLICY workflow_outcome_reports_elevated_no_insert ON public.workflow_outcome_reports
    AS RESTRICTIVE FOR INSERT TO epigraph_app
    WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
CREATE POLICY workflow_outcome_reports_elevated_no_update ON public.workflow_outcome_reports
    AS RESTRICTIVE FOR UPDATE TO epigraph_app
    USING (NOT (SELECT public.epigraph_is_elevated()));
CREATE POLICY workflow_outcome_reports_elevated_no_delete ON public.workflow_outcome_reports
    AS RESTRICTIVE FOR DELETE TO epigraph_app
    USING (NOT (SELECT public.epigraph_is_elevated()));

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.workflow_outcome_reports FROM epigraph_app';
        EXECUTE 'GRANT SELECT, INSERT ON public.workflow_outcome_reports TO epigraph_app';
    END IF;
END
$$;

COMMENT ON TABLE public.workflow_outcome_reports IS
    'One row per hierarchical workflow outcome report (migration 221): what the report said '
    '(success, quality, run_label, outcome_details), its optional idempotency key, unique per '
    '(workflow, reporter), and the result a retry with that key is answered with. Read and '
    'written only by sessions that read the workflow row.';
