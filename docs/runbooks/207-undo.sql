-- ===================================================================
-- 207-undo.sql: take migration 207 (the bug-report intake) back out, in ONE
-- transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Roll every MCP unit back to a build without the
-- `submit_bug_report` and `list_my_bug_reports` tools BEFORE this runs; a unit
-- left serving them answers every call with an error (42883).
--
-- WHAT IT DOES: drops the settings audit trigger and its function, both
-- definers, the preflight and its caller gate, the
-- `security_events_bug_report_privileged` policy and the
-- `bug_report_intake_settings` table (with its one row).
--
-- WHAT IT LEAVES: every claim, trace and evidence row written through the
-- intake (owned by the intake group, authored by their reporters), every
-- `bug_report.*` security_events row, and 207's `_sqlx_migrations` row.
-- Re-introducing the intake is a NEW migration, never a re-run of 207.
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS bug_report_intake_settings_audit ON public.bug_report_intake_settings;
DROP FUNCTION IF EXISTS public.epigraph_bug_report_intake_settings_audit();
DROP FUNCTION IF EXISTS public.epigraph_submit_bug_report(text, text, text, text, text, text,
                                                          text, bytea, bytea, text);
DROP FUNCTION IF EXISTS public.epigraph_my_bug_reports(integer);
DROP FUNCTION IF EXISTS public.epigraph_bug_report_preflight();
DROP FUNCTION IF EXISTS public.epigraph_bug_report_gate(uuid, integer, integer, boolean);
DROP POLICY IF EXISTS security_events_bug_report_privileged ON public.security_events;
DROP TABLE IF EXISTS public.bug_report_intake_settings;

COMMIT;
