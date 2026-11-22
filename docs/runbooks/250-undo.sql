-- ===================================================================
-- 250-undo.sql: take migration 250 back out, in ONE transaction, on the
-- migration (owner) DSN.
--
-- SECTION 1 (telemetry-only prune, backlog 062d7767):
--   * re-grants `epigraph_maintenance` UPDATE (070) and DELETE (186) on
--     `public.events`, the posture before 250: every maintenance session can
--     again delete or rewrite any `events` row, provenance included;
--   * drops `epigraph_prune_telemetry_events(integer)` and
--     `epigraph_prunable_event_types()`.
--   A binary that calls the definer (`RecallEventRepository::
--   prune_telemetry_events` from 250 on) then fails with 42883: roll the
--   binary back to one that issues its own `DELETE FROM events` first, or
--   stop the `prune_recall_events` timer.
--
-- SECTION 2 (`claim.assessed` reserved in the database, backlog a278f16d):
--   * drops the trigger `events_assessment_guard` and its function
--     `epigraph_events_assessment_guard()`. An application session can then
--     again insert a `claim.assessed` row naming any slot row; the API and
--     MCP layers still refuse the type on their caller-typed surfaces.
--   No binary depends on section 2.
--
-- WHAT IT LEAVES: 250's `_sqlx_migrations` row. Re-introducing any of this is
-- a NEW migration, never a re-run of 250.
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT UPDATE, DELETE ON public.events TO epigraph_maintenance';
    END IF;
END $$;
DROP TRIGGER IF EXISTS events_assessment_guard ON public.events;
DROP FUNCTION IF EXISTS public.epigraph_events_assessment_guard();
DROP FUNCTION IF EXISTS public.epigraph_prune_telemetry_events(integer);
DROP FUNCTION IF EXISTS public.epigraph_prunable_event_types();

COMMIT;
