-- Migration 024: backfill cascade_delete_edges triggers
--
-- The cascade_delete_edges trigger function exists since migration 001 and is
-- wired to claims, papers, agents, evidence, analyses, reasoning_traces (and
-- experiments + experiment_results since 023). Three entity tables that
-- participate in edges (tasks, events, workflows) lack the trigger, leaving
-- orphan edges when rows are deleted. This migration closes that gap.
--
-- All trigger creations are guarded by IF NOT EXISTS-equivalent pg_trigger
-- checks so the migration is idempotent on any DB that may have had partial
-- backfills applied directly.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'tasks_cascade_edges'
          AND tgrelid = 'tasks'::regclass
    ) THEN
        CREATE TRIGGER tasks_cascade_edges
            BEFORE DELETE ON tasks
            FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('task');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'events_cascade_edges'
          AND tgrelid = 'events'::regclass
    ) THEN
        CREATE TRIGGER events_cascade_edges
            BEFORE DELETE ON events
            FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('event');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'workflows_cascade_edges'
          AND tgrelid = 'workflows'::regclass
    ) THEN
        CREATE TRIGGER workflows_cascade_edges
            BEFORE DELETE ON workflows
            FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('workflow');
    END IF;
END;
$$;
