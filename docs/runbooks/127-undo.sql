-- ===================================================================
-- 127-undo.sql: take migration 127 (the elevated-access log) back out, in ONE
-- transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Roll back every binary that records elevated accesses BEFORE
-- this runs (docs/deploy.md): the API and MCP HTTP builds that declare the
-- recorder call `epigraph_record_elevated_access` for every elevated request,
-- and without the function each such request is refused (fail-closed), which
-- is safe but noisy. Run it BEFORE 126-undo and 125-undo (127's rows name
-- 125's sessions).
--
-- WHAT IT DOES
--   1. Copies EVERY log row into `security_events` as one
--      `platform.elevated_access` event (the whole row as `details`, plus
--      `archived_by`), so the subjects' record survives the table: the log is
--      history, and an undo must not erase who read whose rows.
--   2. Drops the table (its guards and policies with it) and every 127
--      function.
--
-- WHAT IT LEAVES: the archived `platform.elevated_access` events, and 127's
-- `_sqlx_migrations` row. Re-introducing the log is a NEW migration, never a
-- re-run of 127. Idempotent: a second run archives nothing and drops nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_rows bigint := 0;
BEGIN
    IF to_regclass('public.elevated_access') IS NOT NULL THEN
        EXECUTE $q$
            INSERT INTO public.security_events (event_type, agent_id, success, details)
            SELECT 'platform.elevated_access', a.person_agent_id, true,
                   to_jsonb(a) || jsonb_build_object('archived_by', '127-undo')
              FROM public.elevated_access a
             ORDER BY a.created_at, a.id
        $q$;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
    END IF;
    RAISE NOTICE '127-undo: archived % elevated-access row(s) into security_events', v_rows;
END $$;

-- The audit reader returns the table's row type, so it goes first.
DROP FUNCTION IF EXISTS public.epigraph_elevated_access_audit(timestamptz, integer);

DROP TABLE IF EXISTS public.elevated_access;

DROP FUNCTION IF EXISTS public.epigraph_record_elevated_access(text, jsonb, integer, uuid[]);
DROP FUNCTION IF EXISTS public.epigraph_admin_group_ids();
DROP FUNCTION IF EXISTS public.epigraph_elevated_access_guard_change();
DROP FUNCTION IF EXISTS public.epigraph_elevated_access_guard_insert();

COMMIT;
