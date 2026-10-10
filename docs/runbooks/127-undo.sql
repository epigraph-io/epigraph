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
--      `archived_by`), attributed to the ELEVATING person: the log is
--      history, and an undo must not erase who read whose rows. That event
--      reaches the elevator, the audit readers and the maintenance DSN, not
--      the subjects (no `security_events` policy reads `owner_group_ids`), so
--   1b. it also writes one `platform.elevated_access_subject` copy per row,
--      per group the row names, per LIVE ADMIN member of that group at undo
--      time, attributed to that admin (`agent_id`, the arm through which a
--      principal reads its own `security_events` rows): the subjects' record
--      survives the table too. A group with no live admin then has no reader
--      among its members, as it had none under the table's policy.
--   2. Drops the table (its guards and policies with it) and every 127
--      function.
--
-- WHAT IT LEAVES: the archived `platform.elevated_access` and
-- `platform.elevated_access_subject` events, and 127's
-- `_sqlx_migrations` row. Re-introducing the log is a NEW migration, never a
-- re-run of 127. Idempotent: a second run archives nothing and drops nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_rows    bigint := 0;
    v_subject bigint := 0;
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
        EXECUTE $q$
            INSERT INTO public.security_events (event_type, agent_id, success, details)
            SELECT 'platform.elevated_access_subject', m.agent_id, true,
                   to_jsonb(a) || jsonb_build_object('archived_by', '127-undo',
                                                     'subject_group_id', g.group_id)
              FROM public.elevated_access a
             CROSS JOIN LATERAL unnest(a.owner_group_ids) AS g(group_id)
              JOIN public.group_memberships m
                ON m.group_id = g.group_id AND m.role = 'admin' AND m.revoked_at IS NULL
             ORDER BY a.created_at, a.id, g.group_id, m.agent_id
        $q$;
        GET DIAGNOSTICS v_subject = ROW_COUNT;
    END IF;
    RAISE NOTICE '127-undo: archived % elevated-access row(s) into security_events, and % '
                 'copies for the subjects'' admins', v_rows, v_subject;
END $$;

-- The audit reader returns the table's row type, so it goes first.
DROP FUNCTION IF EXISTS public.epigraph_elevated_access_audit(timestamptz, integer);

DROP TABLE IF EXISTS public.elevated_access;

DROP FUNCTION IF EXISTS public.epigraph_record_elevated_access(text, jsonb, integer, uuid[]);
DROP FUNCTION IF EXISTS public.epigraph_admin_group_ids();
DROP FUNCTION IF EXISTS public.epigraph_elevated_access_guard_change();
DROP FUNCTION IF EXISTS public.epigraph_elevated_access_guard_insert();

COMMIT;
