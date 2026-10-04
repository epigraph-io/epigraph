-- ===================================================================
-- 128-undo.sql: take migration 128 (the admin-scope arming switch) back out,
-- in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST. A binary built with 128 treats a database without it as
-- UNARMED: after this runs, every mint keeps its admin-only scopes again and
-- registration, client approval and `grant-client-scope` hand them out as
-- before. If the switch was ARMED, that is a disarm, so the script records it
-- as one first (below). Rolling binaries back is not required (they read the
-- switch's absence as unarmed), but do it if the reason for the undo is the
-- binaries.
--
-- WHAT IT DOES
--   1. If the switch is armed, disarms it through the table's own guard and
--      audit trigger, with the reason `128-undo`, so the trail holds one
--      `platform.admin_scopes_disarmed` event for the undo: an undo must not
--      silently end enforcement.
--   2. Drops the table (its two triggers with it) and every 128 function.
--
-- WHAT IT LEAVES: every `platform.admin_scopes_*` and
-- `oauth.admin_scope_would_strip` event (history), and 128's
-- `_sqlx_migrations` row. Re-introducing the switch is a NEW migration, never
-- a re-run of 128. Idempotent: a second run records and drops nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_rows bigint := 0;
BEGIN
    IF to_regclass('public.admin_scope_enforcement') IS NOT NULL THEN
        EXECUTE $q$
            UPDATE public.admin_scope_enforcement
               SET armed = false, reason = '128-undo: the switch is being removed'
             WHERE armed
        $q$;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
    END IF;
    RAISE NOTICE '128-undo: disarmed before removal: %', v_rows > 0;
END $$;

DROP TABLE IF EXISTS public.admin_scope_enforcement;

DROP FUNCTION IF EXISTS public.epigraph_record_admin_scope_would_strip(uuid, text, text[]);
DROP FUNCTION IF EXISTS public.epigraph_set_admin_scope_enforcement(boolean, text);
DROP FUNCTION IF EXISTS public.epigraph_admin_scopes_armed();
DROP FUNCTION IF EXISTS public.epigraph_admin_scope_enforcement_audit();
DROP FUNCTION IF EXISTS public.epigraph_admin_scope_enforcement_guard();

COMMIT;
