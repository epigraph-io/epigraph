-- ===================================================================
-- 149-undo.sql: take migration 149 (the author-binding allowlist) back out,
-- in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Every allowlisted client's agent becomes UNBOUND again: once
-- the database is armed, its writes are refused OPL01. Roll back first any
-- binary built against 149 (the operator CLI calls its definers; the MCP
-- signer gate compares its `client_allowlist` label).
--
-- WHAT IT DOES
--   1. Records ONE `platform.author_binding_allowlist_dropped` event naming
--      how many live allowances (and rows) it ends: an undo must not
--      silently unbind.
--   2. Restores migration 122's bodies of `epigraph_human_of` and
--      `epigraph_author_binding` (byte for byte) FIRST, so no reader is ever
--      left calling a dropped helper, and re-asserts their owner and grants.
--   3. Drops the link guard, the two definers, the table (its four triggers
--      with it; DROP TABLE fires no DELETE trigger), the trigger functions
--      and the read helper.
--
-- ORDER: newest first. Run this before undoing the system-agent registry
-- (148); 149 reads that table softly, so the reverse order is not an outage.
--
-- WHAT IT LEAVES: every `platform.author_binding_client_*` event (history)
-- and 149's `_sqlx_migrations` row. Re-introducing the allowlist is a NEW
-- migration, never a re-run of 149. Idempotent: a second run records and
-- drops nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$ BEGIN
    IF to_regclass('public.author_binding_clients') IS NOT NULL THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        SELECT 'platform.author_binding_allowlist_dropped', NULL, true,
               jsonb_build_object('live_allowances', count(*) FILTER (WHERE revoked_at IS NULL),
                                  'rows', count(*),
                                  'reason', '149-undo',
                                  'recorded_by', session_user)
          FROM public.author_binding_clients;
    END IF;
END $$;

-- 1. Migration 122's bodies, byte for byte, FIRST.
CREATE OR REPLACE FUNCTION public.epigraph_human_of(p_agent uuid, p_live_only boolean)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT CASE
             WHEN p_agent IS NULL THEN NULL
             WHEN public.epigraph_is_human_operator(p_agent) THEN p_agent
             ELSE (SELECT l.operator_id FROM public.operator_links l
                    WHERE l.agent_id = p_agent AND (NOT p_live_only OR NOT l.retired))
           END
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_human_of(uuid, boolean) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_author_binding(p_agent uuid)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT CASE
             WHEN p_agent IS NULL THEN NULL
             WHEN public.epigraph_is_human_operator(p_agent) THEN 'human_operator'
             WHEN EXISTS (SELECT 1 FROM public.operator_links l
                           WHERE l.agent_id = p_agent AND NOT l.retired
                             AND public.epigraph_is_human_operator(l.operator_id))
                  THEN 'live_link'
           END
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_author_binding(uuid) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_author_binding(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_human_of(uuid, boolean) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_author_binding(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_human_of(uuid, boolean) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_author_binding(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_human_of(uuid, boolean) '
                'TO epigraph_app';
    END IF;
END $$;

-- 2. The link guard. Its trigger is on `operator_links`, which stays.
DROP TRIGGER IF EXISTS operator_links_refuse_allowlisted_agent ON public.operator_links;
DROP FUNCTION IF EXISTS public.epigraph_operator_links_refuse_allowlisted_agent();

-- 3. The definers; the table (its triggers with it); the trigger functions,
--    which the table's triggers depended on; the read helper last.
DROP FUNCTION IF EXISTS public.epigraph_allow_author_binding_client(uuid, uuid, text);
DROP FUNCTION IF EXISTS public.epigraph_revoke_author_binding_client(uuid, text);
DROP TABLE IF EXISTS public.author_binding_clients;
DROP FUNCTION IF EXISTS public.epigraph_author_binding_clients_audit();
DROP FUNCTION IF EXISTS public.epigraph_author_binding_clients_refuse_delete();
DROP FUNCTION IF EXISTS public.epigraph_author_binding_clients_guard_update();
DROP FUNCTION IF EXISTS public.epigraph_author_binding_clients_guard_insert();
DROP FUNCTION IF EXISTS public.epigraph_allowlisted_operator(uuid);

COMMIT;
