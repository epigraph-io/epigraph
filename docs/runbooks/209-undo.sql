-- ===================================================================
-- 209-undo.sql: take migration 209 (an agent's default can be private; a live
-- human operator sets the default of an agent it operates) back out, in ONE
-- transaction, on the migration (superuser) DSN.
--
-- READ FIRST: ROLL THE BINARIES BACK BEFORE THIS RUNS. A 209 binary calls
-- `epigraph_default_private` on every claim write that names no visibility
-- (`ClaimRepository::resolve_visibility_choice`) and
-- `epigraph_set_agent_default_group` behind `set_default_group`, `PUT
-- /api/v1/agents/{me,:id}/default-group` and `epigraph-operator
-- set-default-group`. A unit left serving after this undo answers every
-- default write with an error (42883). A 206..208 binary calls neither.
--
-- WHAT IT DOES:
--   * re-states 206's `epigraph_set_default_group(uuid)` body byte for byte
--     (209 made it delegate); `CREATE OR REPLACE` keeps its owner and grants;
--   * drops the two functions 209 created;
--   * drops `agents.default_private` and its CHECK.
--
-- WHAT IT LOSES AND LEAVES:
--   * every PRIVATE default is LOST with the column. Those agents then inherit
--     their live human's default team again (206's D-V1 chain), which is the
--     exposure 209 closes: before running this, set each such agent's default
--     to a team on purpose or accept that its next no-visibility write lands
--     in its human's team. List them first:
--       SELECT id FROM public.agents WHERE default_private;
--   * `agents.default_group_id` values (062's column) as they stand;
--   * every claim as it stands (a private claim stays private);
--   * the `security_events` rows 209 wrote (`agent.default_group_set` with
--     `migration` 209);
--   * 209's `_sqlx_migrations` row.
-- Re-introducing any of it is a NEW migration, never a re-run of 209.
-- Idempotent: a second run changes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_set_default_group(p_group uuid)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_prev uuid;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'VIS01: setting a default team needs an authenticated principal; '
                        'nothing was changed' USING ERRCODE = '42501';
    END IF;
    IF p_group IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM public.epigraph_writable_teams(v_principal) t WHERE t.group_id = p_group)
    THEN
        RAISE EXCEPTION 'VIS02: group % is not a team this agent may write (writer or admin, '
                        'its own or its live human''s); nothing was changed', p_group
            USING ERRCODE = '42501';
    END IF;
    SELECT a.default_group_id INTO v_prev FROM public.agents a WHERE a.id = v_principal;
    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);  -- see header
    UPDATE public.agents SET default_group_id = p_group WHERE id = v_principal;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('agent.default_group_set', v_principal, true,
            jsonb_build_object('previous', v_prev, 'default_group_id', p_group,
                               'migration', 206, 'session_user', session_user::text));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);
    RETURN p_group;
END $$;

DROP FUNCTION IF EXISTS public.epigraph_set_agent_default_group(uuid, uuid, boolean);
DROP FUNCTION IF EXISTS public.epigraph_default_private(uuid);

ALTER TABLE public.agents DROP CONSTRAINT IF EXISTS agents_default_private_or_group;
ALTER TABLE public.agents DROP COLUMN IF EXISTS default_private;

COMMIT;
