-- 310: a human principal sets its own `profile_visibility` (spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md
-- section 8).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 309's opt-in arm names a human to everyone when `profile_visibility =
-- 'public'`. The operator's rule is that the human CHOSE that ("unless they
-- chose to make themselves publicly visible"), so the value must be written
-- by the human and by nothing else. Nothing wrote the column before this
-- file: 062 defaulted it to 'public', and 118's column-level UPDATE grant to
-- `epigraph_app` does not name it. 311 resets every existing human to 'group'
-- and provisions new humans as 'group'.
--
-- ===================================================================
-- 2. THE FUNCTION
-- ===================================================================
--
--   epigraph_set_profile_visibility(p_visibility text)
--     RETURNS TABLE (previous text, profile_visibility text,
--                    named_to_everyone boolean)
--
-- WHO. The session principal (`epigraph_principal_id()`), never an argument,
-- so the target is the caller. No operator arm and no admin arm: "set BY H".
--
-- REFUSALS, each changing nothing:
--   PVS01 (42501) no principal;
--   PVS02 (22023) a value other than 'public' / 'group' (the existing CHECK);
--   PVS05 (42501) the principal is not a human principal (309's
--         `epigraph_is_human_principal`): an operated LLM agent or a service
--         would otherwise "succeed" by setting its own, irrelevant row;
--   PVS04 (55000) the UPDATE did not move exactly the one row (a row-security
--         filter would otherwise let an unchanged row be audited as changed).
--
-- RETURNS the previous value, the new one, and `named_to_everyone`: whether
-- an anonymous outsider sees the principal named AFTER the write (309's core
-- with an empty audience). Setting 'group' while an agent ever bound to the
-- principal has a public claim answers true, so the caller is told the truth.
--
-- AUDIT. One `security_events` row per successful call,
-- `agent.profile_visibility_set`, attributed to the principal, with the
-- previous and new values.
--
-- SHAPE. SECURITY DEFINER on 172's path (`pg_catalog, pg_temp`, every name
-- qualified) throughout: 206's search_path write window is not opened,
-- because it existed for INVOKER triggers on `agents` that resolved
-- unqualified names through the definer's path, and 271 pinned every trigger
-- function's own path. Owner `epigraph_maintenance`; EXECUTE revoked from
-- PUBLIC and granted to `epigraph_app` (the MCP tool and the REST route call
-- it on a stamped transaction).
--
-- WHAT IT TRUSTS. The stamped `epigraph.principal_id`, which any login holding
-- the application DSN can set: such a login can set any human's profile. The
-- trust class of 209's self arm and of every principal-keyed write.
--
-- UNDO: `docs/runbooks/310-undo.sql`. No rows change.
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_set_profile_visibility(p_visibility text)
RETURNS TABLE (previous text, profile_visibility text, named_to_everyone boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_prev      text;
    v_moved     bigint := 0;
    v_named     boolean;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'PVS01: setting a profile needs an authenticated principal; nothing was '
                        'changed' USING ERRCODE = '42501';
    END IF;
    IF p_visibility IS NULL OR p_visibility NOT IN ('public', 'group') THEN
        RAISE EXCEPTION 'PVS02: a profile is ''public'' or ''group''; nothing was changed'
            USING ERRCODE = '22023';
    END IF;
    IF NOT public.epigraph_is_human_principal(v_principal) THEN
        RAISE EXCEPTION 'PVS05: only a person (a human principal) sets whether their own name is '
                        'shown; an agent acting for one, or a service, may not; nothing was '
                        'changed' USING ERRCODE = '42501';
    END IF;

    SELECT a.profile_visibility INTO v_prev
      FROM public.agents a WHERE a.id = v_principal FOR UPDATE;

    UPDATE public.agents a
       SET profile_visibility = p_visibility, updated_at = pg_catalog.now()
     WHERE a.id = v_principal;
    GET DIAGNOSTICS v_moved = ROW_COUNT;
    IF v_moved <> 1 THEN
        RAISE EXCEPTION 'PVS04: the profile was not changed (% rows); nothing was changed',
                        v_moved USING ERRCODE = '55000';
    END IF;

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('agent.profile_visibility_set', v_principal, true,
            pg_catalog.jsonb_build_object('previous', v_prev,
                                          'profile_visibility', p_visibility,
                                          'migration', 310,
                                          'session_user', session_user::text));

    SELECT d.named INTO v_named
      FROM public.epigraph_agent_disclosure_for(v_principal, NULL, ARRAY[]::uuid[], false) d;

    RETURN QUERY SELECT v_prev, p_visibility, COALESCE(v_named, false);
END $$;
REVOKE ALL ON FUNCTION public.epigraph_set_profile_visibility(text) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_set_profile_visibility(text) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 310 setter '
                     'stays owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_set_profile_visibility(text) '
                'TO epigraph_app';
    END IF;
END $$;
