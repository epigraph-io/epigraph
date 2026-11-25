-- 276: human principals are provisioned with `profile_visibility = 'group'`,
-- and every existing human principal is reset to 'group' (spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md
-- section 10, M3).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 274's opt-in arm names a human to everyone when `profile_visibility =
-- 'public'`, and the operator's rule makes that a choice the human makes
-- (275's setter). But 062 defaulted the column to 'public' and nothing in
-- production ever wrote it, so today's 'public' is a default, not consent.
-- Every human principal is therefore reset to 'group', and the mint of every
-- OAuth principal (`epigraph_provision_oauth_agent`, 077) inserts a human as
-- 'group' from now on. Non-human principals keep 'public', as before.
--
-- ===================================================================
-- 2. WHAT CHANGES
-- ===================================================================
--
-- a. PRECONDITION (PVR01, 55000): the provisioning definer's body is still
--    077's (md5 of `prosrc`; 271 changed its proconfig only), so a later
--    re-body is never overwritten blind.
-- b. `epigraph_provision_oauth_agent(bytea, text, text)` re-stated: the same
--    upsert, `WHERE a.key_kind = 'derived'` guard and ON CONFLICT re-find
--    included, plus `profile_visibility = CASE WHEN p_agent_type = 'human'
--    THEN 'group' ELSE 'public' END`. It moves to 172's form
--    (`pg_catalog, pg_temp`, `pg_catalog.now()`, every name qualified), so it
--    leaves `definer_search_path_ratchet`'s PUBLIC_PATH_REGISTER. CREATE OR
--    REPLACE keeps its owner and ACL.
-- c. THE RESET: every human principal (274's `epigraph_is_human_principal`,
--    the same evidence the rule reads) with `profile_visibility <> 'group'`
--    becomes 'group'. Its pre-state cannot be recovered and is not consent,
--    so the undo does not reverse it.
-- d. POST-CONDITION (PVR02, 55000). `agents` is FORCE RLS (079) and its
--    UPDATE policy admits only bypass, definer bypass or the row's own
--    principal, so a non-superuser, non-maintenance runner's UPDATE moves 0
--    rows WITHOUT an error, which would leave every existing human reading as
--    consented: the worst failure direction of this change. The file
--    re-counts and refuses if any human principal is still not 'group'.
-- e. One summary `security_events` row, `agent.profile_visibility_reset`,
--    details {migration, before, rows, after}. No per-row audit.
--
-- `lock_timeout` also bounds the reset's row locks: a long `ensure_for_client`
-- transaction holding a human row fails this boot migration, and the API
-- restarts and retries.
--
-- UNDO: `docs/runbooks/276-undo.sql` (restores 077's provisioning body; the
-- reset stays).
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_src text;
BEGIN
    SELECT p.prosrc INTO v_src
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
               'public.epigraph_provision_oauth_agent(bytea, text, text)');
    IF v_src IS NULL OR pg_catalog.md5(v_src) <> 'b0e19c23199a3ccd3d943e3f445922aa' THEN
        RAISE EXCEPTION 'PVR01: epigraph_provision_oauth_agent is absent or its body is not '
                        '077''s; 276 re-states 077''s body and would overwrite another one '
                        'blind; nothing was changed' USING ERRCODE = '55000';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_provision_oauth_agent(
    p_public_key bytea, p_display_name text, p_agent_type text)
RETURNS uuid LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO public.agents AS a
           (public_key, display_name, agent_type, key_kind, labels, profile_visibility)
    VALUES (p_public_key, p_display_name, p_agent_type, 'derived',
            ARRAY['oauth-principal'],
            CASE WHEN p_agent_type = 'human' THEN 'group' ELSE 'public' END)
    ON CONFLICT (public_key) DO UPDATE SET updated_at = pg_catalog.now()
        WHERE a.key_kind = 'derived'
    RETURNING a.id
$$;

DO $$
DECLARE
    v_before bigint;
    v_rows   bigint;
    v_after  bigint;
BEGIN
    SELECT pg_catalog.count(*) INTO v_before
      FROM public.agents a
     WHERE a.profile_visibility <> 'group'
       AND public.epigraph_is_human_principal(a.id);

    UPDATE public.agents a
       SET profile_visibility = 'group'
     WHERE a.profile_visibility <> 'group'
       AND public.epigraph_is_human_principal(a.id);
    GET DIAGNOSTICS v_rows = ROW_COUNT;

    SELECT pg_catalog.count(*) INTO v_after
      FROM public.agents a
     WHERE a.profile_visibility <> 'group'
       AND public.epigraph_is_human_principal(a.id);

    IF v_after <> 0 THEN
        RAISE EXCEPTION 'PVR02: % human principal(s) still have a public profile after the reset '
                        '(% before, % moved): this migration runner cannot update agents under '
                        'its row security; run it as a superuser or a maintenance member; '
                        'nothing was changed', v_after, v_before, v_rows
            USING ERRCODE = '55000';
    END IF;

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('agent.profile_visibility_reset', NULL, true,
            pg_catalog.jsonb_build_object('migration', 276, 'before', v_before,
                                          'rows', v_rows, 'after', v_after));
END $$;
