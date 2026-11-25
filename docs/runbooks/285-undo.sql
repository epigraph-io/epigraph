-- Undo migration 285 (profile_public_consent): restore 281's disclosure core and 275's
-- profile setter (the opt-in arm reads 'public' alone again; the setter writes no stamp),
-- then drop the CHECK and the column, in that order (the 285 bodies read the column). Run on
-- a maintenance connection. No Rust code reads the column. CREATE OR REPLACE keeps the owner
-- and ACL. A consent recorded since 285 is lost; profile values stay. Idempotent.
CREATE OR REPLACE FUNCTION public.epigraph_agent_disclosure_for(
    p_target uuid, p_principal uuid, p_groups uuid[], p_privileged boolean)
RETURNS TABLE (named boolean, details boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER COST 1000
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_groups     uuid[]  := COALESCE(p_groups, ARRAY[]::uuid[]);
    v_privileged boolean := COALESCE(p_privileged, false);
    v_self       boolean := COALESCE(p_target = p_principal, false);
    v_profile    text;
    v_details    boolean;
    v_bound      uuid[];
BEGIN
    SELECT a.profile_visibility INTO v_profile FROM public.agents a WHERE a.id = p_target;

    -- Today's details rule, for every agent.
    v_details := COALESCE(
        v_privileged OR v_self OR v_profile = 'public'
        OR (pg_catalog.cardinality(v_groups) > 0
            AND EXISTS (SELECT 1 FROM public.group_memberships gm
                         WHERE gm.agent_id = p_target
                           AND gm.revoked_at IS NULL
                           AND gm.group_id = ANY (v_groups))),
        false);

    IF NOT public.epigraph_is_human_principal(p_target) THEN
        RETURN QUERY SELECT true, v_details;
        RETURN;
    END IF;

    -- privileged, self, opt-in
    IF v_privileged OR v_self OR COALESCE(v_profile = 'public', false) THEN
        RETURN QUERY SELECT true, v_details;
        RETURN;
    END IF;

    v_bound := ARRAY[p_target]
            || ARRAY(SELECT l.agent_id FROM public.operator_links l
                      WHERE l.operator_id = p_target)
            || ARRAY(SELECT r.agent_id FROM public.author_binding_clients r
                      WHERE r.operator_id = p_target);

    -- public claim: one forced probe per bound agent (no viewer state)
    IF EXISTS (
        SELECT 1
          FROM pg_catalog.unnest(v_bound) b(agent_id)
         CROSS JOIN LATERAL (SELECT 1 FROM public.claims c
                              WHERE c.agent_id = b.agent_id
                                AND c.visibility = 'public'
                              LIMIT 1) x)
    THEN
        RETURN QUERY SELECT true, v_details;
        RETURN;
    END IF;

    IF pg_catalog.cardinality(v_groups) > 0 THEN
        -- team, direct: one probe of the target's rows in the viewer's groups
        IF EXISTS (
            SELECT 1
              FROM public.group_memberships m
              JOIN public.groups g ON g.id = m.group_id
             WHERE m.agent_id = p_target
               AND m.revoked_at IS NULL
               AND m.group_id = ANY (v_groups)
               AND g.kind IN ('team', 'community')
               AND g.status = 'active'
               AND (g.did_key NOT LIKE 'did:epigraph:group:%'
                    OR public.epigraph_is_human_operator(
                           public.epigraph_human_of(p_target, true))))
        THEN
            RETURN QUERY SELECT true, v_details;
            RETURN;
        END IF;

        -- readable claim: one forced probe per (bound agent, viewer group),
        -- two equalities, so 278's (agent_id, owner_group_id) index is the
        -- only fitting one (section 2a)
        IF EXISTS (
            SELECT 1
              FROM pg_catalog.unnest(v_bound) b(agent_id)
             CROSS JOIN pg_catalog.unnest(v_groups) vg(group_id)
             CROSS JOIN LATERAL (SELECT 1 FROM public.claims c
                                  WHERE c.agent_id = b.agent_id
                                    AND c.owner_group_id = vg.group_id
                                    AND c.visibility <> 'public'
                                  LIMIT 1) x)
        THEN
            RETURN QUERY SELECT true, v_details;
            RETURN;
        END IF;

        -- team, role-derived: only a bound group can be one. 281: LAST, and
        -- 249's call only when its candidate set is wider than the target.
        IF EXISTS (SELECT 1 FROM public.group_role_bindings b
                    WHERE b.group_id = ANY (v_groups)) THEN
            IF NOT EXISTS (SELECT 1 FROM public.operator_links l
                            WHERE l.agent_id = p_target)
               AND public.epigraph_allowlisted_operator(p_target) IS NULL THEN
                -- 249's candidates are exactly (target, not via an agent):
                -- its rows are the live bindings whose role the target
                -- holds live, evaluated here per viewer group.
                IF EXISTS (
                    SELECT 1
                      FROM public.group_role_bindings b
                      JOIN public.groups g ON g.id = b.group_id
                     WHERE b.group_id = ANY (v_groups)
                       AND b.created_at <= pg_catalog.now()
                       AND (b.revoked_at IS NULL OR pg_catalog.now() < b.revoked_at)
                       AND g.kind IN ('team', 'community')
                       AND g.status = 'active'
                       AND public.epigraph_live_role_assignment(
                               p_target, b.role, pg_catalog.now()) IS NOT NULL)
                THEN
                    RETURN QUERY SELECT true, v_details;
                    RETURN;
                END IF;
            ELSIF EXISTS (
                SELECT 1
                  FROM public.epigraph_role_derived_memberships(p_target, pg_catalog.now()) d
                  JOIN public.groups g ON g.id = d.group_id
                 WHERE d.group_id = ANY (v_groups)
                   AND g.kind IN ('team', 'community')
                   AND g.status = 'active')
            THEN
                RETURN QUERY SELECT true, v_details;
                RETURN;
            END IF;
        END IF;
    END IF;

    RETURN QUERY SELECT false, false;
END $$;

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
                                          'migration', 275,
                                          'session_user', session_user::text));

    SELECT d.named INTO v_named
      FROM public.epigraph_agent_disclosure_for(v_principal, NULL, ARRAY[]::uuid[], false) d;

    RETURN QUERY SELECT v_prev, p_visibility, COALESCE(v_named, false);
END $$;

ALTER TABLE public.agents DROP CONSTRAINT IF EXISTS agents_profile_public_consent_check;
ALTER TABLE public.agents DROP COLUMN IF EXISTS profile_public_consented_at;
