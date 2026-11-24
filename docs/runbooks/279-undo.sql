-- Undo migration 279 (disclosure_role_derived_arm_last): restore 277's body of the
-- disclosure core (same answers; only the order of the last two arms differs). Run on a
-- maintenance connection. CREATE OR REPLACE keeps the owner and ACL. Idempotent.
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

        -- team, role-derived: only a bound group can be one
        IF EXISTS (SELECT 1 FROM public.group_role_bindings b
                    WHERE b.group_id = ANY (v_groups))
           AND EXISTS (
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

        -- readable claim: one forced probe per (bound agent, viewer group),
        -- two equalities, so 276's (agent_id, owner_group_id) index is the
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
    END IF;

    RETURN QUERY SELECT false, false;
END $$;
