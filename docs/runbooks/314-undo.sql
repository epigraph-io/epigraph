-- Undo migration 314 (disclosure_team_arm_without_the_twin): restore 309's body of
-- `epigraph_agent_disclosure_for` (the team arm through `epigraph_live_memberships_unbound`,
-- the public-claim arm after it). Same answers; only the evaluation (and its cost, spec
-- section 11) changes back. CREATE OR REPLACE keeps the owner and the ACL. Run on a
-- maintenance connection. Idempotent. No rows change.
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

    -- team
    IF pg_catalog.cardinality(v_groups) > 0 AND EXISTS (
        SELECT 1
          FROM public.epigraph_live_memberships_unbound(p_target) m
          JOIN public.groups g ON g.id = m.group_id
         WHERE m.group_id = ANY (v_groups)
           AND g.kind IN ('team', 'community')
           AND g.status = 'active')
    THEN
        RETURN QUERY SELECT true, v_details;
        RETURN;
    END IF;

    v_bound := ARRAY[p_target]
            || ARRAY(SELECT l.agent_id FROM public.operator_links l
                      WHERE l.operator_id = p_target)
            || ARRAY(SELECT r.agent_id FROM public.author_binding_clients r
                      WHERE r.operator_id = p_target);

    -- public claim: one forced probe per bound agent
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

    -- readable claim: one forced probe per bound agent
    IF pg_catalog.cardinality(v_groups) > 0 AND EXISTS (
        SELECT 1
          FROM pg_catalog.unnest(v_bound) b(agent_id)
         CROSS JOIN LATERAL (SELECT 1 FROM public.claims c
                              WHERE c.agent_id = b.agent_id
                                AND c.visibility <> 'public'
                                AND c.owner_group_id = ANY (v_groups)
                              LIMIT 1) x)
    THEN
        RETURN QUERY SELECT true, v_details;
        RETURN;
    END IF;

    RETURN QUERY SELECT false, false;
END $$;
