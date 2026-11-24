-- Undo migration 297 (disclosure_countersigned_authorship): restore 295's body of the
-- disclosure core (no authorship arm). Run on a maintenance connection. CREATE OR
-- REPLACE keeps the owner and ACL. Idempotent. 296's index may stay (unused) or be
-- dropped with DROP INDEX CONCURRENTLY.
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
    v_consented  timestamptz;
    v_human      boolean;
    v_public     boolean;
    v_details    boolean;
    v_bound      uuid[];
    v_since      timestamptz[];
BEGIN
    SELECT a.profile_visibility, a.profile_public_consented_at INTO v_profile, v_consented
      FROM public.agents a WHERE a.id = p_target;

    v_human := public.epigraph_is_human_principal(p_target);

    -- 283 (C11): a human's 'public' counts only with the setter's consent.
    v_public := COALESCE(v_profile = 'public' AND (NOT v_human OR v_consented IS NOT NULL),
                         false);

    -- Today's details rule, for every agent.
    v_details := COALESCE(
        v_privileged OR v_self OR v_public
        OR (pg_catalog.cardinality(v_groups) > 0
            AND EXISTS (SELECT 1 FROM public.group_memberships gm
                         WHERE gm.agent_id = p_target
                           AND gm.revoked_at IS NULL
                           AND gm.group_id = ANY (v_groups))),
        false);

    IF NOT v_human THEN
        RETURN QUERY SELECT true, v_details;
        RETURN;
    END IF;

    -- privileged, self, opt-in
    IF v_privileged OR v_self OR v_public THEN
        RETURN QUERY SELECT true, v_details;
        RETURN;
    END IF;

    -- 288 (C5): B(H) with each agent's binding START. H's own assertions
    -- have no binding to start ('-infinity'); a bound agent's count from the
    -- EARLIEST start of any of its bindings to H (a link's created_at, an
    -- allowance's added_at), and keep counting after the binding is retired
    -- or revoked (no end bound). H first, then by binding start.
    SELECT pg_catalog.array_agg(s.agent_id ORDER BY s.since, s.agent_id),
           pg_catalog.array_agg(s.since ORDER BY s.since, s.agent_id)
      INTO v_bound, v_since
      FROM (SELECT b.agent_id, pg_catalog.min(b.since) AS since
              FROM (SELECT p_target AS agent_id, '-infinity'::timestamptz AS since
                    UNION ALL
                    SELECT l.agent_id, l.created_at FROM public.operator_links l
                     WHERE l.operator_id = p_target
                    UNION ALL
                    SELECT r.agent_id, r.added_at FROM public.author_binding_clients r
                     WHERE r.operator_id = p_target) b
             GROUP BY b.agent_id) s;

    -- public claim: one forced probe per bound agent (no viewer state), from
    -- the agent's binding start (286's (agent_id, created_at) index)
    IF EXISTS (
        SELECT 1
          FROM ROWS FROM (pg_catalog.unnest(v_bound), pg_catalog.unnest(v_since))
               AS b(agent_id, since)
         CROSS JOIN LATERAL (SELECT 1 FROM public.claims c
                              WHERE c.agent_id = b.agent_id
                                AND c.visibility = 'public'
                                AND c.created_at >= b.since
                              LIMIT 1) x)
    THEN
        RETURN QUERY SELECT true, v_details;
        RETURN;
    END IF;

    -- 295 (C6): a PUBLIC assertion of any other kind by B(H) names H, windowed
    -- from the binding start as the claim arm is (288). One forced probe per
    -- bound agent per kind, each on its own partial index (291-294):
    --   evidence        signer_id (the table has no author column)
    --   challenges      challenger_id
    --   mass_functions  source_agent_id (a BBA; a retracted one still counts,
    --                   as a superseded claim does)
    --   edges           a `paper -ingested_claim-> claim` record whose
    --                   properties.ingested_by is the agent and whose ingest
    --                   marker names the same agent (the records' read
    --                   contract, claim_ingest.rs)
    IF EXISTS (
        SELECT 1
          FROM ROWS FROM (pg_catalog.unnest(v_bound), pg_catalog.unnest(v_since))
               AS b(agent_id, since)
         CROSS JOIN LATERAL (SELECT 1 FROM public.evidence e
                              WHERE e.signer_id = b.agent_id
                                AND e.visibility = 'public'
                                AND e.created_at >= b.since
                              LIMIT 1) x)
        OR EXISTS (
            SELECT 1
              FROM ROWS FROM (pg_catalog.unnest(v_bound), pg_catalog.unnest(v_since))
                   AS b(agent_id, since)
             CROSS JOIN LATERAL (SELECT 1 FROM public.challenges ch
                                  WHERE ch.challenger_id = b.agent_id
                                    AND ch.visibility = 'public'
                                    AND ch.created_at >= b.since
                                  LIMIT 1) x)
        OR EXISTS (
            SELECT 1
              FROM ROWS FROM (pg_catalog.unnest(v_bound), pg_catalog.unnest(v_since))
                   AS b(agent_id, since)
             CROSS JOIN LATERAL (SELECT 1 FROM public.mass_functions m
                                  WHERE m.source_agent_id = b.agent_id
                                    AND m.visibility = 'public'
                                    AND m.created_at >= b.since
                                  LIMIT 1) x)
        OR EXISTS (
            SELECT 1
              FROM ROWS FROM (pg_catalog.unnest(v_bound), pg_catalog.unnest(v_since))
                   AS b(agent_id, since)
             CROSS JOIN LATERAL (SELECT 1 FROM public.edges r
                                  WHERE (r.properties ->> 'ingested_by') = b.agent_id::text
                                    AND r.relationship = 'ingested_claim'
                                    AND r.visibility = 'public'
                                    AND r.created_at >= b.since
                                    AND (r.properties -> 'ingest_written' ->> 'by')
                                        = (r.properties ->> 'ingested_by')
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
        -- two equalities and the binding start, so 287's (agent_id,
        -- owner_group_id, created_at) index is the only fitting one
        IF EXISTS (
            SELECT 1
              FROM ROWS FROM (pg_catalog.unnest(v_bound), pg_catalog.unnest(v_since))
                   AS b(agent_id, since)
             CROSS JOIN pg_catalog.unnest(v_groups) vg(group_id)
             CROSS JOIN LATERAL (SELECT 1 FROM public.claims c
                                  WHERE c.agent_id = b.agent_id
                                    AND c.owner_group_id = vg.group_id
                                    AND c.visibility <> 'public'
                                    AND c.created_at >= b.since
                                  LIMIT 1) x)
        THEN
            RETURN QUERY SELECT true, v_details;
            RETURN;
        END IF;

        -- team, role-derived: only a bound group can be one. 279: LAST, and
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
