-- 311: a countersigned authorship of a paper the viewer can read names the
-- human (operator ruling C2; spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- sections 4, 6.1, 11, 15.R3 and 16.R).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- A document ingest may name any agent as an author of a paper; naming one the
-- ingester does not speak for is PENDING until the named agent, or its live
-- operator, countersigns it (208). The core read no authorship, so a person
-- who confirmed "I wrote this paper" stayed unnamed to the paper's readers
-- (spec R3). The operator ruled (C2): a countersigned authorship, H's own act,
-- of a paper the viewer can read names H, like a claim.
--
-- ===================================================================
-- 2. WHAT CHANGES
-- ===================================================================
--
-- a. PRECONDITION (CSN01, 55000): the core's body is still 309's (md5).
-- b. `epigraph_agent_disclosure_for` re-stated (CREATE OR REPLACE: owner and
--    ACL kept; COST 1000, SECURITY DEFINER and 172's path restated). One new
--    arm after 309's, before the team arm: per agent in B(H), a 208 audit row
--    `authorship.countersigned` whose CALLER (`agent_id`) is that agent and
--    whose `created_at` is at or after its binding start, on a paper that is
--    `'public'` or owned by one of the viewer's groups. So H's own countersign
--    (for itself, or as its agent's live operator) names H from any time, and a
--    bound agent's countersign of its own authorship names H only when made
--    after the agent's binding to H began (C5's window). A pending naming
--    nobody countersigned writes no such row and names no one; a declined one
--    writes 'authorship.countersign_declined', which is not read.
-- c. The probe uses 310's partial index.
--
-- WHY THE AUDIT ROW AND NOT THE EDGE LABEL. The confirmed edge carries
-- `epigraph:countersigned_by:<caller>` but no time, so it cannot be windowed.
-- The audit row carries the caller and `created_at = now()`, and 208's
-- RESTRICTIVE policy reserves the event type to bypass and definer frames, so
-- an application session cannot forge or backdate one. No code path deletes
-- `security_events` rows (re-verified on this head), so the arm is sticky.
--
-- UNDO: `docs/runbooks/311-undo.sql` (309's core).
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_core text;
BEGIN
    SELECT p.prosrc INTO v_core
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
               'public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)');
    IF v_core IS NULL OR pg_catalog.md5(v_core) <> '6f264c4760c870d3dabe36556f65ecb9' THEN
        RAISE EXCEPTION 'CSN01: epigraph_agent_disclosure_for is absent or its body is not '
                        '309''s; 311 re-states 309''s body and would overwrite another one '
                        'blind; nothing was changed' USING ERRCODE = '55000';
    END IF;
END $$;

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

    -- 297 (C11): a human's 'public' counts only with the setter's consent.
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

    -- 302 (C5): B(H) with each agent's binding START. H's own assertions
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
    -- the agent's binding start (300's (agent_id, created_at) index)
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

    -- 309 (C6): a PUBLIC assertion of any other kind by B(H) names H, windowed
    -- from the binding start as the claim arm is (302). One forced probe per
    -- bound agent per kind, each on its own partial index (305-308):
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

    -- 311 (C2): a countersigned authorship (the person's own act, or its
    -- agent's) of a paper the viewer can read names H. The act is 208's audit
    -- row (the caller in agent_id, the paper in details), windowed from the
    -- caller's binding start; the paper is readable as 246's papers_read
    -- decides it (public, or owned by one of the viewer's groups).
    IF EXISTS (
        SELECT 1
          FROM ROWS FROM (pg_catalog.unnest(v_bound), pg_catalog.unnest(v_since))
               AS b(agent_id, since)
         CROSS JOIN LATERAL (SELECT 1
                               FROM public.security_events s
                               JOIN public.papers p
                                 ON p.id = (s.details ->> 'paper_id')::uuid
                              WHERE s.agent_id = b.agent_id
                                AND s.event_type = 'authorship.countersigned'
                                AND s.created_at >= b.since
                                AND (p.visibility = 'public'
                                     OR p.owner_group_id = ANY (v_groups))
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
        -- two equalities and the binding start, so 301's (agent_id,
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

        -- team, role-derived: only a bound group can be one. 293: LAST, and
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
