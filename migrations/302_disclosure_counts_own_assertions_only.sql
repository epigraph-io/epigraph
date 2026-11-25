-- 302: count only the assertions an agent ITSELF made (security review of 295,
-- "Addendum 5"; spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- sections 4, 6.1, 11 and 15.R18/R19; operator rulings C5 and C6).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 295's C6 arm counted a PUBLIC row naming a bound agent B of H whoever wrote
-- it. Two of its four kinds do not record the writer:
--
--   mass_functions  `source_agent_id` is "the edge's signer, the evidence
--                   writer, or the assessment slot's owner" (267). The edge
--                   writers (REST edges, MCP link_epistemic, the engine's
--                   `auto_wire_ds_for_edge`) attribute an edge factor to the
--                   SOURCE claim's author, store it on the TARGET claim (whose
--                   visibility it inherits, 070/168) and re-date it on every
--                   re-wire (`store_keyed`: `created_at = NOW()`). So a
--                   stranger's edge from B's pre-binding public claim to the
--                   stranger's own public claim wrote a public, freshly dated
--                   row naming B: H was named to everyone, by a stranger, for
--                   an assertion C5 says never names H. Unscoped rows are
--                   also copied under the original agent's id by another
--                   writer (`copy_to_frame`) and written by operator CLIs.
--   evidence        `signer_id` records who SIGNED the row: the server's own
--                   agent on every MCP write, the packet's agent on a signed
--                   `POST /api/v1/submit/packet`. No column records the
--                   asserting agent, and no database guard pins the signer to
--                   the writing session.
--
-- The two other kinds already record their writer: 170's CR08 pins
-- `challenger_id` to the filing session's principal, and an ingest record
-- counts only while its reserved marker (198/208) names its own ingester.
--
-- ===================================================================
-- 2. WHAT CHANGES
-- ===================================================================
--
-- a. PRECONDITION (OWN01, 55000): the core's body is still 300's (md5).
-- b. `epigraph_agent_disclosure_for` re-stated (CREATE OR REPLACE: owner and
--    ACL kept; COST 1000, SECURITY DEFINER and 172's path restated):
--    * the evidence probe is REMOVED (Addendum 5: "drop evidence from the arm
--      if no such column exists");
--    * the BBA probe counts only `slot_kind = 'assessment'`: the
--      `/claims/:id/assess` slot, keyed by the route to the caller or the
--      caller's live human (`epigraph_human_of`), the one BBA shape no writer
--      files under another identity. When the caller is bound, the row names
--      H itself, which H's own '-infinity' entry counts.
--    Every other arm, its answer and the order are 300's.
-- c. 303 indexes the new BBA probe; 304 and 305 drop 293's and 291's indexes,
--    which no probe reads any more.
--
-- A NARROWING the operator should see (spec 16.R C6): a public BBA a bound
-- agent files through `POST /api/v1/beliefs` (whose writer the route pins) or
-- evidence it signs on a packet no longer names H by itself; each still
-- names H through the claim it accompanies when that claim is B(H)'s. A
-- write-once writer column would let them count again; not built here.
--
-- Pinned by `human_identity_visibility.rs::
-- only_an_agents_own_assertion_names_its_human` and
-- `migration_302_refuses_over_another_core_body`.
--
-- UNDO: `docs/runbooks/302-undo.sql` (300's core; re-apply 291 and 293 first).
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_core text;
BEGIN
    SELECT p.prosrc INTO v_core
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
               'public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)');
    IF v_core IS NULL OR pg_catalog.md5(v_core) <> '2a1d9c98fcb9d39990d30b9666e9216b' THEN
        RAISE EXCEPTION 'OWN01: epigraph_agent_disclosure_for is absent or its body is not '
                        '300''s; 302 re-states 300''s body and would overwrite another one '
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
    v_bound_text text[];
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
    -- 300: the same ids as text, in the same order, cast HERE (a uuid-to-text
    -- cast on a probe's Var is not leakproof, so it could be no index
    -- condition under row security).
    v_bound_text := ARRAY(SELECT u.agent_id::text
                            FROM pg_catalog.unnest(v_bound) WITH ORDINALITY AS u(agent_id, n)
                           ORDER BY u.n);

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

    -- 295 (C6), 302 (Addendum 5): a PUBLIC assertion of any other kind that
    -- B(H) ITSELF made names H, windowed from the binding start as the claim
    -- arm is (288). One forced probe per bound agent per kind, each on its
    -- own partial index (292, 299, 303):
    --   challenges      challenger_id (170's CR08 pins it to the filing
    --                   session's principal)
    --   mass_functions  source_agent_id of an ASSESSMENT slot only (302): the
    --                   assess route keys it to the caller or the caller's
    --                   live human; an edge-factor, evidence-slot or unscoped
    --                   row can be written by another writer under the
    --                   agent's id. A retracted assessment still counts, as a
    --                   superseded claim does.
    --   edges           a `paper -ingested_claim-> claim` record whose
    --                   properties.ingested_by is the agent and whose ingest
    --                   marker names the same agent (the records' read
    --                   contract, claim_ingest.rs)
    -- Evidence is not counted (302): no column records its asserting agent
    -- (signer_id is the server's agent on every MCP write).
    IF EXISTS (
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
                                    AND m.slot_kind = 'assessment'
                                    AND m.visibility = 'public'
                                    AND m.created_at >= b.since
                                  LIMIT 1) x)
        OR EXISTS (
            -- 300: 298's LEAKPROOF accessor against the text ids, so the
            -- probe is an index condition (299) under edges' row security
            SELECT 1
              FROM ROWS FROM (pg_catalog.unnest(v_bound_text), pg_catalog.unnest(v_since))
                   AS b(agent_text, since)
             CROSS JOIN LATERAL (SELECT 1 FROM public.edges r
                                  WHERE public.epigraph_ingest_record_ingester(r.properties)
                                        = b.agent_text
                                    AND r.relationship = 'ingested_claim'
                                    AND r.visibility = 'public'
                                    AND r.created_at >= b.since
                                    AND (r.properties -> 'ingest_written' ->> 'by')
                                        = public.epigraph_ingest_record_ingester(r.properties)
                                  LIMIT 1) x)
    THEN
        RETURN QUERY SELECT true, v_details;
        RETURN;
    END IF;

    -- 297 (C2): a countersigned authorship (the person's own act, or its
    -- agent's) of a paper the viewer can read names H. The act is 208's audit
    -- row (the caller in agent_id, the paper in details), windowed from the
    -- caller's binding start; the paper is readable as 246's papers_read
    -- decides it (public, or owned by one of the viewer's groups).
    IF EXISTS (
        SELECT 1
          FROM ROWS FROM (pg_catalog.unnest(v_bound), pg_catalog.unnest(v_since))
               AS b(agent_id, since)
         CROSS JOIN LATERAL (SELECT 1
                               FROM (SELECT (s.details ->> 'paper_id')::uuid AS paper_id
                                       FROM public.security_events s
                                      WHERE s.agent_id = b.agent_id
                                        AND s.event_type = 'authorship.countersigned'
                                        AND s.created_at >= b.since
                                     OFFSET 0) s
                               -- 300: the id is computed in the fenced
                               -- subquery, so this join is uuid = Var
                               -- (leakproof) and looks the paper up by key
                               -- under papers' row security
                               JOIN public.papers p ON p.id = s.paper_id
                              WHERE (p.visibility = 'public'
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
