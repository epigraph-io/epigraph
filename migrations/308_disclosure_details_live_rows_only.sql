-- 308: the disclosure core's details rule counts only a membership row that
-- still COUNTS (review 2 of the human-identity visibility branch,
-- correctness#3; spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- sections 6.1 and 16a).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- A `group_memberships` row can stop counting without being revoked: 164 (a
-- verb-made `did:epigraph:group:` group's row counts only while its agent's
-- human is a live human operator) and 235 (a personal-group row of an agent
-- allowlisted for the group's owner counts only while an allowance still
-- names the owner). 236's `epigraph_live_memberships_unbound` applies both,
-- so a lapsed member reads nothing of the group. The profile details rule
-- (ORCID, ROR, properties), folded into this core by 274, read raw
-- unrevoked rows, so a viewer sharing only a LAPSED row's group with an
-- agent was still shown its details. Main fixed the same rule in its
-- hand-copied predicates (its migration `group_live_roster`, backlog
-- f712db53) by reading `epigraph_group_live_roster`; this branch has one
-- shared predicate instead, so the fix lands here, and a merge of main keeps
-- it whichever side of the Rust conflict is taken.
--
-- The team-direct arm already carries 164's rule, and 235's concerns
-- personal groups, which that arm excludes; it is unchanged.
--
-- ===================================================================
-- 2. WHAT CHANGES
-- ===================================================================
--
-- a. PRECONDITION (LRD01, 55000): the core's body is still 304's (md5).
-- b. `epigraph_agent_disclosure_for` re-stated (CREATE OR REPLACE: owner and
--    ACL kept; COST 1000, SECURITY DEFINER and 172's path restated): the
--    details EXISTS joins `groups` and applies 164's and 235's rules, written
--    as 236's direct arm writes them with the target in place of the
--    parameter. This is a THIRD copy of that arm (236's, main's roster
--    read): whoever merges main should express it through
--    `epigraph_group_live_roster`'s counting rule, and main's
--    `group_live_roster.rs` md5 pin on 236's twin keeps the copies honest.
--    Every arm, its answer and the order are 304's.
--
-- Pinned by `human_identity_visibility.rs::a_lapsed_membership_row_shares_no_details`
-- (red before) and `migration_306_refuses_over_another_core_body`.
--
-- UNDO: `docs/runbooks/308-undo.sql` (304's core).
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_core text;
BEGIN
    SELECT p.prosrc INTO v_core
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
               'public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)');
    IF v_core IS NULL OR pg_catalog.md5(v_core) <> '326fa106931eb47ca1d2504bfb43ac3b' THEN
        RAISE EXCEPTION 'LRD01: epigraph_agent_disclosure_for is absent or its body is not '
                        '304''s; 308 re-states 304''s body and would overwrite another one '
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

    -- 285 (C11): a human's 'public' counts only with the setter's consent.
    v_public := COALESCE(v_profile = 'public' AND (NOT v_human OR v_consented IS NOT NULL),
                         false);

    -- Today's details rule, for every agent. 308: a shared group counts only
    -- through a membership row that still COUNTS, by the two lapse rules of
    -- 236's direct arm (main's `epigraph_group_live_roster` applies the same
    -- two; backlog f712db53): 164, a verb-made group's row counts while its
    -- agent's human is a live human operator; 235, a personal-group row of an
    -- agent allowlisted for the group's owner counts while an allowance still
    -- names the owner.
    v_details := COALESCE(
        v_privileged OR v_self OR v_public
        OR (pg_catalog.cardinality(v_groups) > 0
            AND EXISTS (SELECT 1 FROM public.group_memberships gm
                          JOIN public.groups g ON g.id = gm.group_id
                         WHERE gm.agent_id = p_target
                           AND gm.revoked_at IS NULL
                           AND gm.group_id = ANY (v_groups)
                           AND (g.did_key NOT LIKE 'did:epigraph:group:%'
                                OR public.epigraph_is_human_operator(
                                       public.epigraph_human_of(p_target, true)))
                           AND (g.kind <> 'personal'
                                OR g.created_by_agent_id = p_target
                                OR NOT EXISTS (
                                       SELECT 1 FROM public.author_binding_clients r
                                        WHERE r.agent_id = p_target
                                          AND r.operator_id = g.created_by_agent_id)
                                OR public.epigraph_human_of(p_target, true)
                                   = g.created_by_agent_id))),
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

    -- 290 (C5): B(H) with each agent's binding START. H's own assertions
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
    -- 302: the same ids as text, in the same order, cast HERE (a uuid-to-text
    -- cast on a probe's Var is not leakproof, so it could be no index
    -- condition under row security).
    v_bound_text := ARRAY(SELECT u.agent_id::text
                            FROM pg_catalog.unnest(v_bound) WITH ORDINALITY AS u(agent_id, n)
                           ORDER BY u.n);

    -- public claim: one forced probe per bound agent (no viewer state), from
    -- the agent's binding start (288's (agent_id, created_at) index)
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

    -- 297 (C6), 304 (Addendum 5): a PUBLIC assertion of any other kind that
    -- B(H) ITSELF made names H, windowed from the binding start as the claim
    -- arm is (290). One forced probe per bound agent per kind, each on its
    -- own partial index (294, 301, 305):
    --   challenges      challenger_id (170's CR08 pins it to the filing
    --                   session's principal)
    --   mass_functions  source_agent_id of an ASSESSMENT slot only (304): the
    --                   assess route keys it to the caller or the caller's
    --                   live human; an edge-factor, evidence-slot or unscoped
    --                   row can be written by another writer under the
    --                   agent's id. A retracted assessment still counts, as a
    --                   superseded claim does.
    --   edges           a `paper -ingested_claim-> claim` record whose
    --                   properties.ingested_by is the agent and whose ingest
    --                   marker names the same agent (the records' read
    --                   contract, claim_ingest.rs)
    -- Evidence is not counted (304): no column records its asserting agent
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
            -- 302: 300's LEAKPROOF accessor against the text ids, so the
            -- probe is an index condition (301) under edges' row security
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

    -- 299 (C2): a countersigned authorship (the person's own act, or its
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
                               -- 302: the id is computed in the fenced
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
        -- two equalities and the binding start, so 289's (agent_id,
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
