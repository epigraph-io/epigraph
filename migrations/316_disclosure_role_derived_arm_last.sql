-- 316: the disclosure predicate's role-derived team probe runs LAST, after
-- the readable-claim arm, and calls 249's derivation only when the target is
-- some agent of a human (review finding correctness#3; spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- section 11.1).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 314 ordered the arms privileged, self, opt-in, public claim, team direct,
-- team ROLE-DERIVED, readable claim. The role-derived probe calls 249's
-- `epigraph_role_derived_memberships(target, now())`, measured at about 0.6 s
-- per call in the section 11 shape, whenever ANY group of the viewer's set
-- carries a `group_role_bindings` row: the production shape (a role bound to
-- a team). The readable-claim arm's worst case is tens of milliseconds. A
-- human named to the viewer through a readable claim therefore paid the
-- role-derived cost first for nothing.
--
-- ===================================================================
-- 2. THE RULE: UNCHANGED
-- ===================================================================
--
-- Same arms, same answers: they are OR-ed, so order changes no answer. The
-- two last blocks swap. Order now: privileged, self, opt-in, public claim,
-- team direct, readable claim, team role-derived.
--
-- THE CHEAP PROBE (review correctness#3 option (b)). 249's
-- `epigraph_role_derived_memberships(P, t)` joins the live bindings to three
-- candidates: (P, not via an agent), (`epigraph_operator_actor(P)`, via an
-- agent) and (`epigraph_allowlisted_operator(P)`, via an agent), and keeps a
-- binding when `epigraph_live_role_assignment(candidate, role, t)` holds
-- inside the binding's window (`created_at <= t < revoked_at`, a
-- future-dated revocation included). When P is linked as nobody's agent
-- (no `operator_links` row with `agent_id = P`, live or retired: a superset
-- of the live actor link) and holds no allowance, the only candidate is
-- (P, false), whose join arm is unconditional, so the rows are exactly the
-- bindings whose role P holds live: the probe below, per viewer group.
-- Otherwise 249's call runs, as in 314. Pinned by
-- `human_identity_visibility.rs::the_cheap_role_probe_answers_as_249_does`
-- (a future-dated revocation, a past one, a target linked as an agent, a
-- target holding an allowance).
--
-- ===================================================================
-- 3. SHAPE
-- ===================================================================
--
-- PRECONDITION (DAO01, 55000): the core's body is still 314's (md5 of
-- `prosrc`), so a concurrent re-body is never overwritten blind. Then
-- `CREATE OR REPLACE` of `epigraph_agent_disclosure_for` only, same
-- signature and return type: owner (epigraph_maintenance) and ACL are kept;
-- COST 1000, SECURITY DEFINER and 172's path are restated.
--
-- ===================================================================
-- 4. WHAT IT DOES NOT FIX (recorded in the spec, section 16.C13)
-- ===================================================================
--
-- A human principal that is ALSO linked as some human's agent, or holds an
-- allowance, still pays 249's call (measured about 0.6 s in the section 11
-- shape) when a viewer group carries a binding. Recorded in the spec.
--
-- UNDO: `docs/runbooks/316-undo.sql` restores 314's body. No rows change.
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_src text;
BEGIN
    SELECT p.prosrc INTO v_src
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
               'public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)');
    IF v_src IS NULL OR pg_catalog.md5(v_src) <> '11a4cc0ff555600b96fef0b657fc36a1' THEN
        RAISE EXCEPTION 'DAO01: epigraph_agent_disclosure_for is absent or its body is not '
                        '314''s; 316 re-orders 314''s body and would overwrite another one '
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
        -- two equalities, so 313's (agent_id, owner_group_id) index is the
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

        -- team, role-derived: only a bound group can be one. 316: LAST, and
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
