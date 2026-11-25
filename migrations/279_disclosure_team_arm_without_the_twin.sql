-- 279: the disclosure predicate's team arm no longer enumerates the target's
-- whole membership set, and the public-claim arm runs before it (spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- section 11).
--
-- ===================================================================
-- 1. WHY (MEASURED)
-- ===================================================================
--
-- `epigraph-db/tests/human_identity_visibility_perf.rs` (a human with 1,500
-- bound agents and 150k group claims, the viewer in 30 groups, 2M other
-- claims, 10k skewed operator links) measured 274's core at about 600 ms per
-- human evaluation, worst case AND with a public claim. Almost all of it is
-- the team arm's `epigraph_live_memberships_unbound(target)` (236), and in
-- it `epigraph_role_derived_memberships(target, now())` (249): about 585 ms
-- even with no `group_role_bindings` row at all. A 200-card read that names
-- one bound human took about 2 s.
--
-- ===================================================================
-- 2. THE RULE: UNCHANGED
-- ===================================================================
--
-- Same arms, same answers; only the evaluation changes.
--   * The team arm asks, per group of the viewer's set, whether the target
--     holds it, instead of enumerating every group the target holds:
--     - direct: a live `group_memberships` row of the target in one of the
--       viewer's groups that is an ACTIVE `team` / `community`, under 236's
--       one status condition for such a group (a verb-made
--       `did:epigraph:group:` group counts only while the target's live human
--       is a registered operator, 164 / 263). 236's personal-group clause
--       (235) cannot apply: a personal group is never a team.
--     - role-derived (165 / 249): every row
--       `epigraph_role_derived_memberships` returns is a `group_role_bindings`
--       group, so it is consulted only when some group of the viewer's set
--       carries a binding; otherwise it cannot contribute and is skipped.
--   * The readable-claim probe is per (bound agent, viewer group) with two
--     equalities (2a). 274's single probe with `owner_group_id = ANY(...)`
--     let the generic plan choose `idx_claims_agent_id` plus a filter in
--     some runs of the same shape (52-74 ms; 18 ms in the runs that chose
--     278): the per-pair equality leaves 278 the only fitting index, so the
--     plan is stable (30-43 ms on the same host); stable over lucky.
--   * Order: privileged, self, opt-in, PUBLIC CLAIM, team, readable claim.
--     The public-claim arm reads no viewer state and costs one index probe
--     per bound agent (about 1 ms at 1,500), so it now precedes the team
--     arm. Order changes no answer: the arms are OR-ed.
--
-- ===================================================================
-- 3. SHAPE
-- ===================================================================
--
-- `CREATE OR REPLACE` of `epigraph_agent_disclosure_for` only, same
-- signature and return type: PostgreSQL keeps the owner (epigraph_maintenance,
-- 274) and the ACL (EXECUTE revoked from PUBLIC, never granted to the
-- application role). COST 1000, SECURITY DEFINER and 172's path are restated
-- (a replace that omits COST resets it). The wrappers and the evidence helper
-- are untouched.
--
-- ===================================================================
-- 4. WHAT IT TRUSTS, AND WHICH WAY IT FAILS
-- ===================================================================
--
-- As 274. The direct team probe reads `group_memberships` (FORCE RLS) and
-- `groups` in the definer frame, admitted by `epigraph_definer_bypass()`;
-- under a non-member NOSUPERUSER owner it reads nothing and the arm fails
-- CLOSED, as 274's did.
--
-- ===================================================================
-- 5. WHAT IT DOES NOT FIX (recorded in the spec)
-- ===================================================================
--
-- * When a viewer group DOES carry a role binding, the role-derived call
--   still costs what 249 costs. That is 249's, not this predicate's.
-- * The readable-claim arm's worst case is |B(H)| x |viewer groups| index
--   descents (measured 30-43 ms at 1,500 x 30 on a shared test host, where
--   the whole core's worst case is 28-38 ms p50): over the spec's 10 ms
--   budget. The options need an operator ruling (spec section 11, C12).
--
-- UNDO: `docs/runbooks/279-undo.sql` restores 274's body. No rows change.
SET LOCAL lock_timeout = '3s';

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
    END IF;

    RETURN QUERY SELECT false, false;
END $$;
