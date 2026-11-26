-- 320: a human's public profile counts as an opt-in only with a recorded
-- consent (operator ruling C11; spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- section 16.C11 and F4).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 309's opt-in arm names a human to everyone when `profile_visibility =
-- 'public'`. 062 defaulted that column to 'public' and nothing wrote it, so
-- the value was a default, not consent; 311 reset every human to 'group'
-- and provisions new humans as 'group'. That makes the reset's completeness
-- load-bearing: any later path that leaves a human row at 'public' (the
-- column default is still 'public', spec F4) reads as consent. The operator
-- ruled (C11) to make consent literal: a timestamp written only by the
-- self-service setter (310) when the human opts in, cleared when it opts
-- out, and required by the opt-in arm.
--
-- ===================================================================
-- 2. WHAT CHANGES
-- ===================================================================
--
-- a. `agents.profile_public_consented_at timestamptz` (nullable, no
--    default). No backfill: no one has consented yet (the operator's
--    ruling). The application role gets NO column privilege on it (118's
--    column-level UPDATE grant names other columns), so only a definer or a
--    maintenance session writes it.
-- b. CHECK `agents_profile_public_consent_check`: a stamp only on a 'public'
--    profile, so an opt-out (or any write that sets 'group') cannot leave a
--    stale consent behind for a later 'public'. Added NOT VALID then
--    VALIDATEd (every existing row is NULL).
-- c. PRECONDITIONS (PCN01, 55000): the core's body is still 316's and the
--    setter's is still 310's (md5 of `prosrc`), so another re-body is never
--    overwritten blind.
-- d. `epigraph_agent_disclosure_for` re-stated (CREATE OR REPLACE: owner and
--    ACL kept; COST 1000, SECURITY DEFINER and 172's path restated). One
--    change: for a HUMAN principal, the profile term is `'public' AND
--    profile_public_consented_at IS NOT NULL`, in the opt-in arm AND in the
--    details rule (an unconsented 'public' must not widen the ORCID / ROR /
--    properties of a human another arm names). A non-human's details rule is
--    unchanged. Every other arm, and their order, is 316's.
-- e. `epigraph_set_profile_visibility` re-stated: the same checks, refusals,
--    audit row and answer, and the UPDATE also writes
--    `profile_public_consented_at = now()` for 'public', NULL for 'group'.
--
-- UNDO: `docs/runbooks/320-undo.sql` (316's core, 310's setter, drop the
-- CHECK and the column).
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_core   text;
    v_setter text;
BEGIN
    SELECT p.prosrc INTO v_core
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
               'public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)');
    IF v_core IS NULL OR pg_catalog.md5(v_core) <> '769d918e6a663bd435dcd46ddb58a98a' THEN
        RAISE EXCEPTION 'PCN01: epigraph_agent_disclosure_for is absent or its body is not '
                        '316''s; 320 re-states 316''s body and would overwrite another one '
                        'blind; nothing was changed' USING ERRCODE = '55000';
    END IF;
    SELECT p.prosrc INTO v_setter
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure('public.epigraph_set_profile_visibility(text)');
    IF v_setter IS NULL OR pg_catalog.md5(v_setter) <> '67ee17ced42c18dcc34f85f68ac8afd5' THEN
        RAISE EXCEPTION 'PCN01: epigraph_set_profile_visibility is absent or its body is not '
                        '310''s; 320 re-states 310''s body and would overwrite another one '
                        'blind; nothing was changed' USING ERRCODE = '55000';
    END IF;
END $$;

ALTER TABLE public.agents ADD COLUMN IF NOT EXISTS profile_public_consented_at timestamptz;
COMMENT ON COLUMN public.agents.profile_public_consented_at IS
    'When this human principal consented to a public profile (320). Written only by '
    'epigraph_set_profile_visibility: now() on public, NULL on group. The disclosure opt-in '
    'arm requires it for a human.';

ALTER TABLE public.agents
    ADD CONSTRAINT agents_profile_public_consent_check
    CHECK (profile_public_consented_at IS NULL OR profile_visibility = 'public') NOT VALID;
ALTER TABLE public.agents VALIDATE CONSTRAINT agents_profile_public_consent_check;

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
BEGIN
    SELECT a.profile_visibility, a.profile_public_consented_at INTO v_profile, v_consented
      FROM public.agents a WHERE a.id = p_target;

    v_human := public.epigraph_is_human_principal(p_target);

    -- 320 (C11): a human's 'public' counts only with the setter's consent.
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

    -- 320 (C11): the opt-in records WHEN the person consented; an opt-out
    -- clears it (the table's CHECK refuses a stamp on a 'group' profile).
    UPDATE public.agents a
       SET profile_visibility = p_visibility,
           profile_public_consented_at = CASE WHEN p_visibility = 'public'
                                              THEN pg_catalog.now() END,
           updated_at = pg_catalog.now()
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
                                          'migration', 320,
                                          'session_user', session_user::text));

    SELECT d.named INTO v_named
      FROM public.epigraph_agent_disclosure_for(v_principal, NULL, ARRAY[]::uuid[], false) d;

    RETURN QUERY SELECT v_prev, p_visibility, COALESCE(v_named, false);
END $$;
