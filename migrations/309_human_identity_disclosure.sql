-- 309: the human-identity disclosure predicate: who may see a human
-- principal's name (spec docs/superpowers/specs/
-- 2026-11-24-human-identity-visibility-design.md, sections 3, 4 and 6.1).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- `agents` is world-readable (077 section 9), and every surface that names an
-- agent shows its `display_name` to every caller. Once a human principal is
-- provisioned under the person's real name, that is the person's name shown
-- to anyone. The operator's rule: a human's agent card is public only if they
-- (or an agent ever bound to them) made a public claim, or they chose to be
-- public; otherwise only their team members see it. "A hidden human is just
-- an unnamed agent id." "No anonymous claims": whoever can read a claim can
-- trace it to its human.
--
-- This file adds the ONE predicate every surface will call. It changes no
-- surface; the read surfaces move onto it in a later change.
--
-- ===================================================================
-- 2. THE RULE
-- ===================================================================
--
-- A target T that is NOT a human principal is NAMED to everyone, and its
-- `details` (ORCID, ROR, properties) follow today's profile rule unchanged:
-- privileged, or self, or `profile_visibility = 'public'`, or T holds a live
-- direct membership of a group in the viewer's set.
--
-- A human principal H (section 3) is NAMED to viewer V when any arm holds,
-- evaluated cheapest first:
--   privileged    V is a maintenance session or a live elevated viewer;
--   self          V is H;
--   opt-in        H's `profile_visibility = 'public'` (written by H through
--                 310's setter; 311 resets every human to 'group');
--   team          V's group set holds an ACTIVE `team` or `community` group
--                 that is among H's live memberships
--                 (`epigraph_live_memberships_unbound`, 236: direct,
--                 role-derived, 164's and 235's lapses);
--   public claim  some agent of B(H) filed a `visibility = 'public'` claim,
--                 current or superseded;
--   readable claim  some agent of B(H) filed a group claim whose owner group
--                 is in V's set.
-- B(H) = H, every `operator_links` agent with `operator_id = H` (retired
-- included), every `author_binding_clients` agent with `operator_id = H`
-- (revoked included). Sticky: no binding row is ever deleted or re-pointed.
-- A human's `details` is `named AND` the profile rule, never wider than today.
--
-- ===================================================================
-- 3. SHAPE
-- ===================================================================
--
--   epigraph_is_human_principal(agent)            the human evidence
--   epigraph_agent_disclosure_for(target, principal, groups, privileged)
--                                                 THE rule, audience explicit
--   epigraph_agent_disclosure(target)             the session as audience
--   epigraph_human_named_to_viewer(target)        name-only convenience
--
-- All four: SECURITY DEFINER on 172's path (`pg_catalog, pg_temp`, every name
-- qualified), owned by `epigraph_maintenance`, EXECUTE revoked from PUBLIC.
-- Only the two session wrappers are granted to `epigraph_app`: an
-- application-callable explicit-audience form would answer "is H named to a
-- member of group X?" for any X without even stamping a session.
--
-- COST 1000 on the core AND both wrappers: a definer with a SET clause is
-- never inlined, so the planner orders quals by the cost of the function a
-- statement calls, which is a wrapper.
--
-- The claim arms are FORCED per-row probes: B(H) is materialised into an
-- array, and each arm is a `LATERAL ... LIMIT 1` probe per bound agent, so
-- the planner has no join method to choose (a hash semi-join over a whole
-- `claims` partition is as bad as a sequential scan). 312 and 313 add the two
-- partial indexes those probes use; `idx_author_binding_clients_operator`
-- (section 5) serves B(H)'s allowance read.
--
-- The core always returns exactly one row, so a CROSS JOIN LATERAL over it
-- never drops the outer row (an unknown target reads as a non-human with no
-- profile).
--
-- ===================================================================
-- 4. WHAT IT TRUSTS, AND WHICH WAY IT FAILS
-- ===================================================================
--
-- The wrappers read the session settings `ScopedPool` stamps from a resolved
-- Viewer (`epigraph.principal_id`, `epigraph.group_ids`) plus
-- `epigraph_bypass()` (session_user) and `epigraph_is_elevated()`. A holder of
-- the application DSN who self-stamps can probe the wrapper for any audience
-- it stamps: the trust class of 236 and 269, and of every principal-keyed
-- policy. On an UNSTAMPED connection the audience is the anonymous outsider,
-- so an unstamped surface hides more, never less.
--
-- `operator_links`, `claims` and `group_memberships` are FORCE RLS and admit
-- the core through `epigraph_definer_bypass()` because its owner is
-- maintenance. Under a superuser owner (the sqlx harness; the production
-- runner) the reads succeed regardless. Under a non-member NOSUPERUSER owner
-- the FORCEd reads see nothing a policy does not admit: no binding, no
-- membership, no group claim, so the arms that need them never hold and the
-- human is UNNAMED (fail CLOSED). `tenancy_backfill`'s registers report a
-- no-op owner block.
--
-- ONE READ FAILS OPEN, so it is pinned (section 6). The human evidence decides
-- whether the rule applies at all: if it ever read empty, H would be treated
-- as non-human and NAMED. It keys on `oauth_clients` (no row policy, 077) and
-- `human_operators` (maintenance holds SELECT, 122), never on
-- `agents.agent_type`, which the legacy create path defaulted to 'human' for
-- every row. A provider-provisioned person who is not a registered operator
-- has only the `oauth_clients` row as evidence. The application role can
-- INSERT `oauth_clients` (122's header): a forged human row only ever HIDES an
-- agent, never names one.
--
-- ===================================================================
-- 5. author_binding_clients(operator_id)
-- ===================================================================
--
-- 149 created only the primary key and the one-live-per-agent index, so
-- B(H)'s allowance read scanned the table on every human evaluation. One row
-- per allowance (an operator act), so a plain CREATE INDEX holds its SHARE
-- lock momentarily; `lock_timeout` bounds it.
--
-- ===================================================================
-- 6. THE EVIDENCE GUARD (SQLSTATE 55000, HEV01)
-- ===================================================================
--
-- `epigraph_oauth_clients_human_evidence_guard`: refuses a DELETE of a
-- `client_type = 'human'` row that is linked to an agent, and an UPDATE that
-- changes such a row's `client_type`. On HEAD no code does either (re-verified
-- by grep); `human_operators.client_id ON DELETE RESTRICT` protects only a
-- registered operator's row. An INVOKER trigger on 271's trigger path.
--
-- UNDO: `docs/runbooks/309-undo.sql`. No rows change.
SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- The human evidence (spec section 3).
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_is_human_principal(p_agent uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT p_agent IS NOT NULL
       AND (EXISTS (SELECT 1 FROM public.oauth_clients c
                     WHERE c.agent_id = p_agent AND c.client_type = 'human')
            OR EXISTS (SELECT 1 FROM public.human_operators h WHERE h.agent_id = p_agent))
$$;
REVOKE ALL ON FUNCTION public.epigraph_is_human_principal(uuid) FROM PUBLIC;

-- -------------------------------------------------------------------
-- THE rule, audience explicit (spec section 6.1).
-- -------------------------------------------------------------------
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
REVOKE ALL ON FUNCTION public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean)
    FROM PUBLIC;

-- -------------------------------------------------------------------
-- The caller's session as the audience.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_agent_disclosure(p_target uuid)
RETURNS TABLE (named boolean, details boolean)
LANGUAGE sql STABLE SECURITY DEFINER COST 1000
SET search_path = pg_catalog, pg_temp AS $$
    SELECT d.named, d.details
      FROM public.epigraph_agent_disclosure_for(
               p_target,
               public.epigraph_principal_id(),
               public.epigraph_session_groups(),
               public.epigraph_bypass() OR public.epigraph_is_elevated()) d
$$;
REVOKE ALL ON FUNCTION public.epigraph_agent_disclosure(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_human_named_to_viewer(p_target uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER COST 1000
SET search_path = pg_catalog, pg_temp AS $$
    SELECT COALESCE((SELECT d.named FROM public.epigraph_agent_disclosure(p_target) d), false)
$$;
REVOKE ALL ON FUNCTION public.epigraph_human_named_to_viewer(uuid) FROM PUBLIC;

-- -------------------------------------------------------------------
-- Section 5: B(H)'s allowance read.
-- -------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_author_binding_clients_operator
    ON public.author_binding_clients (operator_id);

-- -------------------------------------------------------------------
-- Section 6: the evidence guard.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_oauth_clients_human_evidence_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.client_type = 'human' AND OLD.agent_id IS NOT NULL THEN
            RAISE EXCEPTION 'HEV01: a human OAuth client linked to an agent is that agent''s '
                            'human evidence and is never deleted; nothing was changed'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.client_type = 'human' AND OLD.agent_id IS NOT NULL
       AND NEW.client_type IS DISTINCT FROM OLD.client_type THEN
        RAISE EXCEPTION 'HEV01: a human OAuth client linked to an agent is that agent''s '
                        'human evidence and never changes type; nothing was changed'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.epigraph_oauth_clients_human_evidence_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS epigraph_oauth_clients_human_evidence_guard ON public.oauth_clients;
CREATE TRIGGER epigraph_oauth_clients_human_evidence_guard
    BEFORE DELETE OR UPDATE OF client_type ON public.oauth_clients
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_oauth_clients_human_evidence_guard();

-- -------------------------------------------------------------------
-- Ownership and grants (guarded, as every such block since 060 is).
-- -------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_is_human_principal(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_agent_disclosure(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_human_named_to_viewer(uuid) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 309 function '
                     'bodies stay owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_disclosure(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_human_named_to_viewer(uuid) '
                'TO epigraph_app';
    END IF;
END $$;
