-- Migration 122: operator binding. Every claim is authored by an agent that is
-- bound to a human operator.
--
-- ===================================================================
-- 1. THE INVARIANT
--
-- Design rule: every WRITING agent is irrevocably tied to one individual human
-- account. Migration 107 recorded the tie (`operator_links`) but nothing
-- required it: `ClaimRepository::default_decl_for_author` authors an unlinked
-- agent's claim into that agent's OWN personal group, and an explicit tenancy
-- declaration never consults a link at all. This file makes the tie a write
-- precondition.
--
-- A claim INSERT (and an UPDATE that changes `claims.agent_id`) is admitted
-- only when its author is BOUND:
--
--   (a) a HUMAN OPERATOR: the agent of an ACTIVE `client_type = 'human'` OAuth
--       client, or an agent that is the `operator_id` of some `operator_links`
--       row (`epigraph_is_human_operator`); or
--   (b) holds a LIVE link: an `operator_links` row for the agent with
--       `retired = false`.
--
-- Anything else raises SQLSTATE `OPL01` (a custom class, like 105's `RVK01`:
-- `OP` is outside every class PostgreSQL raises), whose message names the fix:
-- record a live link for the agent with the maintenance command
-- `epigraph-operator link`. `epigraph_db::DbError::OperatorLinkRequired` is its
-- named form; HTTP maps it to 403 and MCP to INVALID_REQUEST.
--
-- LIVE means `retired = false`, deliberately NOT the 107 actor read (which also
-- requires a live writer membership). An agent whose membership the operator
-- REVOKED keeps its link row, is still bound, and authors into its own personal
-- group as before (the operator can move those rows with
-- `epigraph-operator reown-linked`). Ending a bound agent's ability to write is
-- a retire, not a revoke.
--
-- ===================================================================
-- 2. WHERE IT IS ENFORCED: A TRIGGER, SO NO WRITE PATH CAN SKIP IT
--
-- `claims_require_operator_binding` is a BEFORE INSERT OR UPDATE OF agent_id
-- row trigger on `claims`. Every claim write reaches it: REST, MCP over HTTP
-- and stdio, the CLIs, workflow ingest, default and explicit declarations, and
-- a raw INSERT on any role (a superuser included: triggers are not bypassed by
-- BYPASSRLS). It is named to sort BEFORE `claims_require_tenancy`, so an
-- unbound author is refused before any tenancy work.
--
-- `default_decl_for_author` calls the same check
-- (`epigraph_require_bound_author`) BEFORE it resolves a personal group, so the
-- default path refuses before 105's definer can provision a group for an
-- author that may not write at all. The trigger is the guarantee; the early
-- call is a cleaner failure, never a second rule.
--
-- ===================================================================
-- 3. ARMING: ONE-WAY, AND SEPARATE FROM THE MIGRATION
--
-- Applying this file changes NO write. Enforcement starts when a maintenance
-- session calls `epigraph_arm_operator_binding()`
-- (`epigraph-operator arm-operator-binding --apply`), which inserts the single
-- row of `operator_binding_arming` and writes one `security_events` row. Two
-- reasons it is not armed here:
--
--   * DEPLOY ORDER. The operator's order is: migrate, LIVE-link the live
--     writers, tie the legacy authors, backfill, re-own, verify, and only THEN
--     deploy the enforcing binaries. A migration that enforced at once would
--     refuse the still-unlinked live writers between the migrate and the link
--     step, through binaries that map `OPL01` to a bare 500.
--   * A fresh database (every `#[sqlx::test]`, every new install) starts with
--     no human and no links, so enforcing from the first INSERT would refuse
--     every fixture and every bootstrap write.
--
-- ONE-WAY: there is no disarm function, the table grants the maintenance role
-- SELECT and INSERT only (no UPDATE, no DELETE), and the application role
-- nothing but SELECT. Only a superuser can remove the row. The only runtime
-- relief is the valve (section 4).
--
-- ===================================================================
-- 4. THE EMERGENCY VALVE: `EPIGRAPH_OPERATOR_LINK_ENFORCEMENT=off`
--
-- A process reads that variable ONCE, at boot (`epigraph_db::operator_binding`),
-- logs a WARN on every boot while it is off, and then stamps
-- `epigraph.operator_link_enforcement = 'off'` on every connection its
-- `ScopedPool` opens. `epigraph_operator_binding_enforced()` honours that
-- session setting. Default (unset, or any other value): ON.
--
-- The setting is the valve's TRANSPORT, not an authority boundary. Any session
-- can set a custom GUC; a session that can do so can equally INSERT a claim
-- naming any bound agent as its author (`claims.agent_id` is a column the
-- writing session supplies, and 077's policies check the OWNER group, not the
-- author). So the setting adds no capability a database session did not
-- already have; what it guards against is a CODE PATH forgetting the rule,
-- which it does, because nothing sets it but the valve.
--
-- ===================================================================
-- 5. DISCLOSURE, ACCEPTED
--
-- `epigraph_author_binding(agent)` and `epigraph_is_human_operator(agent)` are
-- EXECUTE-able by `epigraph_app` (the trigger and the repository call them on
-- the request path) and answer for any agent id. What they add to 107's
-- accepted disclosure is one bit per agent: whether it is a human operator.
-- An agent's human-ness is not a secret the tenancy model protects.
--
-- ===================================================================
-- 6. UNDO
--
-- `DROP TRIGGER IF EXISTS claims_require_operator_binding ON public.claims;`
-- then drop the functions and `operator_binding_arming`. To stop enforcing
-- without DDL, set the valve (section 4) on every writing unit and restart it.
-- **Applied to a throwaway database only, NOT to any deployed database.**

SET LOCAL lock_timeout = '3s';

-- The arming record (section 3). One row or none. Rowless on purpose: its
-- protection is the grant set below, which admits no UPDATE or DELETE to any
-- role but a superuser. No `visibility` / `owner_group_id` columns: it is
-- control state, not a tier-A entity.
CREATE TABLE IF NOT EXISTS public.operator_binding_arming (
    singleton boolean PRIMARY KEY DEFAULT true CONSTRAINT operator_binding_arming_singleton
        CHECK (singleton),
    armed_at  timestamptz NOT NULL DEFAULT now(),
    armed_by  text NOT NULL DEFAULT session_user
);
REVOKE ALL ON public.operator_binding_arming FROM PUBLIC;

-- (a): is this agent a human operator?
CREATE OR REPLACE FUNCTION public.epigraph_is_human_operator(p_agent uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT p_agent IS NOT NULL
       AND (EXISTS (SELECT 1 FROM public.oauth_clients c
                     WHERE c.agent_id = p_agent
                       AND c.client_type = 'human'
                       AND c.status = 'active')
            OR EXISTS (SELECT 1 FROM public.operator_links l
                        WHERE l.operator_id = p_agent))
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_is_human_operator(uuid) FROM PUBLIC;

-- How is this author bound? 'live_link' (b), 'human_operator' (a), or NULL.
CREATE OR REPLACE FUNCTION public.epigraph_author_binding(p_agent uuid)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT CASE
             WHEN p_agent IS NULL THEN NULL
             WHEN EXISTS (SELECT 1 FROM public.operator_links l
                           WHERE l.agent_id = p_agent AND NOT l.retired) THEN 'live_link'
             WHEN public.epigraph_is_human_operator(p_agent) THEN 'human_operator'
           END
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_author_binding(uuid) FROM PUBLIC;

-- Is enforcement in force on THIS session? Armed, and the valve not off.
CREATE OR REPLACE FUNCTION public.epigraph_operator_binding_enforced()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM public.operator_binding_arming)
       AND COALESCE(current_setting('epigraph.operator_link_enforcement', true), '') <> 'off'
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_binding_enforced() FROM PUBLIC;

-- The check itself: returns quietly, or raises OPL01 naming the fix.
CREATE OR REPLACE FUNCTION public.epigraph_require_bound_author(p_agent uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NOT public.epigraph_operator_binding_enforced() THEN
        RETURN;
    END IF;
    IF public.epigraph_author_binding(p_agent) IS NOT NULL THEN
        RETURN;
    END IF;
    RAISE EXCEPTION 'OPL01: agent % is not bound to a human operator (it is neither a human '
                    'operator nor the holder of a live operator link), and every claim must be '
                    'authored by a bound agent', p_agent
        USING ERRCODE = 'OPL01',
              HINT = 'Record a live link for this agent on a maintenance DSN: '
                     'epigraph-operator link --agent <agent id> --operator <human operator '
                     'agent id> --apply. See docs/tenancy.md "Operator binding".';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_bound_author(uuid) FROM PUBLIC;

-- The trigger body. A DEFINER owned by the maintenance role, like 070's
-- trigger bodies: PostgreSQL checks EXECUTE on a trigger function when the
-- trigger is CREATED, not when it fires, and the definer frame is what calls
-- the check above. So no writing role (an operator script's login included)
-- needs a grant of its own, and none can meet a 42501 here instead of the
-- rule. It reads nothing itself; the check reads the link and client tables.
CREATE OR REPLACE FUNCTION public.epigraph_claims_require_operator_binding()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.agent_id IS NOT DISTINCT FROM OLD.agent_id THEN
        RETURN NEW;
    END IF;
    PERFORM public.epigraph_require_bound_author(NEW.agent_id);
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_claims_require_operator_binding() FROM PUBLIC;

DROP TRIGGER IF EXISTS claims_require_operator_binding ON public.claims;
CREATE TRIGGER claims_require_operator_binding
    BEFORE INSERT OR UPDATE OF agent_id ON public.claims
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_claims_require_operator_binding();

-- Arm enforcement, once (section 3). Maintenance only; audited.
CREATE OR REPLACE FUNCTION public.epigraph_arm_operator_binding()
RETURNS TABLE (armed_now boolean, armed_at timestamptz, armed_by text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    INSERT INTO public.operator_binding_arming (singleton, armed_by)
    VALUES (true, session_user)
    ON CONFLICT (singleton) DO NOTHING;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('operator.binding_armed', NULL, true,
                jsonb_build_object('recorded_by', session_user));
    END IF;
    RETURN QUERY
    SELECT v_rows > 0, a.armed_at, a.armed_by FROM public.operator_binding_arming a;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_arm_operator_binding() FROM PUBLIC;

-- Ownership and grants, guarded as every such block since 060 is.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_is_human_operator(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_author_binding(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_operator_binding_enforced() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_require_bound_author(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_arm_operator_binding() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_claims_require_operator_binding() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_is_human_operator(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_author_binding(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_binding_enforced() '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_require_bound_author(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_arm_operator_binding() '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT ON public.operator_binding_arming '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        -- 077's ALTER DEFAULT PRIVILEGES handed the app role DML on the new
        -- table; take it back and leave SELECT (the arming state is not
        -- secret, and every relation must be app-readable).
        EXECUTE 'REVOKE ALL ON public.operator_binding_arming FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.operator_binding_arming TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_arm_operator_binding() '
                'FROM epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_is_human_operator(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_author_binding(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_binding_enforced() '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_require_bound_author(uuid) '
                'TO epigraph_app';
    END IF;
END $$;
