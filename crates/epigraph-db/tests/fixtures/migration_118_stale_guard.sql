-- Migration 118's match_candidates stale guard, copied VERBATIM from
-- migrations/118_app_role_table_lockdown.sql on fix/batch-w11-app-role-table-lockdown
-- (PR #518, at 7cd7089b): its section 1 (the privilege test and its grants) and
-- section 5 (the guard, its trigger, and the two grants beside it).
--
-- #517 (W10) is stacked on #515 and does not carry 118; #518 is based on main.
-- The tests that apply this file show #517's retirement paths work with 118's
-- guard in place, whichever of the two PRs lands first. Delete this file and
-- its callers once both branches have merged (118 then runs in the migrator).

-- ===================================================================
-- 1. THE PRIVILEGE TEST
-- ===================================================================
-- True for a maintenance session (067's `epigraph_bypass`, session_user a
-- member of `epigraph_maintenance`), inside a body owned by a maintenance
-- member (`epigraph_definer_bypass`, current_user), and for a superuser or
-- BYPASSRLS session role. An `epigraph_app` session is none of these.
CREATE OR REPLACE FUNCTION public.epigraph_lockdown_privileged() RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
    SELECT public.epigraph_bypass()
        OR public.epigraph_definer_bypass()
        OR COALESCE((SELECT r.rolsuper OR r.rolbypassrls
                       FROM pg_catalog.pg_roles r
                      WHERE r.rolname = session_user), false);
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_lockdown_privileged() FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_lockdown_privileged() TO epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_lockdown_privileged() '
                'TO epigraph_maintenance';
    END IF;
END $$;


-- ===================================================================
-- 5. MATCH CANDIDATES: STALE IS AN ADMINISTRATIVE STATE
-- ===================================================================
-- `stale` is what a retirement writes, and a retirement retracts the matcher
-- edge and deletes its derived rows, which are not the session's. The table
-- carries no tenancy, so the database cannot tell an administrator's session
-- from any other application session; it can tell a privileged one. The
-- guard keys on the TRANSITION into stale: the matcher's upsert re-touches a
-- decided stale row and keeps it stale (its CASE), and must keep working.
-- No statement in this repository deletes a candidate.
CREATE OR REPLACE FUNCTION public.epigraph_match_candidates_stale_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.status = 'stale'
       AND (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM 'stale')
       AND NOT public.epigraph_lockdown_privileged() THEN
        RAISE EXCEPTION 'MC01: retiring match candidate % (status stale) is an administrative '
            'act and needs a privileged (maintenance) connection', NEW.id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_match_candidates_stale_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS match_candidates_stale_guard ON public.match_candidates;
CREATE TRIGGER match_candidates_stale_guard
    BEFORE INSERT OR UPDATE OF status ON public.match_candidates
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_match_candidates_stale_guard();

-- The retirement now runs on the maintenance connection, and its cascade
-- deletes the matcher edge's `bp_messages`, `factors` and edge-keyed
-- `mass_functions`. 070 gave the maintenance role no DELETE, so on a
-- maintenance login that is not a superuser the retirement stopped at its
-- first DELETE (measured with the real server). The narrowest grant under
-- which it runs; it is the same grant 115 (`mass_functions`) and 117
-- (`factors`, `bp_messages`) make, so the two converge in either order.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE DELETE, TRUNCATE ON public.match_candidates FROM epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT DELETE ON public.factors, public.bp_messages, public.mass_functions '
                'TO epigraph_maintenance';
    END IF;
END $$;
