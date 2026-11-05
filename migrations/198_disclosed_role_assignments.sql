-- 198: the role assignments an agent-lookup card may show (find_agent /
-- get_agent: an MCP client must be able to find a person by name and see the
-- role that person holds).
--
-- ===================================================================
-- 1. WHAT THIS ADDS
--
-- One SECURITY DEFINER reader and nothing else:
--
--   public.epigraph_disclosed_role_assignments(p_agents uuid[])
--     RETURNS TABLE (agent_id uuid, role text, valid_from timestamptz,
--                    valid_to timestamptz)
--
-- For each agent of `p_agents` it returns the LIVE assignment of each catalog
-- role that agent holds right now, exactly as 123's
-- `epigraph_live_role_assignment(holder, role, now())` names it (the window
-- `valid_from <= now() < valid_to`, not ended, and the holder re-checked as a
-- registered human that is no other human's agent), one row per (agent, role),
-- and ONLY for:
--
--   (a) a role that neither elevates nor reads the audit trail
--       (`platform_roles.elevates = false AND reads_audit = false`): the
--       roles 165 binds to a group, whose grant ALSO writes a public,
--       world-owned graph projection naming the holder and the role (123
--       section 5: "the edge is world-readable"); or
--   (b) any role, when the agent IS the session principal
--       (`epigraph_principal_id()`): a holder reads its own assignments, which
--       `role_assignments_self_or_definer` already admits; or
--   (c) any role, on a privileged session (`epigraph_bypass()`, which reads
--       `session_user`).
--
-- ===================================================================
-- 2. WHY THIS IS NOT 083'S ROSTER ORACLE
--
-- 083 and 123 refuse the application role an any-subject reader of an
-- AUTHORITY roster: `instance_admins` and the custodian role are "the
-- highest-value target list in the system". This reader returns no row of an
-- elevating or audit-reading role for anyone but the holder itself (arm (b))
-- or a privileged session (arm (c)), so the custodian and auditor rosters stay
-- exactly as narrow as they were. What it does return for an arbitrary subject
-- (arm (a)) is a SUBSET of what the projection 123 writes on every grant
-- already shows every session: the holder, the role and the window. It adds
-- nothing a reader of the public graph cannot read, and it reads the
-- authority table instead of the projection, so a projection-shaped edge that
-- any writer of the world group could add is never shown as a role.
--
-- It is NOT read for authority and confers none. It answers "which roles does
-- this card show", nothing else; every authority question still goes to
-- 123's subject-bound readers.
--
-- Bounded: at most 200 agents per call (SQLSTATE 22023 above that), so a
-- single call is never a whole-instance roster dump; there is no role ->
-- holders direction at all.
--
-- ===================================================================
-- 3. SHAPE
--
-- Convention as 172: `SET search_path = pg_catalog, pg_temp`, every public
-- object schema-qualified, `pg_catalog.now()`. Owner `epigraph_maintenance`
-- (inside the frame `current_user` is the owner, so
-- `role_assignments_self_or_definer` admits the read through its
-- `epigraph_definer_bypass()` arm, and the owner may call 123's
-- maintenance-only `epigraph_live_role_assignment`); EXECUTE revoked from
-- PUBLIC and granted to `epigraph_app`. The role-guarded owner and grant
-- blocks can silently no-op; `tenancy_backfill.rs`'s registers report it and
-- `agent_lookup.rs` (epigraph-db tests) pins the catalog at head.
--
-- Under a NON-member owner the read of the FORCEd `role_assignments` is
-- filtered to the session principal's own rows: fail CLOSED (quiet, fewer
-- roles shown).
--
-- Callers: `epigraph_db::repos::agent_lookup` (the find_agent / get_agent card).
--
-- UNDO:
--   DROP FUNCTION IF EXISTS public.epigraph_disclosed_role_assignments(uuid[]);
-- No rows, tables or policies change here.
-- **Applied to throwaway databases only, NOT to any deployed database.**
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_disclosed_role_assignments(p_agents uuid[])
RETURNS TABLE (agent_id uuid, role text, valid_from timestamptz, valid_to timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
BEGIN
    IF pg_catalog.cardinality(p_agents) > 200 THEN
        RAISE EXCEPTION 'epigraph_disclosed_role_assignments: at most 200 agents per call (got %)',
                        pg_catalog.cardinality(p_agents)
            USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT ra.holder_person_id, ra.role, ra.valid_from, ra.valid_to
      FROM public.role_assignments ra
      JOIN public.platform_roles r ON r.key = ra.role
     WHERE ra.holder_person_id = ANY (p_agents)
       AND ra.revoked_at IS NULL
       AND ra.id = public.epigraph_live_role_assignment(ra.holder_person_id, ra.role,
                                                        pg_catalog.now())
       AND (   (NOT r.elevates AND NOT r.reads_audit)
            OR ra.holder_person_id = public.epigraph_principal_id()
            OR public.epigraph_bypass())
     ORDER BY ra.holder_person_id, ra.role;
END $$;
REVOKE ALL ON FUNCTION public.epigraph_disclosed_role_assignments(uuid[]) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_disclosed_role_assignments(uuid[]) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_disclosed_role_assignments(uuid[]) '
                'TO epigraph_app';
    END IF;
END $$;
