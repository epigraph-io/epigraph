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
-- For each agent of `p_agents` it returns, per catalog role, the assignment
-- whose WINDOW is open now: not revoked and `valid_from <= now() < valid_to`
-- (`valid_to` NULL: open-ended), the earliest by (`valid_from`, `id`) when
-- several are, exactly as 123's public projection of the grant shows it; one
-- row per (agent, role), and ONLY for:
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
-- DECIDED BY THE WINDOW ALONE, deliberately. 123's
-- `epigraph_live_role_assignment` additionally re-checks the holder as a
-- registered human (`epigraph_is_human_operator`: a live `human_operators`
-- row AND an `active` human OAuth client) that is not linked as an agent.
-- Using that here would make a role vanish from the card, and `kind` drop
-- from human to unknown, while the holder's client is suspended or its
-- registration revoked, when the projection edge and the unrevoked
-- assignment still show it: any reader comparing the two would learn the
-- holder's client and registration status. The card mirrors the projection
-- instead; authority questions keep 123's re-check (below).
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
-- `epigraph_definer_bypass()` arm); EXECUTE revoked from
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
    SELECT DISTINCT ON (ra.holder_person_id, ra.role)
           ra.holder_person_id, ra.role, ra.valid_from, ra.valid_to
      FROM public.role_assignments ra
      JOIN public.platform_roles r ON r.key = ra.role
     WHERE ra.holder_person_id = ANY (p_agents)
       AND ra.revoked_at IS NULL
       AND ra.valid_from <= pg_catalog.now()
       AND (ra.valid_to IS NULL OR pg_catalog.now() < ra.valid_to)
       AND (   (NOT r.elevates AND NOT r.reads_audit)
            OR ra.holder_person_id = public.epigraph_principal_id()
            OR public.epigraph_bypass())
     ORDER BY ra.holder_person_id, ra.role, ra.valid_from, ra.id;
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
