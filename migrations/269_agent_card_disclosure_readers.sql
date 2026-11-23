-- 269: the agent-lookup card's reverse binding read (backlog 0e419970).
--
-- ===================================================================
-- 1. WHAT THIS ADDS
--
--   public.epigraph_agents_linked_to_operator(p_operator uuid)
--     RETURNS TABLE (agent_id uuid)
--
-- The agents whose 107 operator link names `p_operator`, retired links
-- included: the inverse index of 107's `epigraph_operator_of_author(agent)`
-- ("the row alone, retired included"), which the application role already
-- calls for any agent. It decides nothing. The card
-- (`epigraph_db::repos::agent_lookup`) feeds each returned agent, and each
-- agent a 149 allowance row names `p_operator` for (that table is
-- app-readable), to the SAME forward binding rule that fills every card's
-- `operator_human` (`operator_binding_sql`: the live link's operator, else the
-- unrevoked allowance's, never status), and shows `p_operator` as a human
-- (`kind_evidence` `operator_of_bound_agent`) when some agent's binding names
-- it. So the reverse can never disagree with the forward, and no copy of the
-- binding rule lives here.
--
-- ===================================================================
-- 2. WHY THIS DISCLOSES NOTHING NEW
--
-- `agents` is world-readable (077 section 9) and the app role reads any
-- agent's link through `epigraph_operator_of_author`, so this inverse is the
-- image of a function the app role can already evaluate over every agent id.
-- What reaches a reader is one bit per carded agent ("some agent is bound to
-- it"), and that bit is the image of `operator_human`, which every reader
-- already sees on every agent's card. No registration, client or membership
-- status is read, so no suspension or revocation moves it.
--
-- ===================================================================
-- 3. SHAPE
--
-- 172's form: `SET search_path = pg_catalog, pg_temp`, every public object
-- schema-qualified. Owner `epigraph_maintenance`: `operator_links` is FORCE
-- RLS and admits a read only through `epigraph_definer_bypass()` (the owner)
-- or a privileged session, and maintenance holds SELECT on it (107). Under a
-- NON-member owner the read returns no row: fail CLOSED (fewer humans
-- shown, never more). EXECUTE revoked from PUBLIC, granted to `epigraph_app`
-- (the card runs on the request DSN). The guarded owner and grant blocks can
-- silently no-op; `tenancy_backfill.rs`'s registers report it.
--
-- UNDO: `docs/runbooks/269-undo.sql`. No rows, tables or policies change.
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_agents_linked_to_operator(p_operator uuid)
RETURNS TABLE (agent_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT l.agent_id FROM public.operator_links l WHERE l.operator_id = p_operator
$$;
REVOKE ALL ON FUNCTION public.epigraph_agents_linked_to_operator(uuid) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_agents_linked_to_operator(uuid) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agents_linked_to_operator(uuid) '
                'TO epigraph_app';
    END IF;
END $$;
