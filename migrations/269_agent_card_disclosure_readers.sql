-- 269: two reads for the agent-lookup card (find_agent / get_agent), the
-- follow-ups PR #774 recorded (backlog 0e419970): the reverse binding read
-- (sections 1-3) and the role attachments an LLM agent's card may show
-- (section 4).
--
-- ===================================================================
-- 1. WHAT THIS ADDS: THE REVERSE BINDING READ
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
-- ===================================================================
-- 4. THE ROLE ATTACHMENTS A CARD MAY SHOW
--
--   public.epigraph_disclosed_role_attachments(p_agents uuid[])
--     RETURNS TABLE (agent_id uuid, role text, valid_from timestamptz,
--                    valid_to timestamptz)
--
-- 166's `role_agents` records which agents a role runs (its curator, the
-- fleet identities of its schedules). It is FORCE RLS and admits a read only
-- to a privileged session or a maintenance-owned definer, so the application
-- role reads no row and the card showed no attachment. For each agent of
-- `p_agents` this returns, per role, the attachment LIVE now (see WHAT "LIVE"
-- MEANS HERE below: not detached,
-- `valid_from <= now() < valid_to`, `valid_to` NULL: open-ended), the
-- earliest by (`valid_from`, `id`) when several are; one row per (agent,
-- role), and ONLY when the session may see that agent's attachments:
--
--   (a) the agent IS the session principal (`epigraph_principal_id()`);
--   (b) the session principal is the agent's LIVE human
--       (`epigraph_human_of(agent, true)`: the binding in force, the same
--       one the card's `operator_human` shows; a retired link's former
--       operator is no longer the agent's human and sees nothing, including
--       attachments added after the retire, which 166 permits); or
--   (c) a privileged session (`epigraph_bypass()`, which reads
--       `session_user`). An elevated request viewer on the application role
--       is NOT one: it gets (a)/(b) like any principal.
--
-- Current attachments follow the binding in force; reads of an agent's
-- PAST (the prompt-history gate) use `epigraph_human_of(agent, false)`.
--
-- WHAT (a) AND (b) TRUST. Before 269, 166's read policy admitted a
-- `role_agents` read only to `epigraph_bypass()` (session_user role
-- membership) or a maintenance-owned definer: no session setting could get
-- an application session past it. Arms (a) and (b) instead trust the
-- stamped principal (`epigraph_principal_id()`, the `epigraph.principal_id`
-- setting), which the request path stamps from the authenticated caller but
-- which any login holding the application DSN can set itself. Such a login
-- can therefore read any agent's live attachment list (elevating roles
-- included) by stamping that agent, or its live human, as the principal.
-- That is the same trust class as 198's own-assignments arm and every other
-- principal-scoped read on the application role; it is not a new class, but
-- it does widen what a self-stamping application login reads.
--
-- WHAT "LIVE" MEANS HERE. Rows not detached and inside their window now
-- (`valid_from <= now() < valid_to`). That is NOT the set 179's attached
-- mode admits: a succession copy (`inherited_from` set) whose root or any
-- hop is detached still lists here although 195's cutoff makes it admit
-- nothing, and a future-dated row is hidden here although it opens with no
-- operator act. The card is a roster, not an authority check.
--
-- NO OUTSIDER ARM, deliberately. 198 shows any reader the assignments of the
-- non-elevating roles because 123 already writes a world-readable projection
-- of each grant; 166 writes no projection of an attachment (its attach and
-- lineage-follow write `role_agents` and `security_events` only), so an
-- outsider arm would publish a roster no public surface shows today. That
-- is left to a ruling; until then the card of an attached agent reads to
-- everyone else exactly as an unattached look-alike's.
--
-- It is NOT read for authority and confers none (an attachment never grants
-- in itself; 179's attached mode reads `role_agents` directly). Bounded: at
-- most 200 agents per call (SQLSTATE 22023 above that); no role -> agents
-- direction.
--
-- Same shape as section 3: 172's form, owner `epigraph_maintenance` (whose
-- `epigraph_definer_bypass()` admits the read of the FORCEd table, and who
-- holds SELECT on it, 166), EXECUTE revoked from PUBLIC and granted to
-- `epigraph_app`. Under a NON-member owner the read returns no row: fail
-- CLOSED (fewer attachments shown).
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

-- ===================================================================
-- 4. THE ROLE ATTACHMENTS A CARD MAY SHOW (see the header, section 4)
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_disclosed_role_attachments(p_agents uuid[])
RETURNS TABLE (agent_id uuid, role text, valid_from timestamptz, valid_to timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_bypass boolean := public.epigraph_bypass();
BEGIN
    IF pg_catalog.cardinality(p_agents) > 200 THEN
        RAISE EXCEPTION 'epigraph_disclosed_role_attachments: at most 200 agents per call (got %)',
                        pg_catalog.cardinality(p_agents)
            USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT DISTINCT ON (ra.agent_id, ra.role)
           ra.agent_id, ra.role, ra.valid_from, ra.valid_to
      FROM public.role_agents ra
     WHERE ra.agent_id = ANY (p_agents)
       AND ra.detached_at IS NULL
       AND ra.valid_from <= pg_catalog.now()
       AND (ra.valid_to IS NULL OR pg_catalog.now() < ra.valid_to)
       AND (   v_bypass
            OR (v_principal IS NOT NULL
                AND (   ra.agent_id = v_principal
                     OR public.epigraph_human_of(ra.agent_id, true) = v_principal)))
     ORDER BY ra.agent_id, ra.role, ra.valid_from, ra.id;
END $$;
REVOKE ALL ON FUNCTION public.epigraph_disclosed_role_attachments(uuid[]) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_disclosed_role_attachments(uuid[]) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_disclosed_role_attachments(uuid[]) '
                'TO epigraph_app';
    END IF;
END $$;
