-- 198: the role assignments an agent-lookup card may show (find_agent /
-- get_agent: an MCP client must be able to find a person by name and see the
-- role that person holds).
--
-- ===================================================================
-- 1. WHAT THIS ADDS
--
-- One SECURITY DEFINER reader (sections 1-3) and, for the same card's
-- counts, one SECURITY INVOKER trigger on `edges` (section 4):
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
-- ===================================================================
-- 4. THE INGEST-WRITTEN EDGE MARKER (`edges_ingest_written_guard`)
--
-- The card counts an agent's papers and claims from three edge shapes:
-- `agent -authored-> paper`, `paper -asserts-> claim` and
-- `agent -asserts-> claim`. Their shape proves nothing about their writer:
-- `POST /api/v1/edges` accepted both `asserts` shapes from any edges:write
-- caller, so a stranger could write `paper -asserts-> X` onto a paper an
-- agent really authored, then `agent -asserts-> X`, and the agent read as
-- having asserted X. The edge signature does not separate the paths either
-- (the HTTP route and the MCP link tools sign with the same server keys the
-- ingest uses), and a writer group can be shared.
--
-- So the document ingest writes these shapes with a reserved property,
-- `properties.ingest_written` (the writing tool's name), and this trigger
-- makes that property the walk's alone:
--
--   * INSERT carrying the key (any value, JSON null included): refused,
--     IWE01 (SQLSTATE 42501), unless the transaction-local setting
--     `epigraph.ingest_written_edge` is 'on'. Only the walk's writer
--     (`epigraph_db::create_ingest_written_edge_if_absent_conn`) sets it,
--     with set_config(..., true) around its own INSERT, then clears it;
--   * UPDATE that adds the key or changes its value: refused the same way.
--     An UPDATE that keeps or drops it is not;
--   * UPDATE that moves an endpoint or changes the relationship of a marked
--     edge: the key is DROPPED (unless declared), privileged sessions
--     included. 117 lets an owner re-point its edge and the supersede and
--     dedup cascades re-point others; either way the moved edge is not what
--     the walk wrote, so it no longer reads as ingest-written.
--
-- No privileged arm: the superuser and maintenance roles are refused like
-- the application role. A database login can set the setting itself, as it
-- can write any row; the guarantee is against application callers (HTTP,
-- MCP, the staged promote, the workflow executor, any later writer). The
-- application layer also refuses the key (RESERVED_EDGE_PROPERTIES) so such
-- a caller reads a 400 rather than this error.
--
-- The marker records the ingesting principal: `{"tool": ..., "by": <the
-- walk's write identity>}`. It proves which principal's ingest wrote the
-- edge, not that the document is genuine; a read that combines edges into
-- one fact requires them to name the same principal (`same_ingest_sql`).
-- Each principal whose ingest states the same fact writes its own marked
-- row (the walk deduplicates only onto its own principal's row), so every
-- row names exactly one principal; nothing here changes for that, since
-- each row is still one declared INSERT.
--
-- EXISTING ROWS: before this guard any edges:write caller could set the key
-- (it was an ordinary property), so every row that already carries it is a
-- hand-written copy, never the walk's. This migration DROPS the key from
-- each such row (a NOTICE reports how many); the rest of each row is
-- untouched. The strip runs AFTER the trigger is created, in the same
-- transaction: CREATE TRIGGER takes SHARE ROW EXCLUSIVE on `edges`, held to
-- commit, so no insert can land between the two and every earlier row is
-- seen; and the guard admits an UPDATE that drops the key. Edges the ingest
-- wrote before this carry no marker either, and read as unproven until an
-- operator backfills them.
--
-- UNDO:
--   DROP TRIGGER IF EXISTS edges_ingest_written_guard ON public.edges;
--   DROP FUNCTION IF EXISTS public.epigraph_edges_ingest_written_guard();
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

-- ===================================================================
-- 4. THE INGEST-WRITTEN EDGE MARKER (see the header, section 4)
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_edges_ingest_written_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    -- COALESCE: an unset setting reads NULL on a session that never set it
    -- (and '' on one that did), and a NULL here would admit the write.
    v_declared boolean := COALESCE(
        pg_catalog.current_setting('epigraph.ingest_written_edge', true) = 'on', false);
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.properties ? 'ingest_written'
       AND (NEW.source_id, NEW.source_type, NEW.target_id, NEW.target_type, NEW.relationship)
           IS DISTINCT FROM
           (OLD.source_id, OLD.source_type, OLD.target_id, OLD.target_type, OLD.relationship)
       AND NOT v_declared THEN
        NEW.properties := NEW.properties - 'ingest_written';
    END IF;
    IF NEW.properties ? 'ingest_written'
       AND NOT v_declared
       AND (TG_OP = 'INSERT'
            OR NOT (OLD.properties ? 'ingest_written')
            OR (NEW.properties -> 'ingest_written')
               IS DISTINCT FROM (OLD.properties -> 'ingest_written')) THEN
        RAISE EXCEPTION 'IWE01: properties.ingest_written is reserved for the edges the '
                        'document ingest writes; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS edges_ingest_written_guard ON public.edges;
CREATE TRIGGER edges_ingest_written_guard
    BEFORE INSERT OR UPDATE ON public.edges
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_edges_ingest_written_guard();

-- Drop every pre-existing copy of the key (see the header). AFTER the guard
-- exists: CREATE TRIGGER's lock (SHARE ROW EXCLUSIVE, held to commit) keeps
-- every concurrent insert out until this transaction ends, so none lands
-- between the strip and the guard; the guard admits this UPDATE, which only
-- drops the key.
DO $$
DECLARE
    v_stripped bigint;
BEGIN
    -- Fail closed: on a migrating role that row security would filter, the
    -- UPDATE errors instead of silently missing the rows it cannot see.
    PERFORM pg_catalog.set_config('row_security', 'off', true);
    UPDATE public.edges SET properties = properties - 'ingest_written'
     WHERE properties ? 'ingest_written';
    GET DIAGNOSTICS v_stripped = ROW_COUNT;
    RAISE NOTICE '198: dropped properties.ingest_written from % pre-existing edge row(s)',
                 v_stripped;
END $$;
