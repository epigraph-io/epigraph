-- 260: record an edge's DECLARED tenancy, so the privatization re-meet can
-- honour it (backlog 969f01f6).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- An edge's tenancy is the MEET of its endpoints (070, 072, 120, 219), with
-- one exception: 072's no-widening arm of `epigraph_edges_tenancy()` keeps an
-- explicit `('group', H)` declaration (co-owner included) on an edge whose
-- endpoints are both public. That tuple is the author's, not derived; nothing
-- recorded that it was. So every later re-meet treated it as derived:
--
--   * the privatization apply narrows a claim into the target group G, and
--     the propagation trigger (and `recompute_boundary_meet_conn`) re-owned
--     the declared edge to `('group', G)`: H's members lost it, and G's
--     members gained an edge H's author had kept from them;
--   * the revert then recomputed the edge from its (both public again)
--     endpoints and WIDENED it to `public` (the function's own doc said so:
--     "NOT fixed here ... the declaration is not recorded");
--   * a moved WORKFLOW's edges (219) were re-met the same way, in both
--     directions.
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. `edges.declared_owner_group_id` and `edges.declared_co_owner_group_id`:
--      the declaration, when the edge has one. Nullable, no default (a
--      catalog-only ADD on a large table), no foreign key (as 120's
--      `writer_group_id`: a recorded declaration must not become a new
--      obstacle to deleting a group; the live owner columns keep theirs).
--   2. `epigraph_edges_record_declaration()` and its trigger
--      `edges_tenancy_declared`, BEFORE INSERT OR UPDATE OF source_id,
--      target_id: the same events as `edges_tenancy`, and it fires right
--      after it (same-event row triggers fire in name order). It reads the
--      row `edges_tenancy` produced: a `group` row whose endpoints are both
--      public (`epigraph_node_tenancy`) is exactly the row 072's no-widening
--      arm kept, so its (owner, co-owner) is recorded as the declaration.
--      Every other INSERT records none, WHATEVER the caller bound (a caller
--      cannot forge one). A re-point keeps a recorded declaration; a re-point
--      the no-widening arm kept group records the tuple it kept.
--      `epigraph_edges_tenancy` and `epigraph_propagate_tenancy` are NOT
--      re-stated (both are shared, md5-guarded bodies).
--   3. The existing declarations are recorded once: every `group` edge whose
--      endpoints are both public now. This also marks an edge whose
--      endpoint went public by a path that does not re-meet (the propagation
--      never widens an edge), which keeps it narrow (fail-closed). An edge
--      declared before this file and since re-owned by a privatization or a
--      cascade cannot be recognised; it stays what it is.
--   4. `edges_owner_immutable` (115/120) also watches the two new columns: a
--      non-privileged UPDATE that changes a recorded declaration is refused
--      (42501), as for the owner columns and the author record.
--
-- The privatization re-meet (`PrivatizationRepository::
-- recompute_boundary_meet_conn`) reads the columns: an edge with a recorded
-- declaration is never re-owned and never widened. Its owner and visibility
-- stay the declaration's; when the meet is `group`, the edge is narrowed to
-- the intersection of the declaration and the meet (the meet's group as
-- co-owner) when that is expressible in one owner plus one co-owner, and is
-- otherwise HELD on its declaration and recorded in the plan's audit trail.
--
-- NOT changed: the propagation trigger (a claim's re-tenanting outside the
-- privatization re-meet still re-owns a declared edge to the meet), 206's
-- publicize/share re-meet, and a re-point onto a private endpoint (120's
-- trigger takes the meet; the recorded declaration survives it).
--
-- ===================================================================
-- 2. DEPLOY AND UNDO
-- ===================================================================
--
-- Apply as the maintenance role or a superuser (section 3 refuses
-- otherwise: an RLS-filtered backfill would see no private edge). Deploy
-- order: migrate BEFORE rolling out a binary built with it (its re-meet
-- reads the new columns; an older binary on a 260 database re-meets as
-- before). Undo (roll every 260 binary back first):
-- `docs/runbooks/260-undo.sql` drops the trigger, its function and the two
-- columns and re-creates `edges_owner_immutable` with 120's column list.
-- Export `(id, declared_owner_group_id, declared_co_owner_group_id)` of the
-- non-NULL rows first if the declarations may be wanted again.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- GUARD: the backfill (section 3) must read every row
-- ===================================================================
DO $$
BEGIN
    IF NOT (public.epigraph_bypass()
            OR COALESCE((SELECT rolsuper OR rolbypassrls FROM pg_catalog.pg_roles
                          WHERE rolname = current_user), false)) THEN
        RAISE EXCEPTION '260: run as the maintenance role or a superuser; the backfill must '
                        'read every group''s edges and endpoints'
              USING ERRCODE = '42501';
    END IF;
END $$;

-- ===================================================================
-- 1. THE DECLARATION RECORD
-- ===================================================================
ALTER TABLE public.edges
    ADD COLUMN IF NOT EXISTS declared_owner_group_id uuid,
    ADD COLUMN IF NOT EXISTS declared_co_owner_group_id uuid;

COMMENT ON COLUMN public.edges.declared_owner_group_id IS
    'Migration 260: the owner of the edge''s DECLARED (''group'', owner, co-owner) tuple: '
    'an explicit group declaration that 072''s no-widening arm kept on an edge between two '
    'public endpoints. NULL when the edge''s tenancy is derived (the meet). Set only by '
    'epigraph_edges_record_declaration(); immutable to a non-privileged session '
    '(edges_owner_immutable). Read by the privatization re-meet, which never re-owns or '
    'widens a declared edge.';
COMMENT ON COLUMN public.edges.declared_co_owner_group_id IS
    'Migration 260: the co-owner of the edge''s declared tuple (NULL when the declaration '
    'named none, and whenever declared_owner_group_id is NULL).';

-- ===================================================================
-- 2. THE RECORDING TRIGGER
-- ===================================================================
-- 172's form: the path is pg_catalog then pg_temp, and every public name is
-- schema-qualified. A definer, because `epigraph_node_tenancy` (070/219) is
-- revoked from PUBLIC and reads under row security otherwise.
CREATE OR REPLACE FUNCTION public.epigraph_edges_record_declaration() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE sv character varying(16); tv character varying(16);
BEGIN
    IF NEW.visibility = 'group' THEN
        SELECT n.v INTO sv FROM public.epigraph_node_tenancy(NEW.source_id, NEW.source_type) n;
        SELECT n.v INTO tv FROM public.epigraph_node_tenancy(NEW.target_id, NEW.target_type) n;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.declared_owner_group_id IS NOT NULL THEN
        -- A re-point never discards a recorded declaration.
        NEW.declared_owner_group_id := OLD.declared_owner_group_id;
        NEW.declared_co_owner_group_id := OLD.declared_co_owner_group_id;
    ELSIF NEW.visibility = 'group' AND sv = 'public' AND tv = 'public' THEN
        -- `edges_tenancy` kept a group tuple between two public endpoints:
        -- that is its no-widening arm, i.e. a declaration.
        NEW.declared_owner_group_id := NEW.owner_group_id;
        NEW.declared_co_owner_group_id := NEW.co_owner_group_id;
    ELSE
        NEW.declared_owner_group_id := NULL;
        NEW.declared_co_owner_group_id := NULL;
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_edges_record_declaration() FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_edges_record_declaration() '
                'OWNER TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- 3. THE EXISTING DECLARATIONS
-- ===================================================================
-- Before the guard below watches the columns. Only rows whose endpoints
-- exist are written (`edges_validate_refs` fires on every UPDATE and would
-- abort the migration on a dangling one, which `epigraph_node_tenancy`
-- reads as public); the count of skipped rows is reported.
DO $$
DECLARE v_marked bigint; v_dangling bigint;
BEGIN
    WITH cand AS (
        SELECT e.id,
               (public.validate_edge_reference(e.source_id, e.source_type)
                AND public.validate_edge_reference(e.target_id, e.target_type)) AS refs_ok
          FROM public.edges e
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t
         WHERE e.visibility = 'group'
           AND e.declared_owner_group_id IS NULL
           AND s.v = 'public' AND t.v = 'public'
    ), upd AS (
        UPDATE public.edges e
           SET declared_owner_group_id = e.owner_group_id,
               declared_co_owner_group_id = e.co_owner_group_id
          FROM cand c
         WHERE e.id = c.id AND c.refs_ok
        RETURNING e.id
    )
    SELECT (SELECT count(*) FROM upd), (SELECT count(*) FROM cand WHERE NOT cand.refs_ok)
      INTO v_marked, v_dangling;
    RAISE NOTICE '260: recorded % existing declared edge(s); skipped % with a dangling endpoint',
                 v_marked, v_dangling;
END $$;

DROP TRIGGER IF EXISTS edges_tenancy_declared ON public.edges;
CREATE TRIGGER edges_tenancy_declared
    BEFORE INSERT OR UPDATE OF source_id, target_id
    ON public.edges
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_edges_record_declaration();

-- ===================================================================
-- 4. THE OWNER GUARD WATCHES THE DECLARATION
-- ===================================================================
-- 120's trigger, with the two columns added to its column list and its WHEN.
DROP TRIGGER IF EXISTS edges_owner_immutable ON public.edges;
CREATE TRIGGER edges_owner_immutable
    BEFORE UPDATE OF owner_group_id, co_owner_group_id, writer_group_id,
                     declared_owner_group_id, declared_co_owner_group_id
    ON public.edges
    FOR EACH ROW
    WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id
          OR OLD.co_owner_group_id IS DISTINCT FROM NEW.co_owner_group_id
          OR OLD.writer_group_id IS DISTINCT FROM NEW.writer_group_id
          OR OLD.declared_owner_group_id IS DISTINCT FROM NEW.declared_owner_group_id
          OR OLD.declared_co_owner_group_id IS DISTINCT FROM NEW.declared_co_owner_group_id)
    EXECUTE FUNCTION public.epigraph_owner_immutable_guard();
