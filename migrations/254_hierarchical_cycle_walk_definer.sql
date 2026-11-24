-- 254: the cycle guard of the workflow references walks every in-force edge,
-- not only the edges the writing session can read (backlog 7149132e).
--
-- ===================================================================
-- 1. WHY
--
-- MCP `link_hierarchical` refuses an `invokes`, `executes` or `depends_on`
-- edge that would close a cycle (backlog 41d7b27a): `source -rel-> target`
-- closes one exactly when `target` already reaches `source` along in-force
-- edges of the walked relationships. `EdgeRepository::reaches_in_force_conn`
-- ran that walk inline on the writer's STAMPED transaction. `edges` is FORCE
-- ROW LEVEL SECURITY, so the walk saw only the edges that session reads, and
-- a cycle closed through an edge it cannot read was admitted. The shape:
--
--   W1 -executes-> S -invokes-> W2     (S private to another group, so both
--                                       edges take that group's tenancy)
--   W2 -invokes-> W1                   (written by a caller outside the group)
--
-- The caller's walk from W1 never left W1, so the closing edge was written,
-- and every walker with wider visibility (a member of both groups, the
-- maintenance jobs) then met a hierarchical cycle. "Hierarchical edges form no
-- cycle" held per viewer only.
--
-- ===================================================================
-- 2. THE CHANGE
--
-- `public.epigraph_edges_reach(p_from uuid, p_to uuid, p_relationships
-- text[]) RETURNS boolean`: SECURITY DEFINER, owned by `epigraph_maintenance`
-- (whose frame passes `edges_tenancy` through `epigraph_definer_bypass()`),
-- STABLE, with 172's pinned path `pg_catalog, pg_temp` and every name
-- schema-qualified. Its body is the walk `reaches_in_force_conn` ran inline:
-- a recursive UNION from `p_from` along in-force (`valid_to IS NULL OR
-- valid_to > now()`) edges whose relationship is in `p_relationships`,
-- source -> target, answering whether `p_to` is reached. `UNION` discards a
-- node already reached, so it terminates on a graph that already holds a
-- cycle. `reaches_in_force_conn` now calls it.
--
-- It walks ONLY the workflow references: a relationship set that is empty,
-- holds a NULL, or names anything but `invokes`, `executes` or `depends_on`
-- is refused (22023). Those are the sets `link_hierarchical` walks
-- (`cycle_walk_for`), and nothing else asks.
--
-- THE LOCK IS NOT HERE. `reaches_in_force_conn` still takes its
-- transaction-scoped advisory lock (keyed on the walked relationship set) in
-- a statement of its own BEFORE calling this function. That order is the
-- serialization: a STABLE function reads under its calling statement's
-- snapshot, so folding the lock into the same statement would take the
-- snapshot before the wait, and the second of two concurrent writers of
-- `a -> b` and `b -> a` would miss the first's committed edge.
--
-- WHAT IT REVEALS. One boolean: whether one node reaches another along
-- in-force workflow-reference edges. No row, id, count or content leaves the
-- function, and `link_hierarchical` refuses with the same message (naming
-- only the two endpoints the caller has already read) whichever edges closed
-- the cycle. The bit is about edges the caller may not read: that is the
-- point, since the integrity property is graph-wide. The only caller asks it
-- about two endpoints it has just read through its own viewer. The
-- application role is the server, not a caller (an application-DSN holder
-- can stamp itself into any group already), so the function adds no read
-- an application connection did not have.
--
-- EXECUTE: revoked from PUBLIC; granted to `epigraph_app` (the request path)
-- and `epigraph_maintenance`, role-guarded as in 193. A superuser connection
-- (the migrator, `sqlx::test`) needs no grant.
--
-- REGISTERED in `crates/epigraph-cli/src/bin/tenancy_backfill.rs`
-- `DEFERRED_DEFINER_FUNCTIONS` at 254: under a non-bypassing owner its read of
-- `edges` is row-security filtered and the guard fails OPEN (the bug above),
-- so the owner is load-bearing.
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
--
-- Apply BEFORE a binary whose `reaches_in_force_conn` calls the function
-- serves: without it every cycle-checked `link_hierarchical` call (`invokes`,
-- `executes`, `depends_on`) fails with 42883 and writes nothing (fail closed).
-- An older binary ignores the function.
--
-- It does not repair a cycle that already exists; it only refuses new ones.
--
-- UNDO (`docs/runbooks/254-undo.sql`), only AFTER rolling the binary back to
-- one that walks inline:
--   DROP FUNCTION IF EXISTS public.epigraph_edges_reach(uuid, uuid, text[]);
-- Undoing re-opens the per-viewer guard described in section 1.
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_edges_reach(
    p_from uuid,
    p_to uuid,
    p_relationships text[]
)
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_reached boolean;
BEGIN
    IF p_from IS NULL OR p_to IS NULL OR p_relationships IS NULL
       OR pg_catalog.cardinality(p_relationships) = 0 THEN
        RAISE EXCEPTION 'epigraph_edges_reach: a start, an end and a non-empty relationship set are required'
            USING ERRCODE = '22023';
    END IF;
    IF NOT (p_relationships <@ ARRAY['invokes', 'executes', 'depends_on']::text[]) THEN
        RAISE EXCEPTION 'epigraph_edges_reach walks only invokes, executes and depends_on'
            USING ERRCODE = '22023';
    END IF;

    WITH RECURSIVE walk_reach(node) AS (
        SELECT p_from
        UNION
        SELECT walk_e.target_id
          FROM walk_reach
          JOIN public.edges walk_e ON walk_e.source_id = walk_reach.node
         WHERE walk_e.relationship = ANY (p_relationships)
           AND (walk_e.valid_to IS NULL OR walk_e.valid_to > pg_catalog.now())
    )
    SELECT EXISTS (SELECT 1 FROM walk_reach WHERE walk_reach.node = p_to)
      INTO v_reached;
    RETURN v_reached;
END
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_edges_reach(uuid, uuid, text[]) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_edges_reach(uuid, uuid, text[]) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_edges_reach(uuid, uuid, text[]) TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 254 function '
                     'body stays owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_edges_reach(uuid, uuid, text[]) TO epigraph_app';
    END IF;
END $$;
