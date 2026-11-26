-- 318: a binding change and the reconcile pass re-own GENUINE role projection
-- edges only (human-identity visibility spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- section 7 row K1 and section 15 R1; security review of migration 315,
-- finding 1).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 315's binding trigger (`epigraph_group_role_bindings_reown_role_edges`)
-- selected every edge with the projection's relationship, an agent source and
-- `properties.role` equal to the bound role. Nothing makes such a row a
-- projection: any edge writer can write one (123 section 5 says so: "an edge
-- with no such row is not a projection"). So a bind or an unbind
--   * re-owned rows their writer owns (moved them into the bound team, then
--     into the SOURCE's personal group), and minted a personal group for a
--     source that had none;
--   * FAILED whenever a forged row's source had only a revoked personal row
--     (105's RVK01) or a squatted personal key (RVK02): one forged row blocked
--     every binding change of that role.
-- Today no other writer creates that relationship (REST and MCP edge writers
-- exclude it); this is defence in depth against the edge writers changing.
--
-- ===================================================================
-- 2. THE GENUINE-PROJECTION PREDICATE
-- ===================================================================
--
-- An edge is a projection of role assignment RA when ALL hold:
--   * the relationship and `source_type = 'agent'` the audit trigger writes;
--   * the marker the audit trigger writes (123, 130, 315):
--     `properties @> {"source": "role_assignments", "projection": true}`
--     (the JSON boolean `true`, not the string);
--   * `properties.assignment_id = RA.id`, `source_id = RA.holder_person_id`,
--     and `properties.role = RA.role`.
-- A forged row fails the join (no such assignment, another source, another
-- role) or the marker. 319 then makes the marker writable only by
-- maintenance, so an application writer cannot dress a row as a projection.
--
-- ===================================================================
-- 3. WHAT CHANGES
-- ===================================================================
--
-- a. PRECONDITION (OCC03, 55000): the binding trigger's body is still 315's
--    (md5 of `prosrc`), so a concurrent re-body is never overwritten blind.
-- b. NEW `epigraph_reown_role_projection_edges(role text) RETURNS bigint`:
--    re-owns every genuine projection of `role` (NULL: of every role) by 315's
--    `epigraph_role_edge_owner`, writing the declaration columns as 315 did.
--    SECURITY DEFINER on 172's path, owned by the maintenance role, EXECUTE
--    revoked from PUBLIC (an application-callable re-own would let any session
--    trigger personal-group mints).
-- c. `epigraph_group_role_bindings_reown_role_edges()` re-stated to call (b)
--    with the bound role. CREATE OR REPLACE keeps its owner, ACL and path; the
--    trigger is unchanged.
-- d. RECONCILE PASS: (b) over every role, under `lock_timeout`, with one
--    `security_events` summary row `edges.role_projection_edges_reconciled`
--    {migration, before, rows, after} counting GENUINE projections only, and
--    POST-CONDITION OCC04 (55000): a genuine projection still public refuses
--    the migration. A forged public row is neither moved nor counted, so it can
--    no longer make the migration fail (315's OCC02 counted every row of the
--    relationship). On a database that ran 315 this moves nothing.
--
-- NOT CHANGED: 315 itself (the standing rule: an applied migration is never
-- edited). Its one-time backfill and OCC02 still match the relationship alone;
-- the deploy pre-check in spec section 17 covers that window.
--
-- UNDO: `docs/runbooks/318-undo.sql` (restores 315's trigger body, drops (b)).
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_src text;
BEGIN
    SELECT p.prosrc INTO v_src
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
               'public.epigraph_group_role_bindings_reown_role_edges()');
    IF v_src IS NULL OR pg_catalog.md5(v_src) <> 'eb8d5a6a6de5e8cc56b91219f5469fef' THEN
        RAISE EXCEPTION 'OCC03: epigraph_group_role_bindings_reown_role_edges is absent or its '
                        'body is not 315''s; 318 re-states it and would overwrite another one '
                        'blind; nothing was changed' USING ERRCODE = '55000';
    END IF;
END $$;

-- (b) Re-own the genuine projections of one role (NULL: of every role).
CREATE OR REPLACE FUNCTION public.epigraph_reown_role_projection_edges(p_role text)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_rows bigint;
BEGIN
    WITH o AS (
        SELECT e.id, public.epigraph_role_edge_owner(ra.role, e.source_id) AS g
          FROM public.edges e
          JOIN public.role_assignments ra
            ON ra.id::text = e.properties ->> 'assignment_id'
           AND ra.holder_person_id = e.source_id
           AND ra.role = e.properties ->> 'role'
         WHERE e.relationship = 'OCCUPIES' AND e.source_type = 'agent'
           AND e.properties @> '{"source": "role_assignments", "projection": true}'::jsonb
           AND (p_role IS NULL OR ra.role = p_role)
    )
    UPDATE public.edges e
       SET visibility = 'group', owner_group_id = o.g, co_owner_group_id = NULL,
           declared_owner_group_id = o.g, declared_co_owner_group_id = NULL
      FROM o
     WHERE e.id = o.id
       AND (e.visibility, e.owner_group_id, e.co_owner_group_id,
            e.declared_owner_group_id, e.declared_co_owner_group_id)
           IS DISTINCT FROM ('group'::varchar, o.g, NULL::uuid, o.g, NULL::uuid);
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END $$;
REVOKE ALL ON FUNCTION public.epigraph_reown_role_projection_edges(text) FROM PUBLIC;

-- (c) A bind or an unbind re-owns the role's GENUINE projection edges.
CREATE OR REPLACE FUNCTION public.epigraph_group_role_bindings_reown_role_edges()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NOT (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL) THEN
        RETURN NULL;
    END IF;
    IF NEW.role IS NULL THEN
        RETURN NULL;
    END IF;
    -- 318: genuine projections only (a forged row is neither moved nor able
    -- to fail the binding change).
    PERFORM public.epigraph_reown_role_projection_edges(NEW.role);
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION public.epigraph_group_role_bindings_reown_role_edges() FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_reown_role_projection_edges(text) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 318 function '
                     'stays owned by the migration runner.';
    END IF;
END $$;

-- (d) The reconcile pass, count shape only, genuine projections only.
DO $$
DECLARE
    v_before bigint;
    v_rows   bigint;
    v_after  bigint;
BEGIN
    SELECT pg_catalog.count(*) INTO v_before
      FROM public.edges e
      JOIN public.role_assignments ra
        ON ra.id::text = e.properties ->> 'assignment_id'
       AND ra.holder_person_id = e.source_id
       AND ra.role = e.properties ->> 'role'
     WHERE e.relationship = 'OCCUPIES' AND e.source_type = 'agent'
       AND e.properties @> '{"source": "role_assignments", "projection": true}'::jsonb
       AND e.visibility = 'public';

    -- The re-own runs as its owner, the maintenance role, which is subject to
    -- row security and reaches `edges` through `epigraph_definer_bypass()`. A
    -- runner session with `row_security = off` would make that frame raise
    -- 42501 instead (315's backfill ran as the runner itself), so it is turned
    -- on for the rest of this transaction; a superuser runner is unaffected.
    PERFORM pg_catalog.set_config('row_security', 'on', true);
    v_rows := public.epigraph_reown_role_projection_edges(NULL);

    SELECT pg_catalog.count(*) INTO v_after
      FROM public.edges e
      JOIN public.role_assignments ra
        ON ra.id::text = e.properties ->> 'assignment_id'
       AND ra.holder_person_id = e.source_id
       AND ra.role = e.properties ->> 'role'
     WHERE e.relationship = 'OCCUPIES' AND e.source_type = 'agent'
       AND e.properties @> '{"source": "role_assignments", "projection": true}'::jsonb
       AND e.visibility = 'public';

    IF v_after <> 0 THEN
        RAISE EXCEPTION 'OCC04: % genuine role projection edge(s) are still public after the '
                        'reconcile pass (% before, % moved): this migration runner cannot '
                        'update edges under its row security; run it as a superuser or a '
                        'maintenance member; nothing was changed', v_after, v_before, v_rows
            USING ERRCODE = '55000';
    END IF;

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('edges.role_projection_edges_reconciled', NULL, true,
            pg_catalog.jsonb_build_object('migration', 318, 'before', v_before,
                                          'rows', v_rows, 'after', v_after));
END $$;
