-- ===================================================================
-- 194-undo.sql: take migration 194 (H10, the retracted-BBA delete guard)
-- back out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Once undone, a retracted mass function is deletable again by
-- every path that deletes `mass_functions` rows: a claim or frame delete's
-- `ON DELETE CASCADE`, 117's cascade definer (both arms), and any direct
-- DELETE. Rows purged while 194 was in force stay purged; their
-- `mass_functions.purge` security events stay. A binary built for 194
-- (`epigraph-operator delete-frames`, which purges through
-- `epigraph_purge_mass_functions`) then fails on a frame that holds a
-- retracted row ("function does not exist"), with nothing written.
--
-- WHAT IT DOES
--   Drops the trigger `mass_functions_retracted_delete_guard`, its function,
--   `epigraph_purge_mass_functions(uuid[], text)`,
--   `epigraph_mf_purge_granted(uuid)` and the table
--   `mass_function_purge_grants`; restores migration 117's body of
--   `public.epigraph_cascade_delete_edge_bbas(uuid[], text)` byte for byte
--   with `CREATE OR REPLACE` (never DROP, which would reset its owner and
--   ACL), stating `search_path = pg_catalog, public, pg_temp` (slot 190's
--   path), not 117's header, so the undo does not revert a `pg_temp`-last
--   path.
--
-- WHAT IT LEAVES: 194's `_sqlx_migrations` row. Re-introducing the guard is a
-- NEW migration (or a re-run of 194's text, whose precondition accepts the
-- body this file restores). Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS mass_functions_retracted_delete_guard ON public.mass_functions;
DROP FUNCTION IF EXISTS public.mass_functions_retracted_delete_guard();
DROP FUNCTION IF EXISTS public.epigraph_purge_mass_functions(uuid[], text);
DROP FUNCTION IF EXISTS public.epigraph_mf_purge_granted(uuid);
DROP TABLE IF EXISTS public.mass_function_purge_grants;

-- Migration 117's body, verbatim; the path states pg_temp last.
CREATE OR REPLACE FUNCTION public.epigraph_cascade_delete_edge_bbas(
    p_edge_ids uuid[], p_cause text)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_w uuid[] := COALESCE(public.epigraph_writable_groups(), ARRAY[]::uuid[]);
        v_g uuid[] := COALESCE(public.epigraph_session_groups(), ARRAY[]::uuid[]);
        v_total bigint; v_refused bigint; v_n bigint; v_ids uuid[];
BEGIN
    IF p_cause IS NULL OR p_cause NOT IN ('dedup_retracted_edge', 'retraction_cascade',
                                          'match_candidate_retire') THEN
        RAISE EXCEPTION 'CD01: unknown cascade cause %; nothing was deleted', p_cause
            USING ERRCODE = '22023';
    END IF;
    IF p_edge_ids IS NULL OR cardinality(p_edge_ids) = 0 THEN
        RETURN 0;
    END IF;
    -- A privileged SESSION (maintenance login or superuser; `session_user`,
    -- which a definer frame does not change) is the plain statement. This is
    -- where the application's administrative cascade lands.
    IF public.epigraph_bypass() THEN
        DELETE FROM public.mass_functions WHERE perspective_id = ANY (p_edge_ids);
        GET DIAGNOSTICS v_n = ROW_COUNT;
        RETURN v_n;
    END IF;

    -- Any other session: its OWN rows only. Every candidate it can read is
    -- classified, locked so the verdict and the delete see the same rows.
    SELECT count(*),
           count(*) FILTER (WHERE NOT (mf.owner_group_id = ANY (v_w))),
           COALESCE(array_agg(mf.id), ARRAY[]::uuid[])
      INTO v_total, v_refused, v_ids
      FROM (SELECT m.id, m.owner_group_id
              FROM public.mass_functions m
             WHERE m.perspective_id = ANY (p_edge_ids)
               AND (m.visibility = 'public' OR m.owner_group_id = ANY (v_g))
               FOR UPDATE) mf;
    IF v_refused > 0 THEN
        RAISE EXCEPTION 'CD02: % of % edge-keyed mass function(s) for these edges are not '
            'this session''s to delete (cause %); another writer''s rows are removed only '
            'by the administrative cascade on the maintenance connection; nothing was deleted',
            v_refused, v_total, p_cause
            USING ERRCODE = '42501';
    END IF;
    IF v_total = 0 THEN
        RETURN 0;
    END IF;

    DELETE FROM public.mass_functions mf WHERE mf.id = ANY (v_ids);
    GET DIAGNOSTICS v_n = ROW_COUNT;

    IF v_n > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('derived.cascade_bba_delete', v_principal, true,
                jsonb_build_object(
                    'cause',              p_cause,
                    'edge_ids',           to_jsonb(p_edge_ids),
                    'deleted',            v_n,
                    'arms',               jsonb_build_object('owner', v_n),
                    'writable_group_ids', to_jsonb(v_w),
                    'migration',          117));
    END IF;
    RETURN v_n;
END $$;

COMMIT;
