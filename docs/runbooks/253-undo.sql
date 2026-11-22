-- ===================================================================
-- 253-undo.sql: take migration 253 (the legacy edge re-own excludes every
-- server signer itself) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- WHAT IT DOES: re-states `epigraph_reown_legacy_edges_to_signer` with 120's
-- body, byte for byte, on the path migration 190 gave it
-- (`pg_catalog, public, pg_temp`). CREATE OR REPLACE keeps owner and grants.
--
-- WHAT IT LEAVES:
--   * every edge a 253 run re-owned (they were re-owned to a signer the lookup
--     did NOT exclude, which 120 would have re-owned too) and every
--     `edges.legacy_signer_reown` audit row (082: immutable);
--   * 253's `_sqlx_migrations` row. Re-introducing the lookup is a NEW
--     migration, never a re-run of 253.
--
-- AFTER IT: every run of the function must again pass the MCP server's
-- signer agent AND the API's signer agent in `p_exclude_signers` by hand
-- (docs/architecture/noun-claims-and-verb-edges.md, before 253).
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_reown_legacy_edges_to_signer(
    p_limit integer, p_exclude_signers uuid[])
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE v_n bigint;
BEGIN
    IF p_exclude_signers IS NULL THEN
        RAISE EXCEPTION 'RLE01: p_exclude_signers is mandatory; pass every non-author signing '
            'key (an empty array only when there is none); nothing was re-owned'
            USING ERRCODE = '22004';
    END IF;
    WITH base AS (
        SELECT e.id,
               COALESCE(
                 (SELECT o.operator_group_id
                    FROM public.epigraph_operator_of_author(e.signer_id) o
                   ORDER BY o.retired, o.operator_id LIMIT 1),
                 (SELECT g.id FROM public.groups g
                   WHERE g.did_key = 'did:epigraph:personal:' || e.signer_id::text
                     AND g.kind = 'personal'
                     AND g.created_by_agent_id = e.signer_id)) AS w
          FROM public.edges e
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t
         WHERE e.visibility = 'public'
           AND e.owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid
           AND e.signer_id IS NOT NULL
           AND e.signer_id <> ALL (p_exclude_signers)
           AND public.epigraph_edge_writer_scope(e.source_type, e.target_type)
           AND s.v = 'public' AND t.v = 'public'
    ), cand AS (
        SELECT b.id, b.w FROM base b
         WHERE b.w IS NOT NULL
         ORDER BY b.id
         LIMIT p_limit
    )
    UPDATE public.edges e
       SET owner_group_id = cand.w, writer_group_id = cand.w
      FROM cand
     WHERE e.id = cand.id;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('edges.legacy_signer_reown', NULL, true,
                jsonb_build_object('rows', v_n, 'limit', p_limit,
                                   'excluded_signers', cardinality(p_exclude_signers),
                                   'migration', 120));
    END IF;
    RETURN v_n;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_reown_legacy_edges_to_signer(integer, uuid[]) FROM PUBLIC;

COMMIT;
