-- 253: the legacy edge re-own (120's `epigraph_reown_legacy_edges_to_signer`)
-- excludes every server signer ITSELF; `p_exclude_signers` only adds to that.
--
-- ===================================================================
-- 1. WHY (backlog 2f39eee7)
--
-- 120 section 8 re-owns a public, world-owned, signed edge in the D8 scope to
-- its signer's operator's group (else the signer's personal group), skipping
-- only the signers the operator lists in the mandatory `p_exclude_signers`.
-- A signature is an attribution only when the signing key belongs to an
-- author. Two keys never do: the MCP server's (every edge an MCP tool inserts
-- is signed by the server's agent, whoever called it) and the API's own edge
-- key (`epigraph_api::edge_signer`, every edge an HTTP route inserts). Nothing
-- built those two into the function: the operator had to remember to pass
-- both on every run (docs/architecture/noun-claims-and-verb-edges.md). A run
-- that omitted either treated that server as the AUTHOR of every
-- world-owned edge it signed, and re-owned them to the server agent's
-- operator's group, with that group's patch, retract and delete authority.
--
-- ===================================================================
-- 2. THE LOOKUP (computed by the function on every call, never passed)
--
-- A signer is excluded, whatever `p_exclude_signers` says, when ANY of:
--
--   (a) it is named `epigraph-api-signer`: the agent `epigraph-api` registers
--       for its edge key on first boot (`edge_signer::SIGNER_DISPLAY_NAME`).
--       Any client can register an agent under that name; doing so only
--       keeps that agent's own edges world-owned, the safe direction.
--   (b) it signed a CLAIM another agent authored (`claims.signer_id <>
--       claims.agent_id`). Since D1 an MCP server signs the claims its
--       callers author, so this names the MCP server's signer, in the
--       legacy single-key mode and the separate-signing-key mode alike
--       (`signer_id` is the server's agent in both). An agent that signs only
--       what it authors (a stdio agent writing as itself) is not named.
--   (c) it signed an EDGE whose recorded writer (120's `writer_group_id`) is
--       neither the world nor the group this function would re-own that
--       signer's edges to. An HTTP route's edge records its CALLER's group
--       and the API's signature, so this names an API key that resolved to
--       an agent under another name (an attested signing row, or another
--       agent's public key), which (a) misses, and any MCP server that signed
--       an edge but no claim. Its group expression is section 8's, verbatim.
--
-- Wrongly excluding a signer is safe: its edges stay world-owned and
-- administrative, which is what every legacy edge already is. Missing a
-- server signer is the defect. So the three arms are a union, and (b) and
-- (c) also exclude a genuine author whose history shows it signing another
-- author's row (for example an agent re-linked to a different operator
-- since it wrote): its legacy edges are left for the maintenance path.
--
-- `p_exclude_signers` stays MANDATORY (RLE01 on NULL): 120's legacy bulk
-- attestation keys sign no new rows, so no lookup can name them, and the
-- operator still passes them.
--
-- ===================================================================
-- 3. COST
--
-- Arms (b) and (c) read `claims` and `edges` once per call (the partial
-- `signer_id` indexes from 001 serve both). A run batched with `p_limit` pays
-- that per batch; size the batch accordingly. The function is maintenance
-- only and never on a request path.
--
-- ===================================================================
-- 4. WHAT STAYS
--
-- Signature, return type, volatility, SECURITY DEFINER, the path 190 gave it
-- (`pg_catalog, public, pg_temp`), the candidate predicate, the target group,
-- idempotence and the bounded batch are 120's. The one `security_events` row
-- per call that changed anything (`edges.legacy_signer_reown`) now also
-- carries `auto_excluded_signers` (how many signers the lookup excluded) and
-- `migration` 253.
--
-- ===================================================================
-- 5. PRECONDITION, OWNER, GRANTS
--
-- This file re-states one body whole. It refuses to apply over a body other
-- than 120's (md5 of `prosrc`; 190 changed only the function's path, which is
-- not part of `prosrc`). Owner and ACL are unchanged (CREATE OR REPLACE keeps
-- them) and re-asserted below, role-guarded as in 120 section 9.
--
-- ===================================================================
-- UNDO: `docs/runbooks/253-undo.sql` (re-states 120's body on 190's path).
-- DEPLOY: none required; no binary calls the function. Checked before
-- claiming: no `origin/*` ref carries a `253` or re-defines this function.
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_found text;
BEGIN
    SELECT md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_reown_legacy_edges_to_signer(integer, uuid[])');
    IF v_found IS DISTINCT FROM '7dc872eea3f514c5bedd2cc656ac5df7' THEN
        RAISE EXCEPTION '253: epigraph_reown_legacy_edges_to_signer is not the body 253 '
                        're-states (120''s, md5 7dc872eea3f514c5bedd2cc656ac5df7); found md5 %. '
                        'Another migration re-bodied it; nothing was changed',
                        COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
END $$;

-- -------------------------------------------------------------------
-- 120's body; delta = `v_auto` (section 2), its exclusion, and the audit
-- row's `auto_excluded_signers` / `migration`.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_reown_legacy_edges_to_signer(
    p_limit integer, p_exclude_signers uuid[])
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    v_n bigint;
    v_auto uuid[];
BEGIN
    IF p_exclude_signers IS NULL THEN
        RAISE EXCEPTION 'RLE01: p_exclude_signers is mandatory; pass every non-author signing '
            'key (an empty array only when there is none); nothing was re-owned'
            USING ERRCODE = '22004';
    END IF;
    -- 253: the server signers, looked up (header section 2).
    SELECT COALESCE(array_agg(DISTINCT s.id), '{}'::uuid[]) INTO v_auto
      FROM (
        -- (a) the API's registered edge signer.
        SELECT a.id FROM public.agents a
         WHERE a.display_name = 'epigraph-api-signer'
        UNION
        -- (b) signed a claim another agent authored.
        SELECT c.signer_id FROM public.claims c
         WHERE c.signer_id IS NOT NULL
           AND c.signer_id <> c.agent_id
        UNION
        -- (c) signed an edge another writer recorded.
        SELECT x.signer_id
          FROM (SELECT DISTINCT e.signer_id, e.writer_group_id
                  FROM public.edges e
                 WHERE e.signer_id IS NOT NULL
                   AND e.writer_group_id IS NOT NULL
                   AND e.writer_group_id <> '00000000-0000-0000-0000-000000000000'::uuid) x
         WHERE x.writer_group_id IS DISTINCT FROM COALESCE(
                 (SELECT o.operator_group_id
                    FROM public.epigraph_operator_of_author(x.signer_id) o
                   ORDER BY o.retired, o.operator_id LIMIT 1),
                 (SELECT g.id FROM public.groups g
                   WHERE g.did_key = 'did:epigraph:personal:' || x.signer_id::text
                     AND g.kind = 'personal'
                     AND g.created_by_agent_id = x.signer_id))
      ) s(id);
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
           AND e.signer_id <> ALL (v_auto)
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
                                   'auto_excluded_signers', cardinality(v_auto),
                                   'migration', 253));
    END IF;
    RETURN v_n;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_reown_legacy_edges_to_signer(integer, uuid[]) FROM PUBLIC;

-- -------------------------------------------------------------------
-- Owner and grants: unchanged by CREATE OR REPLACE; re-asserted as 120
-- section 9 does.
-- -------------------------------------------------------------------
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_reown_legacy_edges_to_signer(integer, uuid[]) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_reown_legacy_edges_to_signer('
                'integer, uuid[]) TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 253 function '
                     'body stays app-owned. Run `epigraph-tenancy-backfill verify` before '
                     'deploying.';
    END IF;
END $$;
