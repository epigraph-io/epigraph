-- 193: the compound test of the cached-belief owner lookup reads the claim's
-- decomposition with definer rights, so row security cannot make a compound
-- look like an atom (backlog 0dc20fad; atom-level belief program, SPEC §2.1
-- "role is structure").
--
-- ===================================================================
-- 1. WHY
--
-- `MassFunctionRepository::cache_owner_frame_for_claim` gives a COMPOUND (an
-- in-force `decomposes_to` out-edge to a current claim, outside a procedural
-- tree and not a rule) no cache owner, so no recompute that resolves its owner
-- there refolds the compound's own BBAs into its cached belief (its belief is
-- a query over its leaves). The test was the inline `IS_COMPOUND_SQL`
-- predicate (`crates/epigraph-db/src/repos/claim_role.rs`), evaluated on the
-- CALLER's connection. `edges` and `claims` are FORCE ROW LEVEL SECURITY, so
-- on an application session the predicate read only the decomposition edges
-- and child claims that session could see. A caller that can write a compound
-- but cannot see its decomposition (every child private to a group the caller
-- is not in) therefore found "not a compound", and the per-request refreshes
-- (`POST /api/v1/claims/:id/assess`, REST and MCP retract / un-retract of a
-- BBA) refolded, or vacated, the compound's cache: the write the guard exists
-- to prevent. The guard failed OPEN under row security.
--
-- ===================================================================
-- 2. THE CHANGE
--
-- `public.epigraph_claim_is_compound(uuid) RETURNS boolean`: SECURITY
-- DEFINER, owned by `epigraph_maintenance` (whose frame passes every tenancy
-- policy through `epigraph_definer_bypass()`), STABLE, with 172's pinned path
-- `pg_catalog, pg_temp`. Its body is `IS_COMPOUND_SQL` rendered over the
-- claims row `c`, with every relation (`public.claims`, `public.edges`,
-- `public.system_agents`) and the one built-in call (`pg_catalog.now()`)
-- schema-qualified and no other change. So the role is decided on the whole
-- graph whatever the caller can see, exactly as the inline predicate decides
-- it on a connection that bypasses row security.
-- `with_frozen_compound_excluded` calls it instead of splicing the predicate.
--
-- ONE SPELLING. The body is a copy of `IS_COMPOUND_SQL`. The contract test
-- `crates/epigraph-db/tests/claim_is_compound_definer.rs` compares the
-- catalog's `prosrc` (whitespace removed) with the qualified rendering of
-- `IS_COMPOUND_SQL`, so changing the Rust template without a migration that
-- re-states this body fails there; it also checks that the definer and the
-- inline predicate agree on every role fixture.
--
-- WHAT IT REVEALS. One boolean for one claim id: whether a claim with that id
-- is currently a compound. For an id the caller cannot read this is an
-- existence bit for compounds only (claim ids are random v4 UUIDs, and the
-- application role is the server, not a caller). No row, count or content
-- leaves the function.
--
-- EXECUTE: revoked from PUBLIC; granted to `epigraph_app` (the request path)
-- and `epigraph_maintenance` (the bulk recomputers on the maintenance pool),
-- role-guarded like 184. A superuser connection (the migrator, `sqlx::test`)
-- needs no grant.
--
-- REGISTERED in `crates/epigraph-cli/src/bin/tenancy_backfill.rs`
-- `DEFERRED_DEFINER_FUNCTIONS` at 193: under a non-bypassing owner its reads
-- are row-security filtered and it fails OPEN (the bug above), so the owner
-- is load-bearing.
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
--
-- Apply BEFORE a binary whose `cache_owner_frame_for_claim` calls the
-- function serves: without it every owner lookup errors (42883). An older
-- binary ignores it.
--
-- UNDO, only AFTER rolling the binary back to one that splices the inline
-- predicate:
--   DROP FUNCTION IF EXISTS public.epigraph_claim_is_compound(uuid);
-- Undoing re-opens the fail-open guard described in section 1.
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_claim_is_compound(p_claim_id uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.claims c
         WHERE c.id = p_claim_id
           AND (EXISTS (SELECT 1 FROM public.edges role_out
                          JOIN public.claims role_child ON role_child.id = role_out.target_id
                         WHERE role_out.source_id = c.id
                           AND role_out.source_type = 'claim'
                           AND role_out.target_type = 'claim'
                           AND role_out.relationship = 'decomposes_to'
                           AND (role_out.valid_to IS NULL OR role_out.valid_to > pg_catalog.now())
                           AND COALESCE(role_child.is_current, true))
                AND NOT EXISTS (WITH RECURSIVE role_up(id, depth) AS (
                                    SELECT c.id, 0
                                    UNION
                                    SELECT role_ue.source_id, role_up.depth + 1
                                      FROM role_up
                                      JOIN public.edges role_ue ON role_ue.target_id = role_up.id
                                      JOIN public.claims role_upc ON role_upc.id = role_ue.source_id
                                     WHERE role_ue.relationship = 'decomposes_to'
                                       AND role_ue.source_type = 'claim'
                                       AND role_ue.target_type = 'claim'
                                       AND (role_ue.valid_to IS NULL OR role_ue.valid_to > pg_catalog.now())
                                       AND COALESCE(role_upc.is_current, true)
                                       AND role_up.depth < 6)
                                SELECT 1 FROM role_up
                                  JOIN public.claims role_root ON role_root.id = role_up.id
                                 WHERE COALESCE(role_root.properties->>'source_type' = 'workflow'
                                                AND role_root.agent_id IN (
                                                    SELECT role_sa.agent_id FROM public.system_agents role_sa
                                                     WHERE role_sa.role = 'workflow-ingest'), false)
                                   AND NOT EXISTS (SELECT 1 FROM public.edges role_in
                                                     JOIN public.claims role_parent ON role_parent.id = role_in.source_id
                                                    WHERE role_in.target_id = role_up.id
                                                      AND role_in.source_type = 'claim'
                                                      AND role_in.target_type = 'claim'
                                                      AND role_in.relationship = 'decomposes_to'
                                                      AND (role_in.valid_to IS NULL OR role_in.valid_to > pg_catalog.now())
                                                      AND COALESCE(role_parent.is_current, true))
                                   AND NOT EXISTS (SELECT 1 FROM role_up role_uo
                                                     JOIN public.claims role_oroot ON role_oroot.id = role_uo.id
                                                    WHERE NOT COALESCE(role_oroot.properties->>'source_type' = 'workflow'
                                                                       AND role_oroot.agent_id IN (
                                                                           SELECT role_sa.agent_id FROM public.system_agents role_sa
                                                                            WHERE role_sa.role = 'workflow-ingest'), false)
                                                      AND NOT EXISTS (SELECT 1 FROM public.edges role_in
                                                                        JOIN public.claims role_parent ON role_parent.id = role_in.source_id
                                                                       WHERE role_in.target_id = role_uo.id
                                                                         AND role_in.source_type = 'claim'
                                                                         AND role_in.target_type = 'claim'
                                                                         AND role_in.relationship = 'decomposes_to'
                                                                         AND (role_in.valid_to IS NULL OR role_in.valid_to > pg_catalog.now())
                                                                         AND COALESCE(role_parent.is_current, true))))
                AND NOT (c.labels @> ARRAY['rule']::text[]
                         AND EXISTS (SELECT 1 FROM public.edges role_rc
                                       JOIN public.claims role_concl ON role_concl.id = role_rc.target_id
                                      WHERE role_rc.source_id = c.id
                                        AND role_rc.source_type = 'claim'
                                        AND role_rc.target_type = 'claim'
                                        AND role_rc.relationship = 'rule_conclusion'
                                        AND (role_rc.valid_to IS NULL OR role_rc.valid_to > pg_catalog.now())
                                        AND COALESCE(role_concl.is_current, true)))))
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_claim_is_compound(uuid) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_claim_is_compound(uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_claim_is_compound(uuid) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_claim_is_compound(uuid) TO epigraph_app';
    END IF;
END $$;
