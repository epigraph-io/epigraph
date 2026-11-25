-- 276: a one-file prompt-history definer (backlog aaaf3cad).
--
-- ===================================================================
-- 1. WHY
--
-- GET /api/v1/agents/:id/prompt-history/blobs/:hash serves ONE prompt file,
-- named by its key, from a snapshot the caller may read in `:id`'s history.
-- Until now it read that file through 161's `epigraph_agent_prompt_history
-- (agent)` (section 6, design D4), filtering the result to the one key. That
-- definer joins every snapshot of the whole lineage to its four blobs, so
-- each one-file read fetched every file the lineage names inside the
-- database (up to 8 MiB a file) to return one of them: measured on a
-- three-generation lineage naming four files, one file read fetched six
-- `agent_prompt_blobs` rows. 268 moved the listing off that read; the file
-- read was the last caller on the request path.
--
-- ===================================================================
-- 2. THE CHANGE
--
-- `public.epigraph_agent_prompt_history_blob(p_agent uuid, p_blob_hash
-- bytea) RETURNS TABLE (content bytea)`: SECURITY DEFINER, owned by
-- `epigraph_maintenance` (whose frame passes the FORCEd tables' read policy
-- through `epigraph_definer_bypass()`), STABLE, PL/pgSQL, on 172's pinned
-- path `pg_catalog, pg_temp` with every relation and function
-- schema-qualified.
--
-- THE GATE IS 161's, and it runs FIRST, before the key is looked at, so a
-- refused caller learns nothing about which keys exist. The admin test is
-- 161's `v_admin` assignment token for token, and the operator test is 161's
-- `epigraph_human_of(p_agent, false)` against the SESSION principal, raising
-- the same `AID06` for a refused caller. A NULL agent or key is 22004.
--
-- THE WALK IS 161's (breadth-first, a visited set, 64 generations each way),
-- reduced to the SET of lineage members: depth does not decide whether a
-- file may be read. Each member gets 161's per-member `readable` mark, token
-- for token: the agent itself, any member for an admin, and a member whose
-- operator is the session principal.
--
-- ONE FILE. The answer is one row when some snapshot of a READABLE member
-- names `p_blob_hash` in one of its four file columns, carrying that one
-- blob's stored zstd frame, fetched by its primary key; zero rows otherwise
-- (no snapshot names it, or only an unreadable member's does). That is
-- exactly what 161's rows answered for the key (the content of a readable
-- row naming it), so the route's three outcomes are unchanged: the verified
-- file, a 404 for a key no readable snapshot names, and a 500 (withheld) for
-- a stored blob that fails verification. The snapshot rows are read for
-- their keys only; no other blob is fetched
-- (`epigraph-db/tests/prompt_history_blob_definer.rs` counts the blob rows a
-- read fetches: one, where 161 fetched every file of the lineage).
--
-- EXECUTE: revoked from PUBLIC; granted to `epigraph_app` (the request path)
-- and `epigraph_maintenance`, role-guarded as 161 and 268. A superuser
-- connection (the migrator, `sqlx::test`) needs no grant.
--
-- REGISTERED in `crates/epigraph-cli/src/bin/tenancy_backfill.rs`
-- `DEFERRED_DEFINER_FUNCTIONS` at 276 (under a non-bypassing owner its reads
-- of the FORCEd tables see no snapshot and no blob: every file read answers
-- "no readable snapshot names it", a 404, quiet) and in its app-grant check.
--
-- 161's definer is unchanged and stays granted. After this no route calls
-- it; `AgentIdentityRepository::prompt_history` (the whole history, every
-- file verified) still reads through it. Retiring it is a separate decision.
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
--
-- Apply BEFORE a binary whose prompt-history file read calls this function
-- serves: without it every GET .../prompt-history/blobs/:hash errors (42883,
-- a 500). An older binary ignores it.
--
-- UNDO (`docs/runbooks/276-undo.sql`), only AFTER rolling the binary back to
-- one that does not call it:
--   DROP FUNCTION IF EXISTS public.epigraph_agent_prompt_history_blob(uuid, bytea);
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_agent_prompt_history_blob(
    p_agent uuid,
    p_blob_hash bytea)
RETURNS TABLE (content bytea)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_admin     boolean;
    v_up_ids    uuid[] := ARRAY[p_agent];
    v_dn_ids    uuid[] := ARRAY[p_agent];
    v_frontier  uuid[];
    v_next      uuid[];
    v_level     integer;
    v_named     boolean;
BEGIN
    IF p_agent IS NULL THEN
        RAISE EXCEPTION 'epigraph_agent_prompt_history_blob: an agent is required'
            USING ERRCODE = '22004';
    END IF;
    IF p_blob_hash IS NULL THEN
        RAISE EXCEPTION 'epigraph_agent_prompt_history_blob: a file key is required'
            USING ERRCODE = '22004';
    END IF;
    v_admin := public.epigraph_bypass()
               OR (v_principal IS NOT NULL
                   AND CASE WHEN public.epigraph_admin_scopes_armed()
                            THEN public.epigraph_is_elevated()
                            ELSE public.epigraph_is_instance_admin(v_principal)
                       END);
    IF NOT v_admin
       AND (v_principal IS NULL
            OR public.epigraph_human_of(p_agent, false) IS DISTINCT FROM v_principal) THEN
        RAISE EXCEPTION 'AID06: the prompt history of agent % is readable by its operator and by '
                        'admins only', p_agent
            USING ERRCODE = 'AID06';
    END IF;

    -- 161's walk, its members only (a depth decides nothing here).
    v_frontier := ARRAY[p_agent];
    v_level := 0;
    WHILE pg_catalog.cardinality(v_frontier) > 0 AND v_level < 64 LOOP
        v_level := v_level + 1;
        SELECT COALESCE(pg_catalog.array_agg(DISTINCT s.parent_agent_id), '{}'::uuid[])
          INTO v_next
          FROM public.agent_succession s
         WHERE s.child_agent_id = ANY (v_frontier)
           AND s.parent_agent_id <> ALL (v_up_ids);
        v_up_ids := v_up_ids || v_next;
        v_frontier := v_next;
    END LOOP;
    v_frontier := ARRAY[p_agent];
    v_level := 0;
    WHILE pg_catalog.cardinality(v_frontier) > 0 AND v_level < 64 LOOP
        v_level := v_level + 1;
        SELECT COALESCE(pg_catalog.array_agg(DISTINCT s.child_agent_id), '{}'::uuid[])
          INTO v_next
          FROM public.agent_succession s
         WHERE s.parent_agent_id = ANY (v_frontier)
           AND s.child_agent_id <> ALL (v_dn_ids);
        v_dn_ids := v_dn_ids || v_next;
        v_frontier := v_next;
    END LOOP;

    -- Does a snapshot of a READABLE member name the key? Snapshot keys only:
    -- no blob is read here.
    WITH
    walk AS (
        SELECT DISTINCT u.id
          FROM pg_catalog.unnest(v_up_ids || v_dn_ids) AS u(id)
    ),
    admitted AS (
        SELECT w.id,
               COALESCE(w.id = p_agent OR v_admin
                        OR public.epigraph_human_of(w.id, false) = v_principal,
                        false) AS ok
          FROM walk w
    )
    SELECT EXISTS (
        SELECT 1
          FROM admitted a
          JOIN public.agent_prompt_snapshots s ON s.agent_id = a.id
         WHERE a.ok
           AND p_blob_hash IN (s.identity_md, s.global_claude_md, s.group_claude_md,
                               s.learned_md))
      INTO v_named;
    IF NOT v_named THEN
        RETURN;
    END IF;

    -- The one blob, by its primary key.
    RETURN QUERY
    SELECT b.content
      FROM public.agent_prompt_blobs b
     WHERE b.blob_hash = p_blob_hash;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_prompt_history_blob(uuid, bytea) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_agent_prompt_history_blob(uuid, bytea) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_prompt_history_blob(uuid, '
                'bytea) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_prompt_history_blob(uuid, '
                'bytea) TO epigraph_app';
    END IF;
END $$;
