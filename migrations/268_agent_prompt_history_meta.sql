-- 268: a content-free, paged prompt-history definer (backlog bedd59b7 and
-- 24a9f4fa).
--
-- ===================================================================
-- 1. WHY
--
-- 161's `epigraph_agent_prompt_history(agent)` (section 6, design D4) is the
-- only reader of `agent_prompt_snapshots` / `agent_prompt_blobs` /
-- `agent_succession` for the request server (FORCE ROW LEVEL SECURITY, no
-- application policy). It joins every snapshot of the whole lineage to its
-- four blobs, so every call materialises every file's content inside the
-- database, up to 8 MiB a file, even when the caller projects only hashes and
-- metadata (`AgentIdentityRepository::prompt_history_index`, the listing of
-- GET /api/v1/agents/:id/prompt-history). And it returns the whole lineage
-- in one result with no row bound: within the 64-generation walk an identity
-- with many snapshots is one unbounded response.
--
-- ===================================================================
-- 2. THE CHANGE
--
-- `public.epigraph_agent_prompt_history_meta(p_agent uuid, p_after_depth
-- integer, p_after_agent uuid, p_after_first_seen timestamptz,
-- p_after_snapshot uuid, p_limit integer)`: SECURITY DEFINER, owned by
-- `epigraph_maintenance` (whose frame passes the FORCEd tables' read policy
-- through `epigraph_definer_bypass()`), STABLE, PL/pgSQL, on 172's pinned
-- path `pg_catalog, pg_temp` with every relation and function
-- schema-qualified.
--
-- CONTENT-FREE. It returns 161's columns WITHOUT the four content columns:
-- each file is named by its key (`*_hash`, the snapshot row's own column) and
-- `agent_prompt_blobs` is never read, so no prompt text is built inside the
-- database for a listing. File content stays on 161, read one file at a time
-- by the blob route.
--
-- THE GATE IS 161's. The admin test is 161's `v_admin` assignment token for
-- token, and the operator test is 161's `epigraph_human_of(p_agent, false)`
-- against the SESSION principal, raising the same `AID06` for a refused
-- caller (`epigraph-db/tests/prompt_history_meta_definer.rs` compares the
-- catalog bodies and runs both definers over the same caller shapes). Within
-- an admitted read the per-member `readable` mark is 161's too: a lineage
-- member the caller could not read on its own is listed by id with no
-- snapshot.
--
-- THE WALK IS 161's: breadth-first with a visited set, 64 generations each
-- way, a member reached both ways keeping the nearer depth.
--
-- PAGED. Rows come in the order (abs(depth), depth, agent_id, first_seen,
-- snapshot_id): the agent itself, then its nearest generation (ancestors
-- before descendants at the same distance), each agent's snapshots
-- contiguous and oldest first. A row with no snapshot (an unreadable member,
-- or a readable one that never registered) sorts with first_seen
-- '-infinity' and the nil snapshot id. `p_after_*` is the key of the last row
-- of the previous page (all NULL for the first page; `p_after_depth` and
-- `p_after_agent` must be given together, else 22023); the page is the rows
-- strictly after it, at most `p_limit` (NULL or below 1 = 100, clamped to
-- 1000). A caller asks for one row more than it shows to learn whether a next
-- page exists. The cursor is a POSITION only: every page re-runs the gate and
-- the walk, so a forged position reads nothing the caller could not read
-- from the first page.
--
-- THE EXTENT. Every row carries `lineage_min_depth` / `lineage_max_depth`,
-- the farthest ancestor and descendant depth of the WHOLE walk (not of the
-- page), so a page can say whether the walk reached its 64-generation limit
-- without holding the page that lists that member. Member ids and depths are
-- already disclosed by the rows themselves, so this reveals nothing new.
--
-- EXECUTE: revoked from PUBLIC; granted to `epigraph_app` (the request path)
-- and `epigraph_maintenance`, role-guarded as 161 and 199. A superuser
-- connection (the migrator, `sqlx::test`) needs no grant.
--
-- REGISTERED in `crates/epigraph-cli/src/bin/tenancy_backfill.rs`
-- `DEFERRED_DEFINER_FUNCTIONS` at 268 (under a non-bypassing owner its reads
-- of the FORCEd tables see no row: the lineage is the agent alone, with no
-- snapshot, i.e. "this agent ran nothing", quiet) and in its app-grant check.
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
--
-- Apply BEFORE a binary whose prompt-history listing calls this function
-- serves: without it GET /api/v1/agents/:id/prompt-history errors (42883,
-- a 500). An older binary ignores it.
--
-- UNDO (`docs/runbooks/268-undo.sql`), only AFTER rolling the binary back to
-- one that does not call it:
--   DROP FUNCTION IF EXISTS public.epigraph_agent_prompt_history_meta(
--       uuid, integer, uuid, timestamptz, uuid, integer);
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_agent_prompt_history_meta(
    p_agent uuid,
    p_after_depth integer,
    p_after_agent uuid,
    p_after_first_seen timestamptz,
    p_after_snapshot uuid,
    p_limit integer)
RETURNS TABLE (agent_id uuid,
               relation text,
               depth integer,
               readable boolean,
               snapshot_id uuid,
               group_folder text,
               model text,
               prompt_hash text,
               in_prompt jsonb,
               blob_refused text[],
               runner_version text,
               host_sha text,
               first_seen timestamptz,
               last_seen timestamptz,
               identity_md_hash bytea,
               global_claude_md_hash bytea,
               group_claude_md_hash bytea,
               learned_md_hash bytea,
               lineage_min_depth integer,
               lineage_max_depth integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_admin     boolean;
    v_limit     integer;
    v_up_ids    uuid[] := ARRAY[p_agent];
    v_up_depths integer[] := ARRAY[0];
    v_dn_ids    uuid[] := ARRAY[p_agent];
    v_dn_depths integer[] := ARRAY[0];
    v_frontier  uuid[];
    v_next      uuid[];
    v_level     integer;
BEGIN
    IF p_agent IS NULL THEN
        RAISE EXCEPTION 'epigraph_agent_prompt_history_meta: an agent is required'
            USING ERRCODE = '22004';
    END IF;
    IF (p_after_depth IS NULL) <> (p_after_agent IS NULL) THEN
        RAISE EXCEPTION 'epigraph_agent_prompt_history_meta: a page position names both a '
                        'depth and an agent, or neither'
            USING ERRCODE = '22023';
    END IF;
    v_limit := CASE WHEN p_limit IS NULL OR p_limit < 1 THEN 100
                    ELSE LEAST(p_limit, 1000) END;
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

    -- 161's walk, unchanged but for qualification.
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
        v_up_depths := v_up_depths
                       || pg_catalog.array_fill(-v_level, ARRAY[pg_catalog.cardinality(v_next)]);
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
        v_dn_depths := v_dn_depths
                       || pg_catalog.array_fill(v_level, ARRAY[pg_catalog.cardinality(v_next)]);
        v_frontier := v_next;
    END LOOP;

    RETURN QUERY
    WITH
    walk AS (
        SELECT DISTINCT ON (l.id) l.id, l.depth
          FROM (SELECT u.id, u.depth
                  FROM ROWS FROM (pg_catalog.unnest(v_up_ids),
                                  pg_catalog.unnest(v_up_depths)) AS u(id, depth)
                UNION ALL
                SELECT d.id, d.depth
                  FROM ROWS FROM (pg_catalog.unnest(v_dn_ids),
                                  pg_catalog.unnest(v_dn_depths)) AS d(id, depth)) l
         ORDER BY l.id, pg_catalog.abs(l.depth), l.depth
    ),
    extent AS (
        SELECT pg_catalog.min(w.depth) AS lo, pg_catalog.max(w.depth) AS hi FROM walk w
    ),
    admitted AS (
        SELECT w.id, w.depth,
               COALESCE(w.id = p_agent OR v_admin
                        OR public.epigraph_human_of(w.id, false) = v_principal,
                        false) AS ok
          FROM walk w
    ),
    cand AS (
        SELECT a.id, a.depth, a.ok, s.id AS sid, s.group_folder, s.model, s.prompt_hash,
               s.in_prompt, s.blob_refused, s.runner_version, s.host_sha, s.first_seen,
               s.last_seen, s.identity_md, s.global_claude_md, s.group_claude_md,
               s.learned_md,
               COALESCE(s.first_seen, '-infinity'::timestamptz) AS k_seen,
               COALESCE(s.id, '00000000-0000-0000-0000-000000000000'::uuid) AS k_snap
          FROM admitted a
          LEFT JOIN public.agent_prompt_snapshots s ON a.ok AND s.agent_id = a.id
    )
    SELECT c.id,
           CASE WHEN c.depth = 0 THEN 'self'
                WHEN c.depth < 0 THEN 'ancestor'
                ELSE 'descendant' END,
           c.depth,
           c.ok,
           c.sid, c.group_folder, c.model, c.prompt_hash, c.in_prompt, c.blob_refused,
           c.runner_version, c.host_sha, c.first_seen, c.last_seen,
           c.identity_md, c.global_claude_md, c.group_claude_md, c.learned_md,
           e.lo, e.hi
      FROM cand c
     CROSS JOIN extent e
     WHERE p_after_depth IS NULL
        OR (pg_catalog.abs(c.depth), c.depth, c.id, c.k_seen, c.k_snap)
           > (pg_catalog.abs(p_after_depth), p_after_depth, p_after_agent,
              COALESCE(p_after_first_seen, '-infinity'::timestamptz),
              COALESCE(p_after_snapshot, '00000000-0000-0000-0000-000000000000'::uuid))
     ORDER BY pg_catalog.abs(c.depth), c.depth, c.id, c.k_seen, c.k_snap
     LIMIT v_limit;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_prompt_history_meta(
    uuid, integer, uuid, timestamptz, uuid, integer) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_agent_prompt_history_meta(uuid, integer, uuid, '
                'timestamptz, uuid, integer) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_prompt_history_meta(uuid, '
                'integer, uuid, timestamptz, uuid, integer) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_prompt_history_meta(uuid, '
                'integer, uuid, timestamptz, uuid, integer) TO epigraph_app';
    END IF;
END $$;
