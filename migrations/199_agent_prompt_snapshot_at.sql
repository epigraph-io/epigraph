-- 199: the prompt snapshot an agent was running at a given instant, for a
-- claim's provenance (`authored_by.prompt_snapshot` on GET /api/v1/claims/:id
-- and on the MCP `get_claim` tool), read with 161's prompt-history gate.
--
-- ===================================================================
-- 1. WHY
--
-- A claim names the agent that filed it. Who-said-what should also be able to
-- say which prompt state that agent ran with when it filed the claim: its
-- model, its identity prompt hash and the snapshot (161 section 6, design D4)
-- active at the claim's `created_at`. `agent_prompt_snapshots` is FORCE ROW
-- LEVEL SECURITY with a read policy that admits only a bypass session or a
-- maintenance-owned definer frame, so the request server can read it only
-- through a definer. The one that exists, 161's `epigraph_agent_prompt_history`,
-- answers a different question (every snapshot of a whole lineage, with every
-- file's content materialised inside the database) and RAISES `AID06` for a
-- caller it refuses, which is the wrong shape for a field of a claim read that
-- most callers may not see.
--
-- ===================================================================
-- 2. THE CHANGE
--
-- `public.epigraph_agent_prompt_snapshot_at(p_agent uuid, p_at timestamptz,
-- p_open boolean) RETURNS TABLE (snapshot_id uuid, model text, prompt_hash
-- text, started_at timestamptz)`: SECURITY DEFINER, owned by
-- `epigraph_maintenance` (whose frame passes the snapshot table's read policy
-- through `epigraph_definer_bypass()`), STABLE, PL/pgSQL, with 172's pinned
-- path `pg_catalog, pg_temp` and every relation and function
-- schema-qualified.
--
-- THE GATE IS 161's. The admin test is 161's `v_admin` assignment, copied
-- token for token (`epigraph-db/tests/prompt_snapshot_at_definer.rs` compares
-- the two catalog bodies, whitespace aside), and the operator test is 161's
-- `epigraph_human_of(p_agent, false)` against the SESSION principal. So the
-- snapshot is returned to exactly the callers 161 lets read the agent's
-- prompt text: a human the agent is linked to in ANY link state, the operator
-- of its allowlisted client, a registered human operator asking about itself,
-- and admins (an elevated session while admin scopes are armed, an instance
-- admin otherwise, a bypass session). A caller the gate refuses gets ZERO
-- rows, never an error, and zero rows is also the answer for an agent that
-- never registered a snapshot, so the two cannot be told apart.
--
-- `p_open = true` skips the gate: the snapshot is returned to any caller. It
-- exists for the owner's pending call on who may see a claim's model and
-- prompt hash (proposed: every reader of the claim). The request server
-- passes it from ONE constant, `epigraph_db::authored_by::
-- PROMPT_SNAPSHOT_AUDIENCE`, which defaults to the gated audience; the
-- server calls this function only for a claim the caller has already read
-- under its viewer.
--
-- WHY A CALLER-CHOSEN `p_open` ADDS NO CAPABILITY. The gate reads the
-- session principal, `epigraph.principal_id`, which any session on the
-- application DSN may SET (067's `epigraph_principal_id()` is a
-- `current_setting`). A holder of that DSN can therefore already pass 161's
-- gate by setting the principal to the agent's human (which 149's
-- `epigraph_human_of`, executable by the application role, names), and read
-- the files themselves, not just their metadata. The gate is a boundary for
-- the request server's callers, enforced because the server stamps the
-- principal from a verified token; `p_open` is the server choosing a wider
-- audience for its own callers. Prompt TEXT is never returned here.
--
-- WHICH SNAPSHOT. 161 keeps ONE row per prompt state (agent, group, model,
-- files, in_prompt, refused names), with `first_seen` (its first start) and
-- `last_seen` (its latest start: every registration of an existing state
-- moves it forward). So an agent that ran state A, then B, then A again has
-- two rows, and A's `last_seen` is the return to A. Each row's latest known
-- start at or before `p_at` is `last_seen` when `last_seen <= p_at`, else
-- `first_seen` when `first_seen <= p_at`; a row with neither is not a
-- candidate. The answer is the candidate with the latest such start (ties by
-- id, descending), and `started_at` is that start. What stays ambiguous:
-- starts between a row's `first_seen` and `last_seen` are not recorded, so a
-- state that recurred more than once is placed at its first or its latest
-- start only; and an identity that runs in several groups at once has one
-- row per group, of which the latest start wins.
--
-- WHAT IT REVEALS. To an admitted caller: one snapshot id, the model, the
-- identity prompt hash and one start time for (agent, instant). The model and
-- prompt hash are a function of the identity (161 section 5 refuses a
-- registration that changes either), and 161 also writes them, display only,
-- into the agent's `properties` (`llm_model`, `llm_prompt_hash`), which every
-- session can read on `agents`. What this adds is the snapshot id and the
-- start time. No file content, group folder or lineage leaves the function.
--
-- EXECUTE: revoked from PUBLIC; granted to `epigraph_app` (the request path)
-- and `epigraph_maintenance`, role-guarded like 184 and 193. A superuser
-- connection (the migrator, `sqlx::test`) needs no grant.
--
-- REGISTERED in `crates/epigraph-cli/src/bin/tenancy_backfill.rs`
-- `DEFERRED_DEFINER_FUNCTIONS` at 199 (under a non-bypassing owner its read
-- of the FORCEd snapshot table sees no row, so it answers "no snapshot" to
-- every caller: quiet) and in its app-grant check (the request DSN must be
-- able to EXECUTE it, or every claim read errors 42501).
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
--
-- Apply BEFORE a binary whose claim read calls the function serves: without
-- it every GET /api/v1/claims/:id and MCP get_claim errors (42883). An older
-- binary ignores it.
--
-- UNDO, only AFTER rolling the binary back to one that does not call it:
--   DROP FUNCTION IF EXISTS public.epigraph_agent_prompt_snapshot_at(uuid, timestamptz, boolean);
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_agent_prompt_snapshot_at(
    p_agent uuid,
    p_at timestamptz,
    p_open boolean)
RETURNS TABLE (snapshot_id uuid,
               model text,
               prompt_hash text,
               started_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_admin     boolean;
BEGIN
    IF p_agent IS NULL OR p_at IS NULL THEN
        RETURN;
    END IF;
    IF NOT COALESCE(p_open, false) THEN
        v_admin := public.epigraph_bypass()
                   OR (v_principal IS NOT NULL
                       AND CASE WHEN public.epigraph_admin_scopes_armed()
                                THEN public.epigraph_is_elevated()
                                ELSE public.epigraph_is_instance_admin(v_principal)
                           END);
        IF NOT COALESCE(v_admin, false)
           AND (v_principal IS NULL
                OR public.epigraph_human_of(p_agent, false) IS DISTINCT FROM v_principal) THEN
            RETURN;
        END IF;
    END IF;

    RETURN QUERY
    SELECT s.id, s.model, s.prompt_hash, k.started_at
      FROM public.agent_prompt_snapshots s
     CROSS JOIN LATERAL (
            SELECT CASE WHEN s.last_seen <= p_at THEN s.last_seen
                        WHEN s.first_seen <= p_at THEN s.first_seen
                   END AS started_at) k
     WHERE s.agent_id = p_agent
       AND k.started_at IS NOT NULL
     ORDER BY k.started_at DESC, s.id DESC
     LIMIT 1;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_prompt_snapshot_at(uuid, timestamptz, boolean)
    FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_agent_prompt_snapshot_at(uuid, timestamptz, '
                'boolean) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_prompt_snapshot_at(uuid, '
                'timestamptz, boolean) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_prompt_snapshot_at(uuid, '
                'timestamptz, boolean) TO epigraph_app';
    END IF;
END $$;
