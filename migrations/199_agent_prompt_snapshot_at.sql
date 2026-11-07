-- 199: the prompt snapshot an agent was running at a given instant, for a
-- claim's provenance (`authored_by.prompt_snapshot` on GET /api/v1/claims/:id
-- and on the MCP `get_claim` tool), read with 161's prompt-history gate; and
-- the human an agent was BOUND to at a given instant (`authored_by.human`, and
-- each ingester's human), read from the binding record (section 4).
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
-- exists so the audience for a claim's model and prompt hash is ONE switch on
-- the request server, `epigraph_db::authored_by::PROMPT_SNAPSHOT_AUDIENCE`.
-- The owner ruled the gated audience (the model and snapshot stay behind the
-- prompt-history gate), so the server passes `false`; the server calls this
-- function only for a claim the caller has already read under its viewer.
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
-- row per group folder, of which the latest start wins. A claim records no
-- group folder (a folder maps to no tenancy group), so the claim's own group
-- cannot pick the row; the admitted audience may read every folder's rows
-- through 161's prompt history anyway. Both limits are pinned by
-- `epigraph-db/tests/prompt_snapshot_at_definer.rs`.
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
-- UNDO, only AFTER rolling the binary back to one that calls neither:
--   DROP FUNCTION IF EXISTS public.epigraph_agent_prompt_snapshot_at(uuid, timestamptz, boolean);
--   DROP FUNCTION IF EXISTS public.epigraph_operator_bound_at(uuid, timestamptz);
--
-- ===================================================================
-- 4. THE HUMAN BOUND AT AN INSTANT: `epigraph_operator_bound_at`
--
-- `public.epigraph_operator_bound_at(p_agent uuid, p_at timestamptz) RETURNS
-- uuid`: SECURITY DEFINER, owned by `epigraph_maintenance`, STABLE, PL/pgSQL,
-- path `pg_catalog, pg_temp`, every relation schema-qualified. The human
-- operator `p_agent` was bound to at `p_at`, read from the binding RECORD
-- alone, or NULL.
--
-- WHY. A claim names the human its filer was bound to WHEN IT WAS FILED, and
-- every ingester of a claim the human it was bound to when it ingested. The
-- agent card names the human bound NOW (a retired link or a revoked allowance
-- names nobody). A claim filed while a link was live keeps naming that
-- operator after the link is retired (107 section 7: the operator owns the
-- agent's claims), and a claim filed after the retirement names nobody,
-- because the agent no longer acted for anyone. 107's
-- `epigraph_operator_of_author` reports the link but not WHEN it ended, and
-- `operator_links` is readable only in a maintenance-owned definer frame, so
-- the request path needs a definer to answer "at that instant".
--
-- THE RULE, the card's structure (149's `epigraph_human_of` with every status
-- arm left out: no client, registration or membership status is read, so a
-- reader cannot watch a suspension) evaluated at `p_at` instead of now:
--   * A LINK (`operator_links`, one per agent for all time, never re-pointed)
--     names its operator from its creation until its retirement. The
--     retirement instant is the latest `operator.link_retired` audit row 191's
--     trigger wrote for that agent and operator. 191 section (e) makes that row
--     the trigger's alone: an application session cannot insert one, and a
--     maintenance insert must carry `created_at = now()`, so it can be neither
--     forged nor backdated below a superuser. A retired link with NO such row
--     (recorded retired by 107's `epigraph_link_retired_agent`, or retired by a
--     direct UPDATE before 191 audited the flip) is taken as retired since its
--     creation: it names its operator for nothing filed after it was recorded,
--     which never names a human for a claim the agent filed while not bound.
--   * BEFORE a link's creation (an agent filed claims, then was linked), the
--     client allowance in force at `p_at` names its operator; with none, the
--     link's operator does, provided the link was not retired before `p_at`
--     (the operator owns the agent's earlier claims: 107 section 7's purpose
--     for a retired link).
--   * With NO link, the 149 allowance (`author_binding_clients`) in force at
--     `p_at`: `added_at <= p_at` and not revoked at or before `p_at`; the
--     latest such row if several.
-- At `p_at = now()` this is exactly the card's `operator_human`: a live link's
-- operator, nobody for a retired link, else the unrevoked allowance.
--
-- WHAT IT REVEALS. A caller with EXECUTE (the application role) who passes
-- arbitrary instants can bisect a link's creation and retirement instants and
-- an allowance's window. The allowance window is already readable
-- (`author_binding_clients` is SELECT-granted to `epigraph_app`, 149), the
-- retired bit is disclosed by the card (107 section 5 accepts it), and the
-- request path only ever passes a claim's `created_at` or an ingest record's
-- time. What a DSN holder newly learns is the link's creation and retirement
-- instants, to the precision of its bisection. No client, registration or
-- membership status leaves the function.
--
-- EXECUTE: revoked from PUBLIC; granted to `epigraph_app` and
-- `epigraph_maintenance`. REGISTERED in `tenancy_backfill.rs`
-- `DEFERRED_DEFINER_FUNCTIONS` at 199 (under a non-bypassing owner it reads no
-- link and no audit row: it answers from the allowance arm alone, so a linked
-- agent's claims name nobody) and in its app-grant check.
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

CREATE OR REPLACE FUNCTION public.epigraph_operator_bound_at(
    p_agent uuid,
    p_at timestamptz)
RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_operator uuid;
    v_linked   timestamptz;
    v_retired  boolean;
    v_until    timestamptz;
    v_allowed  uuid;
BEGIN
    IF p_agent IS NULL OR p_at IS NULL THEN
        RETURN NULL;
    END IF;

    SELECT l.operator_id, l.created_at, l.retired
      INTO v_operator, v_linked, v_retired
      FROM public.operator_links l
     WHERE l.agent_id = p_agent;
    IF v_operator IS NOT NULL THEN
        IF v_retired THEN
            SELECT max(s.created_at) INTO v_until
              FROM public.security_events s
             WHERE s.agent_id = p_agent
               AND s.event_type = 'operator.link_retired'
               AND s.details ->> 'operator_id' = v_operator::text;
            v_until := COALESCE(v_until, v_linked);
        ELSE
            v_until := 'infinity'::timestamptz;
        END IF;
        IF p_at >= v_linked THEN
            RETURN CASE WHEN p_at < v_until THEN v_operator END;
        END IF;
    END IF;

    SELECT r.operator_id INTO v_allowed
      FROM public.author_binding_clients r
     WHERE r.agent_id = p_agent
       AND r.added_at <= p_at
       AND (r.revoked_at IS NULL OR p_at < r.revoked_at)
     ORDER BY r.added_at DESC, r.client_id
     LIMIT 1;
    IF v_allowed IS NOT NULL THEN
        RETURN v_allowed;
    END IF;
    IF v_operator IS NOT NULL AND p_at < v_until THEN
        RETURN v_operator;
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_bound_at(uuid, timestamptz) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_operator_bound_at(uuid, timestamptz) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_bound_at(uuid, '
                'timestamptz) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_bound_at(uuid, '
                'timestamptz) TO epigraph_app';
    END IF;
END $$;
