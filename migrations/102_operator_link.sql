-- 102_operator_link.sql
-- Operator-scoped ownership: an agent process that is DECLARED to act for a
-- human operator writes into that operator's personal group, and the operator
-- (and the operator's other agents) own what it writes.
--
-- Two SECURITY DEFINER functions, no table, no policy change, no rows written
-- by the migration itself.
--
-- ===================================================================
-- 1. WHY THIS EXISTS
--
-- Agent identity is seeded from `(model, prompt-hash)`
-- (`epigraph_crypto::keypair_from_llm_agent`). Bumping a scheduled job's model
-- therefore mints a NEW agent, and under 077's tenancy every agent owns its
-- claims through its OWN `personal:<agent>` group, so the new identity is locked
-- out of the old identity's work. The `OPERATED_BY` edges that exist today are
-- auth-lineage records written by the HTTP transport
-- (`EpiGraphMcpFull::record_auth_lineage`), stdio writes none, and nothing on
-- the ownership path reads them.
--
-- The link below is the missing record: `agent --OPERATED_BY--> operator` PLUS
-- a live `writer` membership for the agent in the operator's personal group.
-- `ClaimRepository::default_decl_for_author` owns an operated agent's new
-- claims by that group, and `epigraph_mcp::tools::claims::require_owner_or_admin`
-- treats agents sharing an operator (and the operator itself) as owners of each
-- other's claims.
--
-- ===================================================================
-- 2. THE TRUST BASIS: DECLARED BY THE HOST, AUTHORIZED BY THE DSN
--
-- `epigraph_link_operator` is EXECUTE-able by `epigraph_maintenance` only.
-- PUBLIC and `epigraph_app` are revoked explicitly (a first `CREATE` leaves
-- `proacl` NULL, and a NULL `proacl` IS the default grant, which includes
-- EXECUTE to PUBLIC). A superuser can always call it. So the env var that
-- carries the operator id (`EPIGRAPH_OPERATOR_ID`) only DECLARES the link; the
-- privilege of the connection that calls this function is what AUTHORIZES it.
-- On an `epigraph_app` connection the call raises 42501 -- it is never a
-- silent no-op -- and `epigraph-mcp` treats that as fatal at startup.
--
-- ===================================================================
-- 3. RECORDED ONCE: NEVER REVIVE, NEVER ADMIN
--
-- `epigraph_ensure_personal_group` (077) upserts the membership with
-- `ON CONFLICT ... DO UPDATE SET revoked_at = NULL, role = 'admin'` -- correct
-- for an agent's OWN group at token mint, and the privilege-revival bug of
-- issue #493 if reused here. This file neither calls it nor copies its conflict
-- clause:
--
--   * the agent's membership is inserted ONLY when the roster holds NO row of
--     ANY state for (operator group, agent), AND with an untargeted
--     `ON CONFLICT DO NOTHING`. Two guards, on purpose: the conflict clause
--     alone lets a revoked row at a DIFFERENT epoch be shadowed by a fresh
--     epoch-0 insert (the composite UNIQUE is per-epoch and the partial
--     `group_memberships_one_live` index ignores revoked rows); the history
--     check alone races two concurrent first links. An operator who revokes an
--     agent's membership therefore keeps it revoked across every restart.
--   * the role is `writer`, never `admin`, so an operated agent can write rows
--     the operator's group owns and cannot manage that group's membership.
--   * the operator's group is created (if absent) with
--     `created_by_agent_id = p_operator`, NEVER the agent. 077/092's group
--     creator arm grants enrol and key-epoch rights to the creator while it
--     holds a live membership; stamping the agent as creator would make its
--     `writer` row admin-equivalent. When this function creates the group it
--     seeds the operator's own `admin` row, also DO NOTHING.
--   * the `OPERATED_BY` edge is inserted only when no edge of that relationship
--     exists between the pair IN ANY STATE, so a retracted link is not
--     re-asserted either.
--
-- RESIDUAL: a membership row that is HARD-deleted (rather than soft-revoked)
-- leaves no history, and the next link re-creates it. MEASURED on this tree:
-- every removal in `crates/epigraph-db/src/repos/` is a soft `UPDATE ... SET
-- revoked_at = now()`, as 092 section 3 also records.
--
-- ===================================================================
-- 4. THE READ SIDE: `epigraph_operator_of`, AND WHY IT IS A DEFINER
--
-- On an UNSTAMPED `epigraph_app` session `groups_tenancy` and
-- `group_memberships_tenancy` hide every row, so a read-first-then-mint helper
-- turns into an unconditional re-mint there (`claim_helper.rs`'s doc on
-- `begin_author_stamped_tx` records the measurement). The authoring path must
-- ask "does this agent have an operator, and what is the operator's group?"
-- WITHOUT depending on the caller's stamp, so the question is a `STABLE
-- SECURITY DEFINER` read granted to `epigraph_app`. It returns nothing it did
-- not already expose: `OPERATED_BY` edges are public (agent endpoints stamp
-- `('public', world)` in 070/072) and a personal group's id is derived from the
-- public `did:epigraph:personal:<agent>` key.
--
-- A LIVE LINK is BOTH halves: an `OPERATED_BY` edge in force AND a live
-- `writer`/`admin` membership in the target's personal group. The membership
-- conjunct is what keeps an HTTP server's auth-lineage edges (one per OAuth
-- principal that ever called it, and no membership) from reading as links. A
-- revoked membership therefore ends the link for authoring AND for ownership in
-- the same statement, with no second switch to forget.
--
-- More than one live link is returned as more than one row; the Rust callers
-- treat that as ambiguous (no operator for authoring and ownership, a refusal
-- for the HTTP startup gate). `epigraph_link_operator` refuses to create a
-- second live link, so ambiguity is reachable only through out-of-band writes.
--
-- ===================================================================
-- 5. OWNERSHIP IS THE MECHANISM, AS IN 086/089/092
--
-- Both bodies read or write FORCEd-RLS tables (`edges`, `groups`,
-- `group_memberships`), so they work only inside a definer frame that
-- `epigraph_definer_bypass()` admits, i.e. while the OWNER is a member of
-- `epigraph_maintenance`. The `OWNER TO` below sits in a `pg_roles` guard and
-- can silently no-op, so it is pinned in CI by
-- `schema_contract.rs::migration_102_operator_definers_are_owned_and_granted`
-- and at deploy by `tenancy_backfill.rs::DEFERRED_DEFINER_FUNCTIONS`. The
-- failure directions are both CLOSED: an unbypassed `epigraph_operator_of`
-- reads no link (agents author into their own group, as before this file), and
-- an unbypassed `epigraph_link_operator` is refused by the tenancy policies.
--
-- ===================================================================
-- 6. DEPLOY ORDER AND UNDO
--
-- `ClaimRepository::default_decl_for_author` calls `epigraph_operator_of`, so a
-- binary carrying this change FAILS CLOSED on every claim write against a
-- database that has not applied 102 (`42883 function does not exist`). Apply
-- 102 before, or with, the binary.
--
-- UNDO: `DROP FUNCTION IF EXISTS public.epigraph_link_operator(uuid, uuid)`
-- and `DROP FUNCTION IF EXISTS public.epigraph_operator_of(uuid)` -- but only
-- together with a binary that no longer calls them. Links already recorded are
-- ordinary `edges` / `group_memberships` rows; revoking the membership
-- (`UPDATE group_memberships SET revoked_at = now() ...`) ends a link without
-- any DDL. **Applied to a throwaway database only, NOT to any deployed
-- database.**
-- ===================================================================

-- The read. See section 4.
CREATE OR REPLACE FUNCTION public.epigraph_operator_of(p_agent uuid)
RETURNS TABLE (operator_id uuid, operator_group_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT DISTINCT e.target_id, g.id
      FROM public.edges e
      JOIN public.groups g
        ON g.did_key = 'did:epigraph:personal:' || e.target_id::text
       AND g.kind = 'personal'
      JOIN public.group_memberships m
        ON m.group_id = g.id
       AND m.agent_id = p_agent
       AND m.revoked_at IS NULL
       AND m.role IN ('writer', 'admin')
     WHERE e.source_id = p_agent
       AND e.source_type = 'agent'
       AND e.target_type = 'agent'
       AND e.relationship = 'OPERATED_BY'
       AND e.target_id <> p_agent
       AND (e.valid_to IS NULL OR e.valid_to > now())
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_of(uuid) FROM PUBLIC;

-- The write. See sections 2 and 3. Returns one row describing what it did, so
-- the caller can log the outcome rather than infer it.
--
-- The refusals use 22004 / 22023 / 55000 rather than 23503 / 23505 on purpose:
-- `DbError`'s `From<sqlx::Error>` folds foreign-key and unique violations into
-- message-less variants, and a startup refusal an operator cannot read is not a
-- refusal they can act on.
CREATE OR REPLACE FUNCTION public.epigraph_link_operator(p_agent uuid, p_operator uuid)
RETURNS TABLE (operator_group_id uuid,
               group_created boolean,
               membership_created boolean,
               membership_live boolean,
               edge_created boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_group     uuid;
    v_other     uuid;
    v_new_group uuid;
    v_mem_rows  integer := 0;
    v_edge_rows integer := 0;
BEGIN
    IF p_agent IS NULL OR p_operator IS NULL THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent and operator are both required'
            USING ERRCODE = '22004';
    END IF;
    IF p_agent = p_operator THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent % cannot be its own operator', p_agent
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.agents WHERE id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent % does not exist', p_agent
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.agents WHERE id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_operator: operator % does not exist', p_operator
            USING ERRCODE = '22023';
    END IF;
    -- Single hop. An operator that is itself operated would make "who owns
    -- this" depend on a chain nobody declared as a whole.
    IF EXISTS (SELECT 1 FROM public.epigraph_operator_of(p_operator)) THEN
        RAISE EXCEPTION 'epigraph_link_operator: % is itself operated by another agent and '
                        'cannot be an operator', p_operator
            USING ERRCODE = '55000';
    END IF;
    -- One live operator per agent. A second declaration is a configuration
    -- error to surface, not a link to add or a link to silently replace.
    SELECT o.operator_id INTO v_other
      FROM public.epigraph_operator_of(p_agent) o
     WHERE o.operator_id <> p_operator
     LIMIT 1;
    IF v_other IS NOT NULL THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent % already has a live link to operator %; '
                        'revoke that membership before linking it to %',
                        p_agent, v_other, p_operator
            USING ERRCODE = '55000';
    END IF;

    -- (a) The operator's personal group, spelled exactly as
    -- `epigraph_ensure_personal_group` spells it, created BY THE OPERATOR.
    INSERT INTO public.groups (display_name, did_key, public_key, kind,
                               created_by_agent_id)
    VALUES ('personal:' || p_operator::text,
            'did:epigraph:personal:' || p_operator::text,
            ''::bytea, 'personal', p_operator)
    ON CONFLICT DO NOTHING
    RETURNING id INTO v_new_group;

    IF v_new_group IS NOT NULL THEN
        v_group := v_new_group;
        -- A group this call created has an empty roster; give the operator the
        -- admin row its own token mint would have. DO NOTHING, never revive.
        INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share,
                                              epoch, role)
        VALUES (v_group, p_operator, ''::bytea, 0, 'admin')
        ON CONFLICT DO NOTHING;
    ELSE
        SELECT g.id INTO v_group FROM public.groups g
         WHERE g.did_key = 'did:epigraph:personal:' || p_operator::text;
    END IF;

    -- (b) The agent's writer membership: recorded once. Both guards are
    -- load-bearing -- see section 3.
    INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share,
                                          epoch, role)
    SELECT v_group, p_agent, ''::bytea, 0, 'writer'
     WHERE NOT EXISTS (SELECT 1 FROM public.group_memberships m
                        WHERE m.group_id = v_group AND m.agent_id = p_agent)
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_mem_rows = ROW_COUNT;

    -- (c) The edge, if no OPERATED_BY edge exists between the pair in any state.
    INSERT INTO public.edges (source_id, source_type, target_id, target_type,
                              relationship, properties)
    SELECT p_agent, 'agent', p_operator, 'agent', 'OPERATED_BY',
           jsonb_build_object('source', 'epigraph_link_operator')
     WHERE NOT EXISTS (SELECT 1 FROM public.edges e
                        WHERE e.source_id = p_agent AND e.target_id = p_operator
                          AND e.relationship = 'OPERATED_BY');
    GET DIAGNOSTICS v_edge_rows = ROW_COUNT;

    RETURN QUERY
    SELECT v_group,
           v_new_group IS NOT NULL,
           v_mem_rows > 0,
           EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = v_group AND m.agent_id = p_agent
                      AND m.revoked_at IS NULL),
           v_edge_rows > 0;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_link_operator(uuid, uuid) FROM PUBLIC;

-- Ownership and grants. Guarded, as every such block since 060 is: the roles
-- exist in a deployed cluster and not in every throwaway.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_operator_of(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_link_operator(uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_link_operator(uuid, uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_of(uuid) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_link_operator(uuid, uuid) '
                'FROM epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_of(uuid) '
                'TO epigraph_app';
    END IF;
END $$;
