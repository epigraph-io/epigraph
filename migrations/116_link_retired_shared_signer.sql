-- 116: an ATTESTED retired link for a FORMER shared HTTP signer (batch HTTP-id).
--
-- ===================================================================
-- 1. WHY
--
-- Before batch H-b, an HTTP MCP listener authored every caller's writes as
-- its one signer agent, so that agent authored claims -- backlog items
-- among them -- on behalf of every principal that ever called through it.
-- Batch H-b made an authenticated caller's writes its own, and batch HTTP-id
-- made a principal-less caller's writes refused by default, so a listener's
-- signer now authors nothing new. What it already authored still belongs to no
-- human: no link names an operator for it, so over HTTP nobody but a
-- claims:admin can retire those items.
--
-- The existing tool for exactly that shape -- a historical identity whose
-- claims should belong to its operator -- is migration 107's
-- `epigraph_link_retired_agent` (section 7). It refuses a shared signer on
-- purpose (107 section 9): `record_auth_lineage` writes
-- `signer --OPERATED_BY--> P` for every OAuth caller P, so a signer with
-- lineage edges to MORE THAN ONE principal carried other principals' writes,
-- and linking it would make one operator the owner of all of them. That
-- refusal is right in general and stays in force.
--
-- It is wrong for one case: a deployment whose every principal is the same
-- human, who attests that the signer's writes were all theirs (the
-- "Agents are owned by their spawning human" ruling). This function records
-- that attestation explicitly, instead of weakening 107's check for everyone.
--
-- ===================================================================
-- 2. THE ATTESTATION, AND WHAT IT DOES AND DOES NOT PROVE
--
-- `epigraph_link_retired_shared_signer(agent, operator, attested uuid[])`:
-- every distinct OPERATED_BY lineage target of `agent`, other than `agent`
-- itself (the principal-less listener writes a self-loop: its injected
-- principal IS the signer) and other than `operator`, must appear in
-- `attested`. An unattested target refuses the call (55000) and names it.
--
-- That check is a SANITY CHECK, not proof:
--   * lineage edges exist only since `record_auth_lineage` shipped; callers
--     before it left none, so the edge set is not the full caller set;
--   * the edges are forgeable (107 section 9: any app session can insert an
--     agent-to-agent OPERATED_BY edge). A forged edge can only ADD a target,
--     which makes this call refuse more, never less.
-- The authority is the maintenance caller's attestation, which is why the
-- function is EXECUTE-able by `epigraph_maintenance` only and writes the
-- attested set to `security_events` (event `operator.shared_signer_retired`)
-- and onto the OPERATED_BY edge it records.
--
-- ===================================================================
-- 3. EVERYTHING ELSE IS 107's RETIRE, UNCHANGED
--
-- Written out again on purpose (107 does the same for its two link
-- functions), with the same order and the same refusals: both ids required,
-- no self-link, both agents exist, the operator is not itself operated, the
-- agent operates no one, no link to a different operator, no ACTOR link for
-- this pair (a retire is not a demotion), the OPERATOR-side shared-signer
-- fingerprint (unchanged: an operator that fronted many principals is still
-- refused), the operator's personal group through 105's definer (RVK01 /
-- RVK02 abort), and ZERO write authority as a precondition (a live
-- writer/admin row for the agent in the operator's group refuses). The link
-- is `retired = true` and creates NO membership, so the former signer can
-- never act for the operator (107 section 7), and an HTTP listener still
-- refuses to start, and refuses every call, under a signer with any link
-- (`epigraph_mcp::operator`). The key must therefore not be serving when this
-- runs; the ops runbook moves the listeners to fresh keys first.
--
-- An exact relink (a row for this pair already exists) records nothing new and
-- skips the lineage checks, as 107 does, so forged edges added later cannot
-- turn an idempotent re-run into a refusal.
--
-- ===================================================================
-- 4. UNDO
--
-- `DROP FUNCTION IF EXISTS public.epigraph_link_retired_shared_signer(uuid, uuid, uuid[])`.
-- A link it recorded is an `operator_links` row like 107's and is permanent
-- by the same rule (no UPDATE/DELETE policy). **Applied to a throwaway
-- database only, NOT to any deployed database.**

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_link_retired_shared_signer(
    p_agent    uuid,
    p_operator uuid,
    p_attested uuid[])
RETURNS TABLE (operator_group_id uuid,
               group_created boolean,
               link_created boolean,
               link_retired boolean,
               edge_created boolean,
               membership_live boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_group         uuid;
    v_other         uuid;
    v_group_existed boolean;
    v_first_link    boolean;
    v_lineage       uuid[] := '{}';
    v_unattested    uuid[] := '{}';
    v_link_rows     integer := 0;
    v_edge_rows     integer := 0;
BEGIN
    IF p_agent IS NULL OR p_operator IS NULL OR p_attested IS NULL THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent, operator and the attested '
                        'principal set are all required (the set may be empty)'
            USING ERRCODE = '22004';
    END IF;
    IF p_agent = p_operator THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent % cannot be its own operator',
                        p_agent
            USING ERRCODE = '22023';
    END IF;
    -- 107 section 10: every link write takes this lock before reading links.
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    IF NOT EXISTS (SELECT 1 FROM public.agents WHERE id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent % does not exist', p_agent
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.agents WHERE id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: operator % does not exist',
                        p_operator
            USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: % is itself operated by another '
                        'agent and cannot be an operator', p_operator
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.operator_id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: % already operates other agents '
                        'and cannot itself be operated', p_agent
            USING ERRCODE = '55000';
    END IF;
    SELECT l.operator_id INTO v_other
      FROM public.operator_links l
     WHERE l.agent_id = p_agent AND l.operator_id <> p_operator;
    IF v_other IS NOT NULL THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent % already has a link to '
                        'operator %; an agent is linked to one operator, and re-pointing it is '
                        'an out-of-band act', p_agent, v_other
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l
                WHERE l.agent_id = p_agent AND l.operator_id = p_operator
                  AND NOT l.retired) THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent % already has an ACTOR (not '
                        'retired) link to operator %, and a retired link cannot replace it',
                        p_agent, p_operator
            USING ERRCODE = '55000',
                  HINT = 'End its authority by revoking its membership in the operator''s '
                         'group; the operator keeps ownership of its claims either way.';
    END IF;

    v_first_link := NOT EXISTS (SELECT 1 FROM public.operator_links l
                                 WHERE l.agent_id = p_agent AND l.operator_id = p_operator);
    IF v_first_link THEN
        -- The AGENT side: every principal it carried, except itself and the
        -- operator, must be attested (section 2).
        SELECT COALESCE(array_agg(DISTINCT e.target_id ORDER BY e.target_id), '{}')
          INTO v_lineage
          FROM public.edges e
         WHERE e.source_id = p_agent AND e.relationship = 'OPERATED_BY'
           AND e.target_id <> p_agent;
        SELECT COALESCE(array_agg(t ORDER BY t), '{}')
          INTO v_unattested
          FROM unnest(v_lineage) AS t
         WHERE t <> p_operator AND NOT (t = ANY (p_attested));
        IF cardinality(v_unattested) > 0 THEN
            RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent % carried OPERATED_BY '
                            'auth-lineage to principals that were not attested: %; nothing was '
                            'written', p_agent, v_unattested
                USING ERRCODE = '55000',
                      HINT = 'Attest a principal only if every write the signer made for it '
                             'belongs to the operator.';
        END IF;
        -- The OPERATOR side: unchanged from 107 section 9.
        IF (SELECT count(DISTINCT e.target_id) FROM public.edges e
             WHERE e.source_id = p_operator AND e.relationship = 'OPERATED_BY') > 1 THEN
            RAISE EXCEPTION 'epigraph_link_retired_shared_signer: operator % carries OPERATED_BY '
                            'auth-lineage edges to more than one principal, the fingerprint of a '
                            'shared HTTP signer; refusing it as an operator', p_operator
                USING ERRCODE = '55000';
        END IF;
    END IF;

    -- The operator's personal group, through 105's definer (107 section 3).
    v_group_existed := EXISTS (SELECT 1 FROM public.groups g
                                WHERE g.did_key = 'did:epigraph:personal:' || p_operator::text);
    v_group := public.epigraph_ensure_personal_group(p_operator);

    -- ZERO write authority is a precondition (107 section 7), locked in the
    -- order every roster writer takes them.
    PERFORM 1 FROM public.group_memberships m
     WHERE m.group_id = v_group AND m.agent_id = p_agent
       FOR UPDATE;
    PERFORM 1 FROM public.groups g WHERE g.id = v_group FOR UPDATE;
    IF EXISTS (SELECT 1 FROM public.group_memberships m
                WHERE m.group_id = v_group AND m.agent_id = p_agent
                  AND m.revoked_at IS NULL AND m.role IN ('writer', 'admin')) THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent % holds a live writer/admin '
                        'membership in operator group %, and a retired identity may hold no '
                        'write authority there', p_agent, v_group
            USING ERRCODE = '55000',
                  HINT = 'Revoke that membership first, then retire the agent.';
    END IF;

    INSERT INTO public.operator_links (agent_id, operator_id, operator_group_id, retired)
    VALUES (p_agent, p_operator, v_group, true)
    ON CONFLICT (agent_id) DO NOTHING;
    GET DIAGNOSTICS v_link_rows = ROW_COUNT;

    INSERT INTO public.edges (source_id, source_type, target_id, target_type,
                              relationship, properties)
    SELECT p_agent, 'agent', p_operator, 'agent', 'OPERATED_BY',
           jsonb_build_object('source', 'epigraph_link_retired_shared_signer',
                              'attested', to_jsonb(p_attested))
     WHERE NOT EXISTS (SELECT 1 FROM public.edges e
                        WHERE e.source_id = p_agent AND e.target_id = p_operator
                          AND e.relationship = 'OPERATED_BY');
    GET DIAGNOSTICS v_edge_rows = ROW_COUNT;

    -- The attestation, on the record, once: only when this call created the
    -- link (an exact relink attests nothing new).
    IF v_link_rows > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('operator.shared_signer_retired', p_agent, true,
                jsonb_build_object('operator_id', p_operator,
                                   'operator_group_id', v_group,
                                   'attested', to_jsonb(p_attested),
                                   'lineage_targets', to_jsonb(v_lineage),
                                   'recorded_by', session_user));
    END IF;

    RETURN QUERY
    SELECT v_group,
           NOT v_group_existed,
           v_link_rows > 0,
           EXISTS (SELECT 1 FROM public.operator_links l
                    WHERE l.agent_id = p_agent AND l.retired),
           v_edge_rows > 0,
           EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = v_group AND m.agent_id = p_agent
                      AND m.revoked_at IS NULL);
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_link_retired_shared_signer(uuid, uuid, uuid[])
    FROM PUBLIC;

-- Ownership and grants, guarded as every such block since 060 is.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_link_retired_shared_signer(uuid, uuid, uuid[]) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_link_retired_shared_signer(uuid, uuid, uuid[]) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_link_retired_shared_signer(uuid, uuid, uuid[]) '
                'FROM epigraph_app';
    END IF;
END $$;
