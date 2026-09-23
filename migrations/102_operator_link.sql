-- 102_operator_link.sql
-- Operator-scoped ownership: an agent process that is DECLARED to act for a
-- human operator writes into that operator's personal group, and the operator
-- (and the operator's other agents) own what it writes.
--
-- One definer-only table (`operator_links`), two SECURITY DEFINER functions,
-- no change to any existing policy, and no rows written by the migration
-- itself.
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
-- The link below is the missing record: a row in `operator_links` PLUS a live
-- `writer` membership for the agent in the operator's personal group. The
-- `agent --OPERATED_BY--> operator` edge is still written, as the GRAPH record
-- of the link, but it grants nothing (section 4).
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
-- The EXECUTE revoke is only half of that basis. The other half is that the
-- link RECORD cannot be written by anything else: see section 4.
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
--   * an EXISTING group is accepted only if it is `kind = 'personal'` AND
--     `created_by_agent_id = p_operator`, and `epigraph_operator_of` applies
--     the same test. The did_key alone is not proof: `groups_tenancy`'s WITH
--     CHECK lets ANY principal insert a group it creates, including one
--     carrying `did:epigraph:personal:<someone else>` (measured by review as
--     `epigraph_app` stamped as a principal Z, for an operator with no personal
--     group yet), and the link would then have enrolled the agent as a writer
--     in Z's group. Every in-tree personal-group writer (077's
--     `epigraph_ensure_personal_group`, 071's shim, `tenancy_backfill`) stamps
--     the agent itself as creator, so this refuses nothing legitimate.
--   * the `operator_links` row is keyed on the agent and inserted
--     `ON CONFLICT (agent_id) DO NOTHING`. An agent has at most one operator,
--     ever: a row naming a DIFFERENT operator is refused rather than replaced,
--     whatever the state of that other link's membership. Re-pointing an agent
--     is a deliberate out-of-band act, not something a restart can do.
--   * the `OPERATED_BY` edge is inserted only when no edge of that relationship
--     exists between the pair IN ANY STATE, so a retracted edge is not
--     re-asserted either.
--
-- RESIDUAL: a membership row that is HARD-deleted (rather than soft-revoked)
-- leaves no history, and the next link re-creates it. MEASURED on this tree:
-- every removal in `crates/epigraph-db/src/repos/` is a soft `UPDATE ... SET
-- revoked_at = now()`, as 092 section 3 also records.
--
-- ===================================================================
-- 4. THE LINK RECORD IS A DEFINER-ONLY TABLE, NOT AN EDGE
--
-- An earlier form of this file had no table: a link was "an in-force
-- `OPERATED_BY` edge AND a live writer membership". MEASURED by review on a
-- throwaway migrated to this file, as `SET SESSION AUTHORIZATION epigraph_app`
-- stamped exactly as `Viewer::resolve` stamps an ordinary principal P, BOTH
-- halves were writable without `epigraph_maintenance`:
--
--   * `groups_tenancy` / `group_memberships_tenancy` let P insert a `writer`
--     row for ANY agent X into P's own personal group, and `edges` accepts an
--     `X --OPERATED_BY--> P` edge from P's session. P thereby became X's
--     "operator" -- owner of all X's claims, and owner-group of X's future
--     writes -- without X's consent and without the maintenance grant.
--   * worse, `record_auth_lineage` ALREADY writes `signer --OPERATED_BY--> P`
--     for every OAuth caller P of an HTTP server, so ONE membership row from P
--     made the shared HTTP signer "operated by P" at runtime.
--
-- REST `create_edge` also accepts `OPERATED_BY` with arbitrary `properties`, so
-- marking the edge (`properties->>'source'`) would not have been a fix either.
-- The authority therefore lives in `operator_links`, which only a definer frame
-- (or a maintenance login) can write:
--
--   * ENABLE + FORCE row security, with an INSERT policy whose only disjunct is
--     `epigraph_definer_bypass()`, i.e. `current_user` a member of
--     `epigraph_maintenance`. Inside `epigraph_link_operator` that is the
--     function OWNER; on an `epigraph_app` session it is false. A maintenance
--     login satisfies it too, which is the same trust the link function
--     already extends to that role.
--   * a SELECT policy of `epigraph_bypass() OR epigraph_definer_bypass()`, so the
--     definer reads below and a maintenance session can see rows and an app
--     session sees none.
--   * NO UPDATE and NO DELETE policy: under FORCE that is a default-deny for
--     every role that is not a superuser. A link is ended by revoking the
--     membership (section 5), never by editing this row.
--     `rls_enforcement.rs::DELIBERATELY_UNCOVERED` records both pairs.
--   * `REVOKE ALL ... FROM PUBLIC, epigraph_app`, then `GRANT SELECT` back to
--     `epigraph_app`. 077's `ALTER DEFAULT PRIVILEGES` would otherwise hand
--     `epigraph_app` INSERT/UPDATE/DELETE on this table the moment it is
--     created. SELECT is kept because
--     `rls_enforcement.rs::the_app_role_can_reach_every_public_table_without_the_test_fixture`
--     requires it of every relation, and it discloses nothing: the SELECT
--     policy admits no row to an app session. The policies are the control;
--     the revoke is the second lock.
--
-- The table carries no `visibility` / `owner_group_id` columns on purpose: it is
-- control state, not a tenancy-partitioned entity, and
-- `locked_decisions.rs` recovers 062's `tier_a` from exactly those two column
-- names.
--
-- ===================================================================
-- 5. THE READ SIDE: `epigraph_operator_of`, AND WHY IT IS A DEFINER
--
-- On an UNSTAMPED `epigraph_app` session `groups_tenancy` and
-- `group_memberships_tenancy` hide every row, so a read-first-then-mint helper
-- turns into an unconditional re-mint there (`claim_helper.rs`'s doc on
-- `begin_author_stamped_tx` records the measurement). The authoring path must
-- ask "does this agent have an operator, and what is the operator's group?"
-- WITHOUT depending on the caller's stamp, so the question is a `STABLE
-- SECURITY DEFINER` read granted to `epigraph_app`.
--
-- A LIVE LINK is BOTH halves: the `operator_links` row AND a live
-- `writer`/`admin` membership for the agent in the group that row names. The
-- row is what makes the link unforgeable; the membership conjunct is what lets
-- the operator END it with an ordinary revoke. A revoked membership therefore
-- ends the link for authoring AND for ownership in the same statement, with no
-- second switch to forget.
--
-- DISCLOSURE, ACCEPTED: the function answers for ANY agent id, so an app
-- session can learn whether an agent is operated, by whom, and -- through the
-- membership conjunct -- whether that one membership is live, which
-- `group_memberships_tenancy` would otherwise hide from a non-member. The
-- operator relationship is already public through the `OPERATED_BY` edge
-- (agent endpoints stamp `('public', world)` in 070/072) and a personal group's
-- id follows from the public `did:epigraph:personal:<agent>` key, so the new
-- information is one liveness bit per link. That is accepted rather than bound
-- to the session principal (083's shape): the authoring path must ask about
-- the AUTHOR, and the ownership gate about the claim's author, neither of which
-- is the session principal.
--
-- ===================================================================
-- 6. OWNERSHIP IS THE MECHANISM, AS IN 086/089/092
--
-- Both bodies read or write FORCEd-RLS tables (`operator_links`, `edges`,
-- `groups`, `group_memberships`), so they work only inside a definer frame that
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
-- 7. DEPLOY ORDER AND UNDO
--
-- `ClaimRepository::default_decl_for_author` calls `epigraph_operator_of`, so a
-- binary carrying this change FAILS CLOSED on every claim write against a
-- database that has not applied 102 (`42883 function does not exist`). Apply
-- 102 before, or with, the binary.
--
-- UNDO: `DROP FUNCTION IF EXISTS public.epigraph_link_operator(uuid, uuid)`,
-- `DROP FUNCTION IF EXISTS public.epigraph_operator_of(uuid)` and
-- `DROP TABLE IF EXISTS public.operator_links` -- but only together with a
-- binary that no longer calls them, and after removing `operator_links` from
-- `epigraph_api::state::FORCE_PROTECTED_SET` (its boot assertion counts FORCEd
-- relations). Revoking the agent's membership
-- (`UPDATE group_memberships SET revoked_at = now() ...`) ends one link
-- without any DDL. **Applied to a throwaway database only, NOT to any deployed
-- database.**
-- ===================================================================

-- The link record. See section 4.
CREATE TABLE IF NOT EXISTS public.operator_links (
    agent_id          uuid PRIMARY KEY REFERENCES public.agents(id) ON DELETE RESTRICT,
    operator_id       uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    operator_group_id uuid NOT NULL REFERENCES public.groups(id) ON DELETE RESTRICT,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT operator_links_not_self CHECK (agent_id <> operator_id)
);
CREATE INDEX IF NOT EXISTS idx_operator_links_operator
    ON public.operator_links (operator_id);

ALTER TABLE public.operator_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.operator_links FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS operator_links_definer_read ON public.operator_links;
CREATE POLICY operator_links_definer_read ON public.operator_links
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()));

DROP POLICY IF EXISTS operator_links_definer_insert ON public.operator_links;
CREATE POLICY operator_links_definer_insert ON public.operator_links
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_definer_bypass()));

REVOKE ALL ON public.operator_links FROM PUBLIC;

-- The read. See section 5.
CREATE OR REPLACE FUNCTION public.epigraph_operator_of(p_agent uuid)
RETURNS TABLE (operator_id uuid, operator_group_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT l.operator_id, l.operator_group_id
      FROM public.operator_links l
      JOIN public.groups g
        ON g.id = l.operator_group_id
       AND g.kind = 'personal'
       AND g.created_by_agent_id = l.operator_id
      JOIN public.group_memberships m
        ON m.group_id = l.operator_group_id
       AND m.agent_id = l.agent_id
       AND m.revoked_at IS NULL
       AND m.role IN ('writer', 'admin')
     WHERE l.agent_id = p_agent
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
               edge_created boolean,
               link_live boolean)
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
    -- Single hop, enforced from BOTH ends. An operator that is itself
    -- operated, or an agent that already operates others, would make "who
    -- owns this" depend on a chain nobody declared as a whole. Checking only
    -- the first end let the order link(X, O) then link(O, P) build X -> O -> P
    -- (measured by review); the second check closes that order.
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_operator: % is itself operated by another agent and '
                        'cannot be an operator', p_operator
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.operator_id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_link_operator: % already operates other agents and cannot '
                        'itself be operated', p_agent
            USING ERRCODE = '55000';
    END IF;
    -- One operator per agent, ever. A second declaration is a configuration
    -- error to surface, not a link to add or a link to silently replace --
    -- whatever the state of the first link's membership.
    SELECT l.operator_id INTO v_other
      FROM public.operator_links l
     WHERE l.agent_id = p_agent AND l.operator_id <> p_operator;
    IF v_other IS NOT NULL THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent % already has a link to operator %; '
                        'an agent is linked to one operator, and re-pointing it is an '
                        'out-of-band act', p_agent, v_other
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

    -- The group must BE the operator's: a personal group the operator
    -- created. See section 3. A row that merely carries the operator's
    -- did_key -- pre-created by someone else, which `groups_tenancy`'s creator
    -- WITH CHECK permits for any principal -- is refused rather than joined.
    IF NOT EXISTS (SELECT 1 FROM public.groups g
                    WHERE g.id = v_group
                      AND g.kind = 'personal'
                      AND g.created_by_agent_id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_operator: the group carrying did:epigraph:personal:% '
                        'is not a personal group created by that operator; refusing to enrol '
                        '% in it', p_operator, p_agent
            USING ERRCODE = '55000';
    END IF;

    -- (b) The link record: recorded once. See section 4.
    INSERT INTO public.operator_links (agent_id, operator_id, operator_group_id)
    VALUES (p_agent, p_operator, v_group)
    ON CONFLICT (agent_id) DO NOTHING;

    -- (c) The agent's writer membership: recorded once. Both guards are
    -- load-bearing -- see section 3.
    INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share,
                                          epoch, role)
    SELECT v_group, p_agent, ''::bytea, 0, 'writer'
     WHERE NOT EXISTS (SELECT 1 FROM public.group_memberships m
                        WHERE m.group_id = v_group AND m.agent_id = p_agent)
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_mem_rows = ROW_COUNT;

    -- (d) The graph record, if no OPERATED_BY edge exists between the pair in
    -- any state. It grants nothing; see section 4.
    INSERT INTO public.edges (source_id, source_type, target_id, target_type,
                              relationship, properties)
    SELECT p_agent, 'agent', p_operator, 'agent', 'OPERATED_BY',
           jsonb_build_object('source', 'epigraph_link_operator')
     WHERE NOT EXISTS (SELECT 1 FROM public.edges e
                        WHERE e.source_id = p_agent AND e.target_id = p_operator
                          AND e.relationship = 'OPERATED_BY');
    GET DIAGNOSTICS v_edge_rows = ROW_COUNT;

    -- `link_live` is computed by the SAME read the authoring and ownership
    -- paths use, not re-derived here. `membership_live` alone over-reports: a
    -- live membership whose role is no longer writer/admin (review probe: role
    -- set to 'reader', then re-link) returned membership_live=t while
    -- `epigraph_operator_of` returned nothing, and the startup log said the
    -- agent authored into the operator's group when it did not.
    RETURN QUERY
    SELECT v_group,
           v_new_group IS NOT NULL,
           v_mem_rows > 0,
           EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = v_group AND m.agent_id = p_agent
                      AND m.revoked_at IS NULL),
           v_edge_rows > 0,
           EXISTS (SELECT 1 FROM public.epigraph_operator_of(p_agent) o
                    WHERE o.operator_id = p_operator);
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
        EXECUTE 'GRANT SELECT, INSERT ON public.operator_links TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_link_operator(uuid, uuid) '
                'FROM epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_of(uuid) '
                'TO epigraph_app';
        EXECUTE 'REVOKE ALL ON public.operator_links FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.operator_links TO epigraph_app';
    END IF;
END $$;
