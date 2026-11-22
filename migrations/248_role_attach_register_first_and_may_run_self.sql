-- 248_role_attach_register_first_and_may_run_self.sql
-- The role-attach verb refuses an identity the host has not registered yet,
-- and an application session asks "may this agent run?" only about itself.
--
-- ===================================================================
-- 1. WHY
--
-- (a) REGISTER FIRST (backlog 30ec8d72). 161's registration adopts a
-- never-registered identity only while it is FRESH: no row anywhere
-- references it through a foreign key into `agents`, except its own personal
-- group and membership, its `identity-legacy` key, audit rows and claims
-- (which AID05 decides). A `role_agents` row is such a reference. Under 166,
-- attaching an identity BEFORE the host first registered it therefore made
-- that registration abort `AID09`, and the identity stayed refused for
-- good: an operator following a role setup in the natural order (attach the
-- new job identity, then start it) got a job that could never register, and
-- a database error at start rather than a refusal at attach. 166 only
-- documented the order ("REGISTER, THEN ATTACH").
--
-- (b) MAY-RUN IS ABOUT ONESELF (backlog 1afdc93d). 166's
-- `epigraph_role_agent_may_run(agent)` answered `(may_run, role, holder,
-- reason)` about ANY agent to the application role. `agents` is
-- world-readable, so an application session could ask about every agent id
-- and rebuild the role roster (which agents are attached to which role) and
-- whether each role has a holder. Agent containers hold the application
-- DSN, so that reached beyond the server. 166 recorded it as an accepted
-- disclosure because epigraph-mcp needs the answer to refuse its own boot;
-- that need is about its own agent only.
--
-- ===================================================================
-- 2. THE RULES
--
-- (a) `epigraph_attach_agent_to_role` refuses `ROL03` (nothing written)
-- when the agent is one the host's registration would still ADOPT, which is
-- exactly when this attachment would be the thing that makes the
-- registration abort:
--   * it was never registered (no `agent_prompt_snapshots` row, and it is
--     no `agent_succession` child: 161's test), AND
--   * it authored no claim (else 161 refuses it `AID05` anyway), AND
--   * it is FRESH by 161's own scan, copied verbatim from the registration
--     body (161, unchanged through 166, 180 and 195): every single-column
--     foreign key into `agents` except `security_events` and `claims`, with
--     the personal-group, own-membership and `identity-legacy` exemptions,
--     plus the OAuth client owner and a second member of the personal group.
-- The message names the order: register it first (start it under the host
-- once), then attach. An identity the registration would refuse anyway (an
-- operator link already binds it, it authored claims, it holds a second
-- key) is attached as before: the attachment is not what refuses it. An
-- operator link written before the first registration is the same trap
-- through another verb (107's link); this file does not change the link.
-- The check runs under 107's `operator_links` advisory lock, which every
-- registration holds from its start (166's guard takes it too), so a
-- registration cannot commit between the freshness read and the INSERT.
-- Only the verb checks: a direct maintenance INSERT into `role_agents` meets
-- 166's guards alone, as before (the custodial path), and the registration's
-- own succession copy and the lineage follow attach registered successors
-- only.
--
-- (b) `epigraph_role_agent_may_run(agent)` answers in full, as before, a
-- PRIVILEGED session (`epigraph_bypass()`: a maintenance member or a
-- superuser) and a session whose login is a member of
-- `epigraph_identity_attestor` (the host, which asks about every identity it
-- starts). Any other session (the application role) is answered only about
-- its own stamped principal (`epigraph_principal_id()`); about any other
-- agent, or unstamped, it is refused `42501` and gets no row.
-- `AgentRepository::role_agent_may_run` (epigraph-mcp's boot check) stamps
-- the agent it asks about, transaction-local, on the connection it asks on.
-- LIMIT: the principal is a session setting, and a holder of the
-- application DSN can set it to any agent before asking. So this binds the
-- question to the caller's DECLARED principal, as 198's own-assignment read
-- does: it closes enumeration by code that stamps the principal it serves,
-- not by a session that forges its own stamp (the limit every check keyed on
-- the session's stamp shares).
--
-- ===================================================================
-- 3. RE-STATEMENTS
--
-- Both are 166's bodies with the deltas marked `248`. Signatures, owners and
-- ACLs are unchanged (CREATE OR REPLACE keeps both; `may_run` changes
-- LANGUAGE from sql to plpgsql, which CREATE OR REPLACE allows). A
-- precondition refuses (55000, nothing changed) unless each still carries
-- 166's body (md5 of `prosrc`).
--
-- ===================================================================
-- 4. UNDO
--
-- `docs/runbooks/248-undo.sql` re-states both 166 bodies verbatim. No
-- binary needs rolling back first: the repository's stamped ask works on
-- both bodies.
--
-- DEPLOY ORDER: `epigraph-mcp-full` built with this file's repository change
-- FIRST (or together), then this file. An older epigraph-mcp asks may_run
-- unstamped; on an application login it is then refused `42501` and refuses
-- to boot ("could not ask whether agent ... may run"). The new binary works
-- on a database below this file (166's body ignores the stamp). The host
-- asks on the attestor login and is unaffected.

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- Precondition: the two functions this file re-states still carry 166's
-- bodies. Any other body (a later re-statement applied out of order) would
-- be silently dropped by CREATE OR REPLACE; refuse instead.
-- -------------------------------------------------------------------
DO $$
DECLARE
    v_found text;
    v_check record;
BEGIN
    FOR v_check IN
        SELECT * FROM (VALUES
            ('public.epigraph_attach_agent_to_role(text, uuid, timestamptz, timestamptz, text)',
             '434b06ab5e01ac9d13953ed1c4a4b647'),
            ('public.epigraph_role_agent_may_run(uuid)',
             'eac9e167f74f426e664fd2c5e7f1f428')
        ) AS c(signature, expected)
    LOOP
        SELECT md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
         WHERE p.oid = to_regprocedure(v_check.signature);
        IF v_found IS DISTINCT FROM v_check.expected THEN
            RAISE EXCEPTION '248: % is not the body 248 re-states (166''s, md5 %); found md5 %. '
                            'Another migration re-bodied it, or 166 is not applied; nothing '
                            'was changed',
                            v_check.signature, v_check.expected, COALESCE(v_found, '(absent)')
                USING ERRCODE = '55000',
                      HINT = 'Apply a reconciling migration that re-states the function with '
                             'every delta instead of this one.';
        END IF;
    END LOOP;
END $$;

-- ===================================================================
-- (a) The attach verb (166's body); delta: the register-first refusal.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_attach_agent_to_role(
    p_role text, p_agent uuid, p_valid_from timestamptz, p_valid_to timestamptz,
    p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_id uuid;
    -- 248
    v_personal uuid;
    v_fk record;
    v_hit boolean;
    v_binding text;
BEGIN
    IF p_role IS NULL OR p_agent IS NULL OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_attach_agent_to_role: the role, the agent and a reason are '
                        'required'
            USING ERRCODE = '22004';
    END IF;
    -- 248: REGISTER FIRST. Refuse an identity the host's registration would
    -- still adopt, since this attachment would make that registration abort
    -- AID09. Under the lock every registration holds from its start, so none
    -- commits between this read and the INSERT (the guard re-takes it).
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    IF EXISTS (SELECT 1 FROM public.agents a WHERE a.id = p_agent)
       AND NOT EXISTS (SELECT 1 FROM public.agent_succession s WHERE s.child_agent_id = p_agent)
       AND NOT EXISTS (SELECT 1 FROM public.agent_prompt_snapshots s WHERE s.agent_id = p_agent)
       AND NOT EXISTS (SELECT 1 FROM public.claims c WHERE c.agent_id = p_agent) THEN
        -- 161's freshness scan, verbatim but for the variable names.
        SELECT g.id INTO v_personal
          FROM public.groups g
         WHERE g.did_key = 'did:epigraph:personal:' || p_agent::text
           AND g.kind = 'personal'
           AND g.created_by_agent_id = p_agent;
        FOR v_fk IN
            SELECT c.conrelid AS rel, a.attname AS col
              FROM pg_catalog.pg_constraint c
              JOIN pg_catalog.pg_attribute a
                ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
             WHERE c.contype = 'f'
               AND c.confrelid = 'public.agents'::regclass
               AND array_length(c.conkey, 1) = 1
               AND c.conrelid NOT IN ('public.security_events'::regclass,
                                      'public.claims'::regclass)
             ORDER BY c.conrelid::regclass::text, a.attname
        LOOP
            -- A table this owner cannot read is not "unbound" (161 refuses
            -- such an identity anyway), so it is not refused here.
            BEGIN
            EXECUTE format(
                'SELECT EXISTS (SELECT 1 FROM %s WHERE %I = $1%s)',
                v_fk.rel::regclass, v_fk.col,
                CASE
                    WHEN v_fk.rel = 'public.groups'::regclass
                        THEN ' AND id IS DISTINCT FROM $2'
                    WHEN v_fk.rel = 'public.group_memberships'::regclass
                        THEN ' AND group_id IS DISTINCT FROM $2'
                    WHEN v_fk.rel = 'public.agent_keys'::regclass
                         AND v_fk.col = 'agent_id'
                        THEN ' AND key_type <> ''identity-legacy'''
                    ELSE ''
                END)
              INTO v_hit
              USING p_agent, v_personal;
            EXCEPTION WHEN insufficient_privilege THEN
                v_hit := true;
            END;
            IF v_hit THEN
                v_binding := v_fk.rel::regclass::text || '.' || v_fk.col;
                EXIT;
            END IF;
        END LOOP;
        IF v_binding IS NULL AND EXISTS (SELECT 1 FROM public.oauth_clients oc
                                        WHERE oc.owner_id = p_agent) THEN
            v_binding := 'oauth_clients.owner_id';
        END IF;
        IF v_binding IS NULL AND v_personal IS NOT NULL
           AND EXISTS (SELECT 1 FROM public.group_memberships m
                        WHERE m.group_id = v_personal AND m.agent_id <> p_agent) THEN
            v_binding := 'another member of its personal group';
        END IF;
        IF v_binding IS NULL THEN
            RAISE EXCEPTION 'ROL03: agent % has not been registered by the host yet; register it '
                            'first, then attach it. Attaching it now would make its first '
                            'registration abort AID09 (the attachment binds it) and it would '
                            'stay refused', p_agent
                USING ERRCODE = 'ROL03',
                      HINT = 'Nothing was written. Start the identity under the host once (its '
                             'registration adopts it), then attach it to role ' || p_role || '.';
        END IF;
    END IF;
    INSERT INTO public.role_agents (role, agent_id, valid_from, valid_to, reason)
    VALUES (p_role, p_agent, COALESCE(p_valid_from, now()), p_valid_to, p_reason)
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;

-- ===================================================================
-- (b) The question (166's body); delta: an application session asks only
-- about its own stamped principal.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_role_agent_may_run(p_agent uuid)
RETURNS TABLE (may_run boolean, role text, holder uuid, reason text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
#variable_conflict use_column
BEGIN
    -- 248: session_user, never current_user (this frame runs as its owner).
    IF NOT public.epigraph_bypass()
       AND NOT COALESCE(
               (SELECT pg_has_role(session_user, 'epigraph_identity_attestor', 'MEMBER')
                 WHERE EXISTS (SELECT 1 FROM pg_roles
                                WHERE rolname = 'epigraph_identity_attestor')),
               false)
       AND p_agent IS DISTINCT FROM public.epigraph_principal_id() THEN
        RAISE EXCEPTION 'epigraph_role_agent_may_run: an application session asks only about '
                        'its own stamped principal (asked about %, stamped %)',
                        p_agent, COALESCE(public.epigraph_principal_id()::text, 'none')
            USING ERRCODE = '42501',
                  HINT = 'Stamp the agent as epigraph.principal_id on the asking connection '
                         '(AgentRepository::role_agent_may_run does), or ask on the identity '
                         'attestor''s login.';
    END IF;
    RETURN QUERY
    SELECT g.may_run, g.role, g.holder, g.reason
      FROM public.epigraph_role_agent_gate(p_agent, clock_timestamp()) g;
END $$;
