-- 248_role_attach_register_first_and_may_run_self.sql
-- The role-attach verb refuses an identity the host has not registered yet.
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
-- ===================================================================
-- 3. RE-STATEMENTS
--
-- 166's body with the delta marked `248`. Signature, owner and ACL are
-- unchanged (CREATE OR REPLACE keeps both). A precondition refuses (55000,
-- nothing changed) unless it still carries 166's body (md5 of `prosrc`).
--
-- ===================================================================
-- 4. UNDO
--
-- `docs/runbooks/248-undo.sql` re-states 166's body verbatim. No order
-- against the binaries.

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- Precondition: the function this file re-states still carries 166's
-- body. Any other body (a later re-statement applied out of order) would
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
             '434b06ab5e01ac9d13953ed1c4a4b647')
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
