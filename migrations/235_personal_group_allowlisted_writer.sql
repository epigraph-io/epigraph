-- 235: `group-member add --role writer` reaches ONE kind of personal-group
-- member: the client-allowlisted agent of the group's own owner.
--
-- ===================================================================
-- 1. WHY (security ruling SR-3, gap GAP-4; backlog e694b36e)
--
-- SR-3 moves the host orchestrator (epiclaw-host) off the shared service
-- client onto a host-only OAuth client. The shared client's agent holds a
-- `writer` row in two groups: a team group and its operator's PERSONAL group,
-- where the host writes its claims. The new client's agent needs the same
-- rows. Before this file no supported verb could give it the personal one:
-- 164's `group-member add` serves verb-made keyless TEAM groups only
-- (GRP05 for every other kind), and the only REST membership route serves
-- communities. A delegated run token needs the same row: its delegator must
-- hold a live writer/admin membership of the operator's personal group
-- (`AgentRepository::delegated_principal_pool`, via
-- `epigraph_live_memberships`).
--
-- ===================================================================
-- 2. THE ARM (add)
--
-- `epigraph_team_group_add_member(group, agent, role, reason)` admits a
-- group that is not a verb-made team group in exactly one case. ALL of:
--
--   (P) the group is an ACTIVE `personal` group, keyless, whose `did_key` is
--       `did:epigraph:personal:<created_by_agent_id>` (108/176's personal
--       identity); its OWNER is `created_by_agent_id`;
--   (a) the agent's author binding is 'client_allowlist'
--       (`epigraph_author_binding`, 149's arm (c): a live allowance row, an
--       active service/agent client, no operator link of any state, operates
--       no agent, not a human, not a system agent);
--   (b) the agent's live human (`epigraph_human_of(agent, true)`, for an
--       allowlisted agent the allowance's operator) IS the group's owner;
--   (c) the caller is a maintenance session (or a superuser), as for every
--       164 verb: the body's first check, and EXECUTE is the maintenance
--       role's alone;
--   (d) the role is `writer`. Never `admin` (a personal group has one
--       admin, its owner) and never `reader` (the arm exists for the writer
--       the host needs, nothing else).
--
-- (a) and (b) are separate on purpose. (b) alone admits a LIVE-LINKED agent
-- of the owner (its human is the owner too); its row in the owner's group is
-- 107's link path's to write, and an operator who revoked that acting row
-- (the deactivation lever, 107 section 5) must not see it revived here. (a)
-- alone admits an agent allowlisted for ANOTHER human.
--
-- Everything else is refused GRP05, as before. The rest of 164's add runs
-- unchanged after the gate: GRP04 (the agent belongs to a live human; true
-- here by (a)), GRP03 (an operated agent joins only where its operator
-- WRITES: the owner must still hold its own live writer/admin row), the
-- "already a live member at another role" refusal, a new row at the next
-- epoch, and one `group.member_added` audit row, which now also carries
-- `arm = 'personal_client_allowlist'` and the group's kind.
--
-- The `operator_links` advisory lock (107 section 10) is taken BEFORE the
-- gate reads the binding, so a link written concurrently cannot change (a)
-- between the read and the INSERT. 149's revoke does not take that lock; a
-- revoke racing an add can therefore commit just before the add's row. That
-- row then lapses at once (section 4), and `remove` cleans it up.
--
-- ===================================================================
-- 3. REMOVE
--
-- `epigraph_team_group_remove_member(group, agent, reason)` revokes, in a
-- group that satisfies (P), the row of an agent that is NOT the owner and
-- holds an allowance row naming the owner, LIVE OR REVOKED (149 keeps
-- revoked rows forever). A revoked allowance is the main case: remove is
-- the clean-up after a revoke. Every other personal-group row (the owner's
-- own, a linked agent's, a human's, an agent allowlisted for someone else)
-- is still refused GRP05, so 107's link path keeps the rest of the roster.
-- 164's rules after the gate are unchanged (GRP02, GRP03, revoke not delete,
-- one audit row, which now also carries `arm` and the kind).
--
-- `set-role` is not extended: a personal group is still GRP05 there.
--
-- ===================================================================
-- 4. THE ROW LAPSES WITH THE ALLOWANCE (`epigraph_live_memberships`)
--
-- 165's body counts every live row of a group outside the verbs'
-- `did:epigraph:group:` namespace, which includes every personal group. So
-- without this section a row added by the arm would outlive its allowance:
-- after `revoke-author-binding-client` the agent's resolved viewer would
-- still read the owner's group and still carry it as writable. Claim writes
-- are refused OPL01 once the agent is unbound (armed), but evidence and edge
-- writes go through the membership door, which reads links only (149
-- section 1), and reads are not refused at all.
--
-- One conjunct, in 164 section 6's shape (computed at resolve time, the row
-- untouched): a live row of a PERSONAL group held by an agent that is not the
-- group's owner, and that has an allowance row (live or revoked) naming the
-- owner, counts only while `epigraph_human_of(agent, true)` is the owner.
-- Every other row counts exactly as before, in particular every row of an
-- agent that was never allowlisted for the owner (the owner's own, linked
-- agents', and any legacy row). 164's verb-made-group conjunct and 165's
-- derived UNION are kept verbatim.
--
-- On a deployed database this ALSO reaches a pre-existing row of that shape:
-- an agent allowlisted for O that already holds a row in O's personal group
-- keeps it while the allowance is live and loses it (at its next resolve)
-- once the allowance is revoked, which is the intent.
--
-- ===================================================================
-- 5. PRECONDITION, OWNER, GRANTS
--
-- This file re-states three bodies whole. It refuses to apply over a body
-- other than the one it was written from (md5 of `prosrc`, 165's
-- precondition shape): 164's add and remove, and 165's
-- `epigraph_live_memberships`. Owners and grants are unchanged (CREATE OR
-- REPLACE keeps them) and re-asserted below, role-guarded as every such block
-- since 060.
--
-- ===================================================================
-- UNDO: `docs/runbooks/235-undo.sql` (re-states the three predecessor bodies).
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_add    text;
    v_remove text;
    v_live   text;
BEGIN
    SELECT md5(p.prosrc) INTO v_add FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_team_group_add_member(uuid, uuid, text, text)');
    SELECT md5(p.prosrc) INTO v_remove FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_team_group_remove_member(uuid, uuid, text)');
    SELECT md5(p.prosrc) INTO v_live FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_live_memberships(uuid)');
    IF v_add IS DISTINCT FROM 'cb17e2a66f951f5fb59b11e1e5d0ee2d' THEN
        RAISE EXCEPTION '235: epigraph_team_group_add_member is not the body 235 re-states '
                        '(164''s, md5 cb17e2a66f951f5fb59b11e1e5d0ee2d); found md5 %. Another '
                        'migration re-bodied it; nothing was changed', COALESCE(v_add, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
    IF v_remove IS DISTINCT FROM 'd4238f78519cc7c41e6a5aea9bb188bf' THEN
        RAISE EXCEPTION '235: epigraph_team_group_remove_member is not the body 235 re-states '
                        '(164''s, md5 d4238f78519cc7c41e6a5aea9bb188bf); found md5 %. Another '
                        'migration re-bodied it; nothing was changed',
                        COALESCE(v_remove, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
    IF v_live IS DISTINCT FROM '1d22f82a109b5ccd55302670eec719f6' THEN
        RAISE EXCEPTION '235: epigraph_live_memberships(uuid) is not the body 235 re-states '
                        '(165''s, md5 1d22f82a109b5ccd55302670eec719f6); found md5 %. Another '
                        'migration re-bodied it; nothing was changed', COALESCE(v_live, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
END $$;

-- -------------------------------------------------------------------
-- add: 164's body; delta = the personal-group gate (section 2) and the
-- audit row's `arm` / `kind`.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_team_group_add_member(
    p_group uuid, p_agent uuid, p_role text, p_reason text)
RETURNS TABLE (out_membership_id uuid, out_applied boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_kind      text;
    v_did       text;
    v_key_len   integer;
    v_status    text;
    v_owner     uuid;
    v_personal  boolean := false;
    v_binding   text;
    v_human     uuid;
    v_live_id   uuid;
    v_live_role text;
    v_epoch     integer;
    v_id        uuid;
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_team_group_add_member: only a maintenance session changes a '
                        'team group roster' USING ERRCODE = '42501';
    END IF;
    IF p_group IS NULL OR p_agent IS NULL OR p_role IS NULL
       OR p_reason IS NULL OR btrim(p_reason) = '' THEN
        RAISE EXCEPTION 'epigraph_team_group_add_member: a group, an agent, a role and a '
                        'reason are required' USING ERRCODE = '22004';
    END IF;
    IF p_role NOT IN ('reader', 'writer', 'admin') THEN
        RAISE EXCEPTION 'epigraph_team_group_add_member: role % is not reader, writer or admin',
                        p_role USING ERRCODE = '22023';
    END IF;

    -- The group row lock first: every roster verb takes it, so roster
    -- decisions on one group are serialised (NO KEY: foreign-key writers
    -- naming the group are not blocked).
    SELECT g.kind::text, g.did_key, octet_length(g.public_key), g.status::text,
           g.created_by_agent_id
      INTO v_kind, v_did, v_key_len, v_status, v_owner
      FROM public.groups g WHERE g.id = p_group FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'epigraph_team_group_add_member: group % does not exist', p_group
            USING ERRCODE = '22023';
    END IF;
    -- 235 (P): an active personal group carrying its owner's identity.
    IF v_kind = 'personal' AND v_status = 'active' AND v_key_len = 0
       AND v_did = 'did:epigraph:personal:' || v_owner::text THEN
        -- Serialised with every link write BEFORE the binding is read.
        PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
        v_binding := public.epigraph_author_binding(p_agent);
        v_human := public.epigraph_human_of(p_agent, true);
        v_personal := COALESCE(
               p_role = 'writer'                                      -- (d)
           AND v_binding = 'client_allowlist'                         -- (a)
           AND v_human = v_owner                                      -- (b)
           , false);
        IF NOT v_personal THEN
            RAISE EXCEPTION 'GRP05: group % is the personal group of %; these verbs add to a '
                            'personal group only a writer that is its owner''s client-allowlisted '
                            'agent (migration 149), and agent % (binding %, live human %) at role '
                            '% is not; its roster has its own path',
                            p_group, v_owner, p_agent, COALESCE(v_binding, 'none'),
                            COALESCE(v_human::text, 'none'), p_role
                USING ERRCODE = 'GRP05',
                      HINT = 'Allow the agent''s client for the owner first '
                             '(epigraph-operator allow-author-binding-client), then add it '
                             'with --role writer.';
        END IF;
    END IF;
    IF NOT v_personal
       AND (v_kind <> 'team' OR v_did NOT LIKE 'did:epigraph:group:%' OR v_key_len <> 0
            OR v_status <> 'active') THEN
        RAISE EXCEPTION 'GRP05: group % is not an active team group made by these verbs (kind '
                        '%, did_key %, % key bytes, status %); its roster has its own path',
                        p_group, v_kind, v_did, v_key_len, v_status
            USING ERRCODE = 'GRP05';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.agents a WHERE a.id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_team_group_add_member: agent % does not exist', p_agent
            USING ERRCODE = '22023';
    END IF;

    -- Serialised with every link write (107 section 10), so a link or retire
    -- cannot change the answer below between the read and the INSERT.
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    v_human := public.epigraph_human_of(p_agent, true);
    IF v_human IS NULL OR NOT public.epigraph_is_human_operator(v_human) THEN
        RAISE EXCEPTION 'GRP04: agent % belongs to no live human operator (it is unbound, '
                        'retired-linked, or its operator''s registration is revoked); it '
                        'cannot be a member', p_agent
            USING ERRCODE = 'GRP04';
    END IF;
    IF v_human <> p_agent THEN
        IF p_role = 'admin' THEN
            RAISE EXCEPTION 'GRP01: agent % is operated by %, and a team group''s admin is a '
                            'Person', p_agent, v_human
                USING ERRCODE = 'GRP01';
        END IF;
        IF NOT public.epigraph_operator_writes_group(v_human, p_group) THEN
            RAISE EXCEPTION 'GRP03: agent % is operated by %, which holds no live writer or '
                            'admin membership in group %; an operated agent is a member only '
                            'where its operator writes', p_agent, v_human, p_group
                USING ERRCODE = 'GRP03',
                      HINT = 'Add the operator as a writer first.';
        END IF;
    END IF;

    SELECT m.id, m.role::text INTO v_live_id, v_live_role
      FROM public.group_memberships m
     WHERE m.group_id = p_group AND m.agent_id = p_agent AND m.revoked_at IS NULL;
    IF v_live_id IS NOT NULL THEN
        IF v_live_role = p_role THEN
            RETURN QUERY SELECT v_live_id, false;
            RETURN;
        END IF;
        RAISE EXCEPTION 'epigraph_team_group_add_member: agent % is already a live % of group '
                        '%; change the role with set-role', p_agent, v_live_role, p_group
            USING ERRCODE = '55000';
    END IF;

    -- Section 3 (164): a new row at the next epoch, never a revival.
    SELECT COALESCE(max(m.epoch) + 1, 0) INTO v_epoch
      FROM public.group_memberships m
     WHERE m.group_id = p_group AND m.agent_id = p_agent;
    INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
    VALUES (p_group, p_agent, ''::bytea, v_epoch, p_role)
    RETURNING id INTO v_id;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('group.member_added', p_agent, true,
            jsonb_build_object('group_id', p_group, 'member', p_agent, 'role', p_role,
                               'epoch', v_epoch, 'membership_id', v_id,
                               'operator', CASE WHEN v_human <> p_agent THEN v_human END,
                               'kind', v_kind,
                               'arm', CASE WHEN v_personal THEN 'personal_client_allowlist'
                                           ELSE 'team' END,
                               'reason', p_reason, 'session_user', session_user::text,
                               'actor', public.epigraph_team_group_actor()));
    RETURN QUERY SELECT v_id, true;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_team_group_add_member(uuid, uuid, text, text)
    FROM PUBLIC;

-- -------------------------------------------------------------------
-- remove (a revoke): 164's body; delta = the personal-group gate
-- (section 3) and the audit row's `arm` / `kind`.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_team_group_remove_member(
    p_group uuid, p_agent uuid, p_reason text)
RETURNS TABLE (out_membership_id uuid, out_applied boolean, out_prior_role text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_kind      text;
    v_did       text;
    v_key_len   integer;
    v_status    text;
    v_owner     uuid;
    v_personal  boolean := false;
    v_live_id   uuid;
    v_live_role text;
    v_operated  integer;
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_team_group_remove_member: only a maintenance session changes '
                        'a team group roster' USING ERRCODE = '42501';
    END IF;
    IF p_group IS NULL OR p_agent IS NULL OR p_reason IS NULL OR btrim(p_reason) = '' THEN
        RAISE EXCEPTION 'epigraph_team_group_remove_member: a group, an agent and a reason are '
                        'required' USING ERRCODE = '22004';
    END IF;

    SELECT g.kind::text, g.did_key, octet_length(g.public_key), g.status::text,
           g.created_by_agent_id
      INTO v_kind, v_did, v_key_len, v_status, v_owner
      FROM public.groups g WHERE g.id = p_group FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'epigraph_team_group_remove_member: group % does not exist', p_group
            USING ERRCODE = '22023';
    END IF;
    -- 235: in an active personal group, only the row of an agent (not the
    -- owner) that holds an allowance row naming the owner, live OR revoked.
    IF v_kind = 'personal' AND v_status = 'active' AND v_key_len = 0
       AND v_did = 'did:epigraph:personal:' || v_owner::text THEN
        v_personal := p_agent <> v_owner
            AND EXISTS (SELECT 1 FROM public.author_binding_clients r
                         WHERE r.agent_id = p_agent AND r.operator_id = v_owner);
        IF NOT v_personal THEN
            RAISE EXCEPTION 'GRP05: group % is the personal group of %; these verbs remove from '
                            'a personal group only an agent that was client-allowlisted for its '
                            'owner (migration 149), and agent % is not; its roster has its own '
                            'path', p_group, v_owner, p_agent
                USING ERRCODE = 'GRP05';
        END IF;
    END IF;
    IF NOT v_personal
       AND (v_kind <> 'team' OR v_did NOT LIKE 'did:epigraph:group:%' OR v_key_len <> 0
            OR v_status <> 'active') THEN
        RAISE EXCEPTION 'GRP05: group % is not an active team group made by these verbs (kind '
                        '%, did_key %, % key bytes, status %); its roster has its own path',
                        p_group, v_kind, v_did, v_key_len, v_status
            USING ERRCODE = 'GRP05';
    END IF;

    SELECT m.id, m.role::text INTO v_live_id, v_live_role
      FROM public.group_memberships m
     WHERE m.group_id = p_group AND m.agent_id = p_agent AND m.revoked_at IS NULL;
    IF v_live_id IS NULL THEN
        RETURN QUERY SELECT NULL::uuid, false, NULL::text;
        RETURN;
    END IF;

    IF v_live_role = 'admin' AND NOT EXISTS (
           SELECT 1 FROM public.group_memberships m
            WHERE m.group_id = p_group AND m.agent_id <> p_agent
              AND m.role = 'admin' AND m.revoked_at IS NULL
              AND public.epigraph_is_human_operator(m.agent_id)) THEN
        RAISE EXCEPTION 'GRP02: agent % is the last live admin of group % that is a registered '
                        'human operator; add another admin first', p_agent, p_group
            USING ERRCODE = 'GRP02';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    SELECT count(*) INTO v_operated
      FROM public.group_memberships m
     WHERE m.group_id = p_group AND m.agent_id <> p_agent AND m.revoked_at IS NULL
       AND public.epigraph_human_of(m.agent_id, true) = p_agent;
    IF v_operated > 0 THEN
        RAISE EXCEPTION 'GRP03: % agent(s) operated by % are live members of group %; remove '
                        'them first, an operated agent is a member only where its operator '
                        'writes', v_operated, p_agent, p_group
            USING ERRCODE = 'GRP03';
    END IF;

    UPDATE public.group_memberships SET revoked_at = now() WHERE id = v_live_id;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('group.member_removed', p_agent, true,
            jsonb_build_object('group_id', p_group, 'member', p_agent,
                               'prior_role', v_live_role, 'membership_id', v_live_id,
                               'kind', v_kind,
                               'arm', CASE WHEN v_personal THEN 'personal_client_allowlist'
                                           ELSE 'team' END,
                               'reason', p_reason, 'session_user', session_user::text,
                               'actor', public.epigraph_team_group_actor()));
    RETURN QUERY SELECT v_live_id, true, v_live_role;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_team_group_remove_member(uuid, uuid, text)
    FROM PUBLIC;

-- -------------------------------------------------------------------
-- The viewer's group-set read: 165's body (164's verb-made-group conjunct,
-- 165's derived UNION) plus the section-4 conjunct.
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_live_memberships(p_agent uuid)
RETURNS TABLE (group_id uuid, role text) LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT m.group_id, m.role::text
      FROM public.group_memberships m
      JOIN public.groups g ON g.id = m.group_id
     WHERE m.agent_id = p_agent AND m.revoked_at IS NULL
       AND (g.did_key NOT LIKE 'did:epigraph:group:%'
            OR public.epigraph_is_human_operator(public.epigraph_human_of(p_agent, true)))
       -- 235: a personal-group row of an agent allowlisted for the group's
       -- owner lapses with that allowance.
       AND (g.kind <> 'personal'
            OR g.created_by_agent_id = p_agent
            OR NOT EXISTS (SELECT 1 FROM public.author_binding_clients r
                            WHERE r.agent_id = p_agent
                              AND r.operator_id = g.created_by_agent_id)
            OR public.epigraph_human_of(p_agent, true) = g.created_by_agent_id)
    UNION
    SELECT d.group_id, d.role
      FROM public.epigraph_role_derived_memberships(p_agent, now()) d
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_live_memberships(uuid) FROM PUBLIC;

-- Ownership and grants, guarded as every such block since 060. Each
-- ALTER/GRANT names its function literally (tenancy_backfill.rs's static
-- re-own scan reads these statements).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_team_group_add_member(uuid, uuid, text, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_team_group_remove_member(uuid, uuid, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_live_memberships(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_team_group_add_member(uuid, uuid, text, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_team_group_remove_member(uuid, uuid, text) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        -- `Viewer::resolve` calls it on the application role (077, 164, 165).
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_live_memberships(uuid) '
                'TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_team_group_add_member(uuid, uuid, text, text) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_team_group_remove_member(uuid, uuid, text) '
                'FROM epigraph_app';
    END IF;
END $$;
