-- ===================================================================
-- 235-undo.sql: take migration 235 (`group-member add --role writer` of a
-- client-allowlisted agent into its owner's PERSONAL group, and the lapse of
-- such a row with its allowance) back out, in ONE transaction, on the
-- migration (superuser) DSN.
--
-- WHAT IT DOES: re-states the three bodies 235 replaced, verbatim from their
-- predecessors (CREATE OR REPLACE keeps owner and grants):
--   * `epigraph_team_group_add_member`    (164's body: GRP05 for every
--     group that is not a verb-made team group, personal groups included);
--   * `epigraph_team_group_remove_member` (164's body, likewise);
--   * `epigraph_live_memberships`         (165's body: every live row of a
--     personal group counts, whatever its member's binding).
--
-- WHAT IT LEAVES:
--   * every membership row the arm wrote, and its `group.member_added` audit
--     row (082: immutable). Those rows are then counted UNCONDITIONALLY by
--     the viewer (165's body): an agent whose allowance was revoked keeps
--     reading its former operator's personal group. List them first and
--     revoke each with `group-member remove` BEFORE running this file (after
--     it, remove refuses them with GRP05):
--       SELECT details->>'group_id' AS group_id, agent_id, details->>'membership_id'
--         FROM public.security_events
--        WHERE event_type = 'group.member_added'
--          AND details->>'arm' = 'personal_client_allowlist';
--   * 235's `_sqlx_migrations` row. Re-introducing the arm is a NEW
--     migration, never a re-run of 235.
--
-- Roll back first any operator kit step that relies on the arm (SR-3 GAP-4).
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

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
    SELECT g.kind::text, g.did_key, octet_length(g.public_key), g.status::text
      INTO v_kind, v_did, v_key_len, v_status
      FROM public.groups g WHERE g.id = p_group FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'epigraph_team_group_add_member: group % does not exist', p_group
            USING ERRCODE = '22023';
    END IF;
    IF v_kind <> 'team' OR v_did NOT LIKE 'did:epigraph:group:%' OR v_key_len <> 0
       OR v_status <> 'active' THEN
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

    -- Section 3: a new row at the next epoch, never a revival.
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
                               'reason', p_reason, 'session_user', session_user::text,
                               'actor', public.epigraph_team_group_actor()));
    RETURN QUERY SELECT v_id, true;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_team_group_add_member(uuid, uuid, text, text)
    FROM PUBLIC;

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

    SELECT g.kind::text, g.did_key, octet_length(g.public_key), g.status::text
      INTO v_kind, v_did, v_key_len, v_status
      FROM public.groups g WHERE g.id = p_group FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'epigraph_team_group_remove_member: group % does not exist', p_group
            USING ERRCODE = '22023';
    END IF;
    IF v_kind <> 'team' OR v_did NOT LIKE 'did:epigraph:group:%' OR v_key_len <> 0
       OR v_status <> 'active' THEN
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
                               'reason', p_reason, 'session_user', session_user::text,
                               'actor', public.epigraph_team_group_actor()));
    RETURN QUERY SELECT v_live_id, true, v_live_role;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_team_group_remove_member(uuid, uuid, text)
    FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_live_memberships(p_agent uuid)
RETURNS TABLE (group_id uuid, role text) LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT m.group_id, m.role::text
      FROM public.group_memberships m
      JOIN public.groups g ON g.id = m.group_id
     WHERE m.agent_id = p_agent AND m.revoked_at IS NULL
       AND (g.did_key NOT LIKE 'did:epigraph:group:%'
            OR public.epigraph_is_human_operator(public.epigraph_human_of(p_agent, true)))
    UNION
    SELECT d.group_id, d.role
      FROM public.epigraph_role_derived_memberships(p_agent, now()) d
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_live_memberships(uuid) FROM PUBLIC;

COMMIT;
