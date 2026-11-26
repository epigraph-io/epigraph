-- Undo migration 321 (team_invite_no_human_oracle): restore 263's body of the invite, which
-- refuses a non-human invitee (TGP03) again. Run on a maintenance connection. CREATE OR
-- REPLACE keeps the owner and ACL. Invitations written since stay (one addressed to a
-- non-person is never accepted). Idempotent.
CREATE OR REPLACE FUNCTION public.epigraph_invite_to_team_group(
    p_group uuid, p_invitee uuid, p_role text, p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_reason    text := NULLIF(pg_catalog.btrim(COALESCE(p_reason, '')), '');
    v_kind      text;
    v_did       text;
    v_key_len   integer;
    v_status    text;
    v_my_role   text;
    v_id        uuid;
BEGIN
    IF v_principal IS NULL OR NOT public.epigraph_is_human_operator(v_principal) THEN
        RAISE EXCEPTION 'TGP01: only a registered human operator (a Person, signed in as '
                        'themselves) may invite someone into a team group; nothing was changed'
            USING ERRCODE = 'TGP01';
    END IF;
    IF p_group IS NULL OR p_invitee IS NULL THEN
        RAISE EXCEPTION 'TGP09: an invitation needs a group and an invitee; nothing was changed'
            USING ERRCODE = 'TGP09';
    END IF;
    IF p_role IS NULL OR p_role NOT IN ('reader', 'writer', 'admin') THEN
        RAISE EXCEPTION 'TGP09: role % is not reader, writer or admin; nothing was changed',
                        COALESCE(p_role, '(none)')
            USING ERRCODE = 'TGP09';
    END IF;
    IF v_reason IS NOT NULL AND pg_catalog.length(v_reason) > 2000 THEN
        RAISE EXCEPTION 'TGP09: the reason is longer than 2000 characters; nothing was changed'
            USING ERRCODE = 'TGP09';
    END IF;
    IF p_invitee = v_principal THEN
        RAISE EXCEPTION 'TGP09: you cannot invite yourself; nothing was changed'
            USING ERRCODE = 'TGP09';
    END IF;

    -- The group row lock every roster verb takes first (164 section 2).
    SELECT g.kind::text, g.did_key, pg_catalog.octet_length(g.public_key), g.status::text
      INTO v_kind, v_did, v_key_len, v_status
      FROM public.groups g WHERE g.id = p_group FOR NO KEY UPDATE;
    SELECT m.role::text INTO v_my_role
      FROM public.group_memberships m
     WHERE m.group_id = p_group AND m.agent_id = v_principal AND m.revoked_at IS NULL;
    IF v_kind IS NULL OR v_my_role IS NULL THEN
        RAISE EXCEPTION 'TGP08: group % not found', p_group
            USING ERRCODE = 'TGP08';
    END IF;
    IF v_my_role <> 'admin' THEN
        RAISE EXCEPTION 'TGP02: only a live admin of group % may invite into it (you are a %); '
                        'nothing was changed', p_group, v_my_role
            USING ERRCODE = 'TGP02';
    END IF;
    IF v_kind <> 'team' OR v_did NOT LIKE 'did:epigraph:group:%' OR v_key_len <> 0
       OR v_status <> 'active'
       OR NOT EXISTS (SELECT 1 FROM public.person_team_groups ptg
                       WHERE ptg.group_id = p_group) THEN
        RAISE EXCEPTION 'TGP07: group % is not an active keyless team group made by a Person, so '
                        'it takes no invitations (its roster has its own path, the operator''s '
                        'audited verbs); nothing was changed', p_group
            USING ERRCODE = 'TGP07';
    END IF;
    IF NOT public.epigraph_is_human_operator(p_invitee) THEN
        RAISE EXCEPTION 'TGP03: agent % is not a registered human operator; only a Person can be '
                        'invited; nothing was changed', p_invitee
            USING ERRCODE = 'TGP03';
    END IF;
    IF EXISTS (SELECT 1 FROM public.group_memberships m
                WHERE m.group_id = p_group AND m.agent_id = p_invitee
                  AND m.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'TGP04: agent % is already a live member of group %; nothing was changed',
                        p_invitee, p_group
            USING ERRCODE = 'TGP04';
    END IF;
    IF EXISTS (SELECT 1 FROM public.group_invitations i
                WHERE i.group_id = p_group AND i.invitee_agent_id = p_invitee
                  AND i.status = 'pending') THEN
        RAISE EXCEPTION 'TGP04: agent % already has a pending invitation to group %; nothing was '
                        'changed', p_invitee, p_group
            USING ERRCODE = 'TGP04';
    END IF;

    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);  -- 206's write window
    INSERT INTO public.group_invitations (group_id, invitee_agent_id, invited_by, role, reason)
    VALUES (p_group, p_invitee, v_principal, p_role, v_reason)
    RETURNING id INTO v_id;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('group.invitation_created', v_principal, true,
            pg_catalog.jsonb_build_object(
                'group_id', p_group, 'invitation_id', v_id, 'invitee', p_invitee,
                'role', p_role, 'invited_by', v_principal, 'reason', v_reason,
                'arm', 'person', 'session_user', session_user::text, 'migration', 263));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);
    RETURN v_id;
END $$;
