-- 263: a Person creates a keyless team group, lists their groups, and invites
-- another Person, whose membership goes live only when THEY accept
-- (backlog ee9e05b4).
--
-- ===================================================================
-- 1. WHY
--
-- 164's audited verbs (`epigraph-operator create-group` and `group-member
-- add|remove|set-role`) are the only way to make a keyless team group or to
-- change its roster, and they run on the maintenance DSN only. A Person who
-- wants a private working group with a collaborator had to ask the operator,
-- and the operator's `group-member add` places a member with no step in which
-- that member agrees. The keyed REST routes (`POST /api/v1/groups`, `.../members`)
-- need key material a keyless group never has, and also add members directly.
--
-- This file adds the request-path half, in the shape of 206's app-callable
-- definers: create, invite, accept, decline, and two reads (my groups, my
-- pending invitations). The groups it makes are 164's verb-made team groups
-- (same `did:epigraph:group:<id>` namespace, empty key, no key epoch), so
-- 164's guards, its lapse rule (section 6 there) and the operator's verbs all
-- still apply to them.
--
-- Invitations are scoped to the groups a Person made HERE: the create definer
-- records each one in `person_team_groups`, and invite and accept require
-- that record. A team group the operator made with 164's `create-group` has
-- exactly the same shape (kind, namespace, empty key), so the shape alone
-- cannot tell them apart; without the record every human admin of an
-- operator-made group could invite anyone into it, at `admin` too, by a path
-- 164 reserved for the operator's audited verbs. Those groups stay
-- operator-managed: their admins get TGP07.
--
-- ===================================================================
-- 2. WHO THE CALLER IS
--
-- `epigraph_principal_id()`, the session principal every 077 policy keys on,
-- exactly as 206's definers read it (see its header: the database does not
-- protect that setting; only `ScopedPool::begin_as` / `acquire_as` set it,
-- from a resolved viewer). No function here takes the actor as an argument.
--
-- Every write act needs the principal ITSELF to be a registered human
-- operator (`epigraph_is_human_operator`: a live registry row and its human
-- client active), a Person. An operated agent, a delegated run token's
-- principal (always an agent its delegator operates) and a service agent are
-- refused TGP01, including for accept: consent to join a group with other
-- people is the Person's own act, not something an agent acting for them
-- gives. Decline needs only that the caller is the invitee.
--
-- ===================================================================
-- 3. THE RULES
--
--   * CREATE (`epigraph_person_create_team_group(name, reason)`): the caller
--     becomes the group's creator and its one `admin` (epoch 0). A Person
--     holds at most one ACTIVE verb-made team group per name (case and
--     surrounding space ignored), TGP06. The rule is per creator, not 164's
--     global GRP06: that refusal names the holding group and its creator,
--     which one Person must not learn about another's private group. Both
--     paths take 164's name lock, so a person-made group of a name DOES
--     block a later `create-group` of the same name (the operator sees the
--     holder in GRP06's text).
--   * INVITE (`epigraph_invite_to_team_group(group, invitee, role, reason)`):
--     the caller must hold a live `admin` row of the group (TGP02; a caller
--     with no live row at all is told the group does not exist, TGP08, as
--     for a missing one). The group must be an active keyless team group
--     that a Person made through this file's create (`person_team_groups`;
--     TGP07 for any other, including an operator-made team group). The
--     invitee must be a registered human operator other than the caller
--     (TGP03 / TGP09), not already a live member and without
--     a pending invitation to the group (TGP04). One `pending` row; NO
--     membership is written.
--   * ACCEPT (`epigraph_accept_group_invitation(invitation)`): only the
--     invitee (anyone else: TGP08). Decided under the group row lock the
--     164 verbs take (`FOR NO KEY UPDATE`, taken first, then the invitation
--     row), so it is serialised with them and with a second accept. Refused
--     TGP05 unless the invitation is still `pending`, the group is still an
--     active Person-made keyless team group, and the inviter is still a live
--     `admin` of it and still a registered human operator: an admin removed
--     or demoted since, or whose registration lapsed, no longer vouches for
--     the invitation. Refused TGP04 if the invitee became a live member some
--     other way meanwhile. Otherwise ONE new membership row at the next epoch
--     for the pair (164 section 3: the roster is a ledger) with the invited
--     role, and the invitation becomes `accepted` naming that row.
--   * DECLINE (`epigraph_decline_group_invitation(invitation)`): only the
--     invitee; `pending` -> `declined` (TGP05 otherwise).
--   * READS: `epigraph_my_groups()` lists the caller's live memberships
--     (`epigraph_live_memberships`, so 164's lapse, 165's role-derived rows
--     and 235's allowance lapse all apply) with each group's name, kind,
--     status and `invitable` (an active Person-made keyless team group);
--     `epigraph_my_group_invitations()` lists the invitations still
--     `pending` that name the caller. Neither discloses another principal's
--     rows.
--
-- Not added: withdrawing an invitation, expiry, leaving a group, and
-- removing or re-roling a member. The operator's 164 verbs still do the last
-- two; a pending invitation stays until the invitee answers it.
--
-- ===================================================================
-- 4. 164'S GUARDS ADMIT EXACTLY THE ROWS THESE DEFINERS WRITE
--
-- 164 made its verbs the only writer of a verb-made group's roster and row:
-- `epigraph_team_group_roster_verbs_only` (group_memberships) and
-- `epigraph_team_group_row_verbs_only` (groups) refuse every session that is
-- not a maintenance session (`epigraph_bypass()`, keyed on session_user). The
-- definers here run on an APPLICATION session, so both guards are re-stated
-- with ONE more admission, modelled on 194's table-backed purge grant (no
-- session setting, which a caller could set itself):
--
--   * `team_group_roster_grants (group_id, agent_id, xact_id)`: a row admits
--     the INSERT of exactly one roster row (group, agent), or of the group
--     row itself (agent NULL), in the transaction that wrote it (`xact_id`
--     defaults to `pg_current_xact_id()`, the TOP-level id, so a savepoint
--     does not change it). The application role holds no privilege on it;
--     only the definers below (as `epigraph_maintenance`) write it, and each
--     deletes its own rows before it returns. A definer that raises leaves
--     none (its statement, or the caller's savepoint, is rolled back).
--   * `epigraph_team_group_roster_granted(group, agent)`: true when such a
--     row exists for THIS transaction. Read by both guards, on INSERT only.
--
-- Every other path through the two guards is byte-identical to 176's text:
-- the same order, the same GRM05 / GRM06 message and SQLSTATE 42501. A
-- direct application INSERT, even one issued in the same transaction right
-- after one of these definers returned, finds no grant and is refused as
-- before. This file refuses to apply over any body other than 176's (md5 of
-- `prosrc`, 235's precondition shape).
--
-- ===================================================================
-- 5. AUDIT
--
-- One `security_events` row per applied act, in 164's `group.` family (the
-- restrictive policy 164 added admits only a privileged session or a definer
-- frame, so the application role cannot forge one), attributed to the
-- session principal: `group.team_created`, `group.invitation_created`,
-- `group.member_added` (an accept; `arm = 'invitation'`, with the invitation
-- and who sent it) and `group.invitation_declined`. `details` carries the
-- group, the member or invitee, the role, the reason, `session_user`,
-- `arm` and `migration = 263`. It does NOT carry 164's `actor`: that is read
-- from a setting any application session can set, so on this path it would
-- record whatever the caller wrote. The invitation row itself is the
-- decision record (who, when, which membership).
--
-- ===================================================================
-- 6. REFUSAL CODES
--
-- TGP01 the caller is not a registered human operator (or not authenticated)
-- TGP02 the caller is a live member of the group but not an admin
-- TGP03 the invitee is not a registered human operator
-- TGP04 the invitee is already a live member, or already has a pending
--       invitation to the group
-- TGP05 the invitation was already answered, or has lapsed (the group or
--       the inviter no longer qualifies)
-- TGP06 the caller already has an active team group of that name
-- TGP07 the group is not an active keyless team group a Person made through
--       this file (an operator-made team group, a personal, community or
--       keyed group, or an archived one)
-- TGP08 no such group or invitation for this caller (a missing one and one
--       the caller may not see answer the same)
-- TGP09 a malformed request (blank or over-long name or reason, a role
--       outside reader/writer/admin, inviting oneself)
-- `PersonTeamGroupRepository` maps them: TGP01/02 authority, TGP03/09
-- input, TGP04-07 state, TGP08 not found.
--
-- ===================================================================
-- 7. OWNER AND GRANTS
--
-- Every function is SECURITY DEFINER on 172's path (`pg_catalog, pg_temp`,
-- every name qualified) except the two re-stated guards, which keep 176's
-- path (`public, pg_temp`). All are owned by `epigraph_maintenance`
-- (role-guarded block, as every one since 060). The six request-path
-- functions and the grant check are EXECUTE-able by `epigraph_app` (the
-- groups guard is an INVOKER trigger and calls the check as the session's
-- role). `group_invitations` is under FORCEd row security with privileged
-- policies only (166's `role_agents` shape): the application role holds
-- SELECT and sees no row; it reads its own rows through the definers.
-- `person_team_groups` and `team_group_roster_grants` grant the application
-- role nothing (077's default privileges are revoked explicitly), so it can
-- neither mark a group invitable nor grant itself a roster row.
--
-- ===================================================================
-- UNDO: `docs/runbooks/263-undo.sql` (re-states 176's two guard bodies).
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- Section 4: refuse to apply over a guard body other than 176's.
DO $$
DECLARE
    v_roster text;
    v_row    text;
BEGIN
    SELECT md5(p.prosrc) INTO v_roster FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_team_group_roster_verbs_only()');
    SELECT md5(p.prosrc) INTO v_row FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_team_group_row_verbs_only()');
    IF v_roster IS DISTINCT FROM 'dcf4d5722ee28c8a3999fc6bc26ba911' THEN
        RAISE EXCEPTION '263: epigraph_team_group_roster_verbs_only is not the body 263 re-states '
                        '(176''s, md5 dcf4d5722ee28c8a3999fc6bc26ba911); found md5 %. Another '
                        'migration re-bodied it; nothing was changed', COALESCE(v_roster, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
    IF v_row IS DISTINCT FROM 'f66b4e61de3a9528627b3a9de8a208a6' THEN
        RAISE EXCEPTION '263: epigraph_team_group_row_verbs_only is not the body 263 re-states '
                        '(176''s, md5 f66b4e61de3a9528627b3a9de8a208a6); found md5 %. Another '
                        'migration re-bodied it; nothing was changed', COALESCE(v_row, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with both '
                         'deltas instead of this one.';
    END IF;
END $$;

-- ===================================================================
-- Section 4: the roster grant table and its check.
-- ===================================================================
CREATE TABLE public.team_group_roster_grants (
    id       uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    group_id uuid NOT NULL,
    agent_id uuid,
    xact_id  xid8 NOT NULL DEFAULT pg_catalog.pg_current_xact_id()
);
CREATE INDEX team_group_roster_grants_xact_group
    ON public.team_group_roster_grants (xact_id, group_id);
COMMENT ON TABLE public.team_group_roster_grants IS
    'Migration 263: one row admits, in the transaction that wrote it (xact_id), the INSERT of one '
    'roster row (group_id, agent_id) of a verb-made team group, or of the group row itself '
    '(agent_id NULL). Written and cleared only by the person-facing team-group definers; read '
    'only through epigraph_team_group_roster_granted. The application role holds no privilege on '
    'it.';

REVOKE ALL ON public.team_group_roster_grants FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.team_group_roster_grants FROM epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON public.team_group_roster_grants '
                'TO epigraph_maintenance';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_team_group_roster_granted(p_group uuid, p_agent uuid)
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM public.team_group_roster_grants g
                    WHERE g.xact_id = pg_catalog.pg_current_xact_id()
                      AND g.group_id = p_group
                      AND g.agent_id IS NOT DISTINCT FROM p_agent);
END $$;
COMMENT ON FUNCTION public.epigraph_team_group_roster_granted(uuid, uuid) IS
    'Migration 263: true when a roster grant names this (group, agent) -- agent NULL for the group '
    'row -- for the current transaction. The one admission 263 adds to 164''s two team-group '
    'guards.';
REVOKE EXECUTE ON FUNCTION public.epigraph_team_group_roster_granted(uuid, uuid) FROM PUBLIC;

-- ===================================================================
-- Section 1: the record of the groups a Person made here (the only
-- invitable ones).
-- ===================================================================
CREATE TABLE public.person_team_groups (
    group_id   uuid NOT NULL PRIMARY KEY REFERENCES public.groups(id),
    created_by uuid NOT NULL REFERENCES public.agents(id),
    created_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE public.person_team_groups IS
    'Migration 263: one row per keyless team group a Person made through '
    'epigraph_person_create_team_group. Only these groups take invitations; an operator-made '
    'team group (164 create-group) has the same shape and stays operator-managed. Written only '
    'by the create definer; the application role holds no privilege on it.';

REVOKE ALL ON public.person_team_groups FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.person_team_groups FROM epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT SELECT, INSERT ON public.person_team_groups TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- Section 4: 176's two guards, each with the grant admission on INSERT.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_team_group_roster_verbs_only()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() THEN
        RETURN NEW;
    END IF;
    -- NEW.group_id alone: 109 refuses moving a row to another group outside
    -- a maintenance session, and a maintenance session has returned above.
    IF EXISTS (SELECT 1 FROM public.groups g
                WHERE g.id = NEW.group_id AND g.did_key LIKE 'did:epigraph:group:%') THEN
        -- 263: the one row a person-facing team-group definer granted itself
        -- in this transaction (never an UPDATE).
        IF TG_OP = 'INSERT'
           AND public.epigraph_team_group_roster_granted(NEW.group_id, NEW.agent_id) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'GRM05: group_memberships: the roster of team group % is written only by the '
                        'team-group verbs (epigraph-operator group-member, on the maintenance '
                        'DSN); nothing was changed', NEW.group_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_team_group_row_verbs_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() THEN
        RETURN NEW;
    END IF;
    -- 263: the group row a person-facing create granted itself in this
    -- transaction (never an UPDATE).
    IF TG_OP = 'INSERT' AND public.epigraph_team_group_roster_granted(NEW.id, NULL) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'GRM06: groups: a keyless team group, or any group in the did:epigraph:group: '
                    'namespace, is created and changed only by the team-group verbs '
                    '(epigraph-operator create-group, on the maintenance DSN); nothing was '
                    'changed (did_key %, kind %, % key bytes)',
                    NEW.did_key, NEW.kind, octet_length(NEW.public_key)
        USING ERRCODE = '42501';
END $$;

-- ===================================================================
-- Section 3: the invitation ledger.
-- ===================================================================
CREATE TABLE public.group_invitations (
    id               uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    group_id         uuid NOT NULL REFERENCES public.groups(id),
    invitee_agent_id uuid NOT NULL REFERENCES public.agents(id),
    invited_by       uuid NOT NULL REFERENCES public.agents(id),
    role             text NOT NULL,
    status           text NOT NULL DEFAULT 'pending',
    reason           text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    decided_at       timestamptz,
    membership_id    uuid REFERENCES public.group_memberships(id),
    CONSTRAINT group_invitations_role_check CHECK (role IN ('reader', 'writer', 'admin')),
    CONSTRAINT group_invitations_status_check
        CHECK (status IN ('pending', 'accepted', 'declined')),
    CONSTRAINT group_invitations_decided_iff_answered
        CHECK ((status = 'pending') = (decided_at IS NULL)),
    CONSTRAINT group_invitations_membership_iff_accepted
        CHECK ((status = 'accepted') = (membership_id IS NOT NULL)),
    CONSTRAINT group_invitations_reason_length
        CHECK (reason IS NULL OR length(btrim(reason)) BETWEEN 1 AND 2000),
    CONSTRAINT group_invitations_not_self CHECK (invitee_agent_id <> invited_by)
);
-- At most one pending invitation per (group, invitee).
CREATE UNIQUE INDEX group_invitations_one_pending
    ON public.group_invitations (group_id, invitee_agent_id) WHERE status = 'pending';
CREATE INDEX group_invitations_invitee_pending
    ON public.group_invitations (invitee_agent_id) WHERE status = 'pending';
COMMENT ON TABLE public.group_invitations IS
    'Migration 263: an invitation of a registered human operator into a verb-made keyless team '
    'group, sent by a live admin of it. Pending until the invitee accepts (the membership goes '
    'live then, membership_id names it) or declines. Written only by the person-facing '
    'team-group definers; read through epigraph_my_group_invitations.';

ALTER TABLE public.group_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.group_invitations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS group_invitations_privileged_read ON public.group_invitations;
CREATE POLICY group_invitations_privileged_read ON public.group_invitations
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS group_invitations_privileged_insert ON public.group_invitations;
CREATE POLICY group_invitations_privileged_insert ON public.group_invitations
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS group_invitations_privileged_update ON public.group_invitations;
CREATE POLICY group_invitations_privileged_update ON public.group_invitations
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));

REVOKE ALL ON public.group_invitations FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.group_invitations FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.group_invitations TO epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT SELECT, INSERT ON public.group_invitations TO epigraph_maintenance';
        EXECUTE 'GRANT UPDATE (status, decided_at, membership_id) ON public.group_invitations '
                'TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- Section 3: create.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_person_create_team_group(p_name text, p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_name      text := pg_catalog.btrim(COALESCE(p_name, ''));
    v_reason    text := NULLIF(pg_catalog.btrim(COALESCE(p_reason, '')), '');
    v_group     uuid := pg_catalog.gen_random_uuid();
BEGIN
    IF v_principal IS NULL OR NOT public.epigraph_is_human_operator(v_principal) THEN
        RAISE EXCEPTION 'TGP01: only a registered human operator (a Person, signed in as '
                        'themselves) may create a team group; an agent acting for one may not; '
                        'nothing was created'
            USING ERRCODE = 'TGP01';
    END IF;
    IF v_name = '' OR pg_catalog.length(v_name) > 255 THEN
        RAISE EXCEPTION 'TGP09: a team group needs a name of 1 to 255 characters; nothing was '
                        'created'
            USING ERRCODE = 'TGP09';
    END IF;
    IF v_reason IS NOT NULL AND pg_catalog.length(v_reason) > 2000 THEN
        RAISE EXCEPTION 'TGP09: the reason is longer than 2000 characters; nothing was created'
            USING ERRCODE = 'TGP09';
    END IF;

    -- 164's name lock: serialised with another create of the name, either path.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtext('epigraph.team_group_name:' || pg_catalog.lower(v_name)));
    IF EXISTS (SELECT 1 FROM public.groups g
                WHERE g.kind = 'team' AND g.status = 'active'
                  AND g.did_key LIKE 'did:epigraph:group:%'
                  AND g.created_by_agent_id = v_principal
                  AND pg_catalog.lower(pg_catalog.btrim(g.display_name)) = pg_catalog.lower(v_name))
    THEN
        RAISE EXCEPTION 'TGP06: you already have an active team group named %; nothing was '
                        'created', v_name
            USING ERRCODE = 'TGP06';
    END IF;

    INSERT INTO public.team_group_roster_grants (group_id, agent_id)
    VALUES (v_group, NULL), (v_group, v_principal);
    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);  -- 206's write window
    INSERT INTO public.groups (id, display_name, did_key, public_key, kind, created_by_agent_id)
    VALUES (v_group, v_name, 'did:epigraph:group:' || v_group::text, ''::bytea, 'team',
            v_principal);
    INSERT INTO public.person_team_groups (group_id, created_by) VALUES (v_group, v_principal);
    INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
    VALUES (v_group, v_principal, ''::bytea, 0, 'admin');
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('group.team_created', v_principal, true,
            pg_catalog.jsonb_build_object(
                'group_id', v_group, 'display_name', v_name, 'kind', 'team',
                'admin', v_principal, 'reason', v_reason, 'arm', 'person',
                'session_user', session_user::text, 'migration', 263));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);
    DELETE FROM public.team_group_roster_grants gr
     WHERE gr.group_id = v_group AND gr.xact_id = pg_catalog.pg_current_xact_id();
    RETURN v_group;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_person_create_team_group(text, text) FROM PUBLIC;

-- ===================================================================
-- Section 3: invite.
-- ===================================================================
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
REVOKE EXECUTE ON FUNCTION public.epigraph_invite_to_team_group(uuid, uuid, text, text)
    FROM PUBLIC;

-- ===================================================================
-- Section 3: accept.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_accept_group_invitation(p_invitation uuid)
RETURNS TABLE (out_group_id uuid, out_membership_id uuid, out_role text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_group     uuid;
    v_kind      text;
    v_did       text;
    v_key_len   integer;
    v_status    text;
    v_inv_state text;
    v_role      text;
    v_inviter   uuid;
    v_reason    text;
    v_epoch     integer;
    v_id        uuid;
BEGIN
    IF v_principal IS NULL OR NOT public.epigraph_is_human_operator(v_principal) THEN
        RAISE EXCEPTION 'TGP01: only the invited Person, signed in as themselves, may accept an '
                        'invitation; an agent acting for them may not; nothing was changed'
            USING ERRCODE = 'TGP01';
    END IF;
    IF p_invitation IS NULL THEN
        RAISE EXCEPTION 'TGP09: an invitation id is required; nothing was changed'
            USING ERRCODE = 'TGP09';
    END IF;
    SELECT i.group_id INTO v_group
      FROM public.group_invitations i
     WHERE i.id = p_invitation AND i.invitee_agent_id = v_principal;
    IF v_group IS NULL THEN
        RAISE EXCEPTION 'TGP08: invitation % not found', p_invitation
            USING ERRCODE = 'TGP08';
    END IF;

    -- The group row first (the verbs' order), then the invitation.
    SELECT g.kind::text, g.did_key, pg_catalog.octet_length(g.public_key), g.status::text
      INTO v_kind, v_did, v_key_len, v_status
      FROM public.groups g WHERE g.id = v_group FOR NO KEY UPDATE;
    SELECT i.status, i.role, i.invited_by, i.reason
      INTO v_inv_state, v_role, v_inviter, v_reason
      FROM public.group_invitations i WHERE i.id = p_invitation FOR UPDATE;
    IF v_inv_state <> 'pending' THEN
        RAISE EXCEPTION 'TGP05: invitation % was already %; nothing was changed',
                        p_invitation, v_inv_state
            USING ERRCODE = 'TGP05';
    END IF;
    IF v_kind <> 'team' OR v_did NOT LIKE 'did:epigraph:group:%' OR v_key_len <> 0
       OR v_status <> 'active'
       OR NOT EXISTS (SELECT 1 FROM public.person_team_groups ptg
                       WHERE ptg.group_id = v_group) THEN
        RAISE EXCEPTION 'TGP05: invitation % has lapsed: group % is no longer an active keyless '
                        'team group made by a Person; nothing was changed', p_invitation, v_group
            USING ERRCODE = 'TGP05';
    END IF;
    -- Serialised with every link write and registration lookup the 164
    -- verbs serialise with (107 section 10).
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('epigraph.operator_links'));
    IF NOT public.epigraph_is_human_operator(v_inviter)
       OR NOT EXISTS (SELECT 1 FROM public.group_memberships m
                       WHERE m.group_id = v_group AND m.agent_id = v_inviter
                         AND m.role = 'admin' AND m.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'TGP05: invitation % has lapsed: the Person who sent it is no longer a '
                        'live admin of group %; ask a current admin to invite you again; '
                        'nothing was changed', p_invitation, v_group
            USING ERRCODE = 'TGP05';
    END IF;
    IF EXISTS (SELECT 1 FROM public.group_memberships m
                WHERE m.group_id = v_group AND m.agent_id = v_principal
                  AND m.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'TGP04: you are already a live member of group %; decline the invitation '
                        'instead; nothing was changed', v_group
            USING ERRCODE = 'TGP04';
    END IF;

    -- 164 section 3: a new row at the next epoch, never a revival.
    SELECT COALESCE(pg_catalog.max(m.epoch) + 1, 0) INTO v_epoch
      FROM public.group_memberships m
     WHERE m.group_id = v_group AND m.agent_id = v_principal;
    INSERT INTO public.team_group_roster_grants (group_id, agent_id)
    VALUES (v_group, v_principal);
    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);  -- 206's write window
    INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
    VALUES (v_group, v_principal, ''::bytea, v_epoch, v_role)
    RETURNING id INTO v_id;
    UPDATE public.group_invitations
       SET status = 'accepted', decided_at = pg_catalog.now(), membership_id = v_id
     WHERE id = p_invitation;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('group.member_added', v_principal, true,
            pg_catalog.jsonb_build_object(
                'group_id', v_group, 'member', v_principal, 'role', v_role,
                'epoch', v_epoch, 'membership_id', v_id, 'invitation_id', p_invitation,
                'invited_by', v_inviter, 'reason', v_reason, 'arm', 'invitation',
                'session_user', session_user::text, 'migration', 263));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);
    DELETE FROM public.team_group_roster_grants gr
     WHERE gr.group_id = v_group AND gr.xact_id = pg_catalog.pg_current_xact_id();
    RETURN QUERY SELECT v_group, v_id, v_role;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_accept_group_invitation(uuid) FROM PUBLIC;

-- ===================================================================
-- Section 3: decline.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_decline_group_invitation(p_invitation uuid)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_group     uuid;
    v_inv_state text;
    v_role      text;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'TGP01: declining an invitation needs an authenticated principal; '
                        'nothing was changed'
            USING ERRCODE = 'TGP01';
    END IF;
    IF p_invitation IS NULL THEN
        RAISE EXCEPTION 'TGP09: an invitation id is required; nothing was changed'
            USING ERRCODE = 'TGP09';
    END IF;
    SELECT i.group_id, i.status, i.role INTO v_group, v_inv_state, v_role
      FROM public.group_invitations i
     WHERE i.id = p_invitation AND i.invitee_agent_id = v_principal
       FOR UPDATE;
    IF v_group IS NULL THEN
        RAISE EXCEPTION 'TGP08: invitation % not found', p_invitation
            USING ERRCODE = 'TGP08';
    END IF;
    IF v_inv_state <> 'pending' THEN
        RAISE EXCEPTION 'TGP05: invitation % was already %; nothing was changed',
                        p_invitation, v_inv_state
            USING ERRCODE = 'TGP05';
    END IF;
    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);  -- 206's write window
    UPDATE public.group_invitations
       SET status = 'declined', decided_at = pg_catalog.now()
     WHERE id = p_invitation;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('group.invitation_declined', v_principal, true,
            pg_catalog.jsonb_build_object(
                'group_id', v_group, 'invitation_id', p_invitation, 'invitee', v_principal,
                'role', v_role, 'arm', 'invitation', 'session_user', session_user::text,
                'migration', 263));
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);
    RETURN v_group;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_decline_group_invitation(uuid) FROM PUBLIC;

-- ===================================================================
-- Section 3: the two reads.
-- ===================================================================
-- The caller's live memberships, one row per group at its highest role.
CREATE OR REPLACE FUNCTION public.epigraph_my_groups()
RETURNS TABLE (group_id uuid, display_name text, kind text, status text, role text,
               created_by uuid, invitable boolean)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT x.group_id, x.display_name, x.kind, x.status, x.role, x.created_by, x.invitable
      FROM (SELECT DISTINCT ON (g.id)
                   g.id AS group_id, g.display_name::text AS display_name,
                   g.kind::text AS kind, g.status::text AS status, m.role::text AS role,
                   g.created_by_agent_id AS created_by,
                   (g.kind = 'team' AND g.did_key LIKE 'did:epigraph:group:%'
                    AND pg_catalog.octet_length(g.public_key) = 0
                    AND g.status = 'active'
                    AND EXISTS (SELECT 1 FROM public.person_team_groups ptg
                                 WHERE ptg.group_id = g.id)) AS invitable
              FROM public.epigraph_live_memberships(public.epigraph_principal_id()) m
              JOIN public.groups g ON g.id = m.group_id
             WHERE public.epigraph_principal_id() IS NOT NULL
             ORDER BY g.id,
                      CASE m.role::text WHEN 'admin' THEN 0 WHEN 'writer' THEN 1 ELSE 2 END) x
     ORDER BY x.kind, x.display_name, x.group_id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_my_groups() FROM PUBLIC;

-- The invitations still pending that name the caller.
CREATE OR REPLACE FUNCTION public.epigraph_my_group_invitations()
RETURNS TABLE (invitation_id uuid, group_id uuid, display_name text, role text,
               invited_by uuid, reason text, created_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT i.id, i.group_id, g.display_name::text, i.role, i.invited_by, i.reason, i.created_at
      FROM public.group_invitations i
      JOIN public.groups g ON g.id = i.group_id
     WHERE i.invitee_agent_id = public.epigraph_principal_id()
       AND i.status = 'pending'
     ORDER BY i.created_at, i.id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_my_group_invitations() FROM PUBLIC;

-- ===================================================================
-- Section 7: owner and grants, role-guarded as every such block since 060.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_team_group_roster_granted(uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_person_create_team_group(text, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_invite_to_team_group(uuid, uuid, text, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_accept_group_invitation(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_decline_group_invitation(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_my_groups() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_my_group_invitations() '
                'OWNER TO epigraph_maintenance';
        -- The re-stated guards keep their owner; asserted, not assumed.
        EXECUTE 'ALTER FUNCTION public.epigraph_team_group_roster_verbs_only() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_team_group_roster_granted(uuid, uuid) '
                'TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 263 function '
                     'bodies stay owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_team_group_roster_granted(uuid, uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_person_create_team_group(text, text) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_invite_to_team_group(uuid, uuid, text, text) TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_accept_group_invitation(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_decline_group_invitation(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_my_groups() TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_my_group_invitations() '
                'TO epigraph_app';
    END IF;
END $$;
