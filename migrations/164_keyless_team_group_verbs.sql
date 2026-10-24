-- 164: maintenance-only, audited verbs for KEYLESS team groups.
--
-- ===================================================================
-- 1. WHAT THIS ADDS
--
-- Four SECURITY DEFINER functions, owned by `epigraph_maintenance` and
-- executable by that role alone (the operator CLI's `create-group` and
-- `group-member add|remove|set-role`, on the maintenance DSN):
--
--   epigraph_create_team_group(name, admin, reason)            -> group id
--   epigraph_team_group_add_member(group, agent, role, reason)
--   epigraph_team_group_remove_member(group, agent, reason)
--   epigraph_team_group_set_member_role(group, agent, role, reason)
--
-- Before this file the only way to create a non-personal group was the keyed
-- REST route: a 32-byte group public key, a key epoch, a 60-byte wrapped share
-- per member, and a standing admin-only scope for every roster change. The seal
-- that key material served is retired; a team group is now a visibility
-- boundary, not an encryption one ("invisible, not encrypted").
--
-- KEYLESS, in the shape 105's personal groups already have: `public_key` is
-- empty, NO `group_key_epochs` row is written, and every membership carries an
-- empty `wrapped_key_share`. `did_key` is `did:epigraph:group:<id>` (the
-- community precedent, `did:epigraph:community:<id>`), so it is unique by
-- construction and claims nothing about a key. `groups_public_key_shape` (060)
-- required exactly 32 bytes for `kind = 'team'`; the first statement below
-- relaxes it to 0 OR 32, so existing keyed team groups stay valid.
--
-- These verbs are the ONLY writer of a verb-made group's roster and group
-- row. A verb-made group is one whose `did_key` is in the verbs'
-- `did:epigraph:group:` namespace (108 freezes `did_key` outside maintenance,
-- so the mark cannot be moved on or off a group). Three triggers below hold
-- that on every path that is not a maintenance session (`epigraph_bypass()`,
-- keyed on `session_user`, so neither a forged setting nor a definer frame
-- an application session reaches can satisfy it):
--
--   * `group_memberships_team_roster_verbs_only` refuses an INSERT or UPDATE
--     of a membership row of a verb-made group. Without it, 077's group-admin
--     arm and 092's creator arm let an application session stamped as the
--     group's admin or creator (and 122 section 4 is why the application DSN
--     is not the boundary: a holder of it can stamp any principal) add a
--     reader or a human writer (122's scope trigger is quiet for both),
--     restore a demoted creator to admin, or revoke a row, with none of
--     section 2's rules and no audit row. The REST routes therefore cannot
--     change a verb-made roster either: add already needed a key epoch, and
--     remove is now refused (42501) like every other application write.
--   * `groups_team_verbs_only_insert` refuses a new group in the namespace,
--     or a new KEYLESS team group (the CHECK below is relaxed for every
--     session, and an application principal could otherwise mint a
--     keyless team group and enrol itself as its admin through 092's empty-
--     roster arm).
--   * `groups_team_verbs_only_update` refuses any UPDATE of a verb-made group
--     row (a demoted creator keeps 092's creator arm on `groups`, and setting
--     `public_key` or `status` would take the group out of the verbs' hands,
--     GRP05), and an UPDATE that makes any team group keyless.
--
-- ===================================================================
-- 2. THE RULES EACH VERB HOLDS ITSELF
--
-- Every verb runs on a maintenance session, so `epigraph_bypass()` is true for
-- every row it writes. That switches off three guards that protect this table
-- on every other path: 109's retired-writer trigger and identity trigger,
-- 122's `group_memberships_operator_scope` trigger (its exemption admits a
-- privileged session; it is also quiet on an unarmed database), and 092's
-- roster-bounded creator arm (a policy, which a bypass session never meets).
-- So the verbs restate the rules in their own bodies, armed or not:
--
--   * THE ADMIN IS A HUMAN. The creator, and anyone made `admin`, must be a
--     registered human operator (`epigraph_is_human_operator`: a live registry
--     row AND its recorded human client active). `groups.created_by_agent_id`
--     is that Person. (GRP01)
--   * A MEMBER BELONGS TO A LIVE HUMAN. `epigraph_human_of(agent, live)` must
--     name a registered human operator: the agent itself, the operator of its
--     LIVE link, or the operator of its 149 client allowance. An unbound agent,
--     a RETIRED-linked identity (zero authority, 107 section 7) and an agent
--     whose operator was revoked from the registry are refused. (GRP04)
--   * AN OPERATED AGENT IS A MEMBER ONLY WHERE ITS OPERATOR WRITES, at any
--     role: its human must hold a live `writer`/`admin` row in the group
--     (`epigraph_operator_writes_group`). 122 refuses only writer/admin rows;
--     a reader row is held to the same rule here because reading a group the
--     operator cannot read is the same cross-human leak in the read direction.
--     An operated agent is never an `admin`. (GRP03 / GRP01)
--   * NO STRANDED AGENTS. A human cannot be removed, nor demoted to `reader`,
--     while an agent of theirs is a live member: remove the agents first. The
--     alternative (revoke them in the same act) was not taken because it turns
--     one audited act into several unannounced ones. (GRP03)
--   * THE LAST LIVE ADMIN STAYS. Removing or demoting the group's only live
--     `admin` that is still a registered human operator is refused (an admin
--     row of a human whose registration or human client has since lapsed
--     does not count, so the group cannot be left administered only by a
--     revoked identity), decided under a `FOR NO KEY UPDATE` lock on the
--     `groups` row that every verb takes first, so two concurrent removals of
--     two admins cannot both pass. NO KEY: the lock conflicts with itself, so
--     the verbs are serialised against each other, but not with the KEY SHARE
--     a foreign-key insert naming the group takes (a claim, a membership), so
--     a verb in flight, dry runs included, does not stall ordinary writes into
--     the group. (GRP02)
--   * ONLY VERB-MADE TEAM GROUPS. The member verbs refuse any group that is
--     not `kind = 'team'`, in the `did:epigraph:group:` namespace, with an
--     empty key and status `active`: personal groups (107's link path),
--     community groups (106), world and seed, keyed team groups and any
--     keyless team group made some other way each have their own roster path
--     or none. (GRP05)
--   * ONE ACTIVE VERB-MADE TEAM GROUP PER NAME (case and surrounding space
--     ignored), so a repeated `create-group --apply` cannot mint a second
--     group. A keyed team group does not hold a name here (display names are
--     not unique across kinds), and the refusal names the group that does and
--     its creator, so a squat is visible. (GRP06)
--
-- 109's identity rule holds by construction: no verb changes a row's
-- `group_id` or `agent_id`.
--
-- ===================================================================
-- 3. THE ROSTER IS A LEDGER
--
-- A removal is `UPDATE ... SET revoked_at = now()`, never a DELETE (106 took
-- DELETE from the application role; the maintenance role never had it, 070).
-- A re-add after a removal INSERTS A NEW ROW at the next `epoch` for that
-- (group, agent) pair: `UNIQUE (group_id, agent_id, epoch)` would collide with
-- the revoked epoch-0 row, and reviving that row would erase when the member
-- left. The epoch carries no key meaning on a keyless group; it is the row's
-- sequence number. A role change updates the live row in place; the prior role
-- is in its audit row.
--
-- ===================================================================
-- 4. AUDIT
--
-- Every applied act writes one `security_events` row, attributed to the
-- member (or the admin, for a creation): `group.team_created`,
-- `group.member_added`, `group.member_removed`, `group.member_role_set`, with
-- the group, member, roles, epoch, reason, `session_user` and the CLI's
-- process context (`actor`: tool, command, version, uids) in `details`. A
-- no-op (re-adding a member at its current role, removing a non-member,
-- setting the role it already has) writes nothing. The `group.` event family
-- is reserved (a RESTRICTIVE insert policy in the 123 / 148 shape), so the
-- application role cannot forge a roster act.
--
-- ===================================================================
-- 5. GRANTS
--
-- EXECUTE is revoked from PUBLIC and from `epigraph_app` and granted to
-- `epigraph_maintenance` only; each body also refuses a session that is not a
-- maintenance member or a superuser (defence in depth if a later migration
-- grants too widely). The owner (`epigraph_maintenance`) already holds
-- SELECT/INSERT/UPDATE on the three tables written (070) and EXECUTE on the
-- helpers read (122 and 149 own them by the same role). The `OWNER TO` block
-- is role-guarded like every such block since 060 and can silently no-op;
-- `tenancy_backfill.rs`'s register (checked by `verify` and by its
-- `register_matches_the_maintenance_owned_catalog` test) and
-- `team_group_verbs.rs::the_verbs_are_maintenance_owned_definers_only_maintenance_executes`
-- pin the owner. (`schema_contract.rs` has no entry for this file.)
--
-- ===================================================================
-- 6. A MEMBERSHIP LAPSES WITH ITS BINDING
--
-- `epigraph_live_memberships` (077, the source of every viewer's group set)
-- counts a live row of a verb-made group only while the member still belongs
-- to a registered human operator (`epigraph_human_of(member, live)`): a
-- revoked 149 allowance, a revoked registration or a suspended human client
-- ends the member's claim reads and writes (everything decided from its
-- resolved viewer) at its next resolve, without a write. Readers of the
-- roster table itself (the REST group-admin check, group info) still see the
-- row until `group-member remove` revokes it.
-- Rows of every other group count exactly as before. The code block below
-- says why this is computed rather than written.
--
-- ===================================================================
-- UNDO
--
-- DROP FUNCTION IF EXISTS public.epigraph_team_group_set_member_role(uuid, uuid, text, text);
-- DROP FUNCTION IF EXISTS public.epigraph_team_group_remove_member(uuid, uuid, text);
-- DROP FUNCTION IF EXISTS public.epigraph_team_group_add_member(uuid, uuid, text, text);
-- DROP FUNCTION IF EXISTS public.epigraph_create_team_group(text, uuid, text);
-- DROP POLICY IF EXISTS security_events_group_roster_privileged ON public.security_events;
-- DROP TRIGGER IF EXISTS groups_team_verbs_only_update ON public.groups;
-- DROP TRIGGER IF EXISTS groups_team_verbs_only_insert ON public.groups;
-- DROP TRIGGER IF EXISTS group_memberships_team_roster_verbs_only ON public.group_memberships;
-- DROP FUNCTION IF EXISTS public.epigraph_team_group_row_verbs_only();
-- DROP FUNCTION IF EXISTS public.epigraph_team_group_actor();
-- DROP FUNCTION IF EXISTS public.epigraph_team_group_roster_verbs_only();
-- and re-state 077's `epigraph_live_memberships` body (without the verb-made
-- group conjunct; owner and grants unchanged).
-- and, ONLY when no keyless team group exists, restore 060's
-- `groups_public_key_shape` text. Groups and memberships the verbs wrote stay
-- (060 refuses deleting groups; the roster is a ledger), as do their audit
-- rows (082: immutable).
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- Section 1: a team group may be keyless.
ALTER TABLE public.groups DROP CONSTRAINT IF EXISTS groups_public_key_shape;
ALTER TABLE public.groups ADD CONSTRAINT groups_public_key_shape CHECK (
       (kind = 'team' AND octet_length(public_key) IN (0, 32))
    OR (kind <> 'team' AND octet_length(public_key) = 0));

-- Section 4: the `group.` audit family is written only by a privileged session
-- or a definer frame. The row-only arm says WHICH rows the restriction applies
-- to and grants nothing. length('group.') = 6.
DROP POLICY IF EXISTS security_events_group_roster_privileged ON public.security_events;
CREATE POLICY security_events_group_roster_privileged ON public.security_events
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        lower(left(btrim(event_type), 6)) <> 'group.'
        OR (((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
            AND created_at = now()));

-- Section 1: a verb-made group has one writer, the verbs.
--
-- The roster guard reads `groups`, which is under row security, so it is a
-- definer (owned by the maintenance role, section 5): an invoker lookup from
-- an application session that cannot see the group row would read "not
-- verb-made" and let the write through. Inside this frame `current_user` is
-- the owner, which is why the gate is `epigraph_bypass()` (session_user) and
-- never `epigraph_definer_bypass()` (current_user), which would admit every
-- caller.
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
        RAISE EXCEPTION 'group_memberships: the roster of team group % is written only by the '
                        'team-group verbs (epigraph-operator group-member, on the maintenance '
                        'DSN); nothing was changed', NEW.group_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_team_group_roster_verbs_only() FROM PUBLIC;

DROP TRIGGER IF EXISTS group_memberships_team_roster_verbs_only ON public.group_memberships;
CREATE TRIGGER group_memberships_team_roster_verbs_only
    BEFORE INSERT OR UPDATE ON public.group_memberships
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_team_group_roster_verbs_only();

-- The group-row guard reads only the row in hand, so it is an invoker, in
-- 108's shape (but with the session arm alone, for the reason above).
CREATE OR REPLACE FUNCTION public.epigraph_team_group_row_verbs_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'groups: a keyless team group, or any group in the did:epigraph:group: '
                    'namespace, is created and changed only by the team-group verbs '
                    '(epigraph-operator create-group, on the maintenance DSN); nothing was '
                    'changed (did_key %, kind %, % key bytes)',
                    NEW.did_key, NEW.kind, octet_length(NEW.public_key)
        USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS groups_team_verbs_only_insert ON public.groups;
CREATE TRIGGER groups_team_verbs_only_insert
    BEFORE INSERT ON public.groups
    FOR EACH ROW
    WHEN (NEW.did_key LIKE 'did:epigraph:group:%'
          OR (NEW.kind = 'team' AND octet_length(NEW.public_key) = 0))
    EXECUTE FUNCTION public.epigraph_team_group_row_verbs_only();

DROP TRIGGER IF EXISTS groups_team_verbs_only_update ON public.groups;
CREATE TRIGGER groups_team_verbs_only_update
    BEFORE UPDATE ON public.groups
    FOR EACH ROW
    WHEN (OLD.did_key LIKE 'did:epigraph:group:%'
          OR NEW.did_key LIKE 'did:epigraph:group:%'
          OR (NEW.kind = 'team' AND octet_length(NEW.public_key) = 0))
    EXECUTE FUNCTION public.epigraph_team_group_row_verbs_only();

-- Section 6: a membership of a verb-made group LAPSES with the binding that
-- admitted it.
--
-- The verbs check GRP03/GRP04 when a member is added or promoted, but nothing
-- revokes the row when that binding later ends: a 149 client allowance is
-- revoked, the human's registration is revoked, or its human client is
-- suspended (107 refuses to retire a LIVE link, so that is not a path). The
-- row stays live, and `Viewer::resolve` read it, so the agent kept reading
-- (and, unarmed, writing) the group. Revoking the rows in each of those acts
-- would mean re-stating three definers from other migrations and turning one
-- audited act into several; instead the membership is COMPUTED at stamp time,
-- in the one function every viewer's group set comes from: a live row of a
-- verb-made group counts only while `epigraph_human_of(member, live)` names a
-- registered human operator. Every other group's rows count exactly as before.
-- The row itself is untouched; `group-member remove` still cleans it up.
--
-- 077's body plus the conjunct. Re-owned (section 5), so it moves out of the
-- re-own ratchet's frozen pre-register list and into its register.
CREATE OR REPLACE FUNCTION public.epigraph_live_memberships(p_agent uuid)
RETURNS TABLE (group_id uuid, role text) LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT m.group_id, m.role::text
      FROM public.group_memberships m
      JOIN public.groups g ON g.id = m.group_id
     WHERE m.agent_id = p_agent AND m.revoked_at IS NULL
       AND (g.did_key NOT LIKE 'did:epigraph:group:%'
            OR public.epigraph_is_human_operator(public.epigraph_human_of(p_agent, true)))
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_live_memberships(uuid) FROM PUBLIC;

-- Section 4: WHO acted. `session_user` is the shared maintenance login, which
-- names no person. The operator CLI states its process (tool, command,
-- version, real and login uid and their names, the environment's advisory
-- user) in a transaction-local setting before calling a verb, and every audit
-- row carries it under `actor`. It is the caller's statement, not proof, but
-- only a maintenance session reaches the verbs. Absent (a direct SQL call) it
-- is JSON null; a value that is not a JSON object is refused rather than
-- recorded as something it is not. Invoker: it reads only the caller's own
-- setting.
CREATE OR REPLACE FUNCTION public.epigraph_team_group_actor()
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = public, pg_temp AS $$
DECLARE
    v_raw   text := NULLIF(current_setting('epigraph.operator_actor', true), '');
    v_actor jsonb;
BEGIN
    IF v_raw IS NULL THEN
        RETURN NULL;
    END IF;
    v_actor := v_raw::jsonb;
    IF jsonb_typeof(v_actor) <> 'object' THEN
        RAISE EXCEPTION 'epigraph.operator_actor must be a JSON object' USING ERRCODE = '22023';
    END IF;
    RETURN v_actor;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_team_group_actor() FROM PUBLIC;

-- -------------------------------------------------------------------
-- create
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_create_team_group(
    p_name text, p_admin uuid, p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_group        uuid := gen_random_uuid();
    v_name         text := btrim(p_name);
    v_held_by      uuid;
    v_held_creator uuid;
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_create_team_group: only a maintenance session creates a team '
                        'group' USING ERRCODE = '42501';
    END IF;
    IF v_name IS NULL OR v_name = '' OR p_admin IS NULL
       OR p_reason IS NULL OR btrim(p_reason) = '' THEN
        RAISE EXCEPTION 'epigraph_create_team_group: a name, an admin and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    IF length(v_name) > 255 THEN
        RAISE EXCEPTION 'epigraph_create_team_group: the name is longer than 255 characters'
            USING ERRCODE = '22001';
    END IF;
    IF NOT public.epigraph_is_human_operator(p_admin) THEN
        RAISE EXCEPTION 'GRP01: agent % is not a registered human operator; a team group''s '
                        'admin is a Person', p_admin
            USING ERRCODE = 'GRP01',
                  HINT = 'Register the human first: epigraph-operator register-human-operator.';
    END IF;
    -- Serialise two creations of the same name; the check below then sees the
    -- first one's committed row.
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.team_group_name:' || lower(v_name)));
    SELECT g.id, g.created_by_agent_id INTO v_held_by, v_held_creator
      FROM public.groups g
     WHERE g.kind = 'team' AND g.status = 'active'
       AND g.did_key LIKE 'did:epigraph:group:%'
       AND lower(btrim(g.display_name)) = lower(v_name)
     ORDER BY g.created_at
     LIMIT 1;
    IF v_held_by IS NOT NULL THEN
        RAISE EXCEPTION 'GRP06: an active team group named % already exists (group %, created '
                        'by %); nothing was created', v_name, v_held_by, v_held_creator
            USING ERRCODE = 'GRP06';
    END IF;

    INSERT INTO public.groups (id, display_name, did_key, public_key, kind, created_by_agent_id)
    VALUES (v_group, v_name, 'did:epigraph:group:' || v_group::text, ''::bytea, 'team',
            p_admin);
    INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
    VALUES (v_group, p_admin, ''::bytea, 0, 'admin');
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('group.team_created', p_admin, true,
            jsonb_build_object('group_id', v_group, 'display_name', v_name, 'kind', 'team',
                               'admin', p_admin, 'reason', p_reason,
                               'session_user', session_user::text,
                               'actor', public.epigraph_team_group_actor()));
    RETURN v_group;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_create_team_group(text, uuid, text) FROM PUBLIC;

-- -------------------------------------------------------------------
-- add
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

-- -------------------------------------------------------------------
-- remove (a revoke)
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

-- -------------------------------------------------------------------
-- set-role
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_team_group_set_member_role(
    p_group uuid, p_agent uuid, p_role text, p_reason text)
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
    v_human     uuid;
    v_operated  integer;
    v_rank_old  integer;
    v_rank_new  integer;
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_team_group_set_member_role: only a maintenance session '
                        'changes a team group roster' USING ERRCODE = '42501';
    END IF;
    IF p_group IS NULL OR p_agent IS NULL OR p_role IS NULL
       OR p_reason IS NULL OR btrim(p_reason) = '' THEN
        RAISE EXCEPTION 'epigraph_team_group_set_member_role: a group, an agent, a role and a '
                        'reason are required' USING ERRCODE = '22004';
    END IF;
    IF p_role NOT IN ('reader', 'writer', 'admin') THEN
        RAISE EXCEPTION 'epigraph_team_group_set_member_role: role % is not reader, writer or '
                        'admin', p_role USING ERRCODE = '22023';
    END IF;

    SELECT g.kind::text, g.did_key, octet_length(g.public_key), g.status::text
      INTO v_kind, v_did, v_key_len, v_status
      FROM public.groups g WHERE g.id = p_group FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'epigraph_team_group_set_member_role: group % does not exist', p_group
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
        RAISE EXCEPTION 'epigraph_team_group_set_member_role: agent % is not a live member of '
                        'group %; add it instead', p_agent, p_group
            USING ERRCODE = '55000';
    END IF;
    IF v_live_role = p_role THEN
        RETURN QUERY SELECT v_live_id, false, v_live_role;
        RETURN;
    END IF;

    v_rank_old := CASE v_live_role WHEN 'reader' THEN 1 WHEN 'writer' THEN 2 ELSE 3 END;
    v_rank_new := CASE p_role WHEN 'reader' THEN 1 WHEN 'writer' THEN 2 ELSE 3 END;

    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    v_human := public.epigraph_human_of(p_agent, true);
    -- A PROMOTION meets add's eligibility rules again: the member must still
    -- belong to a live human, an operated agent may rise only where its
    -- operator writes, and only a Person is an admin. A demotion is always
    -- eligible (it is how a stale row is narrowed), subject to the two
    -- roster rules below.
    IF v_rank_new > v_rank_old THEN
        IF v_human IS NULL OR NOT public.epigraph_is_human_operator(v_human) THEN
            RAISE EXCEPTION 'GRP04: agent % belongs to no live human operator; it cannot be '
                            'promoted', p_agent
                USING ERRCODE = 'GRP04';
        END IF;
        IF p_role = 'admin' AND v_human <> p_agent THEN
            RAISE EXCEPTION 'GRP01: agent % is operated by %, and a team group''s admin is a '
                            'Person', p_agent, v_human
                USING ERRCODE = 'GRP01';
        END IF;
        IF v_human <> p_agent
           AND NOT public.epigraph_operator_writes_group(v_human, p_group) THEN
            RAISE EXCEPTION 'GRP03: agent % is operated by %, which holds no live writer or '
                            'admin membership in group %; an operated agent is a member only '
                            'where its operator writes', p_agent, v_human, p_group
                USING ERRCODE = 'GRP03';
        END IF;
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

    IF p_role = 'reader' THEN
        SELECT count(*) INTO v_operated
          FROM public.group_memberships m
         WHERE m.group_id = p_group AND m.agent_id <> p_agent AND m.revoked_at IS NULL
           AND public.epigraph_human_of(m.agent_id, true) = p_agent;
        IF v_operated > 0 THEN
            RAISE EXCEPTION 'GRP03: % agent(s) operated by % are live members of group %; '
                            'remove them before demoting their operator to reader',
                            v_operated, p_agent, p_group
                USING ERRCODE = 'GRP03';
        END IF;
    END IF;

    UPDATE public.group_memberships SET role = p_role WHERE id = v_live_id;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('group.member_role_set', p_agent, true,
            jsonb_build_object('group_id', p_group, 'member', p_agent,
                               'prior_role', v_live_role, 'role', p_role,
                               'membership_id', v_live_id, 'reason', p_reason,
                               'session_user', session_user::text,
                               'actor', public.epigraph_team_group_actor()));
    RETURN QUERY SELECT v_live_id, true, v_live_role;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_team_group_set_member_role(uuid, uuid, text, text)
    FROM PUBLIC;

-- Section 5: ownership and grants, guarded as every such block since 060.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_create_team_group(text, uuid, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_team_group_add_member(uuid, uuid, text, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_team_group_remove_member(uuid, uuid, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION '
                'public.epigraph_team_group_set_member_role(uuid, uuid, text, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_team_group_roster_verbs_only() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_live_memberships(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_team_group_actor() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_team_group_actor() '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_create_team_group(text, uuid, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_team_group_add_member(uuid, uuid, text, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_team_group_remove_member(uuid, uuid, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_team_group_set_member_role(uuid, uuid, text, text) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        -- Section 6: `Viewer::resolve` calls it on the application role (077).
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_live_memberships(uuid) '
                'TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_create_team_group(text, uuid, text) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_team_group_add_member(uuid, uuid, text, text) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_team_group_remove_member(uuid, uuid, text) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_team_group_set_member_role(uuid, uuid, text, text) '
                'FROM epigraph_app';
    END IF;
END $$;
