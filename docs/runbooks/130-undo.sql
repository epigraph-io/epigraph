-- ===================================================================
-- 130-undo.sql: take migration 130 (pending admin acts, and the 123 / 124
-- guards bound to confirmed acts) back out, in ONE transaction, on the
-- migration (superuser) DSN.
--
-- READ FIRST. Roll back every binary that calls a 130 function BEFORE this
-- runs (docs/deploy.md, "Pending admin acts (migration 130)"):
-- epigraph-operator (grant-role / end-role-assignment / custodial-supersede /
-- passkey-enroll with --act) and any API or MCP build that proposes or
-- confirms acts. A new binary left serving after this script fails every such
-- call with 42883 or 42P01. Run it BEFORE 129-undo and every earlier undo
-- (130's act table names 125's sessions and 123's assignments).
--
-- WHAT IT DOES
--   1. Copies EVERY act into `security_events` as one
--      `platform.admin_act_archived` event (the whole row as `details`, plus
--      `archived_by`): an act's proposal, confirmation evidence and
--      consumption are what the offline verifier re-checks, and an undo must
--      not erase them.
--   2. Restores, byte for byte, the bodies 130 replaced: 123's
--      `epigraph_role_assignments_guard_insert` (a writer-supplied
--      `grant_act_id` is refused CUS02 again), `_guard_update`, `_audit` and
--      the six-parameter `epigraph_record_custodial_act`; 124's
--      `epigraph_passkey_enrollments_guard_insert` (`confirmed_act` refused
--      ELV03 again). With them every ELV10 requirement goes: the maintenance
--      verbs act unconfirmed, as before 130.
--   3. Drops the act table (its guards and policies with it) and every
--      function 130 created, the act-taking overloads included.
--
-- WHAT IT LEAVES: the `role_assignments.revoke_act_id` column (nullable
-- metadata no 123 body reads; a column drop would rewrite nothing but is not
-- needed to restore 123's behaviour), the `grant_act_id` / `revoke_act_id` /
-- `act_id` values earlier acts wrote, the archived and `platform.admin_act_*`
-- events, and 130's `_sqlx_migrations` row. Re-introducing acts is a NEW
-- migration, never a re-run of 130. Idempotent: a second run archives
-- nothing and drops nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- 1. The acts, archived.
DO $$
DECLARE
    v_rows bigint := 0;
BEGIN
    IF to_regclass('public.pending_admin_acts') IS NOT NULL THEN
        EXECUTE $q$
            INSERT INTO public.security_events (event_type, agent_id, success, details)
            SELECT 'platform.admin_act_archived', a.proposed_by, true,
                   to_jsonb(a) || jsonb_build_object('archived_by', '130-undo')
              FROM public.pending_admin_acts a
             ORDER BY a.proposed_at, a.id
        $q$;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
    END IF;
    RAISE NOTICE '130-undo: archived % admin act(s) into security_events', v_rows;
END $$;

-- 2. The bodies 130 replaced (123's and 124's, verbatim).
CREATE OR REPLACE FUNCTION public.epigraph_role_assignments_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_any_live   boolean;
    v_other_live boolean;
BEGIN
    -- A grant and a link of the same principal see each other (CUS06 and the
    -- shared lock: section 5, "A ROLE HOLDER IS NEVER LINKED AS AN AGENT").
    IF current_setting('transaction_isolation') = 'repeatable read' THEN
        RAISE EXCEPTION 'CUS06: a role assignment is not written under REPEATABLE READ: its '
                        'snapshot predates the wait for a concurrent link of the holder, so '
                        'neither would see the other'
            USING ERRCODE = 'CUS06',
                  HINT = 'Run it under READ COMMITTED (the default) or SERIALIZABLE.';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    IF NOT public.epigraph_is_human_operator(NEW.holder_person_id)
       OR EXISTS (SELECT 1 FROM public.operator_links l
                   WHERE l.agent_id = NEW.holder_person_id) THEN
        RAISE EXCEPTION 'CUS01: % is not a registered human operator that is no other '
                        'human''s agent; agents never hold a role', NEW.holder_person_id
            USING ERRCODE = 'CUS01',
                  HINT = 'Grant the role to the human''s own principal (a live human_operators '
                         'row with an active human OAuth client), never to an agent.';
    END IF;
    IF NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL OR NEW.revoked_reason IS NOT NULL THEN
        RAISE EXCEPTION 'CUS02: an assignment is recorded live; end it with '
                        'epigraph_end_role_assignment'
            USING ERRCODE = 'CUS02';
    END IF;
    IF NEW.valid_from < now() - interval '1 minute' THEN
        RAISE EXCEPTION 'CUS02: an assignment is never back-dated (valid_from % is before now)',
                        NEW.valid_from
            USING ERRCODE = 'CUS02';
    END IF;
    -- Provenance is the database's, never the writer's: the login that wrote
    -- the row, when, and no confirmed-act id until one exists. So a direct
    -- INSERT cannot pose as this migration's carry-over ('migration 123') or
    -- as an older grant.
    IF NEW.granted_via IS DISTINCT FROM session_user::text
       OR NEW.created_at IS DISTINCT FROM now()
       OR NEW.grant_act_id IS NOT NULL THEN
        RAISE EXCEPTION 'CUS02: granted_via, created_at and grant_act_id are recorded by the '
                        'database (the writing login, now(), none); a grant does not supply them'
            USING ERRCODE = 'CUS02';
    END IF;
    -- A LIVE custodian is what `epigraph_live_role_assignment` answers: the
    -- window, the end, and the holder re-checked (registered, not linked).
    SELECT EXISTS (SELECT 1 FROM public.role_assignments ra
                    WHERE ra.role = 'role:platform-custodian'
                      AND public.epigraph_live_role_assignment(ra.holder_person_id,
                              'role:platform-custodian', now()) IS NOT NULL),
           EXISTS (SELECT 1 FROM public.role_assignments ra
                    WHERE ra.role = 'role:platform-custodian'
                      AND ra.holder_person_id IS DISTINCT FROM NEW.holder_person_id
                      AND public.epigraph_live_role_assignment(ra.holder_person_id,
                              'role:platform-custodian', now()) IS NOT NULL)
      INTO v_any_live, v_other_live;
    IF NEW.granted_by IS NULL THEN
        IF v_any_live THEN
            RAISE EXCEPTION 'CUS03: a live custodian exists, so a grant names the granting '
                            'custodian'
                USING ERRCODE = 'CUS03';
        END IF;
    ELSIF public.epigraph_live_role_assignment(NEW.granted_by, 'role:platform-custodian', now())
          IS NULL THEN
        RAISE EXCEPTION 'CUS03: the grantor % holds no live role:platform-custodian assignment',
                        NEW.granted_by
            USING ERRCODE = 'CUS03';
    ELSIF NEW.granted_by = NEW.holder_person_id AND v_other_live THEN
        RAISE EXCEPTION 'CUS03: % may not extend its own assignment while another custodian '
                        'holds; that custodian grants it', NEW.holder_person_id
            USING ERRCODE = 'CUS03';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_role_assignments_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'CUS02: assignment % has ended, and an ended assignment is final',
                        OLD.id
            USING ERRCODE = 'CUS02';
    END IF;
    IF NEW.revoked_at IS NULL OR NEW.revoked_at <> now()
       OR NEW.revoked_by IS DISTINCT FROM session_user::text
       OR NEW.revoked_reason IS NULL OR length(btrim(NEW.revoked_reason)) = 0
       OR (NEW.id, NEW.role, NEW.holder_person_id, NEW.holder_group_id, NEW.valid_from,
           NEW.valid_to, NEW.granted_by, NEW.granted_via, NEW.grant_act_id, NEW.reason,
           NEW.created_at)
          IS DISTINCT FROM
          (OLD.id, OLD.role, OLD.holder_person_id, OLD.holder_group_id, OLD.valid_from,
           OLD.valid_to, OLD.granted_by, OLD.granted_via, OLD.grant_act_id, OLD.reason,
           OLD.created_at) THEN
        RAISE EXCEPTION 'CUS02: an assignment is only ever ended (revoked_at = now(), '
                        'revoked_by = the revoking login, and a revoked_reason), nothing '
                        'else; nothing was changed'
            USING ERRCODE = 'CUS02',
                  HINT = 'End it with epigraph-operator end-role-assignment and grant a new one.';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_role_assignments_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_node uuid;
BEGIN
    SELECT r.role_node_id INTO v_node FROM public.platform_roles r WHERE r.key = NEW.role;
    IF TG_OP = 'INSERT' THEN
        -- Section 5: the projection, holder -> role node, in the edge's own
        -- validity columns. A structural (agent -> agent) edge: 120 owns it
        -- by the world group, public.
        INSERT INTO public.edges (source_id, source_type, target_id, target_type, relationship,
                                  properties, valid_from, valid_to, visibility, owner_group_id)
        VALUES (NEW.holder_person_id, 'agent', v_node, 'agent', 'OCCUPIES',
                jsonb_build_object('assignment_id', NEW.id::text, 'role', NEW.role,
                                   'source', 'role_assignments', 'projection', true),
                NEW.valid_from, NEW.valid_to, 'public',
                '00000000-0000-0000-0000-000000000000'::uuid);
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_granted', NEW.holder_person_id, true,
                jsonb_build_object('assignment_id', NEW.id, 'role', NEW.role,
                                   'holder', NEW.holder_person_id,
                                   'valid_from', NEW.valid_from, 'valid_to', NEW.valid_to,
                                   'granted_by', NEW.granted_by,
                                   'granted_via', NEW.granted_via, 'reason', NEW.reason,
                                   'migrated', NEW.granted_via = 'migration 123'));
    ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        -- The projection closes at the end (or keeps an earlier valid_to).
        -- An assignment ended before it began keeps a one-microsecond window
        -- marked never_effective: `temporal_ordering` requires
        -- valid_to > valid_from.
        UPDATE public.edges e
           SET valid_to = CASE
                            WHEN LEAST(COALESCE(NEW.valid_to, NEW.revoked_at), NEW.revoked_at)
                                 <= NEW.valid_from
                            THEN NEW.valid_from + interval '1 microsecond'
                            ELSE LEAST(COALESCE(NEW.valid_to, NEW.revoked_at), NEW.revoked_at)
                          END,
               properties = e.properties
                   || jsonb_build_object('ended_at', NEW.revoked_at,
                                         'never_effective', NEW.revoked_at <= NEW.valid_from)
         WHERE e.relationship = 'OCCUPIES' AND e.source_type = 'agent'
           AND e.source_id = NEW.holder_person_id
           AND e.properties @> jsonb_build_object('assignment_id', NEW.id::text);
        -- Section 6: the end of the holder's LAST un-ended custodian
        -- assignment is mirrored into a live legacy `instance_admins` row, so a
        -- rollback to 083's body cannot resurrect an authority ended here.
        IF NEW.role = 'role:platform-custodian'
           AND NOT EXISTS (SELECT 1 FROM public.role_assignments ra
                            WHERE ra.holder_person_id = NEW.holder_person_id
                              AND ra.role = 'role:platform-custodian'
                              AND ra.revoked_at IS NULL AND ra.id <> NEW.id) THEN
            UPDATE public.instance_admins SET revoked_at = now()
             WHERE agent_id = NEW.holder_person_id AND revoked_at IS NULL;
        END IF;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_ended', NEW.holder_person_id, true,
                jsonb_build_object('assignment_id', NEW.id, 'role', NEW.role,
                                   'holder', NEW.holder_person_id,
                                   'revoked_at', NEW.revoked_at, 'revoked_by', NEW.revoked_by,
                                   'revoked_reason', NEW.revoked_reason));
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_record_custodial_act(
    p_assignment uuid, p_actor uuid, p_act text, p_target_type text, p_target uuid,
    p_details jsonb)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_row public.role_assignments%ROWTYPE;
    v_id  uuid;
BEGIN
    IF p_act IS NULL OR p_act NOT IN ('claim.supersede', 'privatization.plan_create',
                                      'privatization.plan_transition') THEN
        RAISE EXCEPTION 'epigraph_record_custodial_act: % is not a recorded custodial act', p_act
            USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_row FROM public.role_assignments ra WHERE ra.id = p_assignment;
    IF NOT FOUND
       OR v_row.role <> 'role:platform-custodian'
       OR v_row.holder_person_id IS DISTINCT FROM p_actor
       OR v_row.revoked_at IS NOT NULL
       OR v_row.valid_from > clock_timestamp()
       OR (v_row.valid_to IS NOT NULL AND clock_timestamp() >= v_row.valid_to)
       OR NOT public.epigraph_is_human_operator(p_actor)
       OR EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = p_actor) THEN
        RAISE EXCEPTION 'CUS04: % is not a live role:platform-custodian assignment held by %; '
                        'nothing was recorded or changed', p_assignment, p_actor
            USING ERRCODE = 'CUS04',
                  HINT = 'Name the actor''s own live assignment: epigraph-operator '
                         'list-role-assignments --role role:platform-custodian.';
    END IF;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('platform.custodial_act', p_actor, true,
            jsonb_build_object('assignment_id', v_row.id, 'role', v_row.role,
                               'valid_from', v_row.valid_from, 'valid_to', v_row.valid_to,
                               'actor', p_actor, 'act', p_act,
                               'target_type', p_target_type, 'target', p_target,
                               'details', COALESCE(p_details, '{}'::jsonb),
                               'recorded_by', session_user))
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_passkey_enrollments_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NOT public.epigraph_is_human_operator(NEW.person_agent_id)
       OR EXISTS (SELECT 1 FROM public.operator_links l
                   WHERE l.agent_id = NEW.person_agent_id) THEN
        RAISE EXCEPTION 'ELV01: % is not a registered human operator that is no other '
                        'human''s agent; a passkey belongs only to a human', NEW.person_agent_id
            USING ERRCODE = 'ELV01',
                  HINT = 'Enroll the human''s own principal (a live human_operators row with an '
                         'active human OAuth client), never an agent.';
    END IF;
    IF NEW.created_via <> 'maintenance' THEN
        RAISE EXCEPTION 'ELV03: an enrollment is opened by a maintenance act; no confirmed-act '
                        'path exists yet'
            USING ERRCODE = 'ELV03';
    END IF;
    -- Provenance is the database's: the login that opened it, now, and no
    -- ceremony or consumption a writer could pre-supply.
    IF NEW.created_by IS DISTINCT FROM session_user::text
       OR NEW.created_at IS DISTINCT FROM now()
       OR NEW.challenge_state IS NOT NULL
       OR NEW.consumed_at IS NOT NULL OR NEW.authenticator_id IS NOT NULL THEN
        RAISE EXCEPTION 'ELV03: created_by, created_at, the challenge and the consumption of an '
                        'enrollment are recorded by the database (the opening login, now(), '
                        'none, none); an enrollment does not supply them'
            USING ERRCODE = 'ELV03';
    END IF;
    RETURN NEW;
END $$;

-- 3. The act table, then every 130 function (the overloads by their full
--    signatures: the earlier forms stay).
DROP TABLE IF EXISTS public.pending_admin_acts;

DROP FUNCTION IF EXISTS public.epigraph_confirm_admin_act(uuid, bytea, bigint, boolean, jsonb);
DROP FUNCTION IF EXISTS public.epigraph_passkeys_for_act(uuid);
DROP FUNCTION IF EXISTS public.epigraph_set_admin_act_challenge(uuid, jsonb);
DROP FUNCTION IF EXISTS public.epigraph_act_for_ceremony(uuid);
DROP FUNCTION IF EXISTS public.epigraph_propose_admin_act(text, jsonb, text, text);
DROP FUNCTION IF EXISTS public.epigraph_create_passkey_enrollment(uuid, text, text, uuid);
DROP FUNCTION IF EXISTS public.epigraph_record_custodial_act(uuid, uuid, text, text, uuid, jsonb,
                                                             uuid);
DROP FUNCTION IF EXISTS public.epigraph_end_role_assignment(uuid, text, uuid);
DROP FUNCTION IF EXISTS public.epigraph_grant_role(text, uuid, timestamptz, timestamptz, uuid, text,
                                                   uuid);
DROP FUNCTION IF EXISTS public.epigraph_consume_admin_act(uuid, text, bytea, uuid, jsonb);
DROP FUNCTION IF EXISTS public.epigraph_pending_admin_acts_audit();
DROP FUNCTION IF EXISTS public.epigraph_pending_admin_acts_guard_update();
DROP FUNCTION IF EXISTS public.epigraph_pending_admin_acts_guard_insert();
DROP FUNCTION IF EXISTS public.epigraph_has_live_passkey(uuid);
DROP FUNCTION IF EXISTS public.epigraph_admin_act_digest(jsonb);
DROP FUNCTION IF EXISTS public.epigraph_admin_act_args(text, jsonb);
DROP FUNCTION IF EXISTS public.epigraph_canonical_timestamp(timestamptz);
DROP FUNCTION IF EXISTS public.epigraph_canonical_json(jsonb);

COMMIT;
