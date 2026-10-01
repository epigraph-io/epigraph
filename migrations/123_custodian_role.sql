-- Migration 123: the custodian role. Instance administration becomes a ROLE
-- that a registered human holds through a timestamped, append-only
-- assignment, instead of a row in `instance_admins` that any agent could
-- carry.
--
-- ===================================================================
-- 1. THE MODEL
--
-- `platform_roles` is a two-row catalog: `role:platform-custodian` (the role
-- that administers the instance; `elevates`) and `role:auditor` (reads the
-- platform audit trail). `role_assignments` records who holds which role,
-- from when, until when, granted by whom, on which login, and why. A row is
-- never edited and never deleted: the only change it ever takes is its end
-- (`revoked_at`, stamped `now()`, with who and why), and an ended row is
-- final. Holding a role is a function of time
-- (`epigraph_role_assignment_for(principal, role, at)`), so "who could
-- administer the instance on date D" has an answer.
--
-- AGENTS NEVER HOLD A ROLE. The holder must be a registered human operator
-- (`epigraph_is_human_operator`, migration 122: a live `human_operators` row
-- AND its recorded human OAuth client still active) that is NOT itself linked
-- to a human as an agent (no `operator_links` row with it as the agent, live
-- or retired: 122 admits linking a registered human, and such a principal is
-- an operated agent whatever its registry row says). A live-linked agent, a
-- retired identity, an unbound agent, a registered human that is also linked
-- as an agent, and a human whose client is suspended are refused `CUS01`, and
-- the test is repeated at read time, so a human whose registration is later
-- revoked, or who is later linked as an agent, stops holding at once.
--
-- Group holders are not admitted yet (`holder_group_id IS NULL` CHECK): the
-- column exists so a later batch can admit a group whose member human
-- activates the role, without a table rewrite.
--
-- ===================================================================
-- 2. WHO WRITES IT
--
-- Only a privileged session (`epigraph_bypass()`: the maintenance role or a
-- superuser). The application role holds SELECT only, narrowed by row
-- security to its OWN assignments; the INSERT and UPDATE policies admit only
-- `epigraph_bypass()`, and no DELETE policy exists, so under FORCE no role
-- deletes a row. The rules live on the TABLE (guard triggers), so a direct
-- INSERT on a maintenance login meets exactly what the definers meet:
--
--   CUS01  the holder is not a registered human.
--   CUS02  the row is not append-only: a revoke field set on INSERT, a
--          back-dated `valid_from` (more than a minute in the past), a
--          provenance column the writer supplied (`granted_via` other than
--          the writing login, `created_at` other than `now()`, a
--          `grant_act_id`), any change but the one revoke, a revoke not
--          stamped `now()` by the revoking login (`revoked_by =
--          session_user`) or with no reason, or any change to an ended row.
--
-- WHAT THE TABLE CANNOT PROVE. `granted_by` and the actor of a custodial act
-- are UUIDs the maintenance login supplies; the guards check that they name
-- a live custodian, not that the person behind that custodian made the
-- write. Whoever holds the maintenance DSN can write what the definers
-- write. Binding them to a confirmed act is the elevation batch's work
-- (DESIGN 6.2), not this migration's.
--   CUS03  the grantor rule: once any live custodian exists, every grant
--          names a LIVE custodian as `granted_by`, and a holder never extends
--          itself while another holder exists. With no live custodian (the
--          bootstrap) only a grant with no grantor is admitted.
--
-- ===================================================================
-- 3. UNDO
--
-- `docs/runbooks/123-undo.sql`. Roll back first every binary that calls a
-- function this file creates (docs/deploy.md).

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. THE CATALOG AND ITS PROJECTION NODES
--
-- Each catalog role has a node in the graph: an `agents` row of
-- `agent_type = 'role'` at a fixed id. Its public key is 32 random bytes
-- whose private half exists nowhere, so nothing can sign as it, and the role
-- node is refused as a link or registry subject (section 5), so it can never
-- become a bound writer.
INSERT INTO public.agents (id, public_key, display_name, agent_type, role, labels)
VALUES
    ('00000000-0000-0000-0001-000000000001'::uuid,
     uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()),
     'role:platform-custodian', 'role', 'custom', ARRAY['role', 'platform-role']),
    ('00000000-0000-0000-0001-000000000002'::uuid,
     uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()),
     'role:auditor', 'role', 'custom', ARRAY['role', 'platform-role'])
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS public.platform_roles (
    key          text PRIMARY KEY CONSTRAINT platform_roles_key_shape
                     CHECK (key ~ '^role:[a-z][a-z0-9-]*$'),
    elevates     boolean NOT NULL,
    reads_audit  boolean NOT NULL,
    role_node_id uuid NOT NULL UNIQUE REFERENCES public.agents(id) ON DELETE RESTRICT,
    description  text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   text NOT NULL DEFAULT session_user
);
REVOKE ALL ON public.platform_roles FROM PUBLIC;

INSERT INTO public.platform_roles (key, elevates, reads_audit, role_node_id, description)
VALUES
    ('role:platform-custodian', true, true, '00000000-0000-0000-0001-000000000001'::uuid,
     'Administers the instance: privatization and custodial revision of the platform corpus, '
     'each on the maintenance DSN as a recorded custodial act. Confers nothing on an '
     'application session. Held only by a registered human.'),
    ('role:auditor', false, true, '00000000-0000-0000-0001-000000000002'::uuid,
     'Reads the platform audit trail. Confers no write authority.')
ON CONFLICT (key) DO NOTHING;

-- A catalog row's identity never changes: its key, whether it elevates, and
-- its node are fixed. Only the description may be edited (by a privileged
-- session; the UPDATE policy below).
CREATE OR REPLACE FUNCTION public.epigraph_platform_roles_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF (NEW.key, NEW.elevates, NEW.reads_audit, NEW.role_node_id, NEW.created_at, NEW.created_by)
       IS DISTINCT FROM
       (OLD.key, OLD.elevates, OLD.reads_audit, OLD.role_node_id, OLD.created_at, OLD.created_by) THEN
        RAISE EXCEPTION 'CUS02: platform role %: only its description may change', OLD.key
            USING ERRCODE = 'CUS02';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_platform_roles_guard_update() FROM PUBLIC;

DROP TRIGGER IF EXISTS platform_roles_guard_update ON public.platform_roles;
CREATE TRIGGER platform_roles_guard_update
    BEFORE UPDATE ON public.platform_roles
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_platform_roles_guard_update();

ALTER TABLE public.platform_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.platform_roles FORCE ROW LEVEL SECURITY;
-- A catalog, not a secret: every session reads it.
DROP POLICY IF EXISTS platform_roles_read ON public.platform_roles;
CREATE POLICY platform_roles_read ON public.platform_roles FOR SELECT TO PUBLIC
    USING (true);
DROP POLICY IF EXISTS platform_roles_maintenance_insert ON public.platform_roles;
CREATE POLICY platform_roles_maintenance_insert ON public.platform_roles
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()));
DROP POLICY IF EXISTS platform_roles_maintenance_update ON public.platform_roles;
CREATE POLICY platform_roles_maintenance_update ON public.platform_roles
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()));

-- ===================================================================
-- 2. THE ASSIGNMENTS
-- ===================================================================
CREATE TABLE IF NOT EXISTS public.role_assignments (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role             text NOT NULL REFERENCES public.platform_roles(key) ON DELETE RESTRICT,
    holder_person_id uuid REFERENCES public.agents(id) ON DELETE RESTRICT,
    holder_group_id  uuid REFERENCES public.groups(id) ON DELETE RESTRICT,
    valid_from       timestamptz NOT NULL,
    valid_to         timestamptz,
    -- NULL: the bootstrap grant (no live custodian existed) or a row this
    -- migration carried over from `instance_admins` with no grantor.
    granted_by       uuid REFERENCES public.agents(id) ON DELETE RESTRICT,
    -- The database login that wrote the row.
    granted_via      text NOT NULL DEFAULT session_user,
    -- Reserved for a confirmed-act record; NULL until one exists.
    grant_act_id     uuid,
    reason           text NOT NULL CONSTRAINT role_assignments_reason_present
                         CHECK (length(btrim(reason)) > 0),
    created_at       timestamptz NOT NULL DEFAULT now(),
    revoked_at       timestamptz,
    revoked_by       text,
    revoked_reason   text,
    CONSTRAINT role_assignments_one_holder
        CHECK (num_nonnulls(holder_person_id, holder_group_id) = 1),
    CONSTRAINT role_assignments_no_group_holder_yet CHECK (holder_group_id IS NULL),
    CONSTRAINT role_assignments_window CHECK (valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT role_assignments_revoke_shape
        CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)
               AND (revoked_at IS NULL) = (revoked_reason IS NULL))
);
REVOKE ALL ON public.role_assignments FROM PUBLIC;
CREATE INDEX IF NOT EXISTS idx_role_assignments_live
    ON public.role_assignments (holder_person_id, role) WHERE revoked_at IS NULL;

-- The live assignment of `p_role` held by `p_holder` at `p_at`, answered for
-- ANY holder. Not granted to the application role: an unbound roster read is
-- an oracle (083's header). The guards and definers below call it; the
-- subject-bound reader for every other caller is
-- `epigraph_role_assignment_for` (section 3).
CREATE OR REPLACE FUNCTION public.epigraph_live_role_assignment(
    p_holder uuid, p_role text, p_at timestamptz)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT CASE
             WHEN p_holder IS NULL OR p_role IS NULL OR p_at IS NULL THEN NULL
             WHEN NOT public.epigraph_is_human_operator(p_holder) THEN NULL
             -- A registered human that is also linked as an agent (live or
             -- retired) is an operated agent: agents never hold a role.
             WHEN EXISTS (SELECT 1 FROM public.operator_links l
                           WHERE l.agent_id = p_holder) THEN NULL
             ELSE (SELECT ra.id FROM public.role_assignments ra
                    WHERE ra.role = p_role AND ra.holder_person_id = p_holder
                      AND ra.revoked_at IS NULL
                      AND ra.valid_from <= p_at
                      AND (ra.valid_to IS NULL OR p_at < ra.valid_to)
                    ORDER BY ra.valid_from, ra.id
                    LIMIT 1)
           END
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_live_role_assignment(uuid, text, timestamptz) FROM PUBLIC;

-- BEFORE INSERT: CUS01, CUS02 and CUS03 (section 2 of the header).
CREATE OR REPLACE FUNCTION public.epigraph_role_assignments_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_any_live   boolean;
    v_other_live boolean;
BEGIN
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
REVOKE EXECUTE ON FUNCTION public.epigraph_role_assignments_guard_insert() FROM PUBLIC;

-- BEFORE UPDATE: the only change ever admitted is the revoke, once, stamped
-- now(), with who and why; every other column unchanged. An ended row is
-- final.
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
REVOKE EXECUTE ON FUNCTION public.epigraph_role_assignments_guard_update() FROM PUBLIC;

DROP TRIGGER IF EXISTS role_assignments_guard_update ON public.role_assignments;
CREATE TRIGGER role_assignments_guard_update
    BEFORE UPDATE ON public.role_assignments
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_assignments_guard_update();

-- Row security, 083's pattern: the holder reads its own rows, a privileged
-- session and a maintenance-owned definer frame read all; only a privileged
-- session writes; nobody deletes (no policy).
ALTER TABLE public.role_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_assignments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS role_assignments_self_or_definer ON public.role_assignments;
CREATE POLICY role_assignments_self_or_definer ON public.role_assignments
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR holder_person_id = (SELECT public.epigraph_principal_id()));
DROP POLICY IF EXISTS role_assignments_maintenance_insert ON public.role_assignments;
CREATE POLICY role_assignments_maintenance_insert ON public.role_assignments
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()));
DROP POLICY IF EXISTS role_assignments_maintenance_update ON public.role_assignments;
CREATE POLICY role_assignments_maintenance_update ON public.role_assignments
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()));

-- The insert guard's TRIGGER is created in section 6, after the rows this
-- migration carries over from `instance_admins`: only that seed may carry a
-- past `valid_from` (the legacy `granted_at`).

-- ===================================================================
-- 3. WHO HOLDS A ROLE: SUBJECT-BOUND READERS
--
-- `epigraph_role_assignment_for(principal, role, at)` names the live
-- assignment (the earliest by valid_from, then id) of `role` held by
-- `principal` at `at`; `epigraph_holds_role` is its two-valued boolean. Both
-- are EXECUTE-able by the application role, so both BIND THE SUBJECT IN THE
-- BODY exactly as 083 does for `epigraph_is_instance_admin`: the answer is
-- NULL / false unless `principal` is the session principal or the session is
-- privileged (`epigraph_bypass()`, which reads `session_user`). Never
-- `epigraph_definer_bypass()`: it reads `current_user`, which inside this
-- frame is the owner, so it is always true here and would turn the readers
-- into a roster oracle.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_role_assignment_for(
    p_principal uuid, p_role text, p_at timestamptz)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT CASE
             WHEN p_principal IS NOT NULL
              AND (p_principal = public.epigraph_principal_id() OR public.epigraph_bypass())
             THEN public.epigraph_live_role_assignment(p_principal, p_role, p_at)
           END
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_assignment_for(uuid, text, timestamptz) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_holds_role(
    p_principal uuid, p_role text, p_at timestamptz)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT public.epigraph_role_assignment_for(p_principal, p_role, p_at) IS NOT NULL
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_holds_role(uuid, text, timestamptz) FROM PUBLIC;

-- ===================================================================
-- 4. THE PLATFORM AUDIT TRAIL
--
-- Every assignment change and every custodial act is one `security_events`
-- row whose type starts with `platform.` and whose details name the
-- assignment. The application role
-- keeps INSERT on `security_events` (077: an actor never suppresses its own
-- audit record), so the prefix is RESERVED, as 117 reserves `cascade.` and
-- 118 reserves `oauth.`: a RESTRICTIVE insert policy admits a `platform.` row
-- only from a privileged session or a maintenance-owned definer frame, and
-- only stamped `now()` (no back-dated row). The prefix test ignores case and
-- surrounding blanks, so `Platform.custodial_act` is the reserved prefix too,
-- not a look-alike an application session may write. 082's
-- `security_events_no_mutate` trigger already makes every row immutable, on
-- every role.
--
-- The two arms cannot tell a definer from the maintenance login that called
-- it (`epigraph_definer_bypass()` reads `current_user`, and a maintenance
-- login is a member of the maintenance role either way), so a holder of the
-- maintenance DSN can still write a well-formed `platform.` row. The audit
-- is unforgeable by the APPLICATION; provenance against the maintenance DSN
-- waits for the elevation batch (header, "What the table cannot prove").
-- ===================================================================
DROP POLICY IF EXISTS security_events_platform_privileged ON public.security_events;
CREATE POLICY security_events_platform_privileged ON public.security_events
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        lower(left(btrim(event_type), 9)) <> 'platform.'
        OR (((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
            AND created_at = now()));

-- AFTER INSERT / UPDATE on `role_assignments`: whatever path wrote the row
-- (a definer below, or a direct maintenance statement), one
-- `platform.role_granted` or `platform.role_ended` row, and the OCCUPIES
-- projection (section 5).
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
REVOKE EXECUTE ON FUNCTION public.epigraph_role_assignments_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS role_assignments_audit ON public.role_assignments;
CREATE TRIGGER role_assignments_audit
    AFTER INSERT OR UPDATE ON public.role_assignments
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_assignments_audit();

-- The maintenance verbs (`epigraph-operator grant-role` /
-- `end-role-assignment`) call one function each. They add nothing to the
-- table's own rules: the INSERT and UPDATE meet the guards and the audit
-- above. `revoked_at` is stamped here, in SQL, so no caller supplies a time.
CREATE OR REPLACE FUNCTION public.epigraph_grant_role(
    p_role text, p_holder uuid, p_valid_from timestamptz, p_valid_to timestamptz,
    p_granted_by uuid, p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_id uuid;
BEGIN
    IF p_role IS NULL OR p_holder IS NULL OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_grant_role: the role, the holder and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    INSERT INTO public.role_assignments (role, holder_person_id, valid_from, valid_to,
                                         granted_by, reason)
    VALUES (p_role, p_holder, COALESCE(p_valid_from, now()), p_valid_to, p_granted_by, p_reason)
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_grant_role(text, uuid, timestamptz, timestamptz, uuid, text) FROM PUBLIC;

-- End an assignment now. False when it was already ended (or does not
-- exist): an end is never repeated or re-dated.
CREATE OR REPLACE FUNCTION public.epigraph_end_role_assignment(p_id uuid, p_reason text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF p_id IS NULL OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_end_role_assignment: the assignment and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    UPDATE public.role_assignments
       SET revoked_at = now(), revoked_by = session_user, revoked_reason = p_reason
     WHERE id = p_id AND revoked_at IS NULL;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows > 0;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_end_role_assignment(uuid, text) FROM PUBLIC;

-- One custodial act (a maintenance-DSN custodial supersede, a privatization
-- plan write), recorded in the SAME transaction as the act: a
-- `platform.custodial_act` row naming the assignment, its window, the actor,
-- the act and its target. Refused (`CUS04`) unless `p_assignment` is a LIVE
-- role:platform-custodian assignment held NOW (`clock_timestamp()`: the
-- statement's clock, not the transaction's start) by `p_actor`, a registered
-- human that is no other human's agent, so the refusal rolls the act back
-- with it. The acts are an
-- enumerated list (`22023` otherwise), so the trail's vocabulary is closed.
-- Maintenance-only EXECUTE.
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
REVOKE EXECUTE ON FUNCTION
    public.epigraph_record_custodial_act(uuid, uuid, text, text, uuid, jsonb) FROM PUBLIC;

-- The trail's reader: every `platform.` row since `p_since` (newest first,
-- at most `p_limit`, capped at 1000) for a session that holds a role which
-- `reads_audit` NOW, as its own principal, or a privileged session. Anyone
-- else gets no rows. A definer rather than a `security_events_read` arm, so
-- reading the trail needs no DDL on that table and no change to who reads
-- the rest of it.
CREATE OR REPLACE FUNCTION public.epigraph_platform_audit(p_since timestamptz, p_limit integer)
RETURNS SETOF public.security_events
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT e.*
      FROM public.security_events e
     WHERE left(e.event_type, 9) = 'platform.'
       AND e.created_at >= COALESCE(p_since, '-infinity'::timestamptz)
       AND (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM public.platform_roles r
                        WHERE r.reads_audit
                          AND public.epigraph_holds_role(public.epigraph_principal_id(),
                                                         r.key, now())))
     ORDER BY e.created_at DESC, e.id
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 100), 1), 1000)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_platform_audit(timestamptz, integer) FROM PUBLIC;

-- ===================================================================
-- 5. THE OCCUPIES PROJECTION, AND WHY IT IS NEVER AUTHORITY
--
-- The governance graph says who occupies which role with an `OCCUPIES` edge.
-- The audit trigger above writes one per assignment (holder -> the role's
-- node, `properties.assignment_id`), in the edge's native `valid_from` /
-- `valid_to`, and closes it at the end. It is a PROJECTION: nothing reads it
-- for authority. Every authority question goes to `role_assignments` through
-- the subject-bound readers (section 3); an edge is ordinary graph content
-- that any writer of the world group could add, so authority that read edges
-- could be minted by writing one. The ratchet test
-- `custodian_role.rs::occupies_mirrors_assignments_and_is_never_read_for_authz`
-- fails if any policy or function but the projection mentions OCCUPIES, and
-- `no_rust_source_queries_the_occupies_projection` does the same for Rust.
--
-- The projection (like `role_assignments` row security) is not the
-- disclosure boundary for who holds a role: the edge is world-readable,
-- as the governance graph's other OCCUPIES edges are.
--
-- Nor is an OCCUPIES edge to a role node proof of the projection: a writer of
-- the world group can add an edge of the same shape (this migration takes no
-- lock on `edges`). A governance reader that must know who held a role joins
-- the edge to `role_assignments` on `properties->>'assignment_id'` (holder
-- and window equal), or asks `epigraph_role_assignment_for`; an edge with no
-- such row is not a projection.
--
-- THE ROLE NODE NEVER BECOMES A WRITER. It is refused as the subject of a
-- link (agent or operator) and of a human registration, so no session can
-- bind it to a human and then stamp it.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_refuse_role_node_subject()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.platform_roles r
                WHERE r.role_node_id = NEW.agent_id
                   OR (TG_TABLE_NAME = 'operator_links'
                       AND r.role_node_id = (to_jsonb(NEW)->>'operator_id')::uuid)) THEN
        RAISE EXCEPTION '% is the graph node of a platform role; it is never linked, '
                        'registered or bound to a human', NEW.agent_id
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refuse_role_node_subject() FROM PUBLIC;

DROP TRIGGER IF EXISTS operator_links_refuse_role_node ON public.operator_links;
CREATE TRIGGER operator_links_refuse_role_node
    BEFORE INSERT ON public.operator_links
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_refuse_role_node_subject();
DROP TRIGGER IF EXISTS human_operators_refuse_role_node ON public.human_operators;
CREATE TRIGGER human_operators_refuse_role_node
    BEFORE INSERT ON public.human_operators
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_refuse_role_node_subject();

-- A ROLE HOLDER IS NEVER LINKED AS AN AGENT (review SEC-MTC-9). Holding is
-- re-checked at read time (a principal with any `operator_links` row as the
-- agent holds nothing), so a link made after a grant would end the holding
-- SILENTLY: no `platform.role_ended` row. A new link (live or retired, by any
-- link function) of a principal with an un-ended assignment that has not
-- lapsed (live, or not yet begun) is therefore refused CUS01; its holding
-- ends through `epigraph-operator end-role-assignment`, whose end is audited,
-- and the link is made afterwards. `operator_links` takes no UPDATE (107: no
-- policy, no grant), so the INSERT is the only way in.
CREATE OR REPLACE FUNCTION public.epigraph_operator_links_refuse_role_holder()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_assignment uuid;
    v_role       text;
BEGIN
    SELECT ra.id, ra.role INTO v_assignment, v_role
      FROM public.role_assignments ra
     WHERE ra.holder_person_id = NEW.agent_id
       AND ra.revoked_at IS NULL
       AND (ra.valid_to IS NULL OR ra.valid_to > clock_timestamp())
     ORDER BY ra.valid_from
     LIMIT 1;
    IF v_assignment IS NOT NULL THEN
        RAISE EXCEPTION 'CUS01: % holds % (assignment %); a role holder is never linked as an '
                        'agent: end the assignment first (epigraph-operator '
                        'end-role-assignment), so its end is audited', NEW.agent_id, v_role,
                        v_assignment
            USING ERRCODE = 'CUS01';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_links_refuse_role_holder() FROM PUBLIC;

DROP TRIGGER IF EXISTS operator_links_refuse_role_holder ON public.operator_links;
CREATE TRIGGER operator_links_refuse_role_holder
    BEFORE INSERT ON public.operator_links
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_operator_links_refuse_role_holder();

-- ===================================================================
-- 6. FROM `instance_admins` TO THE ROLE
--
-- (a) CARRY OVER. Every LIVE `instance_admins` row whose agent is a
--     registered human becomes a `role:platform-custodian` assignment from
--     its `granted_at` (`granted_via = 'migration 123'`), audited
--     (`platform.role_granted`, `migrated: true`) and projected by the
--     trigger above. This seed is the only path that writes a past
--     `valid_from`: the insert guard's trigger is created after it.
-- (b) SKIP LOUDLY. A live row of anything else (an agent, a retired
--     identity, a human not registered yet, a registered human linked as
--     another human's agent, a registered human whose human client is not
--     active) is NOT carried: agents never hold the role, and the seed admits
--     exactly the holders the insert guard would. Each one raises a NOTICE
--     and writes a `platform.role_migration_skipped` event naming it and WHY
--     (`details.reason`), so a suspended human client reads as that, not as
--     "not a registered human": re-grant it with `grant-role` once its client
--     is active. A revoked row is not carried; it stays readable in the table
--     as history.
-- (c) ANSWER FROM THE ROLE. `epigraph_is_instance_admin(agent)` keeps its
--     name, signature, grants and subject binding (083's policies, 087's and
--     122's definers call it), and now answers "holds role:platform-custodian
--     now". So a legacy row alone confers nothing from here on.
-- (d) FREEZE. `instance_admins` takes no new row and no edit, on every role
--     (a trigger: the superuser included), with one exception: a `revoked_at`
--     stamp (NULL -> now(), nothing else) on the row of a principal that
--     holds NO live custodian assignment, plus the FK's own SET NULL of
--     `granted_by`. So an N-1 `epigraph-instance-admin revoke` (or a hand
--     UPDATE) of a live custodian fails `CUS05` instead of reporting a revoke
--     the role still contradicts; the role ends with `end-role-assignment`. Ending a holder's last custodian assignment (section 4's
--     trigger) and revoking a human's registration (the trigger below)
--     stamp the holder's live legacy row, so a rollback to 083's body (which
--     reads this table) cannot resurrect an authority ended after 123. The
--     table and its read policy stay as they are, read-compatible.
-- ===================================================================
INSERT INTO public.role_assignments (role, holder_person_id, valid_from, granted_by,
                                     granted_via, reason)
SELECT 'role:platform-custodian', ia.agent_id, ia.granted_at, ia.granted_by, 'migration 123',
       'migrated from instance_admins (083): ' || COALESCE(NULLIF(btrim(ia.note), ''), 'no note')
  FROM public.instance_admins ia
 WHERE ia.revoked_at IS NULL
   AND public.epigraph_is_human_operator(ia.agent_id)
   AND NOT EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = ia.agent_id)
   AND NOT EXISTS (SELECT 1 FROM public.role_assignments ra
                    WHERE ra.holder_person_id = ia.agent_id
                      AND ra.granted_via = 'migration 123');

DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT ia.agent_id, ia.granted_at,
                    CASE
                      WHEN EXISTS (SELECT 1 FROM public.operator_links l
                                    WHERE l.agent_id = ia.agent_id)
                        THEN 'linked to a human operator as its agent'
                      WHEN public.epigraph_is_human_operator(ia.agent_id)
                        THEN NULL
                      WHEN EXISTS (SELECT 1 FROM public.human_operators h
                                    WHERE h.agent_id = ia.agent_id AND h.revoked_at IS NULL)
                        THEN 'a registered human whose human OAuth client is not active'
                      ELSE 'not a registered human operator'
                    END AS reason
               FROM public.instance_admins ia
              WHERE ia.revoked_at IS NULL
                AND NOT EXISTS (SELECT 1 FROM public.security_events e
                                 WHERE e.event_type = 'platform.role_migration_skipped'
                                   AND e.agent_id = ia.agent_id)
              ORDER BY ia.granted_at, ia.agent_id LOOP
        CONTINUE WHEN r.reason IS NULL;
        RAISE NOTICE 'migration 123: instance admin % is NOT carried over to '
                     'role:platform-custodian: %', r.agent_id, r.reason;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_migration_skipped', r.agent_id, false,
                jsonb_build_object('agent_id', r.agent_id, 'granted_at', r.granted_at,
                                   'reason', r.reason));
    END LOOP;
END $$;

DROP TRIGGER IF EXISTS role_assignments_guard_insert ON public.role_assignments;
CREATE TRIGGER role_assignments_guard_insert
    BEFORE INSERT ON public.role_assignments
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_assignments_guard_insert();

CREATE OR REPLACE FUNCTION public.epigraph_is_instance_admin(p_agent uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT COALESCE(
        p_agent IS NOT NULL
        AND (p_agent = public.epigraph_principal_id() OR public.epigraph_bypass())
        AND public.epigraph_holds_role(p_agent, 'role:platform-custodian', now()),
        false)
$$;

CREATE OR REPLACE FUNCTION public.epigraph_instance_admins_frozen()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT'
       OR (NEW.agent_id, NEW.granted_at, NEW.note) IS DISTINCT FROM
          (OLD.agent_id, OLD.granted_at, OLD.note)
       OR (NEW.granted_by IS DISTINCT FROM OLD.granted_by AND NEW.granted_by IS NOT NULL)
       OR (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
           AND NOT (OLD.revoked_at IS NULL AND NEW.revoked_at = now()
                    AND public.epigraph_live_role_assignment(OLD.agent_id,
                            'role:platform-custodian', now()) IS NULL)) THEN
        RAISE EXCEPTION 'CUS05: instance_admins is read-only from migration 123; the only change '
                        'it takes is a revoked_at stamp, on the row of a principal that holds '
                        'no live role:platform-custodian assignment'
            USING ERRCODE = 'CUS05',
                  HINT = 'Grant role:platform-custodian with epigraph-operator grant-role, and '
                         'end it with epigraph-operator end-role-assignment.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_instance_admins_frozen() FROM PUBLIC;

DROP TRIGGER IF EXISTS instance_admins_frozen ON public.instance_admins;
CREATE TRIGGER instance_admins_frozen
    BEFORE INSERT OR UPDATE ON public.instance_admins
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_instance_admins_frozen();

-- A human's revoke (122's `epigraph_revoke_human_operator`, or a direct
-- maintenance UPDATE) stamps that human's live legacy row.
CREATE OR REPLACE FUNCTION public.epigraph_human_operators_mirror_instance_admins()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        UPDATE public.instance_admins SET revoked_at = now()
         WHERE agent_id = NEW.agent_id AND revoked_at IS NULL;
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_human_operators_mirror_instance_admins() FROM PUBLIC;

DROP TRIGGER IF EXISTS human_operators_mirror_instance_admins ON public.human_operators;
CREATE TRIGGER human_operators_mirror_instance_admins
    AFTER UPDATE ON public.human_operators
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_human_operators_mirror_instance_admins();

-- ===================================================================
-- 7. THE 122 CHECKS, AMENDED (signatures unchanged; bodies are 122's, with the
--    deltas each block's comment names)
--
-- THE CUSTODIAL RELIEF IS THE PRIVILEGED SESSION'S ALONE (operator ruling
-- OQ-1 (b)). 122 relieves "the exemption" (`epigraph_operator_scope_exempt()`:
-- a privileged session, or an instance-admin principal) of the cross-human
-- scope (OPL02) at five points: the membership door, the claims-path writer
-- scope, the two attribution arms, and a re-attribution. 123 re-bodies the
-- exemption as `epigraph_bypass()` and nothing else, so holding
-- role:platform-custodian relieves NOTHING on an application session: the
-- principal stamp is an application-settable GUC, and holding a role is not
-- using it (DESIGN 6.1a). A custodial write (a revision of the platform
-- corpus, or of another human's claim) is made on the maintenance DSN with
-- `epigraph-operator custodial-supersede`, which records a
-- `platform.custodial_act` naming the actor's live assignment in the act's own
-- transaction (`epigraph_record_custodial_act`, CUS04 otherwise). The five
-- points keep calling the one function, so the decision lives in one body.
--
-- The three checks below are 122's, STABLE as in 122 (they write nothing);
-- the only delta is the refusal's HINT, which no longer says that admin
-- access crosses groups or humans on an application session.
-- ===================================================================
-- 122's exemption; delta: the instance-admin PRINCIPAL arm is gone.
CREATE OR REPLACE FUNCTION public.epigraph_operator_scope_exempt()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT public.epigraph_bypass()
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_scope_exempt() FROM PUBLIC;

-- 122's membership-door check; delta: the HINT.
CREATE OR REPLACE FUNCTION public.epigraph_require_operator_scope(p_agent uuid, p_group uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_operator uuid;
BEGIN
    IF NOT public.epigraph_operator_binding_armed() THEN
        RETURN;
    END IF;
    IF public.epigraph_is_human_operator(p_agent) THEN
        RETURN;
    END IF;
    SELECT l.operator_id INTO v_operator
      FROM public.operator_links l
     WHERE l.agent_id = p_agent AND NOT l.retired;
    IF v_operator IS NULL OR public.epigraph_operator_writes_group(v_operator, p_group) THEN
        RETURN;
    END IF;
    IF public.epigraph_operator_scope_exempt() THEN
        RETURN;
    END IF;
    RAISE EXCEPTION 'OPL02: agent % is linked to operator %, which holds no writer/admin '
                    'membership in group %; a linked agent writes only where its own operator '
                    'writes', p_agent, v_operator, p_group
        USING ERRCODE = 'OPL02',
              HINT = 'Write into a group the operator writes (its personal group is the '
                     'default), or have the operator join the group first. No application '
                     'session crosses humans, a custodian''s included.';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_operator_scope(uuid, uuid) FROM PUBLIC;

-- 122's claims-path writer scope; delta: the HINT.
CREATE OR REPLACE FUNCTION public.epigraph_require_writer_scope(p_agent uuid, p_group uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_human uuid;
BEGIN
    IF NOT public.epigraph_operator_binding_armed() THEN
        RETURN;
    END IF;
    v_human := public.epigraph_human_of(p_agent, false);
    IF v_human IS NULL OR public.epigraph_operator_writes_group(v_human, p_group) THEN
        RETURN;
    END IF;
    IF public.epigraph_operator_scope_exempt() THEN
        RETURN;
    END IF;
    IF v_human = p_agent THEN
        RAISE EXCEPTION 'OPL02: human operator % holds no writer/admin membership in group %; '
                        'a human writes only where it writes', p_agent, p_group
            USING ERRCODE = 'OPL02',
                  HINT = 'Write into a group you write (your personal group is the default). '
                         'A custodial revision is made on the maintenance DSN with '
                         'epigraph-operator custodial-supersede.';
    END IF;
    RAISE EXCEPTION 'OPL02: agent % is linked to operator %, which holds no writer/admin '
                    'membership in group %; a linked agent writes only where its own operator '
                    'writes', p_agent, v_human, p_group
        USING ERRCODE = 'OPL02',
              HINT = 'Write into a group the operator writes (its personal group is the '
                     'default), or have the operator join the group first. No application '
                     'session crosses humans, a custodian''s included.';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_writer_scope(uuid, uuid) FROM PUBLIC;

-- 122's attribution check; delta: the HINTs.
CREATE OR REPLACE FUNCTION public.epigraph_require_attributable(
    p_author uuid, p_writer uuid, p_inherited boolean)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_author_human uuid;
    v_writer_human uuid;
BEGIN
    IF NOT public.epigraph_operator_binding_armed() THEN
        RETURN;
    END IF;
    v_writer_human := public.epigraph_human_of(p_writer, true);
    v_author_human := public.epigraph_human_of(p_author, NOT COALESCE(p_inherited, false));
    IF v_author_human IS NULL THEN
        -- No human for this row's kind. A RETIRED identity still belongs to
        -- its human: a writer outside that human is refused below (OPL02,
        -- whatever the valve), before the binding check the valve relieves.
        v_author_human := public.epigraph_human_of(p_author, false);
        IF v_author_human IS NULL OR v_author_human = v_writer_human
           OR public.epigraph_operator_scope_exempt() THEN
            PERFORM public.epigraph_require_bound_author(p_author);
            RETURN;
        END IF;
    ELSIF v_writer_human = v_author_human THEN
        RETURN;
    ELSIF public.epigraph_operator_scope_exempt() THEN
        RETURN;
    END IF;
    IF v_writer_human IS NULL THEN
        RAISE EXCEPTION 'OPL02: the writing principal % belongs to no human operator, and a claim '
                        'it writes may not be attributed to %, which belongs to human operator %; '
                        'an unbound writer names no bound author', p_writer, p_author,
                        v_author_human
            USING ERRCODE = 'OPL02',
                  HINT = 'Author the claim as the writing agent itself. The valve relieves the '
                         'binding (OPL01) only; no application session crosses humans.';
    END IF;
    RAISE EXCEPTION 'OPL02: agent % writes a claim attributed to %, which belongs to human '
                    'operator %, not to the writer''s operator %; a claim may name only an '
                    'author of the writer''s own human', p_writer, p_author, v_author_human,
                    v_writer_human
        USING ERRCODE = 'OPL02',
              HINT = 'Author the claim as the writing agent itself. A custodial revision is '
                     'made on the maintenance DSN with epigraph-operator custodial-supersede.';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_attributable(uuid, uuid, boolean) FROM PUBLIC;

-- 122's claims trigger body; deltas: the round-4 fixes, each commented where
-- it lands, and HINTs that no longer offer admin access on an application
-- session. Its exemption (a re-attribution) is `epigraph_operator_scope_exempt()`,
-- the privileged session alone.
CREATE OR REPLACE FUNCTION public.epigraph_claims_require_operator_binding()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_writer uuid;
    v_inherited boolean := false;
    v_reopen boolean := false;
BEGIN
    -- 123 (round 4 DIS-R4-1): A CLAIM NEVER SUPERSEDES ITSELF, on every
    -- session, armed or not. The FIRST statement: the cheap early return
    -- below waves through `SET supersedes = id` on a claim that had none,
    -- which is exactly the first half of the two-statement self-loop. Only a
    -- statement that SETS the self-reference is refused, so a self-loop
    -- written before 123 can still be retired; its re-open is a fresh claim
    -- (`p.id <> NEW.id` in the inherited test below).
    IF NEW.supersedes = NEW.id
       AND (TG_OP = 'INSERT' OR NEW.supersedes IS DISTINCT FROM OLD.supersedes) THEN
        RAISE EXCEPTION 'OPL02: claim % names itself in supersedes; a claim never supersedes '
                        'itself', NEW.id
            USING ERRCODE = 'OPL02',
                  HINT = 'Supersede it with a new claim (the supersede act).';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        -- A re-open is a re-open whatever else the statement changes: an
        -- UPDATE that also re-attributes is checked as an INSERT of NEW too.
        v_reopen := NOT COALESCE(OLD.is_current, true) AND COALESCE(NEW.is_current, true);
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.agent_id IS NOT DISTINCT FROM OLD.agent_id THEN
        -- Only `supersedes` / `is_current` (the trigger's other columns) can
        -- have changed. Cheap OLD/NEW tests first: a retire or an untouched
        -- column returns before any table is read.
        IF NOT v_reopen
           AND (NEW.supersedes IS NOT DISTINCT FROM OLD.supersedes OR OLD.supersedes IS NULL) THEN
            RETURN NEW;
        END IF;
        -- 123 (round 4 COR-R4-1 / SEC-R4-2): the lineage and re-open relief
        -- is the PRIVILEGED session's alone. 122 returned here for "the
        -- exemption", so an instance-admin principal (an application-session
        -- stamp) re-opened what its own INSERT of the row is refused, and
        -- cleared an inherited successor's lineage. Every application session
        -- now meets the lineage guard below, and its re-open is checked as an
        -- INSERT (with OQ-1 (b) the exemption is this same `epigraph_bypass()`).
        IF NOT public.epigraph_operator_binding_armed() OR public.epigraph_bypass() THEN
            RETURN NEW;
        END IF;
    ELSIF NOT public.epigraph_operator_binding_armed() THEN
        RETURN NEW;
    END IF;
    -- THE LINEAGE GUARD, on every non-privileged UPDATE that changes
    -- `supersedes`, whatever the statement does to `agent_id` (review
    -- COR-MTC-2: guarding only the same-author branch let a custodian clear a
    -- lineage by re-attributing in the same statement).
    IF TG_OP = 'UPDATE' AND NOT public.epigraph_bypass()
       AND NEW.supersedes IS DISTINCT FROM OLD.supersedes AND OLD.supersedes IS NOT NULL
       AND (NEW.supersedes IS NULL OR COALESCE(NEW.is_current, true)) THEN
        RAISE EXCEPTION 'OPL02: claim % records that it supersedes %; an application session '
                        'does not clear, or re-point on a current claim, the lineage of an '
                        'existing claim', NEW.id, OLD.supersedes
            USING ERRCODE = 'OPL02',
                  HINT = 'Supersede the claim instead, or retire it in the same statement '
                         '(the dedup act). A custodial revision is made on the maintenance '
                         'DSN with epigraph-operator custodial-supersede.';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.agent_id IS NOT DISTINCT FROM OLD.agent_id
       AND NOT v_reopen THEN
        RETURN NEW;
    END IF;
    -- A RE-OPEN on a non-privileged session (and any re-attribution): checked
    -- below as an INSERT of NEW.
    -- RE-ATTRIBUTION. Every check below reads the NEW author only, so an
    -- UPDATE that changes it would let a writer take over (or hand off) a
    -- claim someone else said, including another human's claim in a group
    -- both humans write. No repository or route changes `claims.agent_id`;
    -- only the exemption (a privileged session: OQ-1 (b)) may, and it is then
    -- checked like an insert below. OPL02, keyed on the
    -- arming: it is attribution, which the valve never relieves.
    IF TG_OP = 'UPDATE' AND NEW.agent_id IS DISTINCT FROM OLD.agent_id
       AND NOT public.epigraph_operator_scope_exempt() THEN
        RAISE EXCEPTION 'OPL02: claim % is attributed to %; an application session does not '
                        're-attribute an existing claim (here to %)', NEW.id, OLD.agent_id,
                        NEW.agent_id
            USING ERRCODE = 'OPL02',
                  HINT = 'Supersede the claim instead: the successor is written, and attributed, '
                         'by the writer. A custodial revision is made on the maintenance DSN '
                         'with epigraph-operator custodial-supersede.';
    END IF;
    v_writer := public.epigraph_principal_id();
    -- NO PRINCIPAL on an application session is an unbound writer, not a
    -- licence to be checked on the author column alone: a route that forgot
    -- to stamp its viewer would otherwise write as whatever bound author its
    -- request body named, into that author's group. Fail closed (OPL01, so
    -- the valve relieves it and nothing else does); with the valve open the
    -- author arm below still applies its OPL02.
    IF v_writer IS NULL AND NOT public.epigraph_bypass()
       AND public.epigraph_operator_binding_enforced() THEN
        RAISE EXCEPTION 'OPL01: this application session carries no authenticated principal, '
                        'so the writer of this claim (attributed to %) is not bound to a human '
                        'operator; once armed, a claim is written only by a bound, stamped '
                        'writer', NEW.agent_id
            USING ERRCODE = 'OPL01',
                  HINT = 'Write on a transaction stamped with the request''s viewer '
                         '(ScopedPool::begin_as). See docs/tenancy.md "Operator binding".';
    END IF;
    IF (TG_OP = 'INSERT' OR v_reopen) AND NEW.supersedes IS NOT NULL THEN
        v_inherited :=
            EXISTS (SELECT 1 FROM public.claims p
                     WHERE p.id = NEW.supersedes
                       AND p.id <> NEW.id  -- 123 (DIS-R4-1): never the row's own OLD version
                       AND p.agent_id IS NOT DISTINCT FROM NEW.agent_id
                       AND p.owner_group_id IS NOT DISTINCT FROM NEW.owner_group_id
                       AND NOT COALESCE(p.is_current, true))
            AND NOT EXISTS (SELECT 1 FROM public.claims s
                             WHERE s.supersedes = NEW.supersedes AND s.id <> NEW.id
                               AND COALESCE(s.is_current, true))
            -- 123 (round 4 SEC-R4-1): on a non-privileged session a retired
            -- identity's claim is restated AT MOST ONCE, ever. "No other
            -- CURRENT successor" alone re-admitted a predecessor whose
            -- successor had been retired, so retire-and-restate doubled the
            -- current claims under the identity each round. A privileged
            -- session keeps 122's rule: its custodial revision of a canonical
            -- claim that retired duplicates point at must still work.
            AND (public.epigraph_bypass()
                 OR NOT EXISTS (SELECT 1 FROM public.claims s
                                 WHERE s.supersedes = NEW.supersedes AND s.id <> NEW.id
                                   AND s.agent_id IS NOT DISTINCT FROM NEW.agent_id))
            -- 123 (review SEC-MTC-3): the at-most-once rule bounds BRANCHING;
            -- a RE-OPEN must not resurrect a version of a lineage that is
            -- current elsewhere either. On a non-privileged session a
            -- re-opened claim inherits nothing while ANY other version of its
            -- lineage, an ancestor up its `supersedes` chain or a descendant
            -- down it, is current. Testing only its own successor still let
            -- alternate versions of a chain be re-opened (S1 while S2 is
            -- retired and S3 current), one more current claim under the
            -- retired identity per two versions. Retiring the head and
            -- re-opening its predecessor (the undo) still works. UNION, not
            -- UNION ALL, so a legacy cycle terminates.
            AND (public.epigraph_bypass() OR NOT v_reopen
                 OR NOT EXISTS (
                     WITH RECURSIVE up(id, supersedes, cur) AS (
                         SELECT c.id, c.supersedes, COALESCE(c.is_current, true)
                           FROM public.claims c WHERE c.id = NEW.supersedes
                         UNION
                         SELECT c.id, c.supersedes, COALESCE(c.is_current, true)
                           FROM public.claims c JOIN up ON c.id = up.supersedes),
                     down(id, cur) AS (
                         SELECT c.id, COALESCE(c.is_current, true)
                           FROM public.claims c WHERE c.supersedes = NEW.id
                         UNION
                         SELECT c.id, COALESCE(c.is_current, true)
                           FROM public.claims c JOIN down ON c.supersedes = down.id)
                     SELECT 1 FROM up WHERE up.cur AND up.id <> NEW.id
                     UNION ALL
                     SELECT 1 FROM down WHERE down.cur AND down.id <> NEW.id));
    END IF;
    IF v_writer IS NULL OR v_writer = NEW.agent_id OR public.epigraph_bypass() THEN
        -- THE PLATFORM CORPUS'S EDIT PATH. A PRIVILEGED session (the
        -- maintenance role or a superuser: `epigraph_bypass()`, which no
        -- application session can forge) restating a retired predecessor
        -- carries that predecessor's author whatever its binding: world-owned
        -- legacy rows are authored by retired-linked or unlinked identities by
        -- construction, so the author check would refuse every such supersede.
        -- Nothing else is relieved: a fresh claim, or a posed successor, is
        -- checked on its author as always, and an instance-admin PRINCIPAL
        -- writing as itself is not relieved here (it is a stamp an application
        -- session sets). Its supersede of ANOTHER author's retired-linked claim
        -- takes the ELSE branch: the attribution check's inherited rule.
        IF NOT (v_inherited AND public.epigraph_bypass()) THEN
            PERFORM public.epigraph_require_bound_author(NEW.agent_id);
        END IF;
        PERFORM public.epigraph_require_writer_scope(NEW.agent_id, NEW.owner_group_id);
    ELSE
        PERFORM public.epigraph_require_bound_writer(v_writer);
        PERFORM public.epigraph_require_writer_scope(v_writer, NEW.owner_group_id);
        PERFORM public.epigraph_require_attributable(NEW.agent_id, v_writer, v_inherited);
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_claims_require_operator_binding() FROM PUBLIC;

-- ===================================================================
-- OWNERSHIP AND GRANTS (guarded, as every such block since 060 is)
--
-- 077's default privileges hand the application role DML on every new
-- table: taken back here, leaving SELECT. Every definer is owned by the
-- maintenance role (its frame then reads FORCEd tables through
-- `epigraph_definer_bypass()`), and no definer the application role must not
-- call is left with an EXECUTE path to it.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_platform_roles_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_live_role_assignment(uuid, text, timestamptz) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_role_assignments_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_role_assignments_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_live_role_assignment(uuid, text, timestamptz) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON public.platform_roles, '
                'public.role_assignments TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_role_assignment_for(uuid, text, timestamptz) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_holds_role(uuid, text, timestamptz) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_role_assignment_for(uuid, text, timestamptz), '
                'public.epigraph_holds_role(uuid, text, timestamptz) TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_role_assignments_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_refuse_role_node_subject() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_operator_links_refuse_role_holder() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_instance_admins_frozen() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_human_operators_mirror_instance_admins() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_record_custodial_act(uuid, uuid, text, text, '
                'uuid, jsonb) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_record_custodial_act(uuid, uuid, text, text, uuid, jsonb) '
                'TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_grant_role(text, uuid, timestamptz, '
                'timestamptz, uuid, text) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_end_role_assignment(uuid, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_platform_audit(timestamptz, integer) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_grant_role(text, uuid, timestamptz, timestamptz, uuid, text), '
                'public.epigraph_end_role_assignment(uuid, text), '
                'public.epigraph_platform_audit(timestamptz, integer) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.platform_roles, public.role_assignments FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.platform_roles, public.role_assignments TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_live_role_assignment(uuid, text, timestamptz) FROM epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_role_assignment_for(uuid, text, timestamptz), '
                'public.epigraph_holds_role(uuid, text, timestamptz) TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_grant_role(text, uuid, timestamptz, timestamptz, uuid, text), '
                'public.epigraph_end_role_assignment(uuid, text) FROM epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_platform_audit(timestamptz, integer) TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_record_custodial_act(uuid, uuid, text, text, uuid, jsonb) '
                'FROM epigraph_app';
    END IF;
END $$;
