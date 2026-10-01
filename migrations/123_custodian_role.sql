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
-- AND its recorded human OAuth client still active). A live-linked agent, a
-- retired identity, an unbound agent and a human whose client is suspended
-- are refused `CUS01`, and the test is repeated at read time, so a human
-- whose registration is later revoked stops holding at once.
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
--          back-dated `valid_from` (more than a minute in the past), any
--          change but the one revoke, a revoke not stamped `now()` or with no
--          reason, or any change to an ended row.
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
-- node is refused as a link or registry subject (section 9), so it can never
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
     'Administers the instance: privatization, custodial revision of the platform corpus, '
     'and the relief from the cross-human write scope. Held only by a registered human.'),
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
    IF NOT public.epigraph_is_human_operator(NEW.holder_person_id) THEN
        RAISE EXCEPTION 'CUS01: % is not a registered human operator; agents never hold a role',
                        NEW.holder_person_id
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
    SELECT EXISTS (SELECT 1 FROM public.role_assignments ra
                    WHERE ra.role = 'role:platform-custodian' AND ra.revoked_at IS NULL
                      AND ra.valid_from <= now()
                      AND (ra.valid_to IS NULL OR now() < ra.valid_to)
                      AND public.epigraph_is_human_operator(ra.holder_person_id)),
           EXISTS (SELECT 1 FROM public.role_assignments ra
                    WHERE ra.role = 'role:platform-custodian' AND ra.revoked_at IS NULL
                      AND ra.valid_from <= now()
                      AND (ra.valid_to IS NULL OR now() < ra.valid_to)
                      AND ra.holder_person_id IS DISTINCT FROM NEW.holder_person_id
                      AND public.epigraph_is_human_operator(ra.holder_person_id))
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
       OR NEW.revoked_by IS NULL
       OR NEW.revoked_reason IS NULL OR length(btrim(NEW.revoked_reason)) = 0
       OR (NEW.id, NEW.role, NEW.holder_person_id, NEW.holder_group_id, NEW.valid_from,
           NEW.valid_to, NEW.granted_by, NEW.granted_via, NEW.grant_act_id, NEW.reason,
           NEW.created_at)
          IS DISTINCT FROM
          (OLD.id, OLD.role, OLD.holder_person_id, OLD.holder_group_id, OLD.valid_from,
           OLD.valid_to, OLD.granted_by, OLD.granted_via, OLD.grant_act_id, OLD.reason,
           OLD.created_at) THEN
        RAISE EXCEPTION 'CUS02: an assignment is only ever ended (revoked_at = now(), '
                        'revoked_by and a revoked_reason), nothing else; nothing was changed'
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

-- The insert guard. Created after every row this migration itself writes
-- (none yet), so only a migration-time seed may carry a past `valid_from`.
DROP TRIGGER IF EXISTS role_assignments_guard_insert ON public.role_assignments;
CREATE TRIGGER role_assignments_guard_insert
    BEFORE INSERT ON public.role_assignments
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_assignments_guard_insert();

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
-- Every assignment change, every custodial act and every relief a custodian
-- principal receives is one `security_events` row whose type starts with
-- `platform.` and whose details name the assignment. The application role
-- keeps INSERT on `security_events` (077: an actor never suppresses its own
-- audit record), so the prefix is RESERVED, as 117 reserves `cascade.` and
-- 118 reserves `oauth.`: a RESTRICTIVE insert policy admits a `platform.` row
-- only from a privileged session or a maintenance-owned definer frame. 082's
-- `security_events_no_mutate` trigger already makes every row immutable, on
-- every role.
-- ===================================================================
DROP POLICY IF EXISTS security_events_platform_privileged ON public.security_events;
CREATE POLICY security_events_platform_privileged ON public.security_events
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        left(event_type, 9) <> 'platform.'
        OR (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()));

-- AFTER INSERT / UPDATE on `role_assignments`: whatever path wrote the row
-- (a definer below, or a direct maintenance statement), one
-- `platform.role_granted` or `platform.role_ended` row.
CREATE OR REPLACE FUNCTION public.epigraph_role_assignments_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_granted', NEW.holder_person_id, true,
                jsonb_build_object('assignment_id', NEW.id, 'role', NEW.role,
                                   'holder', NEW.holder_person_id,
                                   'valid_from', NEW.valid_from, 'valid_to', NEW.valid_to,
                                   'granted_by', NEW.granted_by,
                                   'granted_via', NEW.granted_via, 'reason', NEW.reason,
                                   'migrated', NEW.granted_via = 'migration 123'));
    ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
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
    END IF;
END $$;
