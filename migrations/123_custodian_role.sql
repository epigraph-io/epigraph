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
--     identity, a human not registered yet) is NOT carried: agents never
--     hold the role. Each one raises a NOTICE and writes a
--     `platform.role_migration_skipped` event naming it. A revoked row is
--     not carried; it stays readable in the table as history.
-- (c) ANSWER FROM THE ROLE. `epigraph_is_instance_admin(agent)` keeps its
--     name, signature, grants and subject binding (083's policies, 087's and
--     122's definers call it), and now answers "holds role:platform-custodian
--     now". So a legacy row alone confers nothing from here on.
-- (d) FREEZE. `instance_admins` takes no new row and no edit, on every role
--     (a trigger: the superuser included), with one exception: a `revoked_at`
--     stamp (NULL -> now(), nothing else), plus the FK's own SET NULL of
--     `granted_by`. Ending a holder's last custodian assignment (section 4's
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
   AND NOT EXISTS (SELECT 1 FROM public.role_assignments ra
                    WHERE ra.holder_person_id = ia.agent_id
                      AND ra.granted_via = 'migration 123');

DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT ia.agent_id, ia.granted_at FROM public.instance_admins ia
              WHERE ia.revoked_at IS NULL
                AND NOT public.epigraph_is_human_operator(ia.agent_id)
                AND NOT EXISTS (SELECT 1 FROM public.security_events e
                                 WHERE e.event_type = 'platform.role_migration_skipped'
                                   AND e.agent_id = ia.agent_id)
              ORDER BY ia.granted_at, ia.agent_id LOOP
        RAISE NOTICE 'migration 123: instance admin % is not a registered human operator; it is '
                     'NOT carried over to role:platform-custodian (agents never hold a role)',
                     r.agent_id;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_migration_skipped', r.agent_id, false,
                jsonb_build_object('agent_id', r.agent_id, 'granted_at', r.granted_at,
                                   'reason', 'not a registered human operator'));
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
           AND NOT (OLD.revoked_at IS NULL AND NEW.revoked_at = now())) THEN
        RAISE EXCEPTION 'CUS05: instance_admins is read-only from migration 123; the only change '
                        'it takes is a revoked_at stamp'
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
-- RELIEF IS AUDITED. 122 relieves "the exemption" (a privileged session, or
-- an instance-admin principal) of the cross-human scope (OPL02) at five
-- points: the membership door, the claims-path writer scope, the two
-- attribution arms, and a re-attribution. Each now asks
-- `epigraph_custodial_relief(check, ...)`: true for a privileged session (not
-- audited: that is the operator's own login, already accountable), and true
-- for a principal that holds role:platform-custodian NOW, in which case it
-- writes one `platform.custodial_exempt` row naming the assignment, the check
-- and its subjects (at most one per transaction per check and subjects: the
-- request path's own pre-check and the trigger reach the same point). A
-- refused write rolls its relief row back with it, so a row means a relief
-- that was used.
--
-- THE THREE CHECKS ARE NOW VOLATILE. A STABLE function must not write; the
-- relief writes. (Measured: PostgreSQL does not refuse a STABLE plpgsql
-- function that calls a VOLATILE writer, so the declaration, pinned by
-- `schema_contract.rs`, is the guard.) Callers run them in a plain
-- `SELECT f(...)`, which volatility does not change.
--
-- `epigraph_operator_scope_exempt()` is kept, unchanged; it reads the
-- re-bodied `epigraph_is_instance_admin`.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_custodial_relief(
    p_check text, p_agent uuid, p_group uuid, p_claim uuid)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_principal  uuid;
    v_assignment uuid;
BEGIN
    IF public.epigraph_bypass() THEN
        RETURN true;
    END IF;
    v_principal := public.epigraph_principal_id();
    v_assignment := public.epigraph_role_assignment_for(v_principal, 'role:platform-custodian',
                                                        now());
    IF v_assignment IS NULL THEN
        RETURN false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.security_events e
                    WHERE e.created_at = now()
                      AND e.event_type = 'platform.custodial_exempt'
                      AND e.agent_id = v_principal
                      AND e.details->>'txid' = txid_current()::text
                      AND e.details->>'check' = p_check
                      AND e.details->>'agent' IS NOT DISTINCT FROM p_agent::text
                      AND e.details->>'group' IS NOT DISTINCT FROM p_group::text
                      AND e.details->>'claim' IS NOT DISTINCT FROM p_claim::text) THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.custodial_exempt', v_principal, true,
                jsonb_build_object('assignment_id', v_assignment,
                                   'role', 'role:platform-custodian',
                                   'check', p_check, 'agent', p_agent, 'group', p_group,
                                   'claim', p_claim, 'txid', txid_current()::text));
    END IF;
    RETURN true;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_custodial_relief(text, uuid, uuid, uuid) FROM PUBLIC;

-- 122's membership-door check; delta: VOLATILE, and the audited relief.
CREATE OR REPLACE FUNCTION public.epigraph_require_operator_scope(p_agent uuid, p_group uuid)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
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
    IF public.epigraph_custodial_relief('operator_scope', p_agent, p_group, NULL) THEN
        RETURN;
    END IF;
    RAISE EXCEPTION 'OPL02: agent % is linked to operator %, which holds no writer/admin '
                    'membership in group %; a linked agent writes only where its own operator '
                    'writes', p_agent, v_operator, p_group
        USING ERRCODE = 'OPL02',
              HINT = 'Write into a group the operator writes (its personal group is the '
                     'default), or have the operator join the group first. Admin access '
                     'crosses groups; nothing else does.';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_operator_scope(uuid, uuid) FROM PUBLIC;

-- 122's claims-path writer scope; delta: VOLATILE, and the audited relief.
CREATE OR REPLACE FUNCTION public.epigraph_require_writer_scope(p_agent uuid, p_group uuid)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
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
    IF public.epigraph_custodial_relief('writer_scope', p_agent, p_group, NULL) THEN
        RETURN;
    END IF;
    IF v_human = p_agent THEN
        RAISE EXCEPTION 'OPL02: human operator % holds no writer/admin membership in group %; '
                        'a human writes only where it writes', p_agent, p_group
            USING ERRCODE = 'OPL02',
                  HINT = 'Write into a group you write (your personal group is the default). '
                         'Admin access crosses groups; nothing else does.';
    END IF;
    RAISE EXCEPTION 'OPL02: agent % is linked to operator %, which holds no writer/admin '
                    'membership in group %; a linked agent writes only where its own operator '
                    'writes', p_agent, v_human, p_group
        USING ERRCODE = 'OPL02',
              HINT = 'Write into a group the operator writes (its personal group is the '
                     'default), or have the operator join the group first. Admin access '
                     'crosses groups; nothing else does.';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_writer_scope(uuid, uuid) FROM PUBLIC;

-- 122's attribution check; delta: VOLATILE, and the audited relief at both
-- of its relief points.
CREATE OR REPLACE FUNCTION public.epigraph_require_attributable(
    p_author uuid, p_writer uuid, p_inherited boolean)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
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
           OR public.epigraph_custodial_relief('attribution_retired', p_author, NULL, NULL) THEN
            PERFORM public.epigraph_require_bound_author(p_author);
            RETURN;
        END IF;
    ELSIF v_writer_human = v_author_human THEN
        RETURN;
    ELSIF public.epigraph_custodial_relief('attribution', p_author, NULL, NULL) THEN
        RETURN;
    END IF;
    IF v_writer_human IS NULL THEN
        RAISE EXCEPTION 'OPL02: the writing principal % belongs to no human operator, and a claim '
                        'it writes may not be attributed to %, which belongs to human operator %; '
                        'an unbound writer names no bound author', p_writer, p_author,
                        v_author_human
            USING ERRCODE = 'OPL02',
                  HINT = 'Author the claim as the writing agent itself. The valve relieves the '
                         'binding (OPL01) only; admin access crosses humans; nothing else does.';
    END IF;
    RAISE EXCEPTION 'OPL02: agent % writes a claim attributed to %, which belongs to human '
                    'operator %, not to the writer''s operator %; a claim may name only an '
                    'author of the writer''s own human', p_writer, p_author, v_author_human,
                    v_writer_human
        USING ERRCODE = 'OPL02',
              HINT = 'Author the claim as the writing agent itself. Admin access crosses '
                     'humans; nothing else does.';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_attributable(uuid, uuid, boolean) FROM PUBLIC;

-- 122's claims trigger body; deltas: the audited relief on a
-- re-attribution (and the round-4 fixes, each commented where it lands).
CREATE OR REPLACE FUNCTION public.epigraph_claims_require_operator_binding()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_writer uuid;
    v_inherited boolean := false;
    v_reopen boolean := false;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.agent_id IS NOT DISTINCT FROM OLD.agent_id THEN
        -- Only `supersedes` / `is_current` (the trigger's other columns) can
        -- have changed. Cheap OLD/NEW tests first: a retire or an untouched
        -- column returns before any table is read.
        v_reopen := NOT COALESCE(OLD.is_current, true) AND COALESCE(NEW.is_current, true);
        IF NOT v_reopen
           AND (NEW.supersedes IS NOT DISTINCT FROM OLD.supersedes OR OLD.supersedes IS NULL) THEN
            RETURN NEW;
        END IF;
        -- 123 (round 4 COR-R4-1 / SEC-R4-2): the lineage and re-open relief
        -- is the PRIVILEGED session's alone. 122 returned here for "the
        -- exemption", so an instance-admin principal (an application-session
        -- stamp) re-opened what its own INSERT of the row is refused, and
        -- cleared an inherited successor's lineage. A custodian principal now
        -- meets the lineage guard below, and its re-open is checked as an
        -- INSERT; the cross-human SCOPE inside those checks still relieves it
        -- (audited).
        IF NOT public.epigraph_operator_binding_armed() OR public.epigraph_bypass() THEN
            RETURN NEW;
        END IF;
        IF NEW.supersedes IS DISTINCT FROM OLD.supersedes AND OLD.supersedes IS NOT NULL
           AND (NEW.supersedes IS NULL OR COALESCE(NEW.is_current, true)) THEN
            RAISE EXCEPTION 'OPL02: claim % records that it supersedes %; an application session '
                            'does not clear, or re-point on a current claim, the lineage of an '
                            'existing claim', NEW.id, OLD.supersedes
                USING ERRCODE = 'OPL02',
                      HINT = 'Supersede the claim instead, or retire it in the same statement '
                             '(the dedup act). Admin access crosses humans; nothing else does.';
        END IF;
        IF NOT v_reopen THEN
            RETURN NEW;
        END IF;
        -- A RE-OPEN on a non-privileged session: checked below as an INSERT
        -- of NEW.
    ELSIF NOT public.epigraph_operator_binding_armed() THEN
        RETURN NEW;
    END IF;
    -- RE-ATTRIBUTION. Every check below reads the NEW author only, so an
    -- UPDATE that changes it would let a writer take over (or hand off) a
    -- claim someone else said, including another human's claim in a group
    -- both humans write. No repository or route changes `claims.agent_id`;
    -- only the exemption (a privileged session, an instance-admin principal)
    -- may, and it is then checked like an insert below. OPL02, keyed on the
    -- arming: it is attribution, which the valve never relieves.
    IF TG_OP = 'UPDATE' AND NOT v_reopen
       AND NOT public.epigraph_custodial_relief('reattribute', NEW.agent_id, NEW.owner_group_id,
                                                NEW.id) THEN
        RAISE EXCEPTION 'OPL02: claim % is attributed to %; an application session does not '
                        're-attribute an existing claim (here to %)', NEW.id, OLD.agent_id,
                        NEW.agent_id
            USING ERRCODE = 'OPL02',
                  HINT = 'Supersede the claim instead: the successor is written, and attributed, '
                         'by the writer. Admin access crosses humans; nothing else does.';
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
                       AND p.agent_id IS NOT DISTINCT FROM NEW.agent_id
                       AND p.owner_group_id IS NOT DISTINCT FROM NEW.owner_group_id
                       AND NOT COALESCE(p.is_current, true))
            AND NOT EXISTS (SELECT 1 FROM public.claims s
                             WHERE s.supersedes = NEW.supersedes AND s.id <> NEW.id
                               AND COALESCE(s.is_current, true));
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
        EXECUTE 'ALTER FUNCTION public.epigraph_instance_admins_frozen() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_human_operators_mirror_instance_admins() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_custodial_relief(text, uuid, uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_custodial_relief(text, uuid, uuid, uuid) TO epigraph_maintenance';
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
                'public.epigraph_custodial_relief(text, uuid, uuid, uuid) FROM epigraph_app';
    END IF;
END $$;
