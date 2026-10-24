-- 165: group membership DERIVED from time-windowed role assignments.
--
-- ===================================================================
-- 1. WHAT THIS ADDS
--
-- A group's membership may follow a PLATFORM ROLE (123's catalog and its
-- timestamped `role_assignments`) instead of a hand-kept list. One
-- maintenance-only, append-only table binds a non-elevating role to a group:
--
--   group_role_bindings (group_id, role, member_role, include_agents, reason,
--                        created_at, created_by, revoked_at/by/reason)
--
-- While a binding B = (G, R, member_role, include_agents) is live at time t,
-- principal P is a `member_role` member of G iff
--
--   (1) P is a registered human holding a LIVE assignment of R at t
--       (`epigraph_live_role_assignment(P, R, t)`: 123's window
--       `valid_from <= t < valid_to`, not ended, and P re-checked as a
--       registered human that is no other human's agent); or
--   (2) B.include_agents, and P is REGISTERED TO a human H satisfying (1):
--       * an ACTING live link (107's `epigraph_operator_actor(P)` returns a
--         row: the link is not retired, and both the agent's and H's rows in
--         H's personal group are live); or
--       * a live 149 client allowance (`epigraph_allowlisted_operator(P) = H`).
--       A RETIRED link never derives, nor does an agent whose acting row was
--       revoked (the existing deactivation lever: a live link is never
--       retired in place), nor an agent of a revoked or suspended human.
--
-- `member_role` is `reader` or `writer`, never `admin`: a derived member never
-- administers the roster, so every admin-only reader (077's
-- `epigraph_is_group_admin`, 127's admin group ids, 081's privatization
-- guards) stays direct-only and correct.
--
-- ===================================================================
-- 2. COMPUTED, NEVER WRITTEN
--
-- No membership row is written for a derived member. The derivation runs
-- when the viewer is resolved:
--
--   * `epigraph_live_memberships(uuid)` (077, re-stated by 164; the one
--     source of every viewer's group set, and through it of every stamp-keyed
--     row-security policy and every Rust read filter) becomes 164's direct
--     rows UNION `epigraph_role_derived_memberships(p_agent, now())`.
--     Signature, result, owner and grants are unchanged.
--   * 123's claims-path writer scope, `epigraph_require_writer_scope`
--     (OPL02, armed only), asks `epigraph_writes_group_at(human, group,
--     now(), via_agent)`: 122's direct test OR a live writer binding whose
--     role the human holds at that instant (and, when the subject is an
--     agent, whose binding includes agents). So once armed, a write into the
--     group by a principal outside the window is refused whatever the session
--     stamp says.
--
-- So a membership lapses exactly at `valid_to`, with no job: a read at the
-- next viewer resolution (per request, per tool call, per worker job), a
-- claim write (armed) at the first statement of a transaction that starts at
-- or after `valid_to`. The time base is `now()`, the transaction's start,
-- like the stamp itself; a transaction opened inside the window finishes on
-- it. A materialized row could not represent a second interval (060's
-- `UNIQUE (group_id, agent_id, epoch)`), would need a job at every
-- transition, and a dead job over-grants; this under-grants instead.
--
-- THE MEMBERSHIP DOOR STAYS DIRECT-ONLY. 122's
-- `epigraph_operator_writes_group` (called by the membership door
-- `epigraph_require_operator_scope`, by 164's team-group verbs, and by the
-- legacy link tie) is NOT changed: if it answered the derived question, a
-- group admin could give a role-holding teammate's agent an EXPLICIT row
-- that outlives the window. An agent gets an explicit row only where its
-- human holds one.
--
-- ===================================================================
-- 3. WHO WRITES BINDINGS
--
-- Three maintenance-only SECURITY DEFINERs (the operator CLI's
-- `define-group-role`, `end-group-role-binding`; `bind` for an existing
-- role), each also refusing a non-maintenance session in its body:
--
--   epigraph_define_group_role(key, description, group, member_role,
--                              include_agents, reason)       -> binding id
--   epigraph_bind_group_role(role, group, member_role, include_agents,
--                            reason)                          -> binding id
--   epigraph_end_group_role_binding(binding, reason)          -> ended now?
--
-- `define` writes, in one transaction, the role's graph node (an `agents` row
-- of `agent_type = 'role'` whose 32-byte key has no private half anywhere,
-- 123's precedent), its catalog row with `elevates = false` and
-- `reads_audit = false` forced, and the binding. No role or binding is seeded
-- here: which groups follow which roles is runtime data, and a fresh database
-- keeps exactly 123's two public catalog roles.
--
-- The table's own triggers hold the rules on every path, a direct maintenance
-- statement included:
--   * GRB01: the role must neither elevate nor read the audit trail, so no
--     group membership ever rides on `role:platform-custodian` or
--     `role:auditor` (or any later elevating role);
--   * GRB02: the group must be an active group that is not `personal`,
--     `world` or `seed` (those have their own membership rules or none);
--   * a binding is recorded live, stamped `now()` and `session_user`; the
--     only change it ever takes is its end, once; it is never deleted;
--   * one live binding per (group, role).
-- GRB03: `define` refuses a key already in the catalog (use `bind`).
-- Every bind and end writes one `platform.group_role_bound` /
-- `platform.group_role_unbound` row (123 reserves the `platform.` prefix to
-- a privileged session or a maintenance-owned definer frame).
--
-- ===================================================================
-- 4. NO ROSTER ORACLE
--
-- `epigraph_role_derived_memberships(agent, at)`, `epigraph_writes_group_at`
-- and the roster reader `epigraph_group_role_roster(group, at)` answer for
-- ANY principal, so none is executable by the application role (123: "an
-- unbound roster read is an oracle"). They are called from inside
-- maintenance-owned definers (`epigraph_live_memberships`,
-- `epigraph_require_writer_scope`) or on the maintenance DSN (the CLI's
-- `group-roster`). The residual is 077's: `epigraph_live_memberships(uuid)`
-- stays callable by the application role for any agent id, and now also
-- answers derived membership for it (the parameterised read already
-- accepted for direct membership).
--
-- The roster at an instant evaluates the BINDING and the ROLE WINDOW at that
-- instant; link, allowance and registration state are read as they are now
-- (those tables keep no history the derivation could read at t), and an
-- assignment ENDED early counts at no instant (123's
-- `epigraph_live_role_assignment`).
--
-- ===================================================================
-- 5. WHAT THIS DOES NOT CHANGE
--
--   * Readers of `group_memberships` other than the two above (the REST
--     roster routes, the consolidate act's membership test, the profile
--     detail check) see explicit rows only: a derived member is refused
--     there (fail-closed), never admitted wrongly.
--   * 123's OCCUPIES projection of an assignment stays public.
--   * A binding never changes `group_memberships`; 164's roster verbs and
--     their rules are untouched.
--
-- ===================================================================
-- UNDO
--
-- Re-state 164's `epigraph_live_memberships` body and 123's
-- `epigraph_require_writer_scope` body (CREATE OR REPLACE keeps owner and
-- grants), then:
-- DROP FUNCTION IF EXISTS public.epigraph_group_role_roster(uuid, timestamptz);
-- DROP FUNCTION IF EXISTS public.epigraph_end_group_role_binding(uuid, text);
-- DROP FUNCTION IF EXISTS public.epigraph_bind_group_role(text, uuid, text, boolean, text);
-- DROP FUNCTION IF EXISTS public.epigraph_define_group_role(text, text, uuid, text, boolean, text);
-- DROP FUNCTION IF EXISTS public.epigraph_writes_group_at(uuid, uuid, timestamptz, boolean);
-- DROP FUNCTION IF EXISTS public.epigraph_role_derived_memberships(uuid, timestamptz);
-- DROP TABLE IF EXISTS public.group_role_bindings;   -- its triggers with it
-- DROP FUNCTION IF EXISTS public.epigraph_group_role_bindings_audit();
-- DROP FUNCTION IF EXISTS public.epigraph_group_role_bindings_refuse_delete();
-- DROP FUNCTION IF EXISTS public.epigraph_group_role_bindings_guard_update();
-- DROP FUNCTION IF EXISTS public.epigraph_group_role_bindings_guard_insert();
-- Catalog roles a `define` added stay (123: a catalog row is never deleted),
-- as do their assignments and every audit row (082: immutable).
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- The binding table
-- -------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.group_role_bindings (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id       uuid NOT NULL REFERENCES public.groups(id) ON DELETE RESTRICT,
    role           text NOT NULL REFERENCES public.platform_roles(key) ON DELETE RESTRICT,
    member_role    text NOT NULL
                       CONSTRAINT group_role_bindings_member_role
                       CHECK (member_role IN ('reader', 'writer')),
    include_agents boolean NOT NULL,
    reason         text NOT NULL
                       CONSTRAINT group_role_bindings_reason_present
                       CHECK (length(btrim(reason)) > 0),
    created_at     timestamptz NOT NULL DEFAULT now(),
    created_by     text NOT NULL DEFAULT session_user,
    revoked_at     timestamptz,
    revoked_by     text,
    revoked_reason text,
    CONSTRAINT group_role_bindings_revoke_whole CHECK (
        (revoked_at IS NULL) = (revoked_by IS NULL)
        AND (revoked_at IS NULL) = (revoked_reason IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS group_role_bindings_one_live
    ON public.group_role_bindings (group_id, role) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS group_role_bindings_live_role
    ON public.group_role_bindings (role) WHERE revoked_at IS NULL;
REVOKE ALL ON public.group_role_bindings FROM PUBLIC;

-- Row security, 123's pattern: a privileged session and a maintenance-owned
-- definer frame read; only a privileged session writes; nobody deletes (no
-- policy, and a trigger below).
ALTER TABLE public.group_role_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.group_role_bindings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS group_role_bindings_privileged_read ON public.group_role_bindings;
CREATE POLICY group_role_bindings_privileged_read ON public.group_role_bindings
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS group_role_bindings_maintenance_insert ON public.group_role_bindings;
CREATE POLICY group_role_bindings_maintenance_insert ON public.group_role_bindings
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS group_role_bindings_maintenance_update ON public.group_role_bindings;
CREATE POLICY group_role_bindings_maintenance_update ON public.group_role_bindings
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));

-- BEFORE INSERT: GRB01, GRB02, and the row recorded live by the database.
-- The session gate keys on `session_user` (`epigraph_bypass()`), so neither a
-- forged setting nor a definer frame an application session reaches admits
-- it; the definers below run on a maintenance session.
CREATE OR REPLACE FUNCTION public.epigraph_group_role_bindings_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_elevates boolean;
    v_audit    boolean;
    v_kind     text;
    v_status   text;
BEGIN
    IF NOT public.epigraph_bypass() THEN
        RAISE EXCEPTION 'group_role_bindings: only a maintenance session binds a role to a '
                        'group' USING ERRCODE = '42501';
    END IF;
    SELECT r.elevates, r.reads_audit INTO v_elevates, v_audit
      FROM public.platform_roles r WHERE r.key = NEW.role;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'group_role_bindings: % is not a catalog role', NEW.role
            USING ERRCODE = '22023';
    END IF;
    IF v_elevates OR v_audit THEN
        RAISE EXCEPTION 'GRB01: role % elevates or reads the audit trail; no group membership '
                        'rides on it', NEW.role
            USING ERRCODE = 'GRB01',
                  HINT = 'Define a non-elevating role for the group: '
                         'epigraph-operator define-group-role.';
    END IF;
    SELECT g.kind::text, g.status::text INTO v_kind, v_status
      FROM public.groups g WHERE g.id = NEW.group_id;
    IF NOT FOUND OR v_kind IN ('personal', 'world', 'seed') OR v_status <> 'active' THEN
        RAISE EXCEPTION 'GRB02: group % (kind %, status %) cannot follow a role: only an active '
                        'group that is not personal, world or seed', NEW.group_id, v_kind,
                        v_status
            USING ERRCODE = 'GRB02';
    END IF;
    IF NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL
       OR NEW.revoked_reason IS NOT NULL THEN
        RAISE EXCEPTION 'group_role_bindings: a binding is recorded live; end it with '
                        'epigraph_end_group_role_binding' USING ERRCODE = '55000';
    END IF;
    -- Provenance is the database's, never the writer's.
    NEW.created_at := now();
    NEW.created_by := session_user;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_group_role_bindings_guard_insert() FROM PUBLIC;

-- BEFORE UPDATE: the ONLY change a binding takes is its end, once, stamped
-- here; an ended binding takes no change at all.
CREATE OR REPLACE FUNCTION public.epigraph_group_role_bindings_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NOT public.epigraph_bypass() THEN
        RAISE EXCEPTION 'group_role_bindings: only a maintenance session ends a binding'
            USING ERRCODE = '42501';
    END IF;
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'group_role_bindings: binding % has ended, and an end is final; '
                        'nothing was changed', OLD.id USING ERRCODE = '55000';
    END IF;
    IF NEW.revoked_at IS NULL
       OR NEW.revoked_reason IS NULL OR length(btrim(NEW.revoked_reason)) = 0
       OR (NEW.id, NEW.group_id, NEW.role, NEW.member_role, NEW.include_agents, NEW.reason,
           NEW.created_at, NEW.created_by)
          IS DISTINCT FROM
          (OLD.id, OLD.group_id, OLD.role, OLD.member_role, OLD.include_agents, OLD.reason,
           OLD.created_at, OLD.created_by) THEN
        RAISE EXCEPTION 'group_role_bindings: a binding is only ever ended (revoked_at and a '
                        'revoked_reason set); nothing was changed' USING ERRCODE = '55000',
              HINT = 'End it with epigraph-operator end-group-role-binding and bind anew.';
    END IF;
    NEW.revoked_at := now();
    NEW.revoked_by := session_user;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_group_role_bindings_guard_update() FROM PUBLIC;

-- BEFORE DELETE: never, on any session.
CREATE OR REPLACE FUNCTION public.epigraph_group_role_bindings_refuse_delete()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'group_role_bindings: a binding is never deleted (binding %); end it with '
                    'epigraph_end_group_role_binding', OLD.id USING ERRCODE = '55000';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_group_role_bindings_refuse_delete() FROM PUBLIC;

-- AFTER INSERT / UPDATE: one `platform.` row per bind and per end.
CREATE OR REPLACE FUNCTION public.epigraph_group_role_bindings_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES (CASE TG_OP WHEN 'INSERT' THEN 'platform.group_role_bound'
                       ELSE 'platform.group_role_unbound' END,
            NULL, true,
            jsonb_build_object('binding_id', NEW.id, 'group_id', NEW.group_id,
                               'role', NEW.role, 'member_role', NEW.member_role,
                               'include_agents', NEW.include_agents,
                               'reason', CASE TG_OP WHEN 'INSERT' THEN NEW.reason
                                                    ELSE NEW.revoked_reason END,
                               'recorded_by', session_user::text,
                               'migration', 165));
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_group_role_bindings_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS group_role_bindings_guard_insert ON public.group_role_bindings;
CREATE TRIGGER group_role_bindings_guard_insert
    BEFORE INSERT ON public.group_role_bindings
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_group_role_bindings_guard_insert();
DROP TRIGGER IF EXISTS group_role_bindings_guard_update ON public.group_role_bindings;
CREATE TRIGGER group_role_bindings_guard_update
    BEFORE UPDATE ON public.group_role_bindings
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_group_role_bindings_guard_update();
DROP TRIGGER IF EXISTS group_role_bindings_refuse_delete ON public.group_role_bindings;
CREATE TRIGGER group_role_bindings_refuse_delete
    BEFORE DELETE ON public.group_role_bindings
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_group_role_bindings_refuse_delete();
DROP TRIGGER IF EXISTS group_role_bindings_audit ON public.group_role_bindings;
CREATE TRIGGER group_role_bindings_audit
    AFTER INSERT OR UPDATE ON public.group_role_bindings
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_group_role_bindings_audit();

-- -------------------------------------------------------------------
-- The binding verbs (maintenance only)
-- -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.epigraph_bind_group_role(
    p_role text, p_group uuid, p_member_role text, p_include_agents boolean, p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_id uuid;
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_bind_group_role: only a maintenance session binds a role to '
                        'a group' USING ERRCODE = '42501';
    END IF;
    IF p_role IS NULL OR p_group IS NULL OR p_member_role IS NULL OR p_include_agents IS NULL
       OR p_reason IS NULL OR btrim(p_reason) = '' THEN
        RAISE EXCEPTION 'epigraph_bind_group_role: a role, a group, a member role, '
                        'include_agents and a reason are required' USING ERRCODE = '22004';
    END IF;
    IF p_member_role NOT IN ('reader', 'writer') THEN
        RAISE EXCEPTION 'epigraph_bind_group_role: member role % is not reader or writer; a '
                        'role never confers admin', p_member_role USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM public.group_role_bindings b
                WHERE b.group_id = p_group AND b.role = p_role AND b.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'epigraph_bind_group_role: role % is already bound to group %; end '
                        'that binding first', p_role, p_group USING ERRCODE = '55000';
    END IF;
    INSERT INTO public.group_role_bindings (group_id, role, member_role, include_agents, reason)
    VALUES (p_group, p_role, p_member_role, p_include_agents, p_reason)
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_bind_group_role(text, uuid, text, boolean, text)
    FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_define_group_role(
    p_key text, p_description text, p_group uuid, p_member_role text,
    p_include_agents boolean, p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_node uuid := gen_random_uuid();
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_define_group_role: only a maintenance session defines a '
                        'role' USING ERRCODE = '42501';
    END IF;
    IF p_key IS NULL OR p_description IS NULL OR btrim(p_description) = '' THEN
        RAISE EXCEPTION 'epigraph_define_group_role: a key and a description are required'
            USING ERRCODE = '22004';
    END IF;
    IF p_key !~ '^role:[a-z][a-z0-9-]*$' THEN
        RAISE EXCEPTION 'epigraph_define_group_role: % is not a role key (role:<lowercase>)',
                        p_key USING ERRCODE = '22023';
    END IF;
    IF p_member_role IS NULL OR p_member_role NOT IN ('reader', 'writer') THEN
        RAISE EXCEPTION 'epigraph_define_group_role: member role % is not reader or writer; a '
                        'role never confers admin', p_member_role USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM public.platform_roles r WHERE r.key = p_key) THEN
        RAISE EXCEPTION 'GRB03: role % is already in the catalog; bind it with '
                        'epigraph_bind_group_role instead', p_key
            USING ERRCODE = 'GRB03';
    END IF;
    -- The role's graph node: a key whose private half exists nowhere (123).
    INSERT INTO public.agents (id, public_key, display_name, agent_type, role, labels)
    VALUES (v_node, uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()),
            p_key, 'role', 'custom', ARRAY['role', 'platform-role']);
    INSERT INTO public.platform_roles (key, elevates, reads_audit, role_node_id, description)
    VALUES (p_key, false, false, v_node, p_description);
    RETURN public.epigraph_bind_group_role(p_key, p_group, p_member_role, p_include_agents,
                                           p_reason);
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_define_group_role(text, text, uuid, text, boolean, text) FROM PUBLIC;

-- End a binding now. False when it was already ended (or does not exist).
CREATE OR REPLACE FUNCTION public.epigraph_end_group_role_binding(p_binding uuid, p_reason text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_end_group_role_binding: only a maintenance session ends a '
                        'binding' USING ERRCODE = '42501';
    END IF;
    IF p_binding IS NULL OR p_reason IS NULL OR btrim(p_reason) = '' THEN
        RAISE EXCEPTION 'epigraph_end_group_role_binding: the binding and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    UPDATE public.group_role_bindings
       SET revoked_at = now(), revoked_by = session_user, revoked_reason = p_reason
     WHERE id = p_binding AND revoked_at IS NULL;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows > 0;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_end_group_role_binding(uuid, text) FROM PUBLIC;

-- -------------------------------------------------------------------
-- The derivation
-- -------------------------------------------------------------------
-- The groups `p_agent` holds through a live binding at `p_at` (section 1's
-- rule). The candidate humans are the principal itself (arm 1; the role
-- function answers NULL unless it is a registered human that is nobody's
-- agent), and, for a binding that includes agents, the operator of its ACTING
-- live link and the human of its live client allowance (arm 2).
CREATE OR REPLACE FUNCTION public.epigraph_role_derived_memberships(
    p_agent uuid, p_at timestamptz)
RETURNS TABLE (group_id uuid, role text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    WITH candidates (human, via_agent) AS (
        SELECT p_agent, false
        UNION ALL
        SELECT o.operator_id, true FROM public.epigraph_operator_actor(p_agent) o
        UNION ALL
        SELECT a.h, true FROM public.epigraph_allowlisted_operator(p_agent) AS a(h)
         WHERE a.h IS NOT NULL
    )
    SELECT DISTINCT b.group_id, b.member_role
      FROM public.group_role_bindings b
      JOIN public.groups g ON g.id = b.group_id AND g.status = 'active'
      JOIN candidates c ON (NOT c.via_agent OR b.include_agents)
     WHERE p_agent IS NOT NULL AND p_at IS NOT NULL
       AND b.created_at <= p_at AND (b.revoked_at IS NULL OR p_at < b.revoked_at)
       AND public.epigraph_live_role_assignment(c.human, b.role, p_at) IS NOT NULL
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_derived_memberships(uuid, timestamptz)
    FROM PUBLIC;

-- Does `p_human` WRITE `p_group` at `p_at`: 122's direct test, or a live
-- writer binding whose role it holds then. `p_for_agent`: the question is
-- asked on behalf of one of its agents, so only a binding that includes
-- agents counts on the derived arm (a human-only binding admits the human,
-- not its agents, here as in the viewer's group set).
CREATE OR REPLACE FUNCTION public.epigraph_writes_group_at(
    p_human uuid, p_group uuid, p_at timestamptz, p_for_agent boolean)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT p_human IS NOT NULL AND p_group IS NOT NULL AND p_at IS NOT NULL
       AND (public.epigraph_operator_writes_group(p_human, p_group)
            OR EXISTS (
                SELECT 1 FROM public.group_role_bindings b
                  JOIN public.groups g ON g.id = b.group_id AND g.status = 'active'
                 WHERE b.group_id = p_group AND b.member_role = 'writer'
                   AND (NOT COALESCE(p_for_agent, true) OR b.include_agents)
                   AND b.created_at <= p_at AND (b.revoked_at IS NULL OR p_at < b.revoked_at)
                   AND public.epigraph_live_role_assignment(p_human, b.role, p_at)
                       IS NOT NULL))
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_writes_group_at(uuid, uuid, timestamptz, boolean)
    FROM PUBLIC;

-- Who holds `p_group` through its bindings at `p_at`: every role holder and
-- every agent registered to one, each answered by the derivation itself, so
-- the roster and the viewer can never disagree. Maintenance only.
CREATE OR REPLACE FUNCTION public.epigraph_group_role_roster(p_group uuid, p_at timestamptz)
RETURNS TABLE (out_agent_id uuid, out_role text, out_holder uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_group_role_roster: only a maintenance session reads a role '
                        'roster' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    WITH holders AS (
        SELECT DISTINCT ra.holder_person_id AS h
          FROM public.role_assignments ra
          JOIN public.group_role_bindings b ON b.role = ra.role AND b.group_id = p_group
         WHERE ra.holder_person_id IS NOT NULL
    ), candidates AS (
        SELECT hs.h AS agent, hs.h AS holder FROM holders hs
        UNION
        SELECT l.agent_id, l.operator_id
          FROM public.operator_links l JOIN holders hs ON hs.h = l.operator_id
        UNION
        SELECT r.agent_id, r.operator_id
          FROM public.author_binding_clients r JOIN holders hs ON hs.h = r.operator_id
    )
    SELECT DISTINCT c.agent, d.role, c.holder
      FROM candidates c
     CROSS JOIN LATERAL public.epigraph_role_derived_memberships(c.agent, p_at) d
     WHERE d.group_id = p_group
     ORDER BY 1, 2;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_group_role_roster(uuid, timestamptz) FROM PUBLIC;

-- 164's viewer group-set read (077's body plus 164's verb-made-group
-- conjunct), UNION the derived rows. Signature, result, owner and grants
-- unchanged (CREATE OR REPLACE keeps them; both are re-asserted below).
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

-- 123's claims-path writer scope (122's body, 123's HINT); delta: the
-- effective test `epigraph_writes_group_at(human, group, now(), via agent)`
-- in place of 122's direct one. Signature, owner and grants unchanged.
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
    IF v_human IS NULL
       OR public.epigraph_writes_group_at(v_human, p_group, now(), v_human <> p_agent) THEN
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

-- -------------------------------------------------------------------
-- Ownership and grants, guarded as every such block since 060 is. Each
-- ALTER/GRANT names its function literally (tenancy_backfill.rs's static
-- re-own scan reads these statements).
-- -------------------------------------------------------------------
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_group_role_bindings_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_group_role_bindings_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_group_role_bindings_refuse_delete() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_group_role_bindings_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION '
                'public.epigraph_bind_group_role(text, uuid, text, boolean, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION '
                'public.epigraph_define_group_role(text, text, uuid, text, boolean, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_end_group_role_binding(uuid, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION '
                'public.epigraph_role_derived_memberships(uuid, timestamptz) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION '
                'public.epigraph_writes_group_at(uuid, uuid, timestamptz, boolean) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_group_role_roster(uuid, timestamptz) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_live_memberships(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_bind_group_role(text, uuid, text, boolean, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_define_group_role(text, text, uuid, text, boolean, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_end_group_role_binding(uuid, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_role_derived_memberships(uuid, timestamptz) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_writes_group_at(uuid, uuid, timestamptz, boolean) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_group_role_roster(uuid, timestamptz) '
                'TO epigraph_maintenance';
        -- The definers run as this role, so it holds the DML they issue; the
        -- table's own triggers hold a direct write to the same rules.
        EXECUTE 'GRANT SELECT, INSERT ON public.group_role_bindings TO epigraph_maintenance';
        EXECUTE 'GRANT UPDATE (revoked_at, revoked_by, revoked_reason) '
                'ON public.group_role_bindings TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        -- 077's default privileges handed the app role DML on the new table;
        -- take it back and leave SELECT (row security then shows it nothing).
        EXECUTE 'REVOKE ALL ON public.group_role_bindings FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.group_role_bindings TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_bind_group_role(text, uuid, text, boolean, text) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_define_group_role(text, text, uuid, text, boolean, text) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_end_group_role_binding(uuid, text) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_role_derived_memberships(uuid, timestamptz) FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_writes_group_at(uuid, uuid, timestamptz, boolean) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_group_role_roster(uuid, timestamptz) '
                'FROM epigraph_app';
        -- `Viewer::resolve` calls it on the application role (077, 164).
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_live_memberships(uuid) '
                'TO epigraph_app';
    END IF;
END $$;
