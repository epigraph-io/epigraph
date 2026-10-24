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
-- 2. WHO WRITES BINDINGS
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
-- UNDO
--
-- DROP FUNCTION IF EXISTS public.epigraph_end_group_role_binding(uuid, text);
-- DROP FUNCTION IF EXISTS public.epigraph_bind_group_role(text, uuid, text, boolean, text);
-- DROP FUNCTION IF EXISTS public.epigraph_define_group_role(text, text, uuid, text, boolean, text);
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
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_bind_group_role(text, uuid, text, boolean, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_define_group_role(text, text, uuid, text, boolean, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_end_group_role_binding(uuid, text) '
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
    END IF;
END $$;
