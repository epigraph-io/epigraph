-- 166_role_attached_agents.sql
-- Role-attached agents run only while a human holds the role.
--
-- ===================================================================
-- 1. WHY
--
-- Operator ruling: an agent attached to a role cannot run while no human is
-- attached to that role. A scheduled run that falls in such a gap is skipped
-- (the host's job, with an alert; nothing is queued), and a run in progress
-- when the holder's assignment ends may finish, but every write it makes
-- after the end is refused (this file's job).
--
-- Agents are NOT bound to roles for authority. An agent acts for the human it
-- is linked to (107/122), and that human holds a role through 123's
-- time-windowed `role_assignments`. "Attached to a role" means the role's own
-- agents: its curator and the fleet identities that run the role's schedules.
-- Until now that attachment existed only on the host. This file records it
-- and enforces the ruling at write time, so a container that bypasses the
-- host still writes nothing in a gap.
--
-- `role_agents` CONFERS NOTHING. It only adds a refusal. An attachment never
-- grants an agent a group, a scope or a read; whatever the agent may do, it
-- may do only through its linked human, as before.
--
-- ===================================================================
-- 2. THE RECORD: `role_agents`
--
-- One row per (role, agent, window): `valid_from`, an optional `valid_to`,
-- who wrote it (`attached_by`, the writing login), why, and, for a row a
-- succession copied, the row it was copied from (`inherited_from`). A row is
-- LIVE at time t when it is not detached, `valid_from <= t` and
-- `t < valid_to` (or no `valid_to`).
--
-- Append-only, on every role (a superuser and the table owner included,
-- short of disabling triggers). The guards raise `ROL02`:
--   * on INSERT: a detach field set; a back-dated `valid_from` (more than a
--     minute in the past); provenance the writer supplied (`attached_by`
--     other than the writing login, `created_at` other than `now()`); a
--     HUMAN (a registered human operator, or `agent_type 'human'`) or a role
--     node as the agent (agents only); an un-detached row for the same
--     (role, agent) whose window overlaps; an `inherited_from` row of another
--     role;
--   * on UPDATE: anything but the one detach (`detached_at = now()`,
--     `detached_by` = the detaching login, a reason, every other column
--     unchanged), and any change to a detached row (a detach is final);
--   * DELETE and TRUNCATE are refused outright.
-- Each attach and each detach writes one `security_events` row
-- (`platform.role_agent_attached` / `platform.role_agent_detached`), whatever
-- path wrote it. The `platform.` prefix is already reserved to a privileged
-- session or a maintenance-owned definer (123 section 4), so an application
-- session cannot forge one.
--
-- WHO WRITES IT: a maintenance session (`epigraph_attach_agent_to_role` /
-- `epigraph_detach_agent_from_role`, or a direct statement meeting the same
-- guards) and the identity registration (section 5), which runs as a
-- maintenance-owned definer on the attestor's connection. Row security admits
-- exactly those (`epigraph_bypass()` or `epigraph_definer_bypass()`). The
-- application role holds SELECT only and reads no row.
--
-- ===================================================================
-- 3. THE RULE (`ROL01`)
--
-- A claim INSERT (and a re-open or re-attribution, which 122/123 check as an
-- insert) is refused `ROL01` when the agent WRITING it (the stamped
-- principal) or the agent it is ATTRIBUTED to has a live attachment, unless,
-- for EVERY live attachment of that agent, at `clock_timestamp()`:
--   (a) the role has a live human holder (`epigraph_live_role_assignment`), and
--   (b) the agent's live-linked human (`epigraph_human_of(agent, true)`) is
--       that holder.
-- (b) also refuses an agent still linked to the PREVIOUS holder after a
-- handover, before it is re-linked.
--
-- `clock_timestamp()`, not `now()`: `now()` is the transaction's start, so a
-- long-running transaction opened inside the window would keep writing past
-- `valid_to`. The ruling is "every write after the end is refused".
--
-- WHERE: in the operator-binding path, by re-stating 123's
-- `epigraph_require_writer_scope` (which the claims trigger calls on the
-- author when the writer is the author or no principal is stamped, and on
-- the writer otherwise) and `epigraph_require_attributable` (the author, when
-- the writer is someone else). No new trigger, and 153's trigger body is not
-- touched. A restatement of a RETIRED predecessor (the supersede act's
-- inherited author) is not checked on that author: restating an attached
-- agent's retired claim is its human's act, not the agent running. The writer
-- of such a restatement is still checked.
--
-- EXEMPT: a privileged session (`epigraph_bypass()`: the maintenance role or a
-- superuser, i.e. the custodial path), as it is from OPL02. KEYED ON ARMING
-- like OPL02 (the claims trigger checks nothing on an unarmed database), and
-- NOT relieved by the valve, which relieves OPL01 only.
--
-- COVERAGE: attributed CLAIM writes, which is what the binding covers. An
-- attached agent's evidence, edge or membership writes after the end are not
-- refused by this file.
--
-- ===================================================================
-- 4. THE QUESTION THE HOST AND EPIGRAPH-MCP ASK
--
-- `epigraph_role_agent_may_run(agent)` -> (may_run, role, holder, reason),
-- reason one of `unattached`, `held`, `no_holder`, `not_holder`, answered at
-- `clock_timestamp()` by the same predicate as ROL01. EXECUTE-able by
-- `epigraph_app` (epigraph-mcp refuses to boot on `may_run = false`) and by
-- `epigraph_identity_attestor` (the host asks before starting a container or
-- a role-owned schedule), so neither reads the roster. DISCLOSURE, accepted:
-- for any agent id, an application session learns whether it is attached,
-- the role of the first failing (or first) attachment, and whether the role
-- has a holder; `holder` is returned only when it IS the agent's own linked
-- human (an `operator_links` fact the app role already reads, 107), never the
-- holder an agent of a previous holder is missing.
--
-- ===================================================================
-- 5. SUCCESSION
--
-- 161's `epigraph_register_agent_identity` is re-stated with its body
-- unchanged except for one step (5b): when a parent is named, the parent's
-- live (or not yet started) attachments are copied to the child, each with
-- `inherited_from`, unless the child already has an overlapping un-detached
-- row for that role (so a repeat registration copies nothing and never
-- aborts). The copy is a restriction, never a grant, so copying into an
-- identity shared with another group fails safe: it can only refuse.
--
-- ===================================================================
-- 6. UNDO
--
-- `docs/runbooks/166-undo.sql` restores 123's two check bodies and 161's
-- registration body, then drops what this file creates. Roll back first any
-- epigraph-mcp built against this file: it calls
-- `epigraph_role_agent_may_run` at boot and fails closed without it.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- THE RECORD (section 2)
-- ===================================================================
CREATE TABLE IF NOT EXISTS public.role_agents (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role           text NOT NULL REFERENCES public.platform_roles(key) ON DELETE RESTRICT,
    agent_id       uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    valid_from     timestamptz NOT NULL DEFAULT now(),
    valid_to       timestamptz,
    -- The database login that wrote the row (a maintenance login, or the
    -- attestor's for a succession copy).
    attached_by    text NOT NULL DEFAULT session_user,
    reason         text NOT NULL CONSTRAINT role_agents_reason_present
                       CHECK (length(btrim(reason)) > 0),
    inherited_from uuid REFERENCES public.role_agents(id) ON DELETE RESTRICT,
    created_at     timestamptz NOT NULL DEFAULT now(),
    detached_at    timestamptz,
    detached_by    text,
    detach_reason  text,
    CONSTRAINT role_agents_window CHECK (valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT role_agents_detach_shape
        CHECK ((detached_at IS NULL) = (detached_by IS NULL)
               AND (detached_at IS NULL) = (detach_reason IS NULL))
);
REVOKE ALL ON public.role_agents FROM PUBLIC;
CREATE INDEX IF NOT EXISTS idx_role_agents_live
    ON public.role_agents (agent_id, role) WHERE detached_at IS NULL;

-- BEFORE INSERT: ROL02 (section 2).
CREATE OR REPLACE FUNCTION public.epigraph_role_agents_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    -- One attach (or copy) at a time, so two concurrent writers of the same
    -- (role, agent) see each other's row below.
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.role_agents'));
    IF NEW.detached_at IS NOT NULL OR NEW.detached_by IS NOT NULL
       OR NEW.detach_reason IS NOT NULL THEN
        RAISE EXCEPTION 'ROL02: an attachment is recorded live; end it with '
                        'epigraph_detach_agent_from_role'
            USING ERRCODE = 'ROL02';
    END IF;
    IF NEW.valid_from < now() - interval '1 minute' THEN
        RAISE EXCEPTION 'ROL02: an attachment is never back-dated (valid_from % is before now)',
                        NEW.valid_from
            USING ERRCODE = 'ROL02';
    END IF;
    IF NEW.attached_by IS DISTINCT FROM session_user::text
       OR NEW.created_at IS DISTINCT FROM now() THEN
        RAISE EXCEPTION 'ROL02: attached_by and created_at are recorded by the database (the '
                        'writing login, now()); an attach does not supply them'
            USING ERRCODE = 'ROL02';
    END IF;
    IF public.epigraph_is_human_operator(NEW.agent_id)
       OR EXISTS (SELECT 1 FROM public.agents a
                   WHERE a.id = NEW.agent_id AND a.agent_type IN ('human', 'role')) THEN
        RAISE EXCEPTION 'ROL02: % is a human or a role node; only an agent is attached to a role '
                        '(a human holds a role through role_assignments)', NEW.agent_id
            USING ERRCODE = 'ROL02';
    END IF;
    IF NEW.inherited_from IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM public.role_agents p
                        WHERE p.id = NEW.inherited_from AND p.role = NEW.role) THEN
        RAISE EXCEPTION 'ROL02: inherited_from % is not an attachment to role %',
                        NEW.inherited_from, NEW.role
            USING ERRCODE = 'ROL02';
    END IF;
    IF EXISTS (SELECT 1 FROM public.role_agents e
                WHERE e.role = NEW.role AND e.agent_id = NEW.agent_id
                  AND e.detached_at IS NULL
                  AND (e.valid_to IS NULL OR e.valid_to > NEW.valid_from)
                  AND (NEW.valid_to IS NULL OR NEW.valid_to > e.valid_from)) THEN
        RAISE EXCEPTION 'ROL02: agent % already has an attachment to role % in that window',
                        NEW.agent_id, NEW.role
            USING ERRCODE = 'ROL02',
                  HINT = 'Detach it first (epigraph_detach_agent_from_role).';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_agents_guard_insert() FROM PUBLIC;

-- BEFORE UPDATE: the one detach, nothing else; a detached row is final.
CREATE OR REPLACE FUNCTION public.epigraph_role_agents_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF OLD.detached_at IS NOT NULL THEN
        RAISE EXCEPTION 'ROL02: attachment % is detached, and a detach is final', OLD.id
            USING ERRCODE = 'ROL02';
    END IF;
    IF NEW.detached_at IS NULL OR NEW.detached_at <> now()
       OR NEW.detached_by IS DISTINCT FROM session_user::text
       OR NEW.detach_reason IS NULL OR length(btrim(NEW.detach_reason)) = 0
       OR (NEW.id, NEW.role, NEW.agent_id, NEW.valid_from, NEW.valid_to, NEW.attached_by,
           NEW.reason, NEW.inherited_from, NEW.created_at)
          IS DISTINCT FROM
          (OLD.id, OLD.role, OLD.agent_id, OLD.valid_from, OLD.valid_to, OLD.attached_by,
           OLD.reason, OLD.inherited_from, OLD.created_at) THEN
        RAISE EXCEPTION 'ROL02: an attachment is only ever detached (detached_at = now(), '
                        'detached_by = the detaching login, and a detach_reason), nothing '
                        'else; nothing was changed'
            USING ERRCODE = 'ROL02',
                  HINT = 'Detach it with epigraph_detach_agent_from_role and attach a new one.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_agents_guard_update() FROM PUBLIC;

-- DELETE and TRUNCATE: never (a row trigger never sees a TRUNCATE).
CREATE OR REPLACE FUNCTION public.epigraph_role_agents_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'ROL02: role_agents rows are append-only (migration 166); % refused', TG_OP
        USING ERRCODE = 'ROL02';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_agents_append_only() FROM PUBLIC;

-- AFTER INSERT / UPDATE: one audit row per attach and per detach.
CREATE OR REPLACE FUNCTION public.epigraph_role_agents_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_agent_attached', NEW.agent_id, true,
                jsonb_build_object('attachment_id', NEW.id, 'role', NEW.role,
                                   'agent', NEW.agent_id,
                                   'valid_from', NEW.valid_from, 'valid_to', NEW.valid_to,
                                   'attached_by', NEW.attached_by, 'reason', NEW.reason,
                                   'inherited_from', NEW.inherited_from));
    ELSIF OLD.detached_at IS NULL AND NEW.detached_at IS NOT NULL THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_agent_detached', NEW.agent_id, true,
                jsonb_build_object('attachment_id', NEW.id, 'role', NEW.role,
                                   'agent', NEW.agent_id,
                                   'detached_at', NEW.detached_at,
                                   'detached_by', NEW.detached_by,
                                   'detach_reason', NEW.detach_reason));
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_agents_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS role_agents_guard_insert ON public.role_agents;
CREATE TRIGGER role_agents_guard_insert
    BEFORE INSERT ON public.role_agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_agents_guard_insert();
DROP TRIGGER IF EXISTS role_agents_guard_update ON public.role_agents;
CREATE TRIGGER role_agents_guard_update
    BEFORE UPDATE ON public.role_agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_agents_guard_update();
DROP TRIGGER IF EXISTS role_agents_no_delete ON public.role_agents;
CREATE TRIGGER role_agents_no_delete
    BEFORE DELETE ON public.role_agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_agents_append_only();
DROP TRIGGER IF EXISTS role_agents_no_truncate ON public.role_agents;
CREATE TRIGGER role_agents_no_truncate
    BEFORE TRUNCATE ON public.role_agents
    FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_role_agents_append_only();
DROP TRIGGER IF EXISTS role_agents_audit ON public.role_agents;
CREATE TRIGGER role_agents_audit
    AFTER INSERT OR UPDATE ON public.role_agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_role_agents_audit();

-- Row security: a maintenance session and a maintenance-owned definer frame
-- (the registration's succession copy, on the attestor's connection) read,
-- insert and detach; nobody deletes (no policy, and the trigger above).
ALTER TABLE public.role_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_agents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS role_agents_privileged_read ON public.role_agents;
CREATE POLICY role_agents_privileged_read ON public.role_agents
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS role_agents_privileged_insert ON public.role_agents;
CREATE POLICY role_agents_privileged_insert ON public.role_agents
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
DROP POLICY IF EXISTS role_agents_privileged_update ON public.role_agents;
CREATE POLICY role_agents_privileged_update ON public.role_agents
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));

-- The maintenance verbs. They add nothing to the table's own rules: the
-- INSERT and UPDATE meet the guards and the audit above.
CREATE OR REPLACE FUNCTION public.epigraph_attach_agent_to_role(
    p_role text, p_agent uuid, p_valid_from timestamptz, p_valid_to timestamptz,
    p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_id uuid;
BEGIN
    IF p_role IS NULL OR p_agent IS NULL OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_attach_agent_to_role: the role, the agent and a reason are '
                        'required'
            USING ERRCODE = '22004';
    END IF;
    INSERT INTO public.role_agents (role, agent_id, valid_from, valid_to, reason)
    VALUES (p_role, p_agent, COALESCE(p_valid_from, now()), p_valid_to, p_reason)
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_attach_agent_to_role(text, uuid, timestamptz, timestamptz, text) FROM PUBLIC;

-- Detach every un-detached attachment of `p_agent` to `p_role`, now. Returns
-- how many were detached (0: nothing to detach; a detach is never repeated).
CREATE OR REPLACE FUNCTION public.epigraph_detach_agent_from_role(
    p_role text, p_agent uuid, p_reason text)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF p_role IS NULL OR p_agent IS NULL OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_detach_agent_from_role: the role, the agent and a reason are '
                        'required'
            USING ERRCODE = '22004';
    END IF;
    UPDATE public.role_agents
       SET detached_at = now(), detached_by = session_user, detach_reason = p_reason
     WHERE role = p_role AND agent_id = p_agent AND detached_at IS NULL;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_detach_agent_from_role(text, uuid, text) FROM PUBLIC;

-- ===================================================================
-- OWNERSHIP AND GRANTS for the record, guarded as every such block since 060
-- is. 077's default privileges hand the application role DML on a new table:
-- taken back here, leaving SELECT (row security shows it nothing).
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_role_agents_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_role_agents_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_role_agents_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_attach_agent_to_role(text, uuid, timestamptz, '
                'timestamptz, text) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_detach_agent_from_role(text, uuid, text) '
                'OWNER TO epigraph_maintenance';
        -- SELECT also serves 161's AID09 freshness scan, which reads every
        -- foreign key into `agents` as the registration's owner and treats an
        -- unreadable column as "bound".
        EXECUTE 'GRANT SELECT, INSERT ON public.role_agents TO epigraph_maintenance';
        EXECUTE 'GRANT UPDATE (detached_at, detached_by, detach_reason) ON public.role_agents '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_attach_agent_to_role(text, uuid, '
                'timestamptz, timestamptz, text), '
                'public.epigraph_detach_agent_from_role(text, uuid, text) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.role_agents FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.role_agents TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_attach_agent_to_role(text, uuid, '
                'timestamptz, timestamptz, text), '
                'public.epigraph_detach_agent_from_role(text, uuid, text) FROM epigraph_app';
    END IF;
END $$;
