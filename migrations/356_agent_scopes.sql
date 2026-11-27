-- 356: declared per-agent write scopes, recorded but not yet enforced
-- (backlog d7ee64a6, the first step of the f8cde19f scope model).
--
-- ===================================================================
-- 1. WHY
--
-- An agent's write reach today is the union of grants that none of them
-- declares per agent: its own `group_memberships` rows (a writer row admits
-- every write class), its operator's grants (107, 206/209, 234), a role
-- binding (165/256) and its role attachment (166). Nothing records "agent X
-- may write edges in group G and nothing else". The scope model narrows that:
-- once ARMED, a write door admits an agent for group G and action class C only
-- if a live declared row (G, C) exists AND the door's existing check passes.
-- It only ever NARROWS what a door admits; it never widens it.
--
-- This file is the record only. It adds the table, the arming flag (off) and
-- the two audited maintenance verbs that write the record. NO write door reads
-- any of it yet, so applying it changes no write and no read. Enforcement,
-- arming and the operator CLI are later changes.
--
-- ===================================================================
-- 2. THE RECORD: `agent_scopes`
--
-- One row per declared (agent, group, action class), with a validity window
-- (`valid_from`, `valid_to`; `valid_to` NULL is open-ended), the login that
-- granted it (`granted_by`, recorded by the database as `session_user`), a
-- non-blank `reason`, and optionally the role attachment (166's
-- `role_agents.id`) the scope rides on, so a later handover can carry it with
-- the role rather than with a human. The action classes are a closed set
-- (CHECK): `claim_write`, `evidence_write`, `edge_write`, `label_write`,
-- `share_publicize`, `group_admin`.
--
-- A row is LIVE at time t when `revoked_at IS NULL AND valid_from <= t AND
-- (valid_to IS NULL OR t < valid_to)`. A revoke is recorded on the row
-- (`revoked_at` = now(), `revoked_by` = the revoking login, a non-blank
-- `revoke_reason`) rather than by moving `valid_to`: a grant and its revoke in
-- one transaction would otherwise need `valid_to = valid_from`, and the window
-- would stop saying what was declared.
--
-- Append-only, on every role short of disabling triggers. The guard
-- (`epigraph_agent_scopes_guard`, refusal prefix `AGS02`) refuses:
--   * on INSERT: a revoke field set; provenance the writer supplied
--     (`granted_by` other than the writing login, `created_at` other than
--     now()); a `valid_from` back-dated by more than a minute; a HUMAN (a
--     registered human operator, or `agent_type` 'human' / 'role') as the
--     agent (humans keep membership semantics and are out of the model); a
--     `role_attachment_id` that is not a live (un-detached) attachment OF THE
--     SAME AGENT (a scope may not ride another identity's attachment through a
--     handover);
--   * on UPDATE: anything but the one revoke (every other column unchanged),
--     and any change to a revoked row (a revoke is final);
--   * DELETE and TRUNCATE outright.
-- At most one un-revoked row per (agent, group, class): the partial unique
-- index `agent_scopes_one_unrevoked` (23505). An expired, un-revoked row
-- therefore blocks a new grant for the same key until it is revoked; that
-- keeps "what is declared" one row per key, and the CLI reads it.
--
-- AUDIT: whatever path writes the row (the verbs below, or a direct
-- maintenance statement that meets the guard), each grant writes ONE
-- `security_events` row `platform.agent_scope_granted` and each revoke ONE
-- `platform.agent_scope_revoked`, from the AFTER trigger
-- `epigraph_agent_scopes_audit`. The verbs write no audit row of their own,
-- so a call is exactly one row. A revoke of an already-revoked row changes
-- nothing and writes nothing. The `platform.` prefix is reserved to a
-- privileged session or a maintenance-owned definer frame (123 section 4), so
-- the application role cannot forge either event.
--
-- WHO READS AND WRITES IT: a maintenance session and a maintenance-owned
-- definer frame, and nobody else. Row security (ENABLE + FORCE) admits
-- exactly `epigraph_bypass()` or `epigraph_definer_bypass()` for SELECT,
-- INSERT and UPDATE, and has no DELETE policy. The application role holds NO
-- privilege on the table at all (not even SELECT): a later enforcing door
-- reads it through a definer, and an agent's declared scope set is not the
-- request path's to enumerate.
--
-- ===================================================================
-- 3. THE VERBS (maintenance only)
--
-- `epigraph_agent_scope_grant(agent, group, action_class, reason, valid_from,
--   valid_to, role_attachment) -> uuid` inserts one row (valid_from NULL means
--   now()) and returns its id.
-- `epigraph_agent_scope_revoke(scope_id, reason) -> boolean` revokes one row:
--   true when it revoked it now, false when it was already revoked (no write,
--   no audit row); P0002 when no such row exists.
-- Both are SECURITY DEFINER, owned by `epigraph_maintenance`, on
-- `pg_catalog, pg_temp`, EXECUTE for the maintenance role only (not PUBLIC,
-- not `epigraph_app`), and each body refuses 42501 unless the SESSION is
-- privileged (`epigraph_bypass()`, which reads `session_user`, or a
-- superuser), so a later over-wide EXECUTE grant still opens nothing to the
-- request DSN. A NULL or blank required argument is 22004.
--
-- ===================================================================
-- 4. ARMING: `agent_scope_arming`, OFF
--
-- One row (singleton key plus CHECK), installed here with `armed = false`.
-- Nothing reads it yet; the enforcing doors will (agent and armed: require a
-- live declared row; otherwise unchanged). Unlike 122's one-way arming this is
-- meant to be reversible (disarming restores today's behaviour), and the
-- audited verb that flips it comes with the first enforcing door. Until then
-- no role below a superuser can change it: the application role and the
-- maintenance role hold SELECT only. No row security and no tenancy columns:
-- it is control state, like 122's `operator_binding_arming`.
--
-- ===================================================================
-- 5. TENANCY
--
-- Neither table has a `claim_id` column or a foreign key to `claims`, so
-- neither is in the generated protected set (`tenancy_coverage.rs`), and
-- neither is a tier-A entity: both are governance state, like 166's
-- `role_agents`. `agent_scopes` is classified in `elevation_arms_census.rs`
-- as excluded (maintenance-written, definer-read).
--
-- ===================================================================
-- 6. UNDO
--
-- `docs/runbooks/356-undo.sql` drops both tables, the triggers and the four
-- functions in one transaction. No binary reads any of it, so nothing needs
-- rolling back first. The `platform.agent_scope_*` audit rows stay
-- (`security_events` is immutable, 082).
-- **Applied to throwaway databases only, NOT to any deployed database.**

SET LOCAL lock_timeout = '3s';

CREATE TABLE public.agent_scopes (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id           uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    group_id           uuid NOT NULL REFERENCES public.groups(id) ON DELETE RESTRICT,
    action_class       text NOT NULL CONSTRAINT agent_scopes_action_class_known
                           CHECK (action_class IN ('claim_write', 'evidence_write', 'edge_write',
                                                   'label_write', 'share_publicize',
                                                   'group_admin')),
    valid_from         timestamptz NOT NULL DEFAULT now(),
    valid_to           timestamptz,
    -- The database login that wrote the row (a maintenance login).
    granted_by         text NOT NULL DEFAULT session_user,
    reason             text NOT NULL CONSTRAINT agent_scopes_reason_present
                           CHECK (length(btrim(reason)) > 0),
    role_attachment_id uuid REFERENCES public.role_agents(id) ON DELETE RESTRICT,
    created_at         timestamptz NOT NULL DEFAULT now(),
    revoked_at         timestamptz,
    revoked_by         text,
    revoke_reason      text,
    CONSTRAINT agent_scopes_window CHECK (valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT agent_scopes_revoke_shape CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL AND revoke_reason IS NULL)
        OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL
            AND revoke_reason IS NOT NULL AND length(btrim(revoke_reason)) > 0))
);
COMMENT ON TABLE public.agent_scopes IS
    'Migration 356: declared (agent, group, action class) write scopes with a validity window, '
    'written only by maintenance (epigraph_agent_scope_grant / _revoke) and audited one '
    'security_events row per grant and per revoke. Append-only; a revoke is final. No write '
    'door reads it yet (agent_scope_arming is off).';
REVOKE ALL ON public.agent_scopes FROM PUBLIC;

CREATE UNIQUE INDEX agent_scopes_one_unrevoked
    ON public.agent_scopes (agent_id, group_id, action_class) WHERE revoked_at IS NULL;
CREATE INDEX agent_scopes_by_group
    ON public.agent_scopes (group_id) WHERE revoked_at IS NULL;

CREATE TABLE public.agent_scope_arming (
    singleton  boolean PRIMARY KEY DEFAULT true CONSTRAINT agent_scope_arming_singleton
                   CHECK (singleton),
    armed      boolean NOT NULL DEFAULT false,
    changed_at timestamptz NOT NULL DEFAULT now(),
    changed_by text NOT NULL DEFAULT session_user,
    reason     text NOT NULL CONSTRAINT agent_scope_arming_reason_present
                   CHECK (length(btrim(reason)) > 0)
);
COMMENT ON TABLE public.agent_scope_arming IS
    'Migration 356: whether the declared agent scopes (agent_scopes) are enforced. One row, '
    'installed disarmed; nothing reads it yet.';
REVOKE ALL ON public.agent_scope_arming FROM PUBLIC;
INSERT INTO public.agent_scope_arming (singleton, armed, reason)
VALUES (true, false, 'installed disarmed by migration 356');

-- BEFORE INSERT / UPDATE / DELETE: AGS02 (section 2). INVOKER: it runs as the
-- writer, which is a maintenance session or a maintenance-owned definer; the
-- application role cannot reach the table at all.
CREATE OR REPLACE FUNCTION public.epigraph_agent_scopes_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'AGS02: agent_scopes rows are append-only (migration 356); % refused. '
                        'End a scope with epigraph_agent_scope_revoke', TG_OP
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL
           OR NEW.revoke_reason IS NOT NULL THEN
            RAISE EXCEPTION 'AGS02: a scope is recorded live; end it with '
                            'epigraph_agent_scope_revoke'
                USING ERRCODE = '55000';
        END IF;
        IF NEW.granted_by IS DISTINCT FROM session_user::text
           OR NEW.created_at IS DISTINCT FROM now() THEN
            RAISE EXCEPTION 'AGS02: granted_by and created_at are recorded by the database (the '
                            'writing login, now()); a grant does not supply them'
                USING ERRCODE = '55000';
        END IF;
        IF NEW.valid_from < now() - interval '1 minute' THEN
            RAISE EXCEPTION 'AGS02: a scope is never back-dated (valid_from % is before now)',
                            NEW.valid_from
                USING ERRCODE = '55000';
        END IF;
        IF public.epigraph_is_human_operator(NEW.agent_id)
           OR EXISTS (SELECT 1 FROM public.agents a
                       WHERE a.id = NEW.agent_id AND a.agent_type IN ('human', 'role')) THEN
            RAISE EXCEPTION 'AGS02: % is a human or a role node; only an agent identity is '
                            'given declared scopes', NEW.agent_id
                USING ERRCODE = '55000';
        END IF;
        IF NEW.role_attachment_id IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM public.role_agents r
                            WHERE r.id = NEW.role_attachment_id
                              AND r.agent_id = NEW.agent_id
                              AND r.detached_at IS NULL) THEN
            RAISE EXCEPTION 'AGS02: role attachment % is not a live attachment of agent %',
                            NEW.role_attachment_id, NEW.agent_id
                USING ERRCODE = '55000';
        END IF;
        RETURN NEW;
    END IF;
    -- UPDATE: the one revoke, nothing else; a revoked row is final.
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'AGS02: scope % is revoked, and a revoke is final', OLD.id
            USING ERRCODE = '55000';
    END IF;
    IF NEW.revoked_at IS NULL OR NEW.revoked_at <> now()
       OR NEW.revoked_by IS DISTINCT FROM session_user::text
       OR NEW.revoke_reason IS NULL OR length(btrim(NEW.revoke_reason)) = 0
       OR (NEW.id, NEW.agent_id, NEW.group_id, NEW.action_class, NEW.valid_from, NEW.valid_to,
           NEW.granted_by, NEW.reason, NEW.role_attachment_id, NEW.created_at)
          IS DISTINCT FROM
          (OLD.id, OLD.agent_id, OLD.group_id, OLD.action_class, OLD.valid_from, OLD.valid_to,
           OLD.granted_by, OLD.reason, OLD.role_attachment_id, OLD.created_at) THEN
        RAISE EXCEPTION 'AGS02: a scope is only ever revoked (revoked_at = now(), revoked_by = '
                        'the revoking login, and a revoke_reason), nothing else; nothing was '
                        'changed'
            USING ERRCODE = '55000',
                  HINT = 'Revoke it with epigraph_agent_scope_revoke and grant a new one.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_scopes_guard() FROM PUBLIC;

-- AFTER INSERT / UPDATE: one audit row per grant and per revoke (section 2).
CREATE OR REPLACE FUNCTION public.epigraph_agent_scopes_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.agent_scope_granted', NEW.agent_id, true,
                jsonb_build_object('scope_id', NEW.id, 'agent', NEW.agent_id,
                                   'group', NEW.group_id, 'action_class', NEW.action_class,
                                   'valid_from', NEW.valid_from, 'valid_to', NEW.valid_to,
                                   'granted_by', NEW.granted_by, 'reason', NEW.reason,
                                   'role_attachment_id', NEW.role_attachment_id));
    ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.agent_scope_revoked', NEW.agent_id, true,
                jsonb_build_object('scope_id', NEW.id, 'agent', NEW.agent_id,
                                   'group', NEW.group_id, 'action_class', NEW.action_class,
                                   'revoked_at', NEW.revoked_at, 'revoked_by', NEW.revoked_by,
                                   'revoke_reason', NEW.revoke_reason));
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_scopes_audit() FROM PUBLIC;

CREATE TRIGGER agent_scopes_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.agent_scopes
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_agent_scopes_guard();
CREATE TRIGGER agent_scopes_no_truncate
    BEFORE TRUNCATE ON public.agent_scopes
    FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_agent_scopes_guard();
CREATE TRIGGER agent_scopes_audit
    AFTER INSERT OR UPDATE ON public.agent_scopes
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_agent_scopes_audit();

-- Row security: a maintenance session and a maintenance-owned definer frame
-- read, grant and revoke; nobody deletes (no policy, and the guard above).
ALTER TABLE public.agent_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_scopes_privileged_read ON public.agent_scopes
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
CREATE POLICY agent_scopes_privileged_insert ON public.agent_scopes
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));
CREATE POLICY agent_scopes_privileged_update ON public.agent_scopes
    FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()));

-- The maintenance verbs (section 3). They add nothing to the table's own
-- rules: the INSERT and UPDATE meet the guard and the audit above.
CREATE OR REPLACE FUNCTION public.epigraph_agent_scope_grant(
    p_agent uuid, p_group uuid, p_action_class text, p_reason text,
    p_valid_from timestamptz, p_valid_to timestamptz, p_role_attachment uuid)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_id uuid;
BEGIN
    -- Defence in depth: the grant set is the boundary; this keeps it one if a
    -- later migration grants EXECUTE too widely. `epigraph_bypass()` keys on
    -- session_user, so the definer frame cannot change the answer; the
    -- superuser arm covers a database without the maintenance role.
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'AGS02: only a maintenance session grants an agent scope'
            USING ERRCODE = '42501';
    END IF;
    IF p_agent IS NULL OR p_group IS NULL OR p_action_class IS NULL
       OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_agent_scope_grant: the agent, the group, the action class '
                        'and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    INSERT INTO public.agent_scopes (agent_id, group_id, action_class, valid_from, valid_to,
                                     reason, role_attachment_id)
    VALUES (p_agent, p_group, p_action_class, COALESCE(p_valid_from, now()), p_valid_to,
            p_reason, p_role_attachment)
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_scope_grant(
    uuid, uuid, text, text, timestamptz, timestamptz, uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_agent_scope_revoke(p_scope uuid, p_reason text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'AGS02: only a maintenance session revokes an agent scope'
            USING ERRCODE = '42501';
    END IF;
    IF p_scope IS NULL OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_agent_scope_revoke: the scope and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.agent_scopes s WHERE s.id = p_scope) THEN
        RAISE EXCEPTION 'epigraph_agent_scope_revoke: no agent scope %', p_scope
            USING ERRCODE = 'P0002';
    END IF;
    UPDATE public.agent_scopes
       SET revoked_at = now(), revoked_by = session_user, revoke_reason = p_reason
     WHERE id = p_scope AND revoked_at IS NULL;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows > 0;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_scope_revoke(uuid, text) FROM PUBLIC;

-- ===================================================================
-- OWNERSHIP AND GRANTS, guarded as every such block since 060 is. 077's
-- default privileges hand the application role DML on a new table: taken
-- back here, all of it on `agent_scopes` (not even SELECT), and all but
-- SELECT on `agent_scope_arming`.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_agent_scopes_audit() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_agent_scope_grant(uuid, uuid, text, text, timestamptz, timestamptz, uuid) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_agent_scope_revoke(uuid, text) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_scope_grant('
                'uuid, uuid, text, text, timestamptz, timestamptz, uuid) TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_scope_revoke(uuid, text) '
                'TO epigraph_maintenance';
        -- The definers run as this role, so it holds the DML they issue (no
        -- DELETE: nobody deletes a scope).
        EXECUTE 'GRANT SELECT, INSERT ON public.agent_scopes TO epigraph_maintenance';
        EXECUTE 'GRANT UPDATE (revoked_at, revoked_by, revoke_reason) ON public.agent_scopes '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT ON public.agent_scope_arming TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 356 agent scope '
                     'verbs are owned by the migrating role and only it may call them.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.agent_scopes FROM epigraph_app';
        EXECUTE 'REVOKE ALL ON public.agent_scope_arming FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.agent_scope_arming TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_agent_scope_grant('
                'uuid, uuid, text, text, timestamptz, timestamptz, uuid) FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_agent_scope_revoke(uuid, text) '
                'FROM epigraph_app';
    END IF;
END $$;
