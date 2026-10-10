-- Migration 148: the system-agent registry. Which agent IS "the workflow-ingest
-- system agent" is recorded, not derived from a public constant.
--
-- ===================================================================
-- 1. WHY
--
-- Workflow ingest (MCP store_workflow / ingest_workflow /
-- improve_workflow_hierarchy / add_step / delete_step, REST
-- /api/v1/workflows/*) and REST policy challenges author every row as ONE
-- shared system agent. Until this file, both resolvers
-- (`epigraph_ingest_executor::system_agent::get_or_create_system_agent` and
-- `epigraph_api::routes::workflows::get_or_create_system_agent`) found that
-- agent by the Ed25519 key derived from the PUBLIC constant name
-- "workflow-ingest-system" (`did_key_for_author(None, "workflow-ingest-system")`,
-- whose secret is BLAKE3 of a public string), and created one on a miss.
--
-- So the identity could not be rotated to a secret key: after
-- `UPDATE agents SET public_key = <fresh>` the next ingest misses the lookup and
-- creates a SECOND agent holding the public-constant key (the UNIQUE key
-- constraint no longer blocks it), provisions it a personal group, and carries
-- on under an unlinked identity. The rotation is defeated and attribution
-- splits.
--
-- This file records the mapping role -> agent in a maintenance-only, audited,
-- immutable registry. The resolvers read it first; when a row exists they
-- never look the key up and never create. When no row exists they keep the
-- old behaviour on an UNARMED database (a fresh install, every test database)
-- and REFUSE on an ARMED one (122 section 3), before writing anything. Once
-- armed, the system agent is exactly the registry's.
--
-- The registry also records the key the agent held when it was registered,
-- and `agents` refuses that key to every OTHER agent, on every path and every
-- role. A binary built before this file, or any client that can create an
-- agent, therefore cannot re-create the public-constant identity after a
-- rotation: it is refused, not split.
--
-- ===================================================================
-- 2. THE RULES (on the tables, so a direct statement meets them too)
--
--   * One row per role, one role per agent. `role` is a closed vocabulary.
--   * Only a privileged session registers: a member of epigraph_maintenance,
--     or a superuser (the explicit superuser arm keeps a database without
--     the maintenance role registrable). The definer AND the table's guard
--     both check it.
--   * Immutable: no grant admits UPDATE, DELETE or TRUNCATE to any role, and
--     triggers refuse all three even on a privileged session. Re-pointing a
--     role is a superuser act (section 4); rotation keeps the agent's id and
--     needs none.
--   * Refused as a system agent: a registered human operator (122 (a)), a
--     platform role node (123), the principal of any OAuth client that is not
--     revoked, the key of any agent-type OAuth client that is not revoked
--     (such a client adopts the agent holding its key on first mint), an
--     agent that operates other agents, an agent holding a retired operator
--     link (it can never be bound), a missing agent, a blank reason.
--   * `registered_public_key` is the agent's key at registration, recorded
--     by the guard and never supplied. No other agent may hold it, by INSERT
--     or by key UPDATE (`agents_refuse_registered_system_key`). The
--     registered agent itself may rotate. Register BEFORE rotating, in its
--     own committed transaction: the recorded key is the one protected.
--   * A registered system agent can never later be registered as a human
--     operator (`human_operators_refuse_system_agent`), nor given a RETIRED
--     operator link (`operator_links_refuse_retired_system_agent`): a retired
--     link is permanent and never promoted, so it would leave the agent
--     unbindable behind an immutable registration (every workflow write
--     refused once armed). Every retired-link definer (the bulk legacy-author
--     tie, the single retire, the attested shared-signer retire) meets it; the
--     bulk tie refuses as a whole, so `epigraph-operator link-legacy-authors`
--     excludes every registered system agent itself. A LIVE link is allowed:
--     it is how the registered agent is bound.
--   * The guard and both reverse guards take 107 section 10's advisory lock
--     (`epigraph.operator_links`, which every link definer already takes)
--     before they read, so a registration and a concurrent link or human
--     registration of the same agent see each other instead of both
--     committing. A registration is refused under REPEATABLE READ (its
--     snapshot would predate that wait; 123's CUS06 reasoning). A human
--     registration run under REPEATABLE READ concurrently with a registration
--     of the same agent is the one ordering the lock cannot serialize; 122's
--     human registration is not changed to refuse it.
--   * One `security_events` row (`operator.system_agent_registered`) per row,
--     whatever path inserted it. The `operator.system_agent` event type is
--     reserved to privileged sessions and maintenance-owned definers
--     (`security_events_system_agent_privileged`, the 123 shape).
--   * Registration does NOT bind. Once armed, the registered agent still needs
--     a live operator link to author anything (122); its callers are bound by
--     `require_caller_write_authority` as before.
--
-- ===================================================================
-- 3. DISCLOSURE, ACCEPTED
--
-- `epigraph_app` may SELECT the registry, including `registered_public_key`:
-- which agent is a system agent is not secret (agent ids are not secrets;
-- 122 section 5), a public key is public by definition, and the request path
-- reads the registry on the system-agent-stamped connection.
--
-- ===================================================================
-- 4. UNDO, RESTORE, AND DATABASES WITHOUT THE MAINTENANCE ROLE
--
-- Roll back every binary built against this file FIRST: they read
-- `system_agents` and fail closed without it. That refuses (500 /
-- internal error) workflow ingest (MCP and REST), REST policy challenges, MCP
-- `ingest_document` and `ingest_document_spine` with any author, and
-- `POST /api/v1/claims/:id/provenance` with any author; the operator CLI's
-- arm census and `link-legacy-authors` tolerate the missing table. Then, as a
-- superuser:
--   DROP TRIGGER IF EXISTS agents_refuse_registered_system_key ON public.agents;
--   DROP TRIGGER IF EXISTS human_operators_refuse_system_agent ON public.human_operators;
--   DROP TRIGGER IF EXISTS operator_links_refuse_retired_system_agent ON public.operator_links;
--   DROP POLICY IF EXISTS security_events_system_agent_privileged ON public.security_events;
--   DROP TABLE IF EXISTS public.system_agents;  -- drops its own triggers
--   DROP FUNCTION IF EXISTS public.epigraph_register_system_agent(text, uuid, text);
--   DROP FUNCTION IF EXISTS public.epigraph_system_agents_guard_insert();
--   DROP FUNCTION IF EXISTS public.epigraph_system_agents_immutable();
--   DROP FUNCTION IF EXISTS public.epigraph_system_agents_audit();
--   DROP FUNCTION IF EXISTS public.epigraph_agents_refuse_registered_system_key();
--   DROP FUNCTION IF EXISTS public.epigraph_human_operators_refuse_system_agent();
--   DROP FUNCTION IF EXISTS public.epigraph_operator_links_refuse_retired_system_agent();
-- `security_events` rows it wrote stay (082: immutable).
-- DANGER: after a key rotation of a registered agent, an older binary resolves
-- by the public-constant key again and, once the `agents` guard above is
-- dropped, re-creates the second agent (section 1). Do not roll binaries back
-- past this file once a registered agent's key has been rotated.
--
-- A LOGICAL restore (pg_restore / psql of a dump) must load `system_agents`
-- with triggers disabled (`--disable-triggers`, superuser): the guard refuses
-- a historical `created_at`/`created_by`, and the audit trigger would write a
-- second registration event. The original event travels with
-- `security_events`. Physical backups are unaffected.
--
-- Where `epigraph_maintenance` does not exist, a superuser registers (the
-- definer, or a direct INSERT); every guard and the audit still apply.
-- **Applied to a throwaway database only, NOT to any deployed database.**

SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS public.system_agents (
    role       text PRIMARY KEY
                   CONSTRAINT system_agents_role_known CHECK (role IN ('workflow-ingest')),
    agent_id   uuid NOT NULL
                   CONSTRAINT system_agents_agent_unique UNIQUE
                   REFERENCES public.agents(id) ON DELETE RESTRICT,
    -- Filled by the guard trigger (BEFORE INSERT runs before NOT NULL is checked).
    registered_public_key bytea NOT NULL
                   CONSTRAINT system_agents_registered_key_unique UNIQUE,
    reason     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by text NOT NULL DEFAULT session_user
);
REVOKE ALL ON public.system_agents FROM PUBLIC;

-- BEFORE INSERT: the section-2 refusals, on every path (the definer below and
-- a direct INSERT alike). A definer: `operator_links` is FORCEd and admits
-- only a definer frame (107/122). Each message starts `system_agents:`; the
-- definer's own refusals start `epigraph_register_system_agent:`, so a test
-- can tell which layer answered.
CREATE OR REPLACE FUNCTION public.epigraph_system_agents_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_key bytea;
BEGIN
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'system_agents: only a maintenance session registers a system agent'
            USING ERRCODE = '42501';
    END IF;
    -- Section 2: serialize with every link definer and both reverse guards
    -- BEFORE reading `human_operators` / `operator_links`. Under READ
    -- COMMITTED the reads after the wait see the other side's commit;
    -- REPEATABLE READ's snapshot predates the wait, so it is refused.
    IF current_setting('transaction_isolation') = 'repeatable read' THEN
        RAISE EXCEPTION 'system_agents: a registration is not written under REPEATABLE READ: its '
                        'snapshot predates the wait for a concurrent link or human registration '
                        'of the agent, so neither would see the other'
            USING ERRCODE = '55000',
                  HINT = 'Run it under READ COMMITTED (the default) or SERIALIZABLE.';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    IF NEW.reason IS NULL OR length(trim(NEW.reason)) = 0 THEN
        RAISE EXCEPTION 'system_agents: a reason is required' USING ERRCODE = '22004';
    END IF;
    IF NEW.created_at IS DISTINCT FROM now() OR NEW.created_by IS DISTINCT FROM session_user THEN
        RAISE EXCEPTION 'system_agents: created_at and created_by are recorded, not supplied'
            USING ERRCODE = '55000';
    END IF;
    SELECT a.public_key INTO v_key FROM public.agents a WHERE a.id = NEW.agent_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'system_agents: agent % does not exist', NEW.agent_id
            USING ERRCODE = '22023';
    END IF;
    IF NEW.registered_public_key IS NOT NULL AND NEW.registered_public_key IS DISTINCT FROM v_key THEN
        RAISE EXCEPTION 'system_agents: registered_public_key is recorded, not supplied'
            USING ERRCODE = '55000';
    END IF;
    NEW.registered_public_key := v_key;
    -- 123's role-node rule, inlined (not 123's trigger function: a trigger on
    -- it would block 123's documented undo from dropping that function).
    IF EXISTS (SELECT 1 FROM public.platform_roles r WHERE r.role_node_id = NEW.agent_id) THEN
        RAISE EXCEPTION 'system_agents: % is the graph node of a platform role; it is never a '
                        'system agent', NEW.agent_id USING ERRCODE = '55000';
    END IF;
    IF public.epigraph_is_human_operator(NEW.agent_id) THEN
        RAISE EXCEPTION 'system_agents: % is a registered human operator; a human is never a '
                        'system agent', NEW.agent_id USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.operator_id = NEW.agent_id) THEN
        RAISE EXCEPTION 'system_agents: % operates other agents; an operator is never a system '
                        'agent', NEW.agent_id USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l
                WHERE l.agent_id = NEW.agent_id AND l.retired) THEN
        RAISE EXCEPTION 'system_agents: % holds a retired operator link; a retired link is '
                        'permanent, so this agent can never be bound', NEW.agent_id
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.oauth_clients c
                WHERE c.agent_id = NEW.agent_id AND c.status <> 'revoked') THEN
        RAISE EXCEPTION 'system_agents: % is the principal of an OAuth client that is not '
                        'revoked; a system agent never mints a token', NEW.agent_id
            USING ERRCODE = '55000',
                  HINT = 'Revoke that client on a maintenance or admin DSN, recorded, then '
                         'register the agent.';
    END IF;
    -- An agent client's client_id IS its hex Ed25519 key, and its first mint
    -- adopts the agent holding that key even while `agent_id` is still NULL.
    -- No decode(): lower()/encode() cannot raise on a non-hex client_id, which
    -- simply never matches.
    IF EXISTS (SELECT 1 FROM public.oauth_clients c
                WHERE c.client_type = 'agent' AND c.status <> 'revoked'
                  AND lower(c.client_id) = encode(v_key, 'hex')) THEN
        RAISE EXCEPTION 'system_agents: % holds the key of an agent OAuth client that is not '
                        'revoked; that client would adopt it as its principal', NEW.agent_id
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_system_agents_guard_insert() FROM PUBLIC;

-- BEFORE UPDATE OR DELETE (row) and BEFORE TRUNCATE (statement): never
-- (section 2). Fires on a privileged session too; only a superuser that
-- disables the trigger, or drops the table, can change the mapping. OLD is
-- read only on the row path.
CREATE OR REPLACE FUNCTION public.epigraph_system_agents_immutable()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_LEVEL = 'STATEMENT' THEN
        RAISE EXCEPTION 'system_agents: the registry cannot be truncated; nothing was changed'
            USING ERRCODE = '55000',
                  HINT = 'A registration is immutable; see migration 148 section 4.';
    END IF;
    RAISE EXCEPTION 'system_agents: the registration of role % is immutable; nothing was '
                    'changed', OLD.role
        USING ERRCODE = '55000',
              HINT = 'A key rotation keeps the agent id and needs no change here. '
                     'Re-pointing a role is a superuser act; see migration 148 section 4.';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_system_agents_immutable() FROM PUBLIC;

-- AFTER INSERT: one audit row per registration, whatever path wrote it.
CREATE OR REPLACE FUNCTION public.epigraph_system_agents_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('operator.system_agent_registered', NEW.agent_id, true,
            jsonb_build_object('role', NEW.role, 'reason', NEW.reason,
                               'recorded_by', session_user));
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_system_agents_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS system_agents_guard_insert ON public.system_agents;
CREATE TRIGGER system_agents_guard_insert
    BEFORE INSERT ON public.system_agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_system_agents_guard_insert();
DROP TRIGGER IF EXISTS system_agents_immutable ON public.system_agents;
CREATE TRIGGER system_agents_immutable
    BEFORE UPDATE OR DELETE ON public.system_agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_system_agents_immutable();
DROP TRIGGER IF EXISTS system_agents_no_truncate ON public.system_agents;
CREATE TRIGGER system_agents_no_truncate
    BEFORE TRUNCATE ON public.system_agents
    FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_system_agents_immutable();
DROP TRIGGER IF EXISTS system_agents_audit ON public.system_agents;
CREATE TRIGGER system_agents_audit
    AFTER INSERT ON public.system_agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_system_agents_audit();

-- `agents`: a key recorded for a system agent belongs to that agent alone.
-- Fires for every role (row triggers are not bypassed by BYPASSRLS or by a
-- superuser), so it holds against binaries built before this file, against
-- author-name mints, and against any client that creates agents. The
-- registered agent itself may change its key (NEW.id = agent_id).
CREATE OR REPLACE FUNCTION public.epigraph_agents_refuse_registered_system_key()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_role text;
BEGIN
    SELECT s.role INTO v_role FROM public.system_agents s
     WHERE s.registered_public_key = NEW.public_key AND s.agent_id <> NEW.id;
    IF FOUND THEN
        RAISE EXCEPTION 'agents: this public key was registered for the % system agent '
                        '(migration 148); no other agent may hold it. Nothing was written', v_role
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agents_refuse_registered_system_key() FROM PUBLIC;
DROP TRIGGER IF EXISTS agents_refuse_registered_system_key ON public.agents;
CREATE TRIGGER agents_refuse_registered_system_key
    BEFORE INSERT OR UPDATE OF public_key ON public.agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_agents_refuse_registered_system_key();

-- `human_operators`: a registered system agent is never a human. A new
-- function; 122's human_operators functions are unchanged.
CREATE OR REPLACE FUNCTION public.epigraph_human_operators_refuse_system_agent()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    -- Section 2: wait for a concurrent registration of the agent, then read.
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    IF EXISTS (SELECT 1 FROM public.system_agents s WHERE s.agent_id = NEW.agent_id) THEN
        RAISE EXCEPTION 'human_operators: % is a registered system agent (migration 148); a '
                        'system agent is never a human operator', NEW.agent_id
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_human_operators_refuse_system_agent() FROM PUBLIC;
DROP TRIGGER IF EXISTS human_operators_refuse_system_agent ON public.human_operators;
CREATE TRIGGER human_operators_refuse_system_agent
    BEFORE INSERT OR UPDATE OF agent_id ON public.human_operators
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_human_operators_refuse_system_agent();

-- `operator_links`: a registered system agent is never RETIRE-linked (section
-- 2). The guard above refuses to register a retired-linked agent; this is the
-- other order, on the table, so every retired-link definer (107, 116, 122,
-- 123) meets it without being redefined. A new function; theirs are
-- unchanged. Fires on UPDATE too, although `operator_links` admits none
-- (107: no grant, no policy), so a superuser's direct statement meets it.
CREATE OR REPLACE FUNCTION public.epigraph_operator_links_refuse_retired_system_agent()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_role text;
BEGIN
    IF NOT NEW.retired THEN
        RETURN NEW;
    END IF;
    -- Every link definer already holds this lock; a direct statement takes it
    -- here. Either way a concurrent registration of the agent is waited for.
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    SELECT s.role INTO v_role FROM public.system_agents s WHERE s.agent_id = NEW.agent_id;
    IF FOUND THEN
        RAISE EXCEPTION 'operator_links: % is a registered system agent (role %, migration 148); '
                        'a retired link is permanent and would leave it unbindable. Nothing was '
                        'written', NEW.agent_id, v_role
            USING ERRCODE = '55000',
                  HINT = 'Bind it with a LIVE link (epigraph-operator link), or exclude it from '
                         'the legacy-author tie.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_links_refuse_retired_system_agent() FROM PUBLIC;
DROP TRIGGER IF EXISTS operator_links_refuse_retired_system_agent ON public.operator_links;
CREATE TRIGGER operator_links_refuse_retired_system_agent
    BEFORE INSERT OR UPDATE OF retired, agent_id ON public.operator_links
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_operator_links_refuse_retired_system_agent();

-- Reserve the registration event type (123's RESTRICTIVE shape, scoped to the
-- one new type, so 122's operator.human_* types are untouched). The row-only
-- arm says WHICH rows the restriction applies to and grants nothing.
-- length('operator.system_agent') = 21.
DROP POLICY IF EXISTS security_events_system_agent_privileged ON public.security_events;
CREATE POLICY security_events_system_agent_privileged ON public.security_events
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        lower(left(btrim(event_type), 21)) <> 'operator.system_agent'
        OR (((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
            AND created_at = now()));

-- Register `p_agent` as the system agent for `p_role`. Maintenance only (the
-- grant set below AND the body's own check); audited by the table's trigger;
-- idempotent for the same (role, agent); refuses a different agent for a
-- registered role (immutable).
CREATE OR REPLACE FUNCTION public.epigraph_register_system_agent(
    p_role text, p_agent uuid, p_reason text)
RETURNS TABLE (registered_now boolean, registered_agent uuid,
               registered_at timestamptz, registered_by text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_existing uuid;
    v_rows     integer := 0;
BEGIN
    -- Defence in depth: the grant set is the boundary; this keeps it one if a
    -- later migration grants EXECUTE too widely. `epigraph_bypass()` keys on
    -- session_user, so the definer frame cannot change the answer; the
    -- superuser arm covers a database without the maintenance role.
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'epigraph_register_system_agent: only a maintenance session registers a '
                        'system agent' USING ERRCODE = '42501';
    END IF;
    IF p_role IS NULL OR p_agent IS NULL OR p_reason IS NULL OR length(trim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_register_system_agent: the role, the agent and a reason are '
                        'required' USING ERRCODE = '22004';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.system_agents'));
    IF NOT EXISTS (SELECT 1 FROM public.agents a WHERE a.id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_register_system_agent: agent % does not exist', p_agent
            USING ERRCODE = '22023';
    END IF;
    SELECT s.agent_id INTO v_existing FROM public.system_agents s WHERE s.role = p_role;
    IF v_existing IS NOT NULL AND v_existing <> p_agent THEN
        RAISE EXCEPTION 'epigraph_register_system_agent: role % is registered to agent %, and a '
                        'registration is immutable; nothing was changed', p_role, v_existing
            USING ERRCODE = '55000';
    END IF;
    IF v_existing IS NULL THEN
        INSERT INTO public.system_agents (role, agent_id, reason)
        VALUES (p_role, p_agent, p_reason);
        v_rows := 1;
    END IF;
    RETURN QUERY SELECT v_rows > 0, s.agent_id, s.created_at, s.created_by
                   FROM public.system_agents s WHERE s.role = p_role;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_register_system_agent(text, uuid, text) FROM PUBLIC;

-- Ownership and grants, guarded as every such block since 060 is.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_system_agents_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_system_agents_immutable() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_system_agents_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_agents_refuse_registered_system_key() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_human_operators_refuse_system_agent() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_operator_links_refuse_retired_system_agent() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_register_system_agent(text, uuid, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_register_system_agent(text, uuid, text) '
                'TO epigraph_maintenance';
        -- The definer runs as this role, so it holds the DML it issues; the
        -- table's triggers hold a direct INSERT to the same rules and audit.
        -- No UPDATE, no DELETE, no TRUNCATE: the registry is insert-only.
        EXECUTE 'GRANT SELECT, INSERT ON public.system_agents TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        -- 077's ALTER DEFAULT PRIVILEGES handed the app role DML on the new
        -- table; take it back and leave SELECT (every relation app-readable).
        EXECUTE 'REVOKE ALL ON public.system_agents FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.system_agents TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_register_system_agent(text, uuid, text) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_system_agents_guard_insert() '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_system_agents_immutable() '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_system_agents_audit() '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_agents_refuse_registered_system_key() '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_human_operators_refuse_system_agent() '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_operator_links_refuse_retired_system_agent() '
                'FROM epigraph_app';
    END IF;
END $$;
