-- 352: the system-agent registry definers resolve their names in pg_catalog
-- only (backlog 368ce622, the next family after 190's refresh-token family
-- and 224's OAuth family).
--
-- EVIDENCE (read on a database migrated to 351)
-- 148 created seven SECURITY DEFINER functions for the system-agent registry
-- on `SET search_path = public, pg_temp`, owner `epigraph_maintenance`: the
-- registration definer, the registry's three table triggers, and the three
-- reverse guards on `agents`, `human_operators` and `operator_links` (176
-- re-stated the `agents` guard with a refusal code, on the same path). On
-- that path an unqualified built-in call is resolved over pg_catalog AND
-- public, and a public function whose argument types match the call more
-- exactly than the built-in's polymorphic signature wins (224's header, the
-- resolution 172 fixed for `unnest`). `epigraph_system_agents_audit` writes
-- the `operator.system_agent_registered` row with
-- `jsonb_build_object('role', NEW.role, 'reason', NEW.reason, 'recorded_by',
-- session_user)`: a `public.jsonb_build_object(text, text, text, text, text,
-- name)` decides what that audit row records, and runs as the definer's
-- owner. Operators resolve the same way. The ratchet
-- (`definer_search_path_ratchet.rs`) registers all seven in
-- `PUBLIC_PATH_REGISTER`. No migration after 176 re-bodies any of them.
--
-- CHANGE
-- 1. A precondition refuses to run (55000, nothing changed) unless all seven
--    still carry 148's bodies (176's for the `agents` guard), by md5 of
--    `prosrc`. CREATE OR REPLACE replaces a body whole, so applying this over
--    another body would silently drop that body's change.
-- 2. The seven are re-stated on 172's form, `SET search_path = pg_catalog,
--    pg_temp`, with `current_setting(`, `pg_advisory_xact_lock(`,
--    `hashtext(`, `length(`, `now()`, `lower(`, `encode(`,
--    `jsonb_build_object(` and `format(` written `pg_catalog.`-qualified.
--    Each body is its 148 / 176 body with those qualifiers inserted and no
--    other byte changed: every table and function of `public` they name was
--    already `public.`-qualified, `trim(..)` and `session_user` are SQL
--    syntax the parser binds to pg_catalog itself, and
--    `epigraph_system_agents_immutable` calls no function, so its body is
--    148's byte for byte and only its path moves. Signature, return type,
--    language, volatility, behaviour, owner and ACL are unchanged
--    (`CREATE OR REPLACE` keeps owner and ACL, and this file grants and
--    revokes nothing). The triggers that call them are not touched.
--
-- NOT CHANGED HERE: the 180 other definers still in `PUBLIC_PATH_REGISTER`,
-- among them the writer-grant definers (`epigraph_require_writer_scope`,
-- `epigraph_operator_writes_group`), which a separate change re-states.
-- `crates/epigraph-cli/src/bin/tenancy_backfill.rs` keeps the seven
-- registered at 148, where they are created (as it keeps 224's at 118).
--
-- A LATER MIGRATION THAT RE-STATES ONE OF THE SEVEN must start from this body
-- and keep `SET search_path = pg_catalog, pg_temp`: the ratchet's
-- `the_system_agent_family_resolves_in_pg_catalog_only` reads the catalog at
-- head.
--
-- UNDO: `docs/runbooks/352-undo.sql` (148's and 176's bodies on
-- `public, pg_temp`; guarded by md5, idempotent).
SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- 1. Precondition: the seven functions still carry 148's / 176's bodies.
-- -------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_found text;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('public.epigraph_system_agents_guard_insert()', '404cbdd5fce8c1e235f56e7491f82237'),
        ('public.epigraph_system_agents_immutable()', '56bf5f8e2e80a0c35fc87e8f8c1cc638'),
        ('public.epigraph_system_agents_audit()', 'd1055a37066d851c280c388dffd234f6'),
        ('public.epigraph_agents_refuse_registered_system_key()', '76e5a35c08f8b87e5394fd03985dea8a'),
        ('public.epigraph_human_operators_refuse_system_agent()', 'd84f7ba4ebf76cee2c0c3683551814e5'),
        ('public.epigraph_operator_links_refuse_retired_system_agent()', 'b8224702c39b5cd7c4b2307788db7e86'),
        ('public.epigraph_register_system_agent(text, uuid, text)', '2ca6b7a3812e7f07242919ee78253dcf')) AS t(sig, md5)
    LOOP
        SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
         WHERE p.oid = pg_catalog.to_regprocedure(r.sig);
        IF v_found IS DISTINCT FROM r.md5 THEN
            RAISE EXCEPTION '352: % is not the body 352 re-states (md5 %); found md5 %. '
                            'Another migration re-bodied it, or its migration is not '
                            'applied; nothing was changed',
                            r.sig, r.md5, COALESCE(v_found, '(absent)')
                USING ERRCODE = '55000',
                      HINT = 'Apply a reconciling migration that re-states the body with '
                             'every delta instead of this one.';
        END IF;
    END LOOP;
END $$;

-- -------------------------------------------------------------------
-- 2. The seven bodies on 172's form. Delta from 148 / 176: the path, and
-- the `pg_catalog.` qualifiers; nothing else.
-- -------------------------------------------------------------------

-- 148's body of `epigraph_system_agents_guard_insert`.
CREATE OR REPLACE FUNCTION public.epigraph_system_agents_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
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
    IF pg_catalog.current_setting('transaction_isolation') = 'repeatable read' THEN
        RAISE EXCEPTION 'system_agents: a registration is not written under REPEATABLE READ: its '
                        'snapshot predates the wait for a concurrent link or human registration '
                        'of the agent, so neither would see the other'
            USING ERRCODE = '55000',
                  HINT = 'Run it under READ COMMITTED (the default) or SERIALIZABLE.';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('epigraph.operator_links'));
    IF NEW.reason IS NULL OR pg_catalog.length(trim(NEW.reason)) = 0 THEN
        RAISE EXCEPTION 'system_agents: a reason is required' USING ERRCODE = '22004';
    END IF;
    IF NEW.created_at IS DISTINCT FROM pg_catalog.now() OR NEW.created_by IS DISTINCT FROM session_user THEN
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
                  AND pg_catalog.lower(c.client_id) = pg_catalog.encode(v_key, 'hex')) THEN
        RAISE EXCEPTION 'system_agents: % holds the key of an agent OAuth client that is not '
                        'revoked; that client would adopt it as its principal', NEW.agent_id
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;

-- 148's body of `epigraph_system_agents_immutable`, byte for byte (it calls no
-- function); only the path moves.
CREATE OR REPLACE FUNCTION public.epigraph_system_agents_immutable()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
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

-- 148's body of `epigraph_system_agents_audit`.
CREATE OR REPLACE FUNCTION public.epigraph_system_agents_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('operator.system_agent_registered', NEW.agent_id, true,
            pg_catalog.jsonb_build_object('role', NEW.role, 'reason', NEW.reason,
                               'recorded_by', session_user));
    RETURN NULL;
END $$;

-- 176's body of `epigraph_agents_refuse_registered_system_key`.
CREATE OR REPLACE FUNCTION public.epigraph_agents_refuse_registered_system_key()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_role text;
BEGIN
    SELECT s.role INTO v_role FROM public.system_agents s
     WHERE s.registered_public_key = NEW.public_key AND s.agent_id <> NEW.id;
    IF FOUND THEN
        RAISE EXCEPTION 'AGK01: agents: this public key was registered for a system agent '
                        '(migration 148); no other agent may hold it. Nothing was written'
            USING ERRCODE = '55000',
                  DETAIL = pg_catalog.format('system agent role: %s', v_role);
    END IF;
    RETURN NEW;
END $$;

-- 148's body of `epigraph_human_operators_refuse_system_agent`.
CREATE OR REPLACE FUNCTION public.epigraph_human_operators_refuse_system_agent()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- Section 2: wait for a concurrent registration of the agent, then read.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('epigraph.operator_links'));
    IF EXISTS (SELECT 1 FROM public.system_agents s WHERE s.agent_id = NEW.agent_id) THEN
        RAISE EXCEPTION 'human_operators: % is a registered system agent (migration 148); a '
                        'system agent is never a human operator', NEW.agent_id
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;

-- 148's body of `epigraph_operator_links_refuse_retired_system_agent`.
CREATE OR REPLACE FUNCTION public.epigraph_operator_links_refuse_retired_system_agent()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_role text;
BEGIN
    IF NOT NEW.retired THEN
        RETURN NEW;
    END IF;
    -- Every link definer already holds this lock; a direct statement takes it
    -- here. Either way a concurrent registration of the agent is waited for.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('epigraph.operator_links'));
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

-- 148's body of `epigraph_register_system_agent`.
CREATE OR REPLACE FUNCTION public.epigraph_register_system_agent(
    p_role text, p_agent uuid, p_reason text)
RETURNS TABLE (registered_now boolean, registered_agent uuid,
               registered_at timestamptz, registered_by text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
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
    IF p_role IS NULL OR p_agent IS NULL OR p_reason IS NULL OR pg_catalog.length(trim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_register_system_agent: the role, the agent and a reason are '
                        'required' USING ERRCODE = '22004';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('epigraph.system_agents'));
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
