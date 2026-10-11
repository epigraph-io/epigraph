-- Migration 149: the author-binding allowlist. An OAuth client that the
-- operator NAMES may write as a bound agent of one registered human, without
-- becoming an operated (stdio-only) agent.
--
-- ===================================================================
-- 1. WHY
--
-- Migration 122 binds a writing agent to a human in two ways: (a) it IS a
-- registered human operator, or (b) it holds a LIVE operator link to one.
-- Neither fits a service or agent OAuth client that writes over HTTP on a
-- human's behalf. Such a client cannot be a human (122 section 1c). It cannot
-- be linked either, because a link makes its agent stdio-only: 107's token
-- refusal (`refuse_operated_agent`), the bearer and the MCP viewer all refuse
-- an agent with ANY link record. And an owner rule ("the client's owner_id is
-- a registered human's client") would bind every client such a human owns,
-- with no per-client decision. So once armed, such a client's writes are
-- refused OPL01.
--
-- This file adds a third arm, decided one client's AGENT at a time:
--
--   (c) the agent of a client on the maintenance-only registry
--       `author_binding_clients`, bound to the registered human operator
--       that the row names, while ALL of these hold at read time:
--         * the row is not revoked;
--         * the client is `active` and `client_type` is 'service' or 'agent'
--           (never 'human': a human is registered, not allowlisted);
--         * the client's agent is still the agent the row pinned, and no
--           OTHER non-revoked client has that agent (so the decision is,
--           in effect, about this one client's agent);
--         * the agent is not a human operator, holds no `operator_links`
--           row of any state (a link always wins), operates no agent
--           (107's single hop), and is not a registered system agent;
--         * the operator is a registered human operator
--           (`epigraph_is_human_operator`) that is not itself linked.
--       Anything else: unbound, exactly as before this file.
--
--   The binding is keyed on the AGENT (the session stamp), so any process
--   holding that agent's private key writes as the bound agent too. The MCP
--   HTTP listener refuses an allowlisted signer.
--
-- Only `epigraph_author_binding` (a third label, 'client_allowlist') and
-- `epigraph_human_of` (the operator, for both `p_live_only` values) read the
-- registry. Every 122/123 check reaches arm (c) through those two, so a bound
-- allowlisted writer is scoped like a live-linked agent: it writes only into
-- groups its operator writes (OPL02), and names only authors of its own
-- operator (OPL02). Nothing on the token, bearer, viewer or webhook path reads
-- the registry: an allowlisted client's agent keeps minting tokens, and an
-- operated agent is still refused, allowlisted or not.
--
-- NOT CHANGED, deliberately: the membership door
-- (`epigraph_require_operator_scope`, 123) reads links only, so an
-- allowlisted agent's non-claim writes (evidence, edges, beliefs) into a
-- group its operator does not write are not refused here, while its claims
-- there are (OPL02). The operator CLI lists such write memberships when it
-- allows a client and offers to revoke them; `docs/tenancy.md` names the gap.
--
-- ===================================================================
-- 2. WHO WRITES IT
--
-- Only a privileged session, through two audited definers
-- (`epigraph_allow_author_binding_client`, `epigraph_revoke_author_binding_client`)
-- that only the maintenance role may EXECUTE. The rules live on the TABLE:
-- guard triggers refuse a non-privileged session, an unmet precondition, any
-- change but the one revoke, any change to a revoked row, and any DELETE (on
-- every session: revoke is final, and a row is never removed and re-added).
-- An AFTER trigger writes one `platform.` audit row per allowance and per
-- revoke. So a maintenance login's direct INSERT or UPDATE meets the same
-- checks and leaves the same audit. The application role may only SELECT.
-- No row is seeded: allowances are added on a maintenance DSN after deploy
-- (`epigraph-operator allow-author-binding-client`).
--
-- A new operator link of an allowlisted agent is refused while its client is
-- not revoked: a link makes the agent stdio-only (107). The predicate is the
-- legacy tie's own `skipped:oauth_principal` predicate, so the tie never meets
-- this refusal.
--
-- The system-agent table (`system_agents`, a separate migration) is read
-- SOFTLY, under `to_regclass(...) IS NOT NULL` inside plpgsql: this file
-- applies, and reads correctly, with or without it, in either undo order.
--
-- Applying this file changes no behaviour while the registry is empty.
--
-- ===================================================================
-- 3. UNDO
--
-- `docs/runbooks/149-undo.sql`: restore 122's bodies of
-- `epigraph_author_binding` and `epigraph_human_of` FIRST, then drop the link
-- guard, the definers, the table (which drops its triggers), the trigger
-- functions and the helper. It writes one
-- `platform.author_binding_allowlist_dropped` row first, naming how many live
-- allowances it ends. Roll back first any binary that calls the definers or
-- compares the new label.

SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS public.author_binding_clients (
    client_id      uuid PRIMARY KEY REFERENCES public.oauth_clients(id) ON DELETE RESTRICT,
    agent_id       uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    operator_id    uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    reason         text NOT NULL,
    added_at       timestamptz NOT NULL DEFAULT now(),
    added_by       text NOT NULL DEFAULT session_user,
    revoked_at     timestamptz,
    revoked_by     text,
    revoked_reason text,
    CONSTRAINT author_binding_clients_not_self CHECK (agent_id <> operator_id),
    CONSTRAINT author_binding_clients_revoke_whole CHECK (
        (revoked_at IS NULL) = (revoked_by IS NULL)
        AND (revoked_at IS NULL) = (revoked_reason IS NULL))
);
-- One live allowance per agent, so `epigraph_human_of` never sees two operators.
CREATE UNIQUE INDEX IF NOT EXISTS author_binding_clients_one_live_per_agent
    ON public.author_binding_clients (agent_id) WHERE revoked_at IS NULL;
REVOKE ALL ON public.author_binding_clients FROM PUBLIC;

-- Arm (c), at read time. Created BEFORE the two re-bodies below. Not
-- app-callable: only the maintenance-owned definers below call it.
-- plpgsql (not sql) so the system-agent conjunct can be skipped on a database
-- without the system-agent table: a plpgsql statement is planned when it
-- first runs, so the guarded SELECT never meets a missing table.
-- No `p_agent IS NOT NULL` and no `operator_id <> p_agent` conjunct: a NULL
-- argument matches no row, and the table's CHECK makes the second one true.
-- `NOT epigraph_is_human_operator(p_agent)` is implied by the other-client
-- conjunct (a human operator holds an active human client of its own); it is
-- kept as a stated precondition.
CREATE OR REPLACE FUNCTION public.epigraph_allowlisted_operator(p_agent uuid)
RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_operator uuid;
BEGIN
    -- At most one row: the partial unique index allows one live row per agent.
    SELECT r.operator_id INTO v_operator
      FROM public.author_binding_clients r
      JOIN public.oauth_clients c ON c.id = r.client_id
     WHERE r.agent_id = p_agent
       AND r.revoked_at IS NULL
       AND c.agent_id = p_agent
       AND c.status = 'active'
       AND c.client_type IN ('service', 'agent')
       AND NOT public.epigraph_is_human_operator(p_agent)
       AND NOT EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = p_agent)
       AND NOT EXISTS (SELECT 1 FROM public.operator_links l WHERE l.operator_id = p_agent)
       AND NOT EXISTS (SELECT 1 FROM public.oauth_clients c2
                        WHERE c2.agent_id = p_agent AND c2.id <> r.client_id
                          AND c2.status <> 'revoked')
       AND NOT EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = r.operator_id)
       AND public.epigraph_is_human_operator(r.operator_id);
    IF v_operator IS NULL THEN
        RETURN NULL;
    END IF;
    IF to_regclass('public.system_agents') IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM public.system_agents s WHERE s.agent_id = p_agent) THEN
            RETURN NULL;
        END IF;
    END IF;
    RETURN v_operator;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_allowlisted_operator(uuid) FROM PUBLIC;

-- 122's body plus ONE arm, evaluated LAST. 'client_allowlist' is new; the two
-- existing labels and their order are unchanged.
CREATE OR REPLACE FUNCTION public.epigraph_author_binding(p_agent uuid)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT CASE
             WHEN p_agent IS NULL THEN NULL
             WHEN public.epigraph_is_human_operator(p_agent) THEN 'human_operator'
             WHEN EXISTS (SELECT 1 FROM public.operator_links l
                           WHERE l.agent_id = p_agent AND NOT l.retired
                             AND public.epigraph_is_human_operator(l.operator_id))
                  THEN 'live_link'
             WHEN public.epigraph_allowlisted_operator(p_agent) IS NOT NULL
                  THEN 'client_allowlist'
           END
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_author_binding(uuid) FROM PUBLIC;

-- 122's body, with the link arm made explicit (a link row of ANY state
-- decides, so a RETIRED-linked agent asked with p_live_only reads NULL and
-- never falls through to the allowlist) and arm (c) as the ELSE. Arm (c) has
-- no retired state: a revoked allowance reads NULL for both p_live_only values.
CREATE OR REPLACE FUNCTION public.epigraph_human_of(p_agent uuid, p_live_only boolean)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT CASE
             WHEN p_agent IS NULL THEN NULL
             WHEN public.epigraph_is_human_operator(p_agent) THEN p_agent
             WHEN EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = p_agent)
                  THEN (SELECT l.operator_id FROM public.operator_links l
                         WHERE l.agent_id = p_agent AND (NOT p_live_only OR NOT l.retired))
             ELSE public.epigraph_allowlisted_operator(p_agent)
           END
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_human_of(uuid, boolean) FROM PUBLIC;

-- BEFORE INSERT: a privileged session; a live row; a reason; provenance
-- stamped here, never supplied; an ACTIVE service/agent client that already
-- has its agent (pinned here) and is that agent's only non-revoked client; an
-- agent that is not a human, not linked, operates no agent, is not a system
-- agent and is not the operator; a registered human operator that is not
-- itself linked; and no other live allowance for the agent. Serialised with
-- every link write by 107 section 10's advisory lock.
CREATE OR REPLACE FUNCTION public.epigraph_author_binding_clients_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_agent  uuid;
    v_type   text;
    v_status text;
BEGIN
    IF NOT public.epigraph_bypass() THEN
        RAISE EXCEPTION 'author_binding_clients: only a maintenance session allows a client '
                        '(a member of epigraph_maintenance; on a cluster without that role no '
                        'session qualifies, a superuser included)'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    IF NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL
       OR NEW.revoked_reason IS NOT NULL THEN
        RAISE EXCEPTION 'author_binding_clients: an allowance is recorded live; revoke it with '
                        'epigraph_revoke_author_binding_client' USING ERRCODE = '55000';
    END IF;
    IF NEW.reason IS NULL OR length(trim(NEW.reason)) = 0 THEN
        RAISE EXCEPTION 'author_binding_clients: a reason is required' USING ERRCODE = '22004';
    END IF;
    NEW.added_at := now();
    NEW.added_by := session_user;
    SELECT c.agent_id, c.client_type::text, c.status::text
      INTO v_agent, v_type, v_status
      FROM public.oauth_clients c WHERE c.id = NEW.client_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'author_binding_clients: no OAuth client has id %', NEW.client_id
            USING ERRCODE = '55000';
    END IF;
    IF v_type NOT IN ('service', 'agent') THEN
        RAISE EXCEPTION 'author_binding_clients: OAuth client % is a % client; only a service or '
                        'agent client is allowlisted (a human is registered as a human operator)',
                        NEW.client_id, v_type USING ERRCODE = '55000';
    END IF;
    IF v_status <> 'active' THEN
        RAISE EXCEPTION 'author_binding_clients: OAuth client % is %, not active',
                        NEW.client_id, v_status USING ERRCODE = '55000';
    END IF;
    IF v_agent IS NULL THEN
        RAISE EXCEPTION 'author_binding_clients: OAuth client % has no agent yet (it has never '
                        'minted); allow it after its first token', NEW.client_id
            USING ERRCODE = '55000';
    END IF;
    IF NEW.agent_id IS NULL THEN
        NEW.agent_id := v_agent;
    ELSIF NEW.agent_id <> v_agent THEN
        RAISE EXCEPTION 'author_binding_clients: OAuth client %''s agent is %, not %',
                        NEW.client_id, v_agent, NEW.agent_id USING ERRCODE = '55000';
    END IF;
    IF public.epigraph_is_human_operator(NEW.agent_id) THEN
        RAISE EXCEPTION 'author_binding_clients: agent % is a registered human operator; it is '
                        'bound on its own', NEW.agent_id USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = NEW.agent_id) THEN
        RAISE EXCEPTION 'author_binding_clients: agent % holds an operator link; a linked agent '
                        'is bound by its link and is stdio-only (migration 107)', NEW.agent_id
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.operator_id = NEW.agent_id) THEN
        RAISE EXCEPTION 'author_binding_clients: agent % operates other agents; an operator is '
                        'never bound to another (single hop, migration 107)', NEW.agent_id
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.oauth_clients c2
                WHERE c2.agent_id = NEW.agent_id AND c2.id <> NEW.client_id
                  AND c2.status <> 'revoked') THEN
        RAISE EXCEPTION 'author_binding_clients: agent % is also the agent of another OAuth '
                        'client that is not revoked; an allowance names one client''s agent',
                        NEW.agent_id USING ERRCODE = '55000';
    END IF;
    IF to_regclass('public.system_agents') IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM public.system_agents s WHERE s.agent_id = NEW.agent_id) THEN
            RAISE EXCEPTION 'author_binding_clients: agent % is a registered system agent; a '
                            'system agent is never bound to a human', NEW.agent_id
                USING ERRCODE = '55000';
        END IF;
    END IF;
    IF NEW.operator_id IS NULL OR NOT public.epigraph_is_human_operator(NEW.operator_id) THEN
        RAISE EXCEPTION 'author_binding_clients: operator % is not a registered human operator '
                        '(a live human_operators row and an active human OAuth client are both '
                        'required)', NEW.operator_id USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = NEW.operator_id) THEN
        RAISE EXCEPTION 'author_binding_clients: operator % is itself linked as an agent and '
                        'cannot be an operator', NEW.operator_id USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.author_binding_clients r
                WHERE r.agent_id = NEW.agent_id AND r.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'author_binding_clients: agent % already has a live allowance (through '
                        'another client)', NEW.agent_id USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_author_binding_clients_guard_insert() FROM PUBLIC;

-- BEFORE UPDATE: the ONLY change an allowance takes is its revoke, stamped
-- here; a revoked row takes no change at all.
CREATE OR REPLACE FUNCTION public.epigraph_author_binding_clients_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NOT public.epigraph_bypass() THEN
        RAISE EXCEPTION 'author_binding_clients: only a maintenance session revokes an allowance'
            USING ERRCODE = '42501';
    END IF;
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'author_binding_clients: the allowance of client % was REVOKED, and '
                        'revoke is final; nothing was changed', OLD.client_id
            USING ERRCODE = '55000';
    END IF;
    IF NEW.revoked_at IS NULL
       OR NEW.revoked_reason IS NULL OR length(trim(NEW.revoked_reason)) = 0
       OR (NEW.client_id, NEW.agent_id, NEW.operator_id, NEW.reason, NEW.added_at, NEW.added_by)
          IS DISTINCT FROM
          (OLD.client_id, OLD.agent_id, OLD.operator_id, OLD.reason, OLD.added_at, OLD.added_by) THEN
        RAISE EXCEPTION 'author_binding_clients: an allowance is only ever revoked (revoked_at '
                        'and a revoked_reason set); nothing was changed' USING ERRCODE = '55000';
    END IF;
    NEW.revoked_at := now();
    NEW.revoked_by := session_user;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_author_binding_clients_guard_update() FROM PUBLIC;

-- BEFORE DELETE: never, on any session (a privileged one included). Revoke is
-- final; a DELETE would let the owner remove a revoked row and add a fresh
-- one. Only dropping the table (the undo) or disabling the trigger removes a
-- row. TRUNCATE is not guarded (122's `human_operators` parity); the
-- application role holds no TRUNCATE.
CREATE OR REPLACE FUNCTION public.epigraph_author_binding_clients_refuse_delete()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'author_binding_clients: an allowance is never deleted (client %); revoke '
                    'it with epigraph_revoke_author_binding_client', OLD.client_id
        USING ERRCODE = '55000';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_author_binding_clients_refuse_delete() FROM PUBLIC;

-- AFTER INSERT / UPDATE: one `platform.` row per allowance and per revoke,
-- whatever path wrote it. The `platform.` prefix (123's
-- `security_events_platform_privileged`) is writable only by a privileged
-- session or a maintenance-owned definer frame, so no application session
-- can forge one.
CREATE OR REPLACE FUNCTION public.epigraph_author_binding_clients_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES (CASE TG_OP WHEN 'INSERT' THEN 'platform.author_binding_client_allowed'
                       ELSE 'platform.author_binding_client_revoked' END,
            NEW.agent_id, true,
            jsonb_build_object('client_id', NEW.client_id,
                               'operator_id', NEW.operator_id,
                               'reason', CASE TG_OP WHEN 'INSERT' THEN NEW.reason
                                                    ELSE NEW.revoked_reason END,
                               'recorded_by', session_user,
                               'migration', 149));
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_author_binding_clients_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS author_binding_clients_guard_insert ON public.author_binding_clients;
CREATE TRIGGER author_binding_clients_guard_insert
    BEFORE INSERT ON public.author_binding_clients
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_author_binding_clients_guard_insert();
DROP TRIGGER IF EXISTS author_binding_clients_guard_update ON public.author_binding_clients;
CREATE TRIGGER author_binding_clients_guard_update
    BEFORE UPDATE ON public.author_binding_clients
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_author_binding_clients_guard_update();
DROP TRIGGER IF EXISTS author_binding_clients_refuse_delete ON public.author_binding_clients;
CREATE TRIGGER author_binding_clients_refuse_delete
    BEFORE DELETE ON public.author_binding_clients
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_author_binding_clients_refuse_delete();
DROP TRIGGER IF EXISTS author_binding_clients_audit ON public.author_binding_clients;
CREATE TRIGGER author_binding_clients_audit
    AFTER INSERT OR UPDATE ON public.author_binding_clients
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_author_binding_clients_audit();

-- Allow a client. Maintenance only; audited by the table's trigger.
-- Idempotent for a live row naming the same operator, also under a concurrent
-- retry: the advisory lock is taken BEFORE the existence read, so a second
-- caller waits and then finds the row (the insert guard's own "already a live
-- allowance" check would otherwise raise first). A revoked row is not
-- revived, and a live row naming another operator is not re-pointed.
-- `effective_binding` is the binding the agent has NOW, so a caller re-running
-- this on a dead allowance (client suspended, operator revoked, ...) is not
-- told it is fine.
CREATE OR REPLACE FUNCTION public.epigraph_allow_author_binding_client(
    p_client uuid, p_operator uuid, p_reason text)
RETURNS TABLE (allowed_now boolean, agent_id uuid, operator_id uuid,
               added_at timestamptz, added_by text, effective_binding text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_row  public.author_binding_clients%ROWTYPE;
    v_rows integer := 0;
BEGIN
    IF p_client IS NULL OR p_operator IS NULL OR p_reason IS NULL
       OR length(trim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_allow_author_binding_client: the client, the operator and a '
                        'reason are required' USING ERRCODE = '22004';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    SELECT * INTO v_row FROM public.author_binding_clients r WHERE r.client_id = p_client;
    IF NOT FOUND THEN
        INSERT INTO public.author_binding_clients (client_id, operator_id, reason)
        VALUES (p_client, p_operator, p_reason)
        ON CONFLICT (client_id) DO NOTHING;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        SELECT * INTO v_row FROM public.author_binding_clients r WHERE r.client_id = p_client;
    END IF;
    IF v_rows = 0 THEN
        IF v_row.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'epigraph_allow_author_binding_client: client % was allowed and '
                            'REVOKED; a revoked allowance is not revived', p_client
                USING ERRCODE = '55000';
        END IF;
        IF v_row.operator_id <> p_operator THEN
            RAISE EXCEPTION 'epigraph_allow_author_binding_client: client % is already allowed '
                            'for operator %; revoke it first', p_client, v_row.operator_id
                USING ERRCODE = '55000';
        END IF;
    END IF;
    RETURN QUERY SELECT v_rows > 0, r.agent_id, r.operator_id, r.added_at, r.added_by,
                        public.epigraph_author_binding(r.agent_id)
                   FROM public.author_binding_clients r WHERE r.client_id = p_client;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_allow_author_binding_client(uuid, uuid, text)
    FROM PUBLIC;

-- Revoke an allowance. Maintenance only; audited by the table's trigger; final.
CREATE OR REPLACE FUNCTION public.epigraph_revoke_author_binding_client(
    p_client uuid, p_reason text)
RETURNS TABLE (revoked_now boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF p_client IS NULL OR p_reason IS NULL OR length(trim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_revoke_author_binding_client: the client and a reason are '
                        'required' USING ERRCODE = '22004';
    END IF;
    UPDATE public.author_binding_clients r
       SET revoked_at = now(), revoked_by = session_user, revoked_reason = p_reason
     WHERE r.client_id = p_client AND r.revoked_at IS NULL;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN QUERY SELECT v_rows > 0;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_revoke_author_binding_client(uuid, text) FROM PUBLIC;

-- A new link of an allowlisted agent is refused while its client is not
-- revoked: a link makes the agent stdio-only (107), which would end its
-- client's HTTP access as a side effect. `c.status <> 'revoked'` is the legacy
-- tie's own `skipped:oauth_principal` predicate (123), so the tie skips every
-- agent this refuses and never aborts here; a REVOKED client's agent links
-- normally, and the link then decides its binding.
-- An exact re-link (a row for the agent exists) is discarded by the caller's
-- ON CONFLICT DO NOTHING and never refused here (122's precedent).
CREATE OR REPLACE FUNCTION public.epigraph_operator_links_refuse_allowlisted_agent()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_client uuid;
BEGIN
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = NEW.agent_id) THEN
        RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    SELECT r.client_id INTO v_client
      FROM public.author_binding_clients r
      JOIN public.oauth_clients c ON c.id = r.client_id
     WHERE r.agent_id = NEW.agent_id AND r.revoked_at IS NULL
       AND c.status <> 'revoked';
    IF v_client IS NOT NULL THEN
        RAISE EXCEPTION 'agent % is the agent of OAuth client %, which is on the author-binding '
                        'allowlist; a linked agent is stdio-only (migration 107), so a link '
                        'would end that client''s HTTP access', NEW.agent_id, v_client
            USING ERRCODE = '55000',
                  HINT = 'Revoke the allowance first: epigraph-operator '
                         'revoke-author-binding-client --client <id> --reason <text> --apply.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_links_refuse_allowlisted_agent() FROM PUBLIC;

DROP TRIGGER IF EXISTS operator_links_refuse_allowlisted_agent ON public.operator_links;
CREATE TRIGGER operator_links_refuse_allowlisted_agent
    BEFORE INSERT ON public.operator_links
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_operator_links_refuse_allowlisted_agent();

-- Ownership and grants, guarded as every such block since 060 is. The
-- re-bodied 122 functions keep their owner and ACL under CREATE OR REPLACE;
-- both are re-asserted. Each ALTER/GRANT names its function literally
-- (tenancy_backfill.rs's static re-own scan reads these statements).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_allowlisted_operator(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_author_binding(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_human_of(uuid, boolean) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_author_binding_clients_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_author_binding_clients_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_author_binding_clients_refuse_delete() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_author_binding_clients_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_allow_author_binding_client(uuid, uuid, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_revoke_author_binding_client(uuid, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_operator_links_refuse_allowlisted_agent() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_allowlisted_operator(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_author_binding(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_human_of(uuid, boolean) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_allow_author_binding_client(uuid, uuid, text) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_revoke_author_binding_client(uuid, text) '
                'TO epigraph_maintenance';
        -- The definers run as this role, so it holds the DML they issue; the
        -- table's own triggers hold a direct write to the same rules and audit.
        EXECUTE 'GRANT SELECT, INSERT ON public.author_binding_clients TO epigraph_maintenance';
        EXECUTE 'GRANT UPDATE (revoked_at, revoked_by, revoked_reason) '
                'ON public.author_binding_clients TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        -- 077's ALTER DEFAULT PRIVILEGES handed the app role DML on the new
        -- table; take it back and leave SELECT (every relation app-readable).
        EXECUTE 'REVOKE ALL ON public.author_binding_clients FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.author_binding_clients TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_allowlisted_operator(uuid) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_allow_author_binding_client(uuid, uuid, text) FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_revoke_author_binding_client(uuid, text) FROM epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_author_binding(uuid) TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_human_of(uuid, boolean) '
                'TO epigraph_app';
    END IF;
END $$;
