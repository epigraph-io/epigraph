-- 118: the application role loses direct UPDATE/DELETE on credential and
-- ledger tables (batch W11).
--
-- WHAT THIS FILE DOES
--
-- 077 granted `epigraph_app` SELECT/INSERT/UPDATE/DELETE on every table in
-- `public` (and, through ALTER DEFAULT PRIVILEGES, on every later one). Tables
-- without row security therefore sat fully writable by any application
-- session: OAuth clients, refresh tokens, authorization codes, authorize
-- sessions, agent signing keys and the migration ledger among them. This file:
--
--   1. adds `epigraph_lockdown_privileged()`, a 067-era privilege test (it uses
--      only `epigraph_bypass()`, `epigraph_definer_bypass()` and the session
--      role's attributes, so it does not depend on 111-117);
--   2. revokes every write on the ledgers (`_sqlx_migrations` and the four
--      tenancy bookkeeping tables) from `epigraph_app`, and on
--      `_sqlx_migrations` from `epigraph_maintenance` too;
--   3. moves every UPDATE/DELETE the request path runs on a credential table
--      into a SECURITY DEFINER owned by `epigraph_maintenance`, then revokes
--      UPDATE and DELETE on those tables from `epigraph_app`:
--        refresh_tokens            check (reuse detection), rotate (atomic;
--                                  successor scopes and expiry derived),
--                                  revoke, revoke-by-hash, revoke-for-client
--        oauth_authorization_codes consume (single use)
--        oauth_authorize_sessions  to-consent, take (single use)
--        oauth_clients             lock-for-link, link-agent (write-once),
--                                  approve (audited)
--        agent_keys                set-status (no un-revoke)
--      INSERT stays: registration, provisioning and token minting insert on
--      the application role, and none of them updates or deletes;
--   4. `agents`: table-level UPDATE and DELETE are revoked and UPDATE is
--      granted back on the columns the live paths write (display_name, labels,
--      orcid, ror_id, properties, updated_at), so no application session can
--      change `id`, `public_key` or `key_kind` (the row policies of 077 still
--      apply to what is left); `properties` is not a pure profile column, so a
--      trigger keeps its `competence_scopes` key out of the agent's reach
--      (section 8);
--   5. `match_candidates`: DELETE revoked; a trigger refuses the transition to
--      `stale` (INSERT or UPDATE) on a non-privileged session. Retirement is an
--      administrative act and runs on the maintenance connection;
--   6. append-only tables (provenance_log among them) lose UPDATE/DELETE, and
--      tables with no writer lose every write;
--   7. `oauth.` security events become writable by the definers only;
--   8. `agents.properties.competence_scopes` is no longer writable by the agent.
--
-- Refresh-token families. `family_id` (nullable; NULL reads as the row's own
-- id, so rows inserted by an older binary during the deploy are their own
-- family) links a rotated token to its successor; `revoked_reason` records why
-- a row was revoked. Presenting a token whose revocation reason is `rotated`
-- more than 30 seconds after that rotation is reuse (OAuth 2.0 Security BCP,
-- refresh token rotation): every live token of its family is revoked and a
-- `security_events` row is written. Inside those 30 seconds it is a benign
-- concurrent refresh (the GRACE WINDOW): refused with the same answer, and
-- the family, the race winner's successor included, stays live. The definers
-- RETURN an outcome and never RAISE on that path, because a RAISE would roll
-- the family revocation back with it. The application role no longer reads
-- `token_hash`, so no application session can name another client's chain
-- to these definers.
--
-- INSERT is not narrowed here, and on these tables INSERT carries authority
-- of its own: a client row inserted with a chosen `agent_id`, status and
-- scopes, an authorization code inserted for a chosen client, and an agent key
-- inserted for a chosen agent can each be redeemed or used as that principal.
-- Moving those inserts behind definers that derive the security-relevant
-- columns from checked state is a named follow-up.
--
-- ORDERING. This file uses no object created by 111-117 and replaces no
-- function any of them creates, and none of them grants table privileges to
-- `epigraph_app`, so applying 118 before or after them converges on the same
-- privileges (measured; see the PR). It does not re-issue any `ON ALL TABLES`
-- grant: every statement names its table.
--
-- UNDO. The GRANTs that restore the prior privileges are at the end of this
-- file, commented. Reverting them re-opens exactly what this file closes.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. THE PRIVILEGE TEST
-- ===================================================================
-- True for a maintenance session (067's `epigraph_bypass`, session_user a
-- member of `epigraph_maintenance`), inside a body owned by a maintenance
-- member (`epigraph_definer_bypass`, current_user), and for a superuser or
-- BYPASSRLS session role. An `epigraph_app` session is none of these.
CREATE OR REPLACE FUNCTION public.epigraph_lockdown_privileged() RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
    SELECT public.epigraph_bypass()
        OR public.epigraph_definer_bypass()
        OR COALESCE((SELECT r.rolsuper OR r.rolbypassrls
                       FROM pg_catalog.pg_roles r
                      WHERE r.rolname = session_user), false);
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_lockdown_privileged() FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_lockdown_privileged() TO epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_lockdown_privileged() '
                'TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- 2. LEDGERS: NO APPLICATION WRITES
-- ===================================================================
-- `_sqlx_migrations` is written only by the migrator, which runs on the
-- migration DSN (the schema owner); the application reads it for the head
-- check and keeps SELECT. The tenancy bookkeeping tables are written only by
-- migrations and by `epigraph-tenancy-backfill`, which connects on the
-- maintenance DSN. No statement in this repository writes any of them on the
-- application role.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public._sqlx_migrations, '
                'public.tenancy_backfill_progress, public.tenancy_exempt, '
                'public.tenancy_transcription_log, public.tenancy_undeclared_writes '
                'FROM epigraph_app';
    END IF;
    -- 070 granted the maintenance role SELECT/INSERT/UPDATE on every table,
    -- the migration ledger included. Nothing on the maintenance DSN writes it.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public._sqlx_migrations '
                'FROM epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- 3a. REFRESH TOKENS
-- ===================================================================
ALTER TABLE public.refresh_tokens ADD COLUMN IF NOT EXISTS family_id uuid;
ALTER TABLE public.refresh_tokens ADD COLUMN IF NOT EXISTS revoked_reason text;
COMMENT ON COLUMN public.refresh_tokens.family_id IS
    'Migration 118: the rotation chain this token belongs to; NULL means the row''s own id.';
COMMENT ON COLUMN public.refresh_tokens.revoked_reason IS
    'Migration 118: why revoked_at was set (rotated | denied | revoked | reuse | client). '
    'Only a presented token revoked as rotated is reuse.';
CREATE INDEX IF NOT EXISTS refresh_tokens_live_family_idx
    ON public.refresh_tokens ((COALESCE(family_id, id)))
    WHERE revoked_at IS NULL;

-- Reuse handling, shared by check and rotate. Not granted to the application:
-- it is reached only through the two definers below.
--
-- GRACE WINDOW. A token presented again within 30 seconds of its OWN rotation
-- is a benign race (two tabs, connectors or processes refreshing with one
-- token and no lock), not a replay: the answer is `grace`, which the token
-- endpoint turns into the same 401 as `invalid`, and the family stays live, so
-- the race's winner keeps the successor it was handed. Presented later than
-- that, it is reuse and the family is revoked (strict BCP). The window is
-- measured on the database clock against the row's own `revoked_at`, never
-- against anything the caller supplies. `grace` issues nothing: a replayer
-- inside the window gets a 401 and learns nothing a 401 does not already say.
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_on_reuse(p_hash bytea)
RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
    v_id uuid;
    v_client uuid;
    v_family uuid;
    v_reason text;
    v_revoked_at timestamptz;
    v_n bigint;
BEGIN
    SELECT t.id, t.client_id, COALESCE(t.family_id, t.id), t.revoked_reason, t.revoked_at
      INTO v_id, v_client, v_family, v_reason, v_revoked_at
      FROM public.refresh_tokens t
     WHERE t.token_hash = p_hash;
    IF NOT FOUND OR v_reason IS DISTINCT FROM 'rotated' THEN
        RETURN 'invalid';
    END IF;
    IF v_revoked_at > now() - interval '30 seconds' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('oauth.refresh_token_grace', NULL, false,
                jsonb_build_object('client_id', v_client, 'family_id', v_family,
                                   'presented_token_id', v_id, 'migration', 118));
        RETURN 'grace';
    END IF;
    UPDATE public.refresh_tokens
       SET revoked_at = now(), revoked_reason = 'reuse'
     WHERE COALESCE(family_id, id) = v_family AND revoked_at IS NULL;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('oauth.refresh_token_reuse', NULL, false,
            jsonb_build_object('client_id', v_client, 'family_id', v_family,
                               'presented_token_id', v_id, 'revoked', v_n,
                               'migration', 118));
    RETURN 'reuse';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refresh_token_on_reuse(bytea) FROM PUBLIC;

-- The refresh grant's first read. `valid` has no side effect; a token revoked
-- by rotation is `grace` inside the window and reuse (family revoked) after
-- it; anything else is `invalid`.
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_check(p_hash bytea)
RETURNS TABLE (outcome text, token_id uuid, client_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    RETURN QUERY
        SELECT 'valid'::text, t.id, t.client_id
          FROM public.refresh_tokens t
         WHERE t.token_hash = p_hash AND t.revoked_at IS NULL AND t.expires_at > now();
    IF FOUND THEN
        RETURN;
    END IF;
    RETURN QUERY SELECT public.epigraph_refresh_token_on_reuse(p_hash), NULL::uuid, NULL::uuid;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refresh_token_check(bytea) FROM PUBLIC;

-- The rotation, ATOMIC: claim the presented token (one UPDATE, so of any
-- number of concurrent callers presenting it exactly one gets the row) and
-- insert its successor in the same family, for the same client. 0 rows
-- claimed is not an error: the token was spent, revoked or expired, and a
-- token spent by rotation is `grace` or reuse (above).
--
-- The successor's authority is DERIVED here, not taken from the caller: its
-- scopes are the client's current `granted_scopes` (what the refresh grant
-- mints access tokens from anyway), and its expiry is capped at the client
-- type's refresh TTL (agent 24 h, human 30 d, service 90 d, anything else
-- 24 h; the same table as `oauth/token.rs`). The caller may shorten the
-- expiry, never lengthen it.
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_rotate(
    p_old_hash bytea, p_new_hash bytea, p_new_expires_at timestamptz)
RETURNS TABLE (outcome text, token_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
    v_client uuid;
    v_family uuid;
    v_scopes text[];
    v_ttl interval;
    v_new uuid;
BEGIN
    IF p_new_hash IS NULL OR p_new_expires_at IS NULL OR p_new_expires_at <= now() THEN
        RAISE EXCEPTION 'RT01: a rotation needs a successor hash and a future expiry'
            USING ERRCODE = '22023';
    END IF;
    UPDATE public.refresh_tokens t
       SET revoked_at = now(), revoked_reason = 'rotated'
     WHERE t.token_hash = p_old_hash AND t.revoked_at IS NULL AND t.expires_at > now()
    RETURNING t.client_id, COALESCE(t.family_id, t.id) INTO v_client, v_family;
    IF NOT FOUND THEN
        RETURN QUERY SELECT public.epigraph_refresh_token_on_reuse(p_old_hash), NULL::uuid;
        RETURN;
    END IF;
    SELECT COALESCE(c.granted_scopes, ARRAY[]::text[]),
           CASE c.client_type
               WHEN 'human' THEN interval '30 days'
               WHEN 'service' THEN interval '90 days'
               ELSE interval '24 hours'
           END
      INTO v_scopes, v_ttl
      FROM public.oauth_clients c
     WHERE c.id = v_client;
    INSERT INTO public.refresh_tokens (token_hash, client_id, scopes, expires_at, family_id)
    VALUES (p_new_hash, v_client, COALESCE(v_scopes, ARRAY[]::text[]),
            LEAST(p_new_expires_at, now() + COALESCE(v_ttl, interval '24 hours')), v_family)
    RETURNING id INTO v_new;
    RETURN QUERY SELECT 'rotated'::text, v_new;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refresh_token_rotate(bytea, bytea, timestamptz)
    FROM PUBLIC;

-- A deliberate revocation of one live token (a denied refresh, /revoke).
-- `rotated` and `reuse` are the rotation's and the detector's own reasons.
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_revoke(p_id uuid, p_reason text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF p_reason IS NULL OR p_reason NOT IN ('denied', 'revoked') THEN
        RAISE EXCEPTION 'RT02: a revocation reason is denied or revoked, not %', p_reason
            USING ERRCODE = '22023';
    END IF;
    UPDATE public.refresh_tokens
       SET revoked_at = now(), revoked_reason = p_reason
     WHERE id = p_id AND revoked_at IS NULL;
    RETURN FOUND;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refresh_token_revoke(uuid, text) FROM PUBLIC;

-- RFC 7009 revocation by the token itself (`/oauth/revoke`). The application
-- role cannot read `token_hash` (section 3e), so the lookup by hash happens
-- here. Idempotent: an unknown or already revoked token is `false`, and the
-- endpoint answers 200 either way.
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_revoke_by_hash(p_hash bytea)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    UPDATE public.refresh_tokens
       SET revoked_at = now(), revoked_reason = 'revoked'
     WHERE token_hash = p_hash AND revoked_at IS NULL AND expires_at > now();
    RETURN FOUND;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refresh_token_revoke_by_hash(bytea) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_revoke_client(p_client_id uuid)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_n bigint;
BEGIN
    UPDATE public.refresh_tokens
       SET revoked_at = now(), revoked_reason = 'client'
     WHERE client_id = p_client_id AND revoked_at IS NULL;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refresh_token_revoke_client(uuid) FROM PUBLIC;

-- ===================================================================
-- 3b. AUTHORIZATION CODES AND AUTHORIZE SESSIONS
-- ===================================================================
-- The same statements the repositories ran, as the definer.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_code_consume(p_code_hash bytea)
RETURNS SETOF public.oauth_authorization_codes
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
    UPDATE public.oauth_authorization_codes
       SET used_at = now()
     WHERE code_hash = p_code_hash AND used_at IS NULL AND expires_at > now()
    RETURNING *;
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_oauth_code_consume(bytea) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_oauth_session_to_consent(
    p_from_state text, p_to_state text, p_resolved_oauth_client_id uuid, p_granted_scopes text[])
RETURNS SETOF public.oauth_authorize_sessions
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
    UPDATE public.oauth_authorize_sessions
       SET state = p_to_state, resolved_oauth_client_id = p_resolved_oauth_client_id,
           granted_scopes = p_granted_scopes
     WHERE state = p_from_state AND expires_at > now()
    RETURNING *;
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_oauth_session_to_consent(text, text, uuid, text[])
    FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_oauth_session_take(p_state text)
RETURNS SETOF public.oauth_authorize_sessions
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
    DELETE FROM public.oauth_authorize_sessions
     WHERE state = p_state AND expires_at > now()
    RETURNING *;
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_oauth_session_take(text) FROM PUBLIC;

-- ===================================================================
-- 3c. OAUTH CLIENTS
-- ===================================================================
-- `AgentRepository::ensure_for_client` locks the client row for the whole
-- mint transaction. A row lock taken inside a function is held until the
-- CALLER's transaction ends, so the lock is the same one the direct
-- `SELECT ... FOR UPDATE` took (which needed the UPDATE privilege).
CREATE OR REPLACE FUNCTION public.epigraph_oauth_client_lock_for_link(p_id uuid)
RETURNS TABLE (agent_id uuid, client_id text, client_type text)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
    SELECT c.agent_id, c.client_id::text, c.client_type::text
      FROM public.oauth_clients c
     WHERE c.id = p_id
       FOR UPDATE;
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_oauth_client_lock_for_link(uuid) FROM PUBLIC;

-- Write-once: a linked client is never re-bound. The agent must exist.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_client_link_agent(p_id uuid, p_agent_id uuid)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF p_agent_id IS NULL OR NOT EXISTS (SELECT 1 FROM public.agents a WHERE a.id = p_agent_id) THEN
        RAISE EXCEPTION 'OC01: an OAuth client is linked to an existing agent'
            USING ERRCODE = '23503';
    END IF;
    UPDATE public.oauth_clients
       SET agent_id = p_agent_id, updated_at = now()
     WHERE id = p_id AND agent_id IS NULL;
    RETURN FOUND;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_oauth_client_link_agent(uuid, uuid) FROM PUBLIC;

-- The admin approval (`POST /api/v1/admin/clients/:id/approve`, clients:admin
-- scope checked by the route). Same columns as before; now leaves an audit row.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_client_approve(
    p_id uuid, p_granted_scopes text[], p_approved_by uuid)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_prev text;
BEGIN
    SELECT c.status INTO v_prev FROM public.oauth_clients c WHERE c.id = p_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    UPDATE public.oauth_clients
       SET granted_scopes = COALESCE(p_granted_scopes, ARRAY[]::text[]), status = 'active',
           created_by = p_approved_by, updated_at = now()
     WHERE id = p_id;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('oauth.client_approved', NULL, true,
            jsonb_build_object('oauth_client_id', p_id, 'approved_by', p_approved_by,
                               'previous_status', v_prev,
                               'granted_scopes', to_jsonb(COALESCE(p_granted_scopes, ARRAY[]::text[])),
                               'migration', 118));
    RETURN true;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_oauth_client_approve(uuid, text[], uuid) FROM PUBLIC;

-- ===================================================================
-- 3d. AGENT KEYS
-- ===================================================================
-- Rotation (active -> rotated) and revocation (anything but revoked ->
-- revoked). A revoked key is never re-activated through this path, and no
-- other column than status / revocation_reason / revoked_by changes.
CREATE OR REPLACE FUNCTION public.epigraph_agent_key_set_status(
    p_key_id uuid, p_status text, p_revocation_reason text, p_revoked_by uuid)
RETURNS SETOF public.agent_keys
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_cur text;
BEGIN
    SELECT k.status INTO v_cur FROM public.agent_keys k WHERE k.id = p_key_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF NOT ((p_status = 'rotated' AND v_cur = 'active')
            OR (p_status = 'revoked' AND v_cur IS DISTINCT FROM 'revoked')) THEN
        RAISE EXCEPTION 'AK01: agent key % cannot move from % to %', p_key_id, v_cur, p_status
            USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
        UPDATE public.agent_keys
           SET status = p_status,
               revocation_reason = COALESCE(p_revocation_reason, revocation_reason),
               revoked_by = COALESCE(p_revoked_by, revoked_by)
         WHERE id = p_key_id
        RETURNING *;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_key_set_status(uuid, text, text, uuid) FROM PUBLIC;

-- ===================================================================
-- 3e. OWNERSHIP, GRANTS, AND THE REVOKE
-- ===================================================================
-- Owner `epigraph_maintenance` (the pattern since 092/106): the bodies write
-- tables the application can no longer update. 070 gave the maintenance role
-- SELECT/INSERT/UPDATE but not DELETE; `epigraph_oauth_session_take` deletes.
DO $$
DECLARE f text;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT DELETE ON public.oauth_authorize_sessions TO epigraph_maintenance';
        FOREACH f IN ARRAY ARRAY[
            'public.epigraph_refresh_token_on_reuse(bytea)',
            'public.epigraph_refresh_token_check(bytea)',
            'public.epigraph_refresh_token_rotate(bytea, bytea, timestamptz)',
            'public.epigraph_refresh_token_revoke(uuid, text)',
            'public.epigraph_refresh_token_revoke_by_hash(bytea)',
            'public.epigraph_refresh_token_revoke_client(uuid)',
            'public.epigraph_oauth_code_consume(bytea)',
            'public.epigraph_oauth_session_to_consent(text, text, uuid, text[])',
            'public.epigraph_oauth_session_take(text)',
            'public.epigraph_oauth_client_lock_for_link(uuid)',
            'public.epigraph_oauth_client_link_agent(uuid, uuid)',
            'public.epigraph_oauth_client_approve(uuid, text[], uuid)',
            'public.epigraph_agent_key_set_status(uuid, text, text, uuid)']
        LOOP
            EXECUTE format('ALTER FUNCTION %s OWNER TO epigraph_maintenance', f);
        END LOOP;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        FOREACH f IN ARRAY ARRAY[
            'public.epigraph_refresh_token_check(bytea)',
            'public.epigraph_refresh_token_rotate(bytea, bytea, timestamptz)',
            'public.epigraph_refresh_token_revoke(uuid, text)',
            'public.epigraph_refresh_token_revoke_by_hash(bytea)',
            'public.epigraph_refresh_token_revoke_client(uuid)',
            'public.epigraph_oauth_code_consume(bytea)',
            'public.epigraph_oauth_session_to_consent(text, text, uuid, text[])',
            'public.epigraph_oauth_session_take(text)',
            'public.epigraph_oauth_client_lock_for_link(uuid)',
            'public.epigraph_oauth_client_link_agent(uuid, uuid)',
            'public.epigraph_oauth_client_approve(uuid, text[], uuid)',
            'public.epigraph_agent_key_set_status(uuid, text, text, uuid)']
        LOOP
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO epigraph_app', f);
        END LOOP;
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON public.refresh_tokens, '
                'public.oauth_authorization_codes, public.oauth_authorize_sessions, '
                'public.oauth_clients, public.agent_keys FROM epigraph_app';
        -- `token_hash` is the bearer secret's image: with it, the check, rotate
        -- and revoke definers act on another client's chain. No application
        -- path reads it (every lookup by hash is a definer above), so the
        -- application role reads every column but that one. A column GRANT is
        -- only additive, so the table-level SELECT goes first; `id` stays
        -- readable because the mint's `INSERT ... RETURNING id` needs it.
        EXECUTE 'REVOKE SELECT ON public.refresh_tokens FROM epigraph_app';
        EXECUTE 'GRANT SELECT (id, client_id, scopes, expires_at, revoked_at, created_at, '
                'family_id, revoked_reason) ON public.refresh_tokens TO epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 4. AGENTS: PROFILE COLUMNS ONLY
-- ===================================================================
-- 077's row policies already confine an application UPDATE to the session's
-- own agent and admit no DELETE. What they do not confine is the COLUMN: a
-- session could rewrite its own `public_key` or `key_kind` (or its own
-- `role`, `state`, or the reputation kept in `metadata`). The live
-- application writes are `AgentRepository::update` (display_name, labels,
-- orcid, ror_id) and `set_llm_properties` (properties), each with
-- updated_at; the reputation writer of `metadata` has no application-role
-- caller. A column GRANT is only additive, so the table-level UPDATE goes
-- first.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON public.agents FROM epigraph_app';
        EXECUTE 'GRANT UPDATE (display_name, labels, orcid, ror_id, properties, updated_at) '
                'ON public.agents TO epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 5. MATCH CANDIDATES: STALE IS AN ADMINISTRATIVE STATE
-- ===================================================================
-- `stale` is what a retirement writes, and a retirement retracts the matcher
-- edge and deletes its derived rows, which are not the session's. The table
-- carries no tenancy, so the database cannot tell an administrator's session
-- from any other application session; it can tell a privileged one. The
-- guard keys on the TRANSITION into stale: the matcher's upsert re-touches a
-- decided stale row and keeps it stale (its CASE), and must keep working.
-- No statement in this repository deletes a candidate.
CREATE OR REPLACE FUNCTION public.epigraph_match_candidates_stale_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.status = 'stale'
       AND (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM 'stale')
       AND NOT public.epigraph_lockdown_privileged() THEN
        RAISE EXCEPTION 'MC01: retiring match candidate % (status stale) is an administrative '
            'act and needs a privileged (maintenance) connection', NEW.id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_match_candidates_stale_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS match_candidates_stale_guard ON public.match_candidates;
CREATE TRIGGER match_candidates_stale_guard
    BEFORE INSERT OR UPDATE OF status ON public.match_candidates
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_match_candidates_stale_guard();

-- The retirement now runs on the maintenance connection, and its cascade
-- deletes the matcher edge's `bp_messages`, `factors` and edge-keyed
-- `mass_functions`. 070 gave the maintenance role no DELETE, so on a
-- maintenance login that is not a superuser the retirement stopped at its
-- first DELETE (measured with the real server). The narrowest grant under
-- which it runs; it is the same grant 115 (`mass_functions`) and 117
-- (`factors`, `bp_messages`) make, so the two converge in either order.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE DELETE, TRUNCATE ON public.match_candidates FROM epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT DELETE ON public.factors, public.bp_messages, public.mass_functions '
                'TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- 6. APPEND-ONLY AND WRITER-LESS TABLES
-- ===================================================================
-- Measured over every repository that shares this database, at their origin
-- refs, and over every function body a fresh 001 -> 118 install carries: the
-- only writers of these tables INSERT. None updates, deletes or truncates one.
-- Rows removed by a foreign-key cascade (graph_cluster_runs / claim_themes ->
-- graph_neighborhoods -> neighborhood_edges, reasoning_traces ->
-- trace_parents) are removed by the referential action, which does not need
-- the deleting session to hold DELETE on the child.
--   provenance_log            a signed, append-only ledger (its rows carry
--                             provenance_sig and authorization_chain)
--   agent_state_history, analyses, analysis_methods, behavioral_executions,
--   counterfactual_scenarios, gap_analyses, graph_neighborhoods,
--   learning_events, neighborhood_edges, pattern_templates, trace_parents
--                             append-only records and derived rows
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON public.provenance_log, '
                'public.agent_state_history, public.analyses, public.analysis_methods, '
                'public.behavioral_executions, public.counterfactual_scenarios, '
                'public.gap_analyses, public.graph_neighborhoods, public.learning_events, '
                'public.neighborhood_edges, public.pattern_templates, public.trace_parents '
                'FROM epigraph_app';
        -- No writer at all: no INSERT either. `agent_capabilities` is authority
        -- content (privileged_access, can_modify_policies), and its only
        -- statement, `AgentRepository::update_capabilities`, has no caller: it
        -- now needs a privileged connection.
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.agent_capabilities, '
                'public.authorization_votes, public.authorizers, '
                'public.entity_merge_candidates, public.experiment_entities, '
                'public.harvester_audit_reports, public.harvester_enriched_concepts, '
                'public.harvester_sources, public.source_artifacts FROM epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 7. AUDIT ROWS 118's DEFINERS WRITE ARE THEIRS ALONE
-- ===================================================================
-- `oauth.client_approved`, `oauth.refresh_token_reuse` and
-- `oauth.refresh_token_grace` are written by the definers above. The
-- application role keeps INSERT on `security_events` (077: an actor must never
-- be able to suppress its own audit record), so without this an application
-- session could forge one. Same shape as 117's `cascade.` arm. `left()`, not
-- LIKE: the application's own provisioning events are `oauth_...`, and `_` is
-- a LIKE wildcard.
DROP POLICY IF EXISTS security_events_oauth_privileged ON public.security_events;
CREATE POLICY security_events_oauth_privileged ON public.security_events
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        left(event_type, 6) <> 'oauth.'
        OR (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()));

-- ===================================================================
-- 8. AGENTS: COMPETENCE SCOPES ARE NOT SELF-SERVICE
-- ===================================================================
-- Section 4 leaves `properties` application-updatable (on the own row, 077's
-- policy) because `AgentRepository::set_llm_properties` merges its three keys
-- there. But `properties->'competence_scopes'` is read by the belief route to
-- discount evidence from an out-of-scope agent, so an agent that could rewrite
-- it could remove its own discount. No statement in this repository writes
-- it; a non-privileged session may not change it.
CREATE OR REPLACE FUNCTION public.epigraph_agents_competence_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF (NEW.properties -> 'competence_scopes') IS DISTINCT FROM (OLD.properties -> 'competence_scopes')
       AND NOT public.epigraph_lockdown_privileged() THEN
        RAISE EXCEPTION 'AG01: agents.properties.competence_scopes of agent % is set by a '
            'privileged connection, not by the agent', NEW.id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agents_competence_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS agents_competence_guard ON public.agents;
CREATE TRIGGER agents_competence_guard
    BEFORE UPDATE OF properties ON public.agents
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_agents_competence_guard();

-- UNDO (restores the prior privileges; re-opens what this file closes):
--   GRANT INSERT, UPDATE, DELETE ON public._sqlx_migrations, public.tenancy_backfill_progress,
--     public.tenancy_exempt, public.tenancy_transcription_log,
--     public.tenancy_undeclared_writes TO epigraph_app;
--   GRANT INSERT, UPDATE ON public._sqlx_migrations TO epigraph_maintenance;
--   GRANT UPDATE, DELETE ON public.refresh_tokens, public.oauth_authorization_codes,
--     public.oauth_authorize_sessions, public.oauth_clients, public.agent_keys TO epigraph_app;
--   GRANT UPDATE, DELETE ON public.agents TO epigraph_app;
--   GRANT DELETE ON public.match_candidates TO epigraph_app;
--   DROP TRIGGER IF EXISTS match_candidates_stale_guard ON public.match_candidates;
--   GRANT SELECT ON public.refresh_tokens TO epigraph_app;
--   GRANT UPDATE, DELETE ON public.provenance_log, public.agent_state_history,
--     public.analyses, public.analysis_methods, public.behavioral_executions,
--     public.counterfactual_scenarios, public.gap_analyses, public.graph_neighborhoods,
--     public.learning_events, public.neighborhood_edges, public.pattern_templates,
--     public.trace_parents TO epigraph_app;
--   GRANT INSERT, UPDATE, DELETE ON public.agent_capabilities, public.authorization_votes,
--     public.authorizers, public.entity_merge_candidates, public.experiment_entities,
--     public.harvester_audit_reports, public.harvester_enriched_concepts,
--     public.harvester_sources, public.source_artifacts TO epigraph_app;
--   DROP POLICY IF EXISTS security_events_oauth_privileged ON public.security_events;
--   DROP TRIGGER IF EXISTS agents_competence_guard ON public.agents;
--   REVOKE DELETE ON public.factors, public.bp_messages, public.mass_functions
--     FROM epigraph_maintenance;   (only where 115 / 117 are NOT applied: they
--     grant the same privileges and need them)
-- The definers, the two refresh_tokens columns and the index may stay: the
-- previous binaries do not call or read them.
