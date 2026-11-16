-- ===================================================================
-- 224-undo.sql: take migration 224 (the OAuth code, session and client
-- definers on `pg_catalog, pg_temp`) back out, in ONE transaction, on the
-- migration (superuser) DSN.
--
-- READ FIRST: no binary depends on 224, so nothing needs rolling back first.
--
-- WHAT IT DOES: re-states 118's bodies of the six definers byte for byte, on
-- the path 190's sweep left them on (`pg_catalog, public, pg_temp`, NOT 118's
-- own `pg_catalog, public`, which 190 had already moved). It grants and
-- revokes nothing: `CREATE OR REPLACE` keeps owner and ACL, so 188's revoke
-- of the application role's EXECUTE on the approve definer stands. From then
-- on their unqualified built-in calls resolve over public again, so a
-- `public.to_jsonb(text[])` decides the scopes an approval's audit row
-- records (224's header).
--
-- PRECONDITION: each body in place must be 224's or already 118's (a second
-- run); over any other body it raises 55000 and changes nothing (a later
-- migration re-bodied it: undo that one first).
--
-- WHAT IT LEAVES: every client, code and session as it stands, and 224's
-- `_sqlx_migrations` row. Re-introducing the change is a NEW migration,
-- never a re-run of 224. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    r record;
    v_found text;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('public.epigraph_oauth_code_consume(bytea)',
         'bf87c27d8878585429e0bc531deba9bc', '557b8c5bd66e3ac316aaf033b2e08e17'),
        ('public.epigraph_oauth_session_to_consent(text, text, uuid, text[])',
         'c7c76dddde6d0d16f4961da05ca64f34', 'fdfeaeb7169e0791a66861b656cd9f9f'),
        ('public.epigraph_oauth_session_take(text)',
         'b180756ccecd2967557393b119a309f4', '91f41caf88884d22b7fe36825ed65653'),
        ('public.epigraph_oauth_client_lock_for_link(uuid)',
         '9828f2761f7a996e309784573ac29488', '9828f2761f7a996e309784573ac29488'),
        ('public.epigraph_oauth_client_link_agent(uuid, uuid)',
         'efcbd12d06a81b530e7cbdffaf19a34f', 'e5866f127def85941627fd481636e864'),
        ('public.epigraph_oauth_client_approve(uuid, text[], uuid)',
         '05515492ef7b666f728f9caeb48967fe', '93410ab4e684da44da38fd5ddd8d91d3'))
        AS t(sig, md5_224, md5_118)
    LOOP
        SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
         WHERE p.oid = pg_catalog.to_regprocedure(r.sig);
        IF v_found IS NULL OR v_found NOT IN (r.md5_224, r.md5_118) THEN
            RAISE EXCEPTION '224-undo: % is neither 224''s body nor 118''s; found md5 %. '
                            'Nothing was changed', r.sig, COALESCE(v_found, '(absent)')
                USING ERRCODE = '55000';
        END IF;
    END LOOP;
END $$;

-- 118's body of `epigraph_oauth_code_consume`.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_code_consume(p_code_hash bytea)
RETURNS SETOF public.oauth_authorization_codes
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
    UPDATE public.oauth_authorization_codes
       SET used_at = now()
     WHERE code_hash = p_code_hash AND used_at IS NULL AND expires_at > now()
    RETURNING *;
$$;

-- 118's body of `epigraph_oauth_session_to_consent`.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_session_to_consent(
    p_from_state text, p_to_state text, p_resolved_oauth_client_id uuid, p_granted_scopes text[])
RETURNS SETOF public.oauth_authorize_sessions
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
    UPDATE public.oauth_authorize_sessions
       SET state = p_to_state, resolved_oauth_client_id = p_resolved_oauth_client_id,
           granted_scopes = p_granted_scopes
     WHERE state = p_from_state AND expires_at > now()
    RETURNING *;
$$;

-- 118's body of `epigraph_oauth_session_take`.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_session_take(p_state text)
RETURNS SETOF public.oauth_authorize_sessions
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
    DELETE FROM public.oauth_authorize_sessions
     WHERE state = p_state AND expires_at > now()
    RETURNING *;
$$;

-- 118's body of `epigraph_oauth_client_lock_for_link` (224's, byte for byte).
CREATE OR REPLACE FUNCTION public.epigraph_oauth_client_lock_for_link(p_id uuid)
RETURNS TABLE (agent_id uuid, client_id text, client_type text)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
    SELECT c.agent_id, c.client_id::text, c.client_type::text
      FROM public.oauth_clients c
     WHERE c.id = p_id
       FOR UPDATE;
$$;

-- 118's body of `epigraph_oauth_client_link_agent`.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_client_link_agent(p_id uuid, p_agent_id uuid)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
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

-- 118's body of `epigraph_oauth_client_approve`.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_client_approve(
    p_id uuid, p_granted_scopes text[], p_approved_by uuid)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
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

COMMIT;
