-- 224: the OAuth authorization-code, authorize-session and client definers
-- resolve their names in pg_catalog only (backlog 368ce622, the next family
-- after 190's refresh-token and access-token revocation family).
--
-- EVIDENCE (read on a database migrated to 221)
-- 118 sections 3b and 3c created six SECURITY DEFINER functions on
-- `SET search_path = pg_catalog, public`; 190's sweep appended `pg_temp`, so
-- each runs on `pg_catalog, public, pg_temp`, owner `epigraph_maintenance`.
-- On that path an unqualified built-in call is resolved over pg_catalog AND
-- public, and a public function whose argument types match the call more
-- exactly than the built-in's polymorphic signature wins (the resolution
-- 172 fixed for `unnest`, backlog 1228c284). `epigraph_oauth_client_approve`
-- writes its audit row with `to_jsonb(text[])` and `jsonb_build_object(..)`:
-- a `public.to_jsonb(text[])` decides the `granted_scopes` the
-- `oauth.client_approved` event records, and runs as the definer's owner.
-- The ratchet (`definer_search_path_ratchet.rs`) registers all six in
-- `PUBLIC_PATH_REGISTER`. No migration after 118 re-bodies any of them (188
-- only revokes the application role's EXECUTE on the approve definer).
--
-- CHANGE
-- 1. A precondition refuses to run (55000, nothing changed) unless all six
--    still carry 118's bodies (md5 of `prosrc`). CREATE OR REPLACE replaces
--    a body whole, so applying this over another body would silently drop
--    that body's change.
-- 2. The six are re-stated on 172's form, `SET search_path = pg_catalog,
--    pg_temp`, with `now()`, `jsonb_build_object(` and `to_jsonb(` written
--    `pg_catalog.now()`, `pg_catalog.jsonb_build_object(` and
--    `pg_catalog.to_jsonb(`. Each body is its 118 body with those qualifiers
--    inserted and no other byte changed: every table and the two row types
--    they name were already `public.`-qualified, and
--    `epigraph_oauth_client_lock_for_link` calls no function, so its body is
--    118's byte for byte and only its path moves. Signature, return type,
--    language, volatility, behaviour, owner and ACL are unchanged
--    (`CREATE OR REPLACE` keeps owner and ACL, and this file grants and
--    revokes nothing, so 188's revoke on the approve definer stands).
--
-- NOT CHANGED HERE: the 192 other definers still in `PUBLIC_PATH_REGISTER`.
-- `crates/epigraph-cli/src/bin/tenancy_backfill.rs` keeps the six registered
-- at 118, where they are created (as it keeps 190's family at 118 / 141).
--
-- A LATER MIGRATION THAT RE-STATES ONE OF THE SIX must start from this body
-- and keep `SET search_path = pg_catalog, pg_temp`: the ratchet's
-- `the_oauth_family_resolves_in_pg_catalog_only` reads the catalog at head.
--
-- UNDO: `docs/runbooks/224-undo.sql` (118's bodies on 190's
-- `pg_catalog, public, pg_temp`; guarded by md5, idempotent).
SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- 1. Precondition: the six functions still carry 118's bodies.
-- -------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_found text;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('public.epigraph_oauth_code_consume(bytea)', '557b8c5bd66e3ac316aaf033b2e08e17'),
        ('public.epigraph_oauth_session_to_consent(text, text, uuid, text[])', 'fdfeaeb7169e0791a66861b656cd9f9f'),
        ('public.epigraph_oauth_session_take(text)', '91f41caf88884d22b7fe36825ed65653'),
        ('public.epigraph_oauth_client_lock_for_link(uuid)', '9828f2761f7a996e309784573ac29488'),
        ('public.epigraph_oauth_client_link_agent(uuid, uuid)', 'e5866f127def85941627fd481636e864'),
        ('public.epigraph_oauth_client_approve(uuid, text[], uuid)', '93410ab4e684da44da38fd5ddd8d91d3')) AS t(sig, md5)
    LOOP
        SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
         WHERE p.oid = pg_catalog.to_regprocedure(r.sig);
        IF v_found IS DISTINCT FROM r.md5 THEN
            RAISE EXCEPTION '224: % is not the body 224 re-states (md5 %); found md5 %. '
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
-- 2. The six bodies on 172's form. Delta from 118: the path, and the
-- `pg_catalog.` qualifiers; nothing else.
-- -------------------------------------------------------------------
-- 118's body of `epigraph_oauth_code_consume`.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_code_consume(p_code_hash bytea)
RETURNS SETOF public.oauth_authorization_codes
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    UPDATE public.oauth_authorization_codes
       SET used_at = pg_catalog.now()
     WHERE code_hash = p_code_hash AND used_at IS NULL AND expires_at > pg_catalog.now()
    RETURNING *;
$$;

-- 118's body of `epigraph_oauth_session_to_consent`.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_session_to_consent(
    p_from_state text, p_to_state text, p_resolved_oauth_client_id uuid, p_granted_scopes text[])
RETURNS SETOF public.oauth_authorize_sessions
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    UPDATE public.oauth_authorize_sessions
       SET state = p_to_state, resolved_oauth_client_id = p_resolved_oauth_client_id,
           granted_scopes = p_granted_scopes
     WHERE state = p_from_state AND expires_at > pg_catalog.now()
    RETURNING *;
$$;

-- 118's body of `epigraph_oauth_session_take`.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_session_take(p_state text)
RETURNS SETOF public.oauth_authorize_sessions
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    DELETE FROM public.oauth_authorize_sessions
     WHERE state = p_state AND expires_at > pg_catalog.now()
    RETURNING *;
$$;

-- 118's body of `epigraph_oauth_client_lock_for_link`, byte for byte (it
-- calls no function); only the path moves.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_client_lock_for_link(p_id uuid)
RETURNS TABLE (agent_id uuid, client_id text, client_type text)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT c.agent_id, c.client_id::text, c.client_type::text
      FROM public.oauth_clients c
     WHERE c.id = p_id
       FOR UPDATE;
$$;

-- 118's body of `epigraph_oauth_client_link_agent`.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_client_link_agent(p_id uuid, p_agent_id uuid)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_agent_id IS NULL OR NOT EXISTS (SELECT 1 FROM public.agents a WHERE a.id = p_agent_id) THEN
        RAISE EXCEPTION 'OC01: an OAuth client is linked to an existing agent'
            USING ERRCODE = '23503';
    END IF;
    UPDATE public.oauth_clients
       SET agent_id = p_agent_id, updated_at = pg_catalog.now()
     WHERE id = p_id AND agent_id IS NULL;
    RETURN FOUND;
END $$;

-- 118's body of `epigraph_oauth_client_approve`.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_client_approve(
    p_id uuid, p_granted_scopes text[], p_approved_by uuid)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_prev text;
BEGIN
    SELECT c.status INTO v_prev FROM public.oauth_clients c WHERE c.id = p_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    UPDATE public.oauth_clients
       SET granted_scopes = COALESCE(p_granted_scopes, ARRAY[]::text[]), status = 'active',
           created_by = p_approved_by, updated_at = pg_catalog.now()
     WHERE id = p_id;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('oauth.client_approved', NULL, true,
            pg_catalog.jsonb_build_object('oauth_client_id', p_id, 'approved_by', p_approved_by,
                               'previous_status', v_prev,
                               'granted_scopes', pg_catalog.to_jsonb(COALESCE(p_granted_scopes, ARRAY[]::text[])),
                               'migration', 118));
    RETURN true;
END $$;
