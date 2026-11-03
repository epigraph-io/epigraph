-- 190: every SECURITY DEFINER function lists `pg_temp` LAST on its pinned
-- `search_path`, and the OAuth refresh-token and access-token revocation
-- definers resolve their names in pg_catalog only (backlog 368ce622).
--
-- EVIDENCE (measured on a database migrated to 186)
-- 207 SECURITY DEFINER functions, all in `public`, all with a `search_path`
-- pinned: 174 `public, pg_temp`, 4 `pg_catalog, pg_temp` (172's form), and 29
-- `pg_catalog, public` with no `pg_temp`. A path that does not list `pg_temp`
-- searches the session's temporary schema FIRST for relation and type names
-- (PostgreSQL's documented resolution order); listing it last puts it after
-- every other schema. Separately, a path that lists `public` resolves
-- unqualified built-in calls through it (172's header); the form that does not
-- depend on `public` is `pg_catalog, pg_temp` with every name qualified.
--
-- CHANGE
-- 1. The refresh-token and access-token revocation family (the family the
--    backlog item names first; 172 already moved its rotate definer):
--    `epigraph_refresh_token_on_reuse`, `_check`, `_revoke`,
--    `_revoke_by_hash`, `_revoke_client` (118) and
--    `epigraph_access_token_revoke` (141) are re-stated on 172's form:
--    `SET search_path = pg_catalog, pg_temp`, with `now()` and
--    `jsonb_build_object(` written `pg_catalog.now()` and
--    `pg_catalog.jsonb_build_object(`. Each body is its 118 / 141 body with
--    those qualifiers inserted and no other byte changed; every table and
--    function they name was already `public.`-qualified. Signature, return
--    type, volatility, behaviour, owner and ACL are unchanged
--    (`CREATE OR REPLACE` keeps owner and ACL, and this file grants and
--    revokes nothing). A precondition refuses to run (55000, nothing changed)
--    unless all six still carry those bodies (md5 of `prosrc`).
-- 2. A catalog sweep: every SECURITY DEFINER function outside the system
--    schemas and outside any extension whose path does not list `pg_temp`
--    LAST gets `, pg_temp` appended (`ALTER FUNCTION .. SET search_path`,
--    which changes that one configuration entry and neither the body nor any
--    other entry, so 184's `epigraph.mf_unretract_id` survives). A definer
--    with no path at all gets `pg_catalog, <its schema>, pg_temp` (none exists
--    at 186). A path that lists `pg_temp` anywhere but last (including one
--    that also lists it last) is refused (55000, nothing changed), not
--    guessed at (none exists at 186). The sweep reads the catalog, so it also
--    covers a definer a lower-numbered migration created before this file is
--    applied. Each change is reported as a NOTICE.
-- 3. A postcondition refuses (55000) if any definer still lacks a trailing
--    `pg_temp` or lists it before another schema.
--
-- NOT CHANGED HERE: the 197 definers that keep `public` on the path. Moving
-- each to 172's form needs its body re-stated with every name qualified,
-- family by family; `crates/epigraph-db/tests/definer_search_path_ratchet.rs`
-- records them (`PUBLIC_PATH_REGISTER`, which may only shrink) and fails on a
-- new definer that is unpinned, does not list `pg_temp` last, or resolves
-- through `public` without being registered.
--
-- A LATER MIGRATION THAT RE-STATES ONE OF THE SIX must start from this body:
-- the ratchet's `the_refresh_and_revocation_family_resolves_in_pg_catalog_only`
-- reads the catalog at head. A later `CREATE OR REPLACE` of ANY definer must
-- pin a path that lists `pg_temp` last (it replaces the path this file set).
-- A definer created by a migration numbered below 190 that is applied AFTER
-- 190 is not swept by it, so it must pin `pg_temp` last itself.
--
-- UNDO (re-opens the resolution order described above):
-- (a) Re-run, verbatim, only the `CREATE OR REPLACE FUNCTION` statements of
--     these six functions, and no GRANT or REVOKE (owner and ACL survive a
--     replace; a re-grant would undo later revokes): from 118 section 3a,
--     epigraph_refresh_token_on_reuse, epigraph_refresh_token_check,
--     epigraph_refresh_token_revoke, epigraph_refresh_token_revoke_by_hash,
--     epigraph_refresh_token_revoke_client (NOT epigraph_refresh_token_rotate,
--     whose current body is 172's); from 141, epigraph_access_token_revoke.
-- (b) Set the path back to `pg_catalog, public` on the 23 other definers the
--     sweep changed at 186 (each was `pg_catalog, public` and is
--     `pg_catalog, public, pg_temp` after 190; no definer had that path
--     before 190):
--       epigraph_admin_audit_write(uuid, uuid, uuid, text, jsonb)
--       epigraph_admin_patch_claim(uuid, uuid, uuid, text, text[], text[], jsonb, uuid)
--       epigraph_agent_key_set_status(uuid, text, text, uuid)
--       epigraph_cascade_delete_edge_bbas(uuid[], text)
--       epigraph_dedup_move_bbas(uuid, uuid, uuid[])
--       epigraph_foreign_aggregate_audit(uuid, uuid, text, jsonb, jsonb)
--       epigraph_foreign_aggregate_target(uuid)
--       epigraph_foreign_belief_cache(uuid, double precision, double precision,
--         double precision, double precision, double precision, uuid)
--       epigraph_foreign_belief_clear(uuid)
--       epigraph_foreign_claim_classification(uuid, text, uuid)
--       epigraph_foreign_claim_frame(uuid, uuid, integer)
--       epigraph_oauth_client_approve(uuid, text[], uuid)
--       epigraph_oauth_client_link_agent(uuid, uuid)
--       epigraph_oauth_client_lock_for_link(uuid)
--       epigraph_oauth_code_consume(bytea)
--       epigraph_oauth_session_take(text)
--       epigraph_oauth_session_to_consent(text, text, uuid, text[])
--       epigraph_record_cascade_deferral(text, uuid, uuid, uuid, uuid[], jsonb, text)
--       epigraph_reown_legacy_edges_to_signer(integer, uuid[])
--       epigraph_reown_legacy_writer_bbas(integer)
--       epigraph_resolve_challenge(uuid, text, jsonb)
--       epigraph_retract_mass_function(uuid, text, uuid, uuid)
--       epigraph_unretract_mass_function(uuid, text, uuid, uuid)
--     (all in `public`). A definer a later migration created on
--     `pg_catalog, public, pg_temp` is not one of these; do not revert it.
SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- 1a. Precondition: the six functions still carry the bodies this file
-- re-states (118's and 141's). CREATE OR REPLACE replaces a body whole, so
-- applying this over any other body would silently drop that body's change.
-- Refuse instead. The md5 is of `prosrc`, the exact text between the dollar
-- quotes.
-- -------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_found text;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('public.epigraph_refresh_token_on_reuse(bytea)', '6c3b19a5c95de580fa94edae17ab215f'),
        ('public.epigraph_refresh_token_check(bytea)', '7a0a18ac278a89b33116b398b15b5b86'),
        ('public.epigraph_refresh_token_revoke(uuid, text)', '4b72ecd708b56548ca5eae0b0e9e8fbb'),
        ('public.epigraph_refresh_token_revoke_by_hash(bytea)', '2dbf94a861a1020d05fa4ff6b9707da0'),
        ('public.epigraph_refresh_token_revoke_client(uuid)', 'b93fe7a640463f95d787ed7ca18d4e7f'),
        ('public.epigraph_access_token_revoke(uuid, uuid, timestamptz)', 'db8ef29ed9fbd29ee7956b568f20390e')) AS t(sig, md5)
    LOOP
        SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
         WHERE p.oid = pg_catalog.to_regprocedure(r.sig);
        IF v_found IS DISTINCT FROM r.md5 THEN
            RAISE EXCEPTION '190: % is not the body 190 re-states (md5 %); found md5 %. '
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
-- 1b. The six bodies on 172's form. Delta from 118 / 141: the path, and the
-- `pg_catalog.` qualifiers; nothing else.
-- -------------------------------------------------------------------
-- 118's body of `epigraph_refresh_token_on_reuse`.
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_on_reuse(p_hash bytea)
RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
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
    IF v_revoked_at > pg_catalog.now() - interval '30 seconds' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('oauth.refresh_token_grace', NULL, false,
                pg_catalog.jsonb_build_object('client_id', v_client, 'family_id', v_family,
                                   'presented_token_id', v_id, 'migration', 118));
        RETURN 'grace';
    END IF;
    UPDATE public.refresh_tokens
       SET revoked_at = pg_catalog.now(), revoked_reason = 'reuse'
     WHERE COALESCE(family_id, id) = v_family AND revoked_at IS NULL;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('oauth.refresh_token_reuse', NULL, false,
            pg_catalog.jsonb_build_object('client_id', v_client, 'family_id', v_family,
                               'presented_token_id', v_id, 'revoked', v_n,
                               'migration', 118));
    RETURN 'reuse';
END $$;

-- 118's body of `epigraph_refresh_token_check`.
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_check(p_hash bytea)
RETURNS TABLE (outcome text, token_id uuid, client_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RETURN QUERY
        SELECT 'valid'::text, t.id, t.client_id
          FROM public.refresh_tokens t
         WHERE t.token_hash = p_hash AND t.revoked_at IS NULL AND t.expires_at > pg_catalog.now();
    IF FOUND THEN
        RETURN;
    END IF;
    RETURN QUERY SELECT public.epigraph_refresh_token_on_reuse(p_hash), NULL::uuid, NULL::uuid;
END $$;

-- 118's body of `epigraph_refresh_token_revoke`.
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_revoke(p_id uuid, p_reason text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_reason IS NULL OR p_reason NOT IN ('denied', 'revoked') THEN
        RAISE EXCEPTION 'RT02: a revocation reason is denied or revoked, not %', p_reason
            USING ERRCODE = '22023';
    END IF;
    UPDATE public.refresh_tokens
       SET revoked_at = pg_catalog.now(), revoked_reason = p_reason
     WHERE id = p_id AND revoked_at IS NULL;
    RETURN FOUND;
END $$;

-- 118's body of `epigraph_refresh_token_revoke_by_hash`.
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_revoke_by_hash(p_hash bytea)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE public.refresh_tokens
       SET revoked_at = pg_catalog.now(), revoked_reason = 'revoked'
     WHERE token_hash = p_hash AND revoked_at IS NULL AND expires_at > pg_catalog.now();
    RETURN FOUND;
END $$;

-- 118's body of `epigraph_refresh_token_revoke_client`.
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_revoke_client(p_client_id uuid)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_n bigint;
BEGIN
    UPDATE public.refresh_tokens
       SET revoked_at = pg_catalog.now(), revoked_reason = 'client'
     WHERE client_id = p_client_id AND revoked_at IS NULL;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n;
END $$;

-- 141's body of `epigraph_access_token_revoke`.
CREATE OR REPLACE FUNCTION public.epigraph_access_token_revoke(
    p_jti uuid, p_client_id uuid, p_expires_at timestamptz)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_jti IS NULL OR p_client_id IS NULL OR p_expires_at IS NULL THEN
        RAISE EXCEPTION 'AT01: an access-token revocation names a jti, a client and an expiry'
            USING ERRCODE = '22023';
    END IF;
    -- Both margins are the clock-skew allowance in the header: keep them equal.
    DELETE FROM public.revoked_access_tokens
     WHERE expires_at < pg_catalog.now() - interval '24 hours';
    IF p_expires_at <= pg_catalog.now() - interval '24 hours' THEN
        RETURN false;
    END IF;
    INSERT INTO public.revoked_access_tokens (jti, client_id, expires_at)
    VALUES (p_jti, p_client_id, p_expires_at)
    ON CONFLICT (jti) DO NOTHING;
    RETURN FOUND;
END $$;

-- -------------------------------------------------------------------
-- 2. The sweep: `pg_temp` LAST on every definer's path.
-- -------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_items text[];
    v_new text;
BEGIN
    FOR r IN
        SELECT p.oid::pg_catalog.regprocedure AS sig, n.nspname,
               (SELECT pg_catalog.substr(c, 13) FROM pg_catalog.unnest(p.proconfig) c
                 WHERE c LIKE 'search_path=%' LIMIT 1) AS path
          FROM pg_catalog.pg_proc p
          JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
         WHERE p.prosecdef
           AND n.nspname NOT IN ('pg_catalog', 'information_schema')
           AND n.nspname !~ '^pg_(toast|temp)'
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                            WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
                              AND d.objid = p.oid AND d.deptype = 'e')
         ORDER BY p.oid::pg_catalog.regprocedure::text
    LOOP
        IF r.path IS NULL THEN
            v_new := pg_catalog.format('pg_catalog, %I, pg_temp', r.nspname);
        ELSE
            v_items := pg_catalog.string_to_array(
                pg_catalog.regexp_replace(r.path, '[\s"]', '', 'g'), ',');
            -- Refuse first: a path listing pg_temp before its last item
            -- (`pg_temp, public` or `pg_temp, public, pg_temp`) is searched
            -- in that order whatever follows, so appending cannot fix it.
            IF 'pg_temp' = ANY (v_items[1:pg_catalog.array_upper(v_items, 1) - 1]) THEN
                RAISE EXCEPTION '190: % lists pg_temp before another schema (search_path=%); '
                                'nothing was changed', r.sig, r.path
                    USING ERRCODE = '55000',
                          HINT = 'Re-state it with pg_temp last, then apply 190.';
            END IF;
            IF v_items[pg_catalog.array_upper(v_items, 1)] = 'pg_temp' THEN
                CONTINUE;
            END IF;
            v_new := r.path || ', pg_temp';
        END IF;
        RAISE NOTICE '190: % search_path % -> %', r.sig, COALESCE(r.path, '(unpinned)'), v_new;
        EXECUTE pg_catalog.format('ALTER FUNCTION %s SET search_path = %s', r.sig, v_new);
    END LOOP;
END $$;

-- -------------------------------------------------------------------
-- 3. Postcondition.
-- -------------------------------------------------------------------
DO $$
DECLARE
    v_bad text;
BEGIN
    SELECT pg_catalog.string_agg(p.oid::pg_catalog.regprocedure::text, ', ') INTO v_bad
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE p.prosecdef
       AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND n.nspname !~ '^pg_(toast|temp)'
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                        WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
                          AND d.objid = p.oid AND d.deptype = 'e')
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(p.proconfig) c
                        WHERE c ~ '^search_path=(.*[ ,"])?pg_temp"?$'
                          AND pg_catalog.regexp_replace(c, '[\s"]', '', 'g') !~ '[=,]pg_temp,');
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION '190: definers without pg_temp listed only last remain: %', v_bad
            USING ERRCODE = '55000';
    END IF;
END $$;
