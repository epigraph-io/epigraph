-- 172: the refresh-token rotation definer resolves its built-ins in pg_catalog
-- only (backlog 1228c284).
--
-- EVIDENCE
-- 140's `epigraph_refresh_token_rotate` is SECURITY DEFINER with
-- `SET search_path = pg_catalog, public` and calls `unnest(...)` and `now()`
-- unqualified. Listing pg_catalog first does not keep a call in pg_catalog:
-- PostgreSQL prefers an EXACT argument-type match over a polymorphic one
-- before it consults search_path order, so a `public.unnest(text[])` is chosen
-- over `pg_catalog.unnest(anyarray)` wherever `public` sits in the path, and it
-- runs with the definer owner's privileges. Creating such an overload needs
-- CREATE on `public`, which no application role should hold; the contract a
-- SECURITY DEFINER body has to meet is that it never resolves to an object a
-- less-privileged role could create.
--
-- CHANGE
-- 140's body with these changes and no other (one line is re-wrapped):
--   * `SET search_path = pg_catalog, pg_temp`. `public` leaves the path; every
--     table and function the body names in `public` is already
--     schema-qualified. `pg_temp` is listed LAST so it is not searched first
--     (an omitted `pg_temp` is implicitly searched FIRST for relations).
--   * `unnest(` and `now()` are written `pg_catalog.unnest(` and
--     `pg_catalog.now()`, so the body states its resolution rather than relying
--     on the path alone.
-- Signature, `RETURNS TABLE`, behaviour, owner and ACL are unchanged; owner and
-- grant are re-asserted below, idempotently, as 140 does.
--
-- NOT CHANGED HERE: other SECURITY DEFINER bodies of this class remain; they
-- are left for the backlog 1228c284 sweep.
--
-- A LATER MIGRATION THAT RE-STATES THIS FUNCTION must start from this body,
-- not 140's: `schema_contract.rs::migration_140_rotate_definer_keeps_owner_
-- grant_and_search_path` reads the catalog at head and fails if the path or a
-- qualification is lost.
--
-- UNDO: re-run 140's `CREATE OR REPLACE FUNCTION
-- public.epigraph_refresh_token_rotate` block verbatim (owner and ACL survive
-- `CREATE OR REPLACE`).
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_rotate(
    p_old_hash bytea, p_new_hash bytea, p_new_expires_at timestamptz)
RETURNS TABLE (outcome text, token_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_client uuid;
    v_family uuid;
    v_old_scopes text[];
    v_scopes text[];
    v_ttl interval;
    v_new uuid;
BEGIN
    IF p_new_hash IS NULL OR p_new_expires_at IS NULL OR p_new_expires_at <= pg_catalog.now() THEN
        RAISE EXCEPTION 'RT01: a rotation needs a successor hash and a future expiry'
            USING ERRCODE = '22023';
    END IF;
    UPDATE public.refresh_tokens t
       SET revoked_at = pg_catalog.now(), revoked_reason = 'rotated'
     WHERE t.token_hash = p_old_hash AND t.revoked_at IS NULL AND t.expires_at > pg_catalog.now()
    RETURNING t.client_id, COALESCE(t.family_id, t.id), t.scopes
         INTO v_client, v_family, v_old_scopes;
    IF NOT FOUND THEN
        RETURN QUERY SELECT public.epigraph_refresh_token_on_reuse(p_old_hash), NULL::uuid;
        RETURN;
    END IF;
    SELECT ARRAY(SELECT o.s
                   FROM pg_catalog.unnest(COALESCE(v_old_scopes, ARRAY[]::text[]))
                        WITH ORDINALITY AS o(s, ord)
                  WHERE o.s = ANY (COALESCE(c.granted_scopes, ARRAY[]::text[]))
                  ORDER BY o.ord),
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
            LEAST(p_new_expires_at, pg_catalog.now() + COALESCE(v_ttl, interval '24 hours')),
            v_family)
    RETURNING id INTO v_new;
    RETURN QUERY SELECT 'rotated'::text, v_new;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refresh_token_rotate(bytea, bytea, timestamptz)
    FROM PUBLIC;

-- Owner and grant as 118 section 3e and 140 left them (`CREATE OR REPLACE`
-- keeps both; re-asserted so a database where they drifted is corrected here).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_refresh_token_rotate(bytea, bytea, timestamptz) OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_refresh_token_rotate(bytea, bytea, timestamptz) TO epigraph_app';
    END IF;
END $$;
