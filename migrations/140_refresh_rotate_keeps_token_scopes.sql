-- Migration 140: a refresh-token rotation keeps the PRESENTED token's scopes
-- (narrowed to the client's current grant), not the client's whole grant.
--
-- EVIDENCE
-- 118's `epigraph_refresh_token_rotate` gave the successor
-- `oauth_clients.granted_scopes`, and the refresh grant minted its access token
-- from the same array. The authorization-code grant mints the FIRST refresh
-- token from the consent (`requested ∩ granted`, authorize.rs), keyed to the
-- per-user human client, so the first refresh widened a consent narrowed to
-- `claims:read` to everything the human holds (for a Google user, the
-- provider's default write scopes). `client_credentials` with a narrowing
-- `scope` widened the same way. RFC 6749 section 6: the refreshed token "MUST
-- NOT include any scope not originally granted by the resource owner".
--
-- CHANGE
-- The same body as 118 with one difference: the claim of the presented token
-- also returns its `scopes`, and the successor's scopes are those scopes that
-- the client is still granted, in the presented token's order. A grant revoked
-- since the consent therefore still leaves the chain at its next rotation; a
-- grant added since does not reach it (the human re-consents instead). The
-- signature, `RETURNS TABLE`, owner and ACL are unchanged; owner and grant are
-- re-asserted below, idempotently.
--
-- The request path (`oauth/token.rs::handle_refresh_token`) computes the same
-- intersection from the scopes `RefreshTokenRepository::check` reads. The two
-- read `granted_scopes` at different moments; a grant changed in between can
-- only make the stored successor narrower than the issued access token's
-- ceiling, never wider.
--
-- Existing rows keep what they store. Chains rotated under 118 already carry
-- the client's whole grant, and this file does NOT heal them: every rotation
-- re-caps the successor's expiry at now() + the client type's TTL and nothing
-- caps a family's age, so a chain refreshed at least once per TTL never
-- expires, and its whole-grant scopes rotate into each successor (they are
-- still within the grant). Only revoking such families (forcing a fresh
-- consent) narrows them; that is an operator decision, not this file's.
--
-- UNDO: re-run 118's `CREATE OR REPLACE FUNCTION
-- public.epigraph_refresh_token_rotate` block verbatim (owner and ACL survive
-- `CREATE OR REPLACE`).
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_rotate(
    p_old_hash bytea, p_new_hash bytea, p_new_expires_at timestamptz)
RETURNS TABLE (outcome text, token_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
    v_client uuid;
    v_family uuid;
    v_old_scopes text[];
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
    RETURNING t.client_id, COALESCE(t.family_id, t.id), t.scopes
         INTO v_client, v_family, v_old_scopes;
    IF NOT FOUND THEN
        RETURN QUERY SELECT public.epigraph_refresh_token_on_reuse(p_old_hash), NULL::uuid;
        RETURN;
    END IF;
    SELECT ARRAY(SELECT o.s
                   FROM unnest(COALESCE(v_old_scopes, ARRAY[]::text[]))
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
            LEAST(p_new_expires_at, now() + COALESCE(v_ttl, interval '24 hours')), v_family)
    RETURNING id INTO v_new;
    RETURN QUERY SELECT 'rotated'::text, v_new;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refresh_token_rotate(bytea, bytea, timestamptz)
    FROM PUBLIC;

-- Owner and grant as 118 section 3e left them (`CREATE OR REPLACE` keeps both;
-- re-asserted so a database where they drifted is corrected here).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_refresh_token_rotate(bytea, bytea, timestamptz) OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_refresh_token_rotate(bytea, bytea, timestamptz) TO epigraph_app';
    END IF;
END $$;
