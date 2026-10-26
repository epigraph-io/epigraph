-- Migration 174: an authorization-code refresh chain is bound to the connector
-- app that obtained it (backlog 7a2111e6).
--
-- EVIDENCE
-- The code exchange (`oauth/token.rs::handle_authorization_code`) checks the
-- requesting app against the code's `client_id`, then mints the refresh row
-- under the per-user HUMAN client (`oauth_authorization_codes.oauth_client_id`),
-- so the app's identity was lost at the hand-off, and the refresh grant only
-- ever consulted the human client. Suspending one connector app (a dynamically
-- registered client) stopped its new `/authorize` calls while its live chains
-- kept rotating. The only lever was
-- `epigraph_refresh_token_revoke_client(<human client>)`, which logs that
-- person out of every connector (and, through migration 125's trigger, ends
-- their elevation sessions).
--
-- CHANGE
-- 1. `refresh_tokens.issued_to_client_id`: the `oauth_clients.id` of the app
--    that obtained the chain. Set by the code exchange (NULL for every other
--    grant: `client_credentials`, the external-provider grants, which have no
--    separate app). Readable by the application role (column grant), which the
--    refresh grant needs to check the app's status. NO foreign key, on
--    purpose: a NO ACTION/RESTRICT key would block deleting an orphaned app
--    while it holds chains, SET NULL would silently UNBIND a chain from a
--    deleted app, and CASCADE would delete credential rows behind 125's
--    UPDATE trigger. The refresh grant instead reads an app it cannot find as
--    not active (fail closed): the chain is refused and burned.
-- 2. `epigraph_refresh_token_rotate`: 140's body with one difference, the
--    successor carries the presented token's `issued_to_client_id`, so the
--    binding survives every rotation. Signature, `RETURNS TABLE`, owner, ACL
--    and the pinned `search_path` are unchanged; owner and grant are
--    re-asserted below, idempotently, as 140 does.
-- 3. `epigraph_refresh_token_revoke_client_app(p_client_id, p_app_client_id)`:
--    the operator revoke keyed by (person, app). It revokes the live tokens of
--    the per-user client `p_client_id` that were issued to the app
--    `p_app_client_id` (reason `client`, as `revoke_client`), and returns how
--    many. SECURITY INVOKER: it runs with the caller's privileges, so only a
--    role that may already UPDATE `refresh_tokens` (the maintenance role) can
--    use it, and EXECUTE is granted to the maintenance role alone. Migration
--    125's `refresh_tokens_end_elevations` trigger ends the elevation
--    sessions of the families it revokes, exactly as for any other revoke.
--
-- Existing rows keep NULL and stay unbound: a chain minted before this
-- migration is not tied to any app until its person re-consents (a new code
-- exchange). Nothing is backfilled; the hand-off that would say which app a
-- chain came from was never recorded.
--
-- DEPLOY ORDER: this migration BEFORE the API binary built against it (that
-- binary's refresh grant reads `issued_to_client_id`, and its code exchange
-- writes it). The previous binary runs unchanged on a migrated database.
--
-- UNDO (roll the API binary back first): re-run 140's `CREATE OR REPLACE
-- FUNCTION public.epigraph_refresh_token_rotate` block verbatim (owner and ACL
-- survive `CREATE OR REPLACE`), then
--   DROP FUNCTION IF EXISTS public.epigraph_refresh_token_revoke_client_app(uuid, uuid);
--   ALTER TABLE public.refresh_tokens DROP COLUMN IF EXISTS issued_to_client_id;
SET LOCAL lock_timeout = '3s';

-- 1. The binding column.
ALTER TABLE public.refresh_tokens ADD COLUMN IF NOT EXISTS issued_to_client_id uuid;
COMMENT ON COLUMN public.refresh_tokens.issued_to_client_id IS
    'Migration 174: the oauth_clients.id of the connector app that obtained this chain '
    '(set at the authorization-code exchange, carried through every rotation); NULL for '
    'grants with no separate app and for chains minted before 174. No foreign key: the '
    'refresh grant reads an app it cannot find as not active.';

-- 2. The rotation carries the binding.
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_rotate(
    p_old_hash bytea, p_new_hash bytea, p_new_expires_at timestamptz)
RETURNS TABLE (outcome text, token_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
    v_client uuid;
    v_family uuid;
    v_old_scopes text[];
    v_issued_to uuid;
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
    RETURNING t.client_id, COALESCE(t.family_id, t.id), t.scopes, t.issued_to_client_id
         INTO v_client, v_family, v_old_scopes, v_issued_to;
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
    INSERT INTO public.refresh_tokens
           (token_hash, client_id, scopes, expires_at, family_id, issued_to_client_id)
    VALUES (p_new_hash, v_client, COALESCE(v_scopes, ARRAY[]::text[]),
            LEAST(p_new_expires_at, now() + COALESCE(v_ttl, interval '24 hours')), v_family,
            v_issued_to)
    RETURNING id INTO v_new;
    RETURN QUERY SELECT 'rotated'::text, v_new;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refresh_token_rotate(bytea, bytea, timestamptz)
    FROM PUBLIC;

-- 3. The operator revoke keyed by (person, app).
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_revoke_client_app(
    p_client_id uuid, p_app_client_id uuid)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
DECLARE v_n bigint;
BEGIN
    IF p_client_id IS NULL OR p_app_client_id IS NULL THEN
        RAISE EXCEPTION 'RT03: a per-app revoke names both the client and the app'
            USING ERRCODE = '22023';
    END IF;
    UPDATE public.refresh_tokens
       SET revoked_at = now(), revoked_reason = 'client'
     WHERE client_id = p_client_id AND issued_to_client_id = p_app_client_id
       AND revoked_at IS NULL;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refresh_token_revoke_client_app(uuid, uuid)
    FROM PUBLIC;

-- Owners and grants. The rotate definer as 118 section 3e and 140 left it
-- (`CREATE OR REPLACE` keeps both; re-asserted so a database where they drifted
-- is corrected here). The per-app revoke to the maintenance role only. The new
-- column to the application role (118 replaced its table SELECT with a column
-- list; a column GRANT is additive).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_refresh_token_rotate(bytea, bytea, timestamptz) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_refresh_token_revoke_client_app(uuid, uuid) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_refresh_token_rotate(bytea, bytea, timestamptz) TO epigraph_app';
        EXECUTE 'GRANT SELECT (issued_to_client_id) ON public.refresh_tokens TO epigraph_app';
    END IF;
END $$;
