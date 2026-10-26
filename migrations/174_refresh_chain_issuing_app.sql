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
-- 2. The binding survives every rotation through a BEFORE INSERT trigger,
--    `refresh_tokens_inherit_issuing_app`: a successor row (one inserted with
--    a `family_id`) that names no app takes the app of its family's bound
--    rows. `epigraph_refresh_token_rotate` is NOT restated here. The backlog
--    item suggested carrying the column through the rotate definer; a
--    restatement here would be one more full copy of that definer's body, and
--    whichever restatement applied last would decide both the carry and the
--    definer's hardening (its pinned `search_path` and pg_catalog-qualified
--    built-ins, backlog 1228c284), depending on the order the migrations
--    apply. The trigger is independent of the rotate body, so every body
--    (140's or any later restatement) yields bound successors and this
--    migration commutes with any migration that restates the rotate definer.
--    The trigger reads ANY bound row of the family, not only its first row:
--    `RefreshTokenRepository::cleanup_expired` deletes expired rows, and a
--    chain's first row can expire while its successors live. The row the
--    rotation has just spent is always present (rotate refuses an expired
--    one). A partial index over the bound rows keeps the lookup an index
--    probe; it is empty when built (every existing row is unbound).
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
-- Both new functions set `search_path = pg_catalog, pg_temp` and name their
-- built-ins in pg_catalog, so neither resolves a name `public` could shadow.
--
-- Existing rows keep NULL and stay unbound: a chain minted before this
-- migration is not tied to any app until its person re-consents (a new code
-- exchange). Nothing is backfilled; the hand-off that would say which app a
-- chain came from was never recorded.
--
-- DEPLOY ORDER: this migration BEFORE the API binary built against it. That
-- binary reads `issued_to_client_id` on every refresh and writes it on every
-- refresh-token mint, so on a database without 174 every grant that mints or
-- refreshes a refresh token fails (the code exchange, `client_credentials`,
-- the external-provider grants and the refresh grant). The previous binary
-- runs unchanged on a migrated database. Order relative to a migration that
-- restates `epigraph_refresh_token_rotate` does not matter (see 2).
--
-- UNDO (roll the API binary back first):
--   DROP TRIGGER IF EXISTS refresh_tokens_inherit_issuing_app ON public.refresh_tokens;
--   DROP FUNCTION IF EXISTS public.epigraph_refresh_token_inherit_issuing_app();
--   DROP FUNCTION IF EXISTS public.epigraph_refresh_token_revoke_client_app(uuid, uuid);
--   DROP INDEX IF EXISTS public.refresh_tokens_bound_family_idx;
--   ALTER TABLE public.refresh_tokens DROP COLUMN IF EXISTS issued_to_client_id;
SET LOCAL lock_timeout = '3s';

-- 1. The binding column.
ALTER TABLE public.refresh_tokens ADD COLUMN IF NOT EXISTS issued_to_client_id uuid;
COMMENT ON COLUMN public.refresh_tokens.issued_to_client_id IS
    'Migration 174: the oauth_clients.id of the connector app that obtained this chain '
    '(set at the authorization-code exchange, inherited by every rotation through the '
    'refresh_tokens_inherit_issuing_app trigger); NULL for grants with no separate app and '
    'for chains minted before 174. No foreign key: the refresh grant reads an app it '
    'cannot find as not active.';

-- 2. Every successor inherits its family's binding.
CREATE INDEX IF NOT EXISTS refresh_tokens_bound_family_idx
    ON public.refresh_tokens ((COALESCE(family_id, id)))
    WHERE issued_to_client_id IS NOT NULL;

CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_inherit_issuing_app()
RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.family_id IS NOT NULL AND NEW.issued_to_client_id IS NULL THEN
        SELECT t.issued_to_client_id
          INTO NEW.issued_to_client_id
          FROM public.refresh_tokens t
         WHERE COALESCE(t.family_id, t.id) = NEW.family_id
           AND t.issued_to_client_id IS NOT NULL
         LIMIT 1;
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refresh_token_inherit_issuing_app() FROM PUBLIC;

DROP TRIGGER IF EXISTS refresh_tokens_inherit_issuing_app ON public.refresh_tokens;
CREATE TRIGGER refresh_tokens_inherit_issuing_app
    BEFORE INSERT ON public.refresh_tokens
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_refresh_token_inherit_issuing_app();

-- 3. The operator revoke keyed by (person, app).
CREATE OR REPLACE FUNCTION public.epigraph_refresh_token_revoke_client_app(
    p_client_id uuid, p_app_client_id uuid)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_n bigint;
BEGIN
    IF p_client_id IS NULL OR p_app_client_id IS NULL THEN
        RAISE EXCEPTION 'RT03: a per-app revoke names both the client and the app'
            USING ERRCODE = '22023';
    END IF;
    UPDATE public.refresh_tokens
       SET revoked_at = pg_catalog.now(), revoked_reason = 'client'
     WHERE client_id = p_client_id AND issued_to_client_id = p_app_client_id
       AND revoked_at IS NULL;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refresh_token_revoke_client_app(uuid, uuid)
    FROM PUBLIC;

-- Grants. The per-app revoke to the maintenance role only. The new column to
-- the application role (118 replaced its table SELECT with a column list; a
-- column GRANT is additive). The trigger function needs no EXECUTE grant: a
-- trigger fires without one.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_refresh_token_revoke_client_app(uuid, uuid) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT SELECT (issued_to_client_id) ON public.refresh_tokens TO epigraph_app';
    END IF;
END $$;
