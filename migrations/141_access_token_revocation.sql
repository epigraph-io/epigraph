-- Migration 141: durable RFC 7009 revocation of JWT access tokens (a `jti`
-- denylist), read by the HTTP API and the MCP bearer middleware.
--
-- EVIDENCE
-- `POST /oauth/revoke` with `token_type_hint=access_token` inserted the raw
-- token into `AppState::revoked_tokens`, an in-memory set of ONE API process
-- that nothing ever pruned. A revoked access token therefore worked again
-- after an API restart, on every other API process, and always on the MCP
-- HTTP transport (`:3101`, production), whose bearer middleware consulted no
-- revocation state at all. Review finding on epigraph#282 (drain unit U003).
--
-- CHANGE
--   1. `revoked_access_tokens(jti, client_id, expires_at, revoked_at)`: one row
--      per revoked access token, keyed by the token's `jti` (a uuid minted per
--      token by `JwtConfig::issue_access_token`). It holds no bearer secret: a
--      `jti` cannot be presented without the token's signature.
--   2. `epigraph_access_token_revoke(jti, client, exp)`: the ONLY write path, a
--      SECURITY DEFINER owned by `epigraph_maintenance`, EXECUTE granted to
--      `epigraph_app`. The application role holds no INSERT, UPDATE, DELETE or
--      TRUNCATE on the table (077's default privileges granted all four; they
--      are revoked here), so no application session can un-revoke a token or
--      plant arbitrary rows. The caller (`oauth/revoke.rs`) passes only a `jti`
--      read from a token whose signature it has verified.
--      It also PRUNES, lazily: rows whose token expired more than 24 HOURS ago
--      are deleted on every call. No timer is needed: the table grows only by
--      revocations, and each revocation trims it.
--      CLOCK SKEW. The definer compares `expires_at` with the DATABASE clock;
--      the API and the MCP server check `exp` on their OWN clock with zero
--      leeway. A row matters for as long as ANY host still thinks its token
--      unexpired, so both of the definer's time checks keep a 24-hour margin:
--      the prune deletes only rows a day past expiry (an API host an hour or
--      more behind the database would otherwise re-admit a revoked token once
--      its row was pruned), and a token is declined as "already expired" only
--      when it is a day past expiry (`/oauth/revoke` verifies the token's
--      signature but leaves its expiry to this guard, so a token another host
--      may still admit must be recorded here, not answered 200 and dropped). A
--      day costs at most a day's revocations of extra rows, and it outlasts any
--      skew an NTP host can drift into; beyond it a skewed host is broken in
--      other ways.
--   3. The application role keeps SELECT, and the read is a plain primary-key
--      lookup (`RevokedAccessTokenRepository::is_revoked`) run by both servers
--      AFTER signature validation. `rls_enforcement.rs` requires every public
--      table to be readable by `epigraph_app`; nothing here is secret.
--
-- The table carries no tenancy columns and no row security: a revocation is a
-- property of a credential, not of tenant content (like `refresh_tokens`).
--
-- DEPLOY ORDER. Apply with (or before) the binaries that read it: an API or
-- MCP binary that predates this file never consults the denylist, and a
-- current binary on a database without it fails CLOSED (every authenticated
-- request is refused while the lookup errors). Tokens revoked before the deploy
-- lived only in process memory and are lost at the restart anyway.
--
-- UNDO:
--   DROP FUNCTION IF EXISTS public.epigraph_access_token_revoke(uuid, uuid, timestamptz);
--   DROP TABLE IF EXISTS public.revoked_access_tokens;
-- (and roll the binaries back first: current binaries fail closed without it).

SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS public.revoked_access_tokens (
    jti        uuid        PRIMARY KEY,
    client_id  uuid        NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now()
);

-- The prune's predicate.
CREATE INDEX IF NOT EXISTS idx_revoked_access_tokens_expires_at
    ON public.revoked_access_tokens (expires_at);

-- Record one revoked access token. Returns whether a row was written: `false`
-- for a token already revoked or more than the 24-hour skew margin past its
-- expiry (a no-op either way; RFC 7009 answers 200 regardless). Idempotent.
CREATE OR REPLACE FUNCTION public.epigraph_access_token_revoke(
    p_jti uuid, p_client_id uuid, p_expires_at timestamptz)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF p_jti IS NULL OR p_client_id IS NULL OR p_expires_at IS NULL THEN
        RAISE EXCEPTION 'AT01: an access-token revocation names a jti, a client and an expiry'
            USING ERRCODE = '22023';
    END IF;
    -- Both margins are the clock-skew allowance in the header: keep them equal.
    DELETE FROM public.revoked_access_tokens
     WHERE expires_at < now() - interval '24 hours';
    IF p_expires_at <= now() - interval '24 hours' THEN
        RETURN false;
    END IF;
    INSERT INTO public.revoked_access_tokens (jti, client_id, expires_at)
    VALUES (p_jti, p_client_id, p_expires_at)
    ON CONFLICT (jti) DO NOTHING;
    RETURN FOUND;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_access_token_revoke(uuid, uuid, timestamptz)
    FROM PUBLIC;

DO $$
DECLARE f text;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        -- The definer inserts and prunes as its owner.
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON public.revoked_access_tokens '
                'TO epigraph_maintenance';
        FOREACH f IN ARRAY ARRAY[
            'public.epigraph_access_token_revoke(uuid, uuid, timestamptz)']
        LOOP
            EXECUTE format('ALTER FUNCTION %s OWNER TO epigraph_maintenance', f);
        END LOOP;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        FOREACH f IN ARRAY ARRAY[
            'public.epigraph_access_token_revoke(uuid, uuid, timestamptz)']
        LOOP
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO epigraph_app', f);
        END LOOP;
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.revoked_access_tokens '
                'FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.revoked_access_tokens TO epigraph_app';
    END IF;
END $$;
