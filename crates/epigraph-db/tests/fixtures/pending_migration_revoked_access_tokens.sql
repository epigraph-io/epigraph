-- PENDING MIGRATION BODY — `revoked_access_tokens`.
--
-- THIS FILE IS NOT A MIGRATION AND IS NOT IN `migrations/` ON PURPOSE. The
-- branch that wrote `RevokedAccessTokenRepository` was not allowed to allocate
-- a migration number (another branch owns the series), so the DDL lives here,
-- where the tests that exercise the repository, the API revoke path and the
-- MCP bearer middleware apply it on top of a fresh `#[sqlx::test]` migrate.
--
-- TO PROMOTE IT: copy this body verbatim to `migrations/NNN_revoked_access_tokens.sql`
-- (the next free public number — 101 at ba6f6d68 — with a row in
-- `migrations/README.md`), then delete this file and every
-- `include_str!(".../pending_migration_revoked_access_tokens.sql")` that names
-- it. Every statement is idempotent (`IF NOT EXISTS`, a guarded GRANT), so the
-- tests stay green in the window where both exist.
--
-- UNTIL IT IS PROMOTED, a deployed API or MCP server finds the table absent at
-- boot, logs an ERROR, and keeps the pre-existing behaviour: the API revokes
-- process-locally and MCP does not consult revocation at all. See
-- `RevokedAccessTokenRepository::probe`.
--
-- ---------------------------------------------------------------------------
-- WHAT IT IS
--
-- The shared, durable list of revoked OAuth access tokens. Access tokens are
-- self-contained JWTs, so a revocation has to be recorded somewhere every
-- validating process can read: before this table the list was a per-process
-- `HashSet` inside the API, which MCP never saw, which a restart emptied, and
-- which a second API replica did not share.
--
-- KEYED ON `jti`, NOT ON THE TOKEN. The token is a bearer secret; the jti is
-- an identifier. Nothing that could be replayed is stored at rest.
--
-- `expires_at` IS THE TOKEN'S OWN `exp`, taken only from a token whose
-- signature verified (the revoke endpoint is anonymous, so an unverified token
-- is a 200 no-op and never reaches this table). A row is useless once its token
-- has expired, because the JWT is then rejected on `exp` alone; pruning keys on
-- this column, with a grace window for clock skew between the validating
-- process and the database.
--
-- TENANCY: NONE, AND ROW SECURITY STAYS OFF. The table has no `visibility` and
-- no `owner_group_id`: a jti is a global identifier and the lookup runs in the
-- bearer middleware BEFORE any principal exists, on a connection that carries
-- no tenancy GUCs. This is the `oauth_clients` posture
-- (`rls_enforcement.rs::oauth_clients_is_deliberately_unprotected`), and it is
-- load-bearing in the same way: ENABLE ROW LEVEL SECURITY with no policy would
-- make every lookup return "not revoked" to a non-owner role — a revocation
-- check that silently fails OPEN. `RevokedAccessTokenRepository::probe` refuses
-- to report the store ready when `relrowsecurity` is set, so that mistake
-- stops the server at boot instead of admitting revoked tokens.
--
-- GRANTS: 077's `ALTER DEFAULT PRIVILEGES FOR ROLE epigraph` already covers a
-- table this role creates; the explicit, guarded grant below is the 078
-- `rls_canary` precedent for a database where the migration runner is not
-- `epigraph`. SELECT for the lookup, INSERT for the revoke path, DELETE for the
-- prune the revoke path runs.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.revoked_access_tokens (
    jti        uuid        PRIMARY KEY,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_revoked_access_tokens_expires_at
    ON public.revoked_access_tokens (expires_at);

COMMENT ON TABLE public.revoked_access_tokens IS
    'Revoked OAuth access tokens (JWTs), keyed by jti. Read by the API and MCP '
    'bearer middleware. No tenancy and no row security by design: see the '
    'migration header.';

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON public.revoked_access_tokens '
                'TO epigraph_app';
    END IF;
END $$;
