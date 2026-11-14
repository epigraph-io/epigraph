-- ===================================================================
-- 213-undo.sql: take migration 213 (agent assertion nonces) back out, in ONE
-- transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Roll every API binary back to a build that does not call
-- `epigraph_oauth_assertion_nonce_consume` BEFORE this runs. A current binary
-- left serving fails CLOSED without it: every agent client_credentials and
-- agent refresh grant answers 500 (42883).
--
-- WHAT IT DOES: drops the definer and the `oauth_assertion_nonces` table
-- (with its rows, all of which expire within minutes anyway).
--
-- WHAT IT LEAVES: 213's `_sqlx_migrations` row. Re-introducing nonce
-- tracking is a NEW migration, never a re-run of 213. After this, a captured
-- agent assertion replays for its freshness window again.
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP FUNCTION IF EXISTS public.epigraph_oauth_assertion_nonce_consume(uuid, bytea, timestamptz);
DROP TABLE IF EXISTS public.oauth_assertion_nonces;

COMMIT;
