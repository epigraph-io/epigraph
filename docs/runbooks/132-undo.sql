-- ===================================================================
-- 132-undo.sql: take migration 132 (open elevation) back out, in ONE
-- transaction, on the migration (superuser) DSN.
--
-- WHAT IT DOES: restores migration 125's body of the recorder gate,
-- `epigraph_elevated_access_ready()`, which answers false. The gate is ANDed
-- into the one liveness test, so every elevation session stops being live at
-- the next statement that asks: no request elevates, no grant-mode ticket
-- redeems, and the elevated read arms (126) read as if no session existed.
-- `CREATE OR REPLACE` keeps the owner and the ACL, as 132 did.
--
-- ORDER: run this FIRST, before every other elevation undo (131 down to
-- 124). It needs no binary rolled back first: a recording build on a
-- gate-closed database serves every request unelevated.
--
-- WHAT IT LEAVES: every session, ticket, act and log row (ended or not), and
-- 132's `_sqlx_migrations` row. Re-opening elevation is a NEW migration,
-- never a re-run of 132. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_elevated_access_ready()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT false
$$;

COMMIT;
