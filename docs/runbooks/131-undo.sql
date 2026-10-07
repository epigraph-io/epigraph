-- ===================================================================
-- 131-undo.sql: take migration 131 (a person reads their own admin acts)
-- back out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Roll back every binary that calls
-- `epigraph_admin_acts_of_principal` BEFORE this runs (docs/deploy.md: the
-- API's `GET /api/v1/admin/acts`); a new binary left serving answers that
-- route with an error (42883).
--
-- ORDER: run this BEFORE `130-undo.sql`. The function's `LANGUAGE sql` body
-- reads 130's act table but records no dependency on it, so 130-undo's
-- `DROP TABLE` would succeed and leave this function behind, pointing at a
-- table that no longer exists.
--
-- WHAT IT DOES: drops the one function 131 created.
--
-- WHAT IT LEAVES: every act (130's table is untouched) and 131's
-- `_sqlx_migrations` row. Re-introducing the reader is a NEW migration, never
-- a re-run of 131. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP FUNCTION IF EXISTS public.epigraph_admin_acts_of_principal(integer);

COMMIT;
