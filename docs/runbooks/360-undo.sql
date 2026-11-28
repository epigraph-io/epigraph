-- ===================================================================
-- 360-undo.sql: take migration 360 (`epigraph_role_owner_may_run`, the
-- host's owner-role question for a role's schedule) back out, in ONE
-- transaction, on the migration (superuser) DSN.
--
-- READ FIRST: after this runs, a host that asks the question gets 42883
-- (the function does not exist), which it treats as "this database predates
-- the question": it logs a warning and fires every schedule that names an
-- owner role WITHOUT the check (the identity attached / role held tripwire
-- is off). 166's `epigraph_role_agent_may_run` still gates every attached
-- identity as before. No binary needs rolling back first.
--
-- WHAT IT DOES: drops `public.epigraph_role_owner_may_run(uuid, uuid)` (its
-- grants go with it). Nothing else in 360 exists to undo: the migration
-- created no table, trigger, policy or row.
--
-- WHAT IT LEAVES: 360's `_sqlx_migrations` row. Re-introducing the function
-- is a NEW migration, never a re-run of 360. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP FUNCTION IF EXISTS public.epigraph_role_owner_may_run(uuid, uuid);

COMMIT;
