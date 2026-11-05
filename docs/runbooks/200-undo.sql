-- ===================================================================
-- 200-undo.sql: take migration 200 (the anchored passkey path's reader)
-- back out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Turn `EPIGRAPH_WEBAUTHN_ALLOW_SYNCED_ANCHORED_PASSKEY` off (or
-- roll back to a binary without it) on every API unit BEFORE this runs
-- (docs/deploy.md section 10); a unit left serving with it on answers every
-- enrollment challenge with an error (42883).
--
-- WHAT IT DOES: drops the one function 200 created.
--
-- WHAT IT LEAVES: every enrollment, act and passkey (no table is touched),
-- including a passkey registered on the anchored path, which stays live
-- (`epigraph-operator revoke-passkey` removes one), and 200's
-- `_sqlx_migrations` row. Re-introducing the reader is a NEW migration,
-- never a re-run of 200. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP FUNCTION IF EXISTS public.epigraph_enrollment_anchor(uuid);

COMMIT;
