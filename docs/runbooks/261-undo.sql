-- ===================================================================
-- 261-undo.sql: take migration 261 (the not-before time on `jobs`) back
-- out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: ROLL `drain_jobs` BACK BEFORE THIS RUNS. A `drain_jobs` built
-- with the backoff-honouring drain names `jobs.run_after` in its claim; after
-- this undo every run of it fails with 42703 (undefined column) and drains
-- nothing. An older `drain_jobs` never reads the column.
--
-- WHAT IT DOES: drops `jobs.run_after`.
--
-- WHAT IT LOSES AND LEAVES:
--   * every deferred row's not-before time is LOST, so each such `pending` row
--     becomes due at once. Harmless: that is what the older drain this undo
--     goes back to did with every retryable failure.
--   * 261's `_sqlx_migrations` row. Re-introducing the column is a NEW
--     migration, never a re-run of 261.
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

ALTER TABLE public.jobs DROP COLUMN IF EXISTS run_after;

COMMIT;
