-- ===================================================================
-- 220-undo.sql: take migration 220 (the crash re-delivery counter on
-- `jobs`) back out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: ROLL `drain_jobs` BACK BEFORE THIS RUNS. A `drain_jobs` built
-- with the bounded reaper names `jobs.redelivery_count` in its first
-- statement; after this undo every run of it fails with 42703 (undefined
-- column) and drains nothing. An older `drain_jobs` never reads the column.
--
-- WHAT IT DOES: drops `jobs.redelivery_count` and its CHECK
-- `jobs_redelivery_count_non_negative`.
--
-- WHAT IT LOSES AND LEAVES:
--   * every row's re-delivery count is LOST. Harmless: the older reaper this
--     undo goes back to re-delivers a one-attempt job without a bound.
--   * every row a bounded reap already FAILED stays `failed`, with its
--     `error_message`; re-queue one by hand if it should run again.
--   * 220's `_sqlx_migrations` row. Re-introducing the column is a NEW
--     migration, never a re-run of 220.
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

ALTER TABLE public.jobs DROP CONSTRAINT IF EXISTS jobs_redelivery_count_non_negative;
ALTER TABLE public.jobs DROP COLUMN IF EXISTS redelivery_count;

COMMIT;
