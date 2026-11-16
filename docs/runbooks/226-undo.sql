-- ===================================================================
-- 226-undo.sql: take migration 226 (papers.licence) back out, in ONE
-- transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Roll every MCP unit back to a build that does not read
-- `papers.licence` BEFORE this runs; a unit left serving the 226 ingest
-- writers fails every document ingest (42703, column does not exist).
--
-- WHAT IT DOES: drops the `papers_licence_nonblank` CHECK and the
-- `papers.licence` column.
--
-- WHAT IT LOSES: every recorded licence. Evidence rows already written keep
-- whatever body they were written with (a retained passage stays retained).
--
-- WHAT IT LEAVES: 226's `_sqlx_migrations` row. Re-introducing the column is
-- a NEW migration, never a re-run of 226. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

ALTER TABLE public.papers DROP CONSTRAINT IF EXISTS papers_licence_nonblank;
ALTER TABLE public.papers DROP COLUMN IF EXISTS licence;

COMMIT;
