-- ===================================================================
-- 255-undo.sql: take migration 255 (papers.licence set by the operator
-- only, backlog 9ee6799d) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- READ FIRST. Once undone, every application session can again INSERT a
-- paper with a licence or UPDATE any paper's licence, and so make every later
-- ingest of that paper keep its publisher text in evidence (226's convention,
-- unenforced). No binary needs 255, so the undo has no binary ordering of its
-- own.
--
-- WHAT IT DOES
--   1. Restores 077's table-level INSERT and UPDATE on `public.papers` to
--      `epigraph_app`. The table-level REVOKE first also removes 255's column
--      grants, so no column ACL is left behind.
--   2. Drops the RESTRICTIVE `security_events_paper_licence_privileged`
--      policy and the definer `public.epigraph_set_paper_licence`.
--   3. Restores 226's comment on `papers.licence`.
--
-- WHAT IT LEAVES: 255's `_sqlx_migrations` row, every licence as it stands,
-- and every `paper.licence_set` audit row (082's trigger makes
-- `security_events` immutable). Re-introducing 255 is a NEW migration (or a
-- re-run of 255's text, which is idempotent). This file is idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE INSERT, UPDATE ON public.papers FROM epigraph_app';
        EXECUTE 'GRANT INSERT, UPDATE ON public.papers TO epigraph_app';
    END IF;
END $$;

DROP POLICY IF EXISTS security_events_paper_licence_privileged ON public.security_events;
DROP FUNCTION IF EXISTS public.epigraph_set_paper_licence(uuid, text, text);

-- Migration 226's text, verbatim.
COMMENT ON COLUMN public.papers.licence IS
    'SPDX-style licence of the source (e.g. CC-BY-4.0). NULL = unknown, treated as '
    'all rights reserved: ingest stores a passage locator and hash, never the text. '
    'Set by an operator by convention, never by ingest (migration 226, backlog 8709d128).';

COMMIT;
