-- ===================================================================
-- 351-undo.sql: take migration 351 (`papers_doi_fold_idx` and
-- `public.epigraph_document_key_fold(text)`; backlog cc71759f) back out, in
-- ONE transaction, on the migration (superuser) DSN.
--
-- ROLL THE BINARY BACK FIRST. A binary built with 351 names
-- `public.epigraph_document_key_fold` in every `papers` document-key lookup
-- (`epigraph_db::repos::paper::document_key_rows_in_sql`); with the function
-- dropped, each such lookup fails with 42883.
--
-- WHAT IT DOES: drops the index, then the function (RESTRICT: anything else
-- that came to depend on the function refuses the drop, with nothing changed).
--
-- WHAT IT LEAVES: every `papers` row; 351's `_sqlx_migrations` row.
-- Re-introducing the index is a NEW migration, never a re-run of 351. The
-- bare-DOI miss path scans `papers` again, as it did before 351.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';
DROP INDEX IF EXISTS public.papers_doi_fold_idx;
DROP FUNCTION IF EXISTS public.epigraph_document_key_fold(text) RESTRICT;
COMMIT;
