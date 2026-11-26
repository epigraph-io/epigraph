-- ===================================================================
-- 349-undo.sql: take migration 349 (the evidence passage-licence guard,
-- backlog b62ae3f2) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- READ FIRST. Once undone, every application session (and every API client,
-- through POST /api/v1/evidence and /api/v1/submit) can again store a
-- verbatim publisher passage, figure image or caption in a literature or
-- figure evidence row whatever the paper's licence; only the Rust ingest
-- writers apply the licence rule. No binary needs 349, so the undo has no
-- binary ordering of its own.
--
-- WHAT IT DOES: drops the two triggers on `public.evidence`, the trigger
-- function `epigraph_evidence_passage_licence_guard()` and the allowlist
-- mirror `epigraph_passage_retention_permitted(text)` (and with it 349's
-- EXECUTE grant on it to `epigraph_app`).
--
-- WHAT IT LEAVES: 349's `_sqlx_migrations` row and every evidence row as it
-- stands (349 changed no row). Re-introducing 349 is a NEW migration (or a
-- re-run of 349's text, which is idempotent). This file is idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS evidence_passage_licence_insert ON public.evidence;
DROP TRIGGER IF EXISTS evidence_passage_licence_update ON public.evidence;
DROP FUNCTION IF EXISTS public.epigraph_evidence_passage_licence_guard();
DROP FUNCTION IF EXISTS public.epigraph_passage_retention_permitted(text);

COMMIT;
