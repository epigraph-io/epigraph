-- ===================================================================
-- 229-undo.sql: take migration 229 (the `dataset` evidence type) back out, in
-- ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: ROLL THE BINARIES BACK BEFORE THIS RUNS. A 229 binary writes
-- `dataset` evidence from MCP `submit_claim` / `batch_submit_claims` (their
-- `dataset` input) and `POST /api/v1/evidence` (`evidence_type.type =
-- "dataset"`). A unit left serving after this undo answers each such write
-- with a CHECK violation (23514), and writes nothing.
--
-- DATASET ROWS BLOCK IT. Re-narrowing `evidence_type_valid` re-validates every
-- row, so it fails while any `dataset` row exists. This script refuses up
-- front instead, naming the count, and changes nothing. Decide what those rows
-- become first. List them:
--     SELECT id, claim_id, properties->>'root_uri', properties->>'manifest_hash'
--       FROM public.evidence WHERE evidence_type = 'dataset';
-- An older binary reads a `dataset` row's `properties` as an unparseable
-- `EvidenceType` and shows it as an `application/octet-stream` Document, so
-- leaving them in place behind a rolled-back binary is lossy only on read.
--
-- WHAT IT DOES: re-creates `evidence_type_valid` with migration 001's seven
-- values, in 001's own spelling. Tested by
-- `epigraph-db/tests/evidence_type_dataset.rs` (run twice, it returns the
-- constraint to its definition below 229; it refuses while a dataset row
-- exists).
--
-- WHAT IT LEAVES: 229's `_sqlx_migrations` row. Re-introducing the type is a
-- NEW migration, never a re-run of 229. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM public.evidence WHERE evidence_type = 'dataset';
    IF n > 0 THEN
        RAISE EXCEPTION '229-undo: % evidence row(s) have evidence_type = ''dataset''; '
                        'resolve them before narrowing evidence_type_valid', n;
    END IF;
END
$$;

-- Migration 001's definition, spelled as 001 spells it, so the catalog after
-- this undo is the catalog below 229.
ALTER TABLE public.evidence
    DROP CONSTRAINT IF EXISTS evidence_type_valid,
    ADD CONSTRAINT evidence_type_valid CHECK (((evidence_type)::text = ANY ((ARRAY['document'::character varying, 'observation'::character varying, 'testimony'::character varying, 'computation'::character varying, 'reference'::character varying, 'figure'::character varying, 'conversational'::character varying])::text[])));

COMMIT;
