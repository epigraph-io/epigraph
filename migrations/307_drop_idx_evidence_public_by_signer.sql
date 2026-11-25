-- no-transaction
--
-- 293's `idx_evidence_public_by_signer (signer_id, created_at) WHERE
-- visibility = 'public'` served 297's evidence probe. 304 drops evidence from
-- the disclosure core (no column records its asserting agent), so no reader
-- uses the index; it is write cost on every public evidence row.
--
-- Exactly one statement (see 277).
-- Undo: re-run 293 (CREATE INDEX CONCURRENTLY IF NOT EXISTS ...).
DROP INDEX CONCURRENTLY IF EXISTS public.idx_evidence_public_by_signer;
