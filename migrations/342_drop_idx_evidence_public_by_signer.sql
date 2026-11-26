-- no-transaction
--
-- 328's `idx_evidence_public_by_signer (signer_id, created_at) WHERE
-- visibility = 'public'` served 332's evidence probe. 339 drops evidence from
-- the disclosure core (no column records its asserting agent), so no reader
-- uses the index; it is write cost on every public evidence row.
--
-- Exactly one statement (see 312).
-- Undo: re-run 328 (CREATE INDEX CONCURRENTLY IF NOT EXISTS ...).
DROP INDEX CONCURRENTLY IF EXISTS public.idx_evidence_public_by_signer;
