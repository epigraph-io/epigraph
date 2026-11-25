-- no-transaction
--
-- 296's `idx_edges_public_ingest_records_by_ingester ((properties ->>
-- 'ingested_by'), created_at)` is unusable by the disclosure core: under edges'
-- row security in the definer frame the bare `->>` is no index condition (300,
-- section 1). 301's index on the LEAKPROOF accessor replaces it.
--
-- Exactly one statement (see 277).
-- Undo: re-run 296 (CREATE INDEX CONCURRENTLY IF NOT EXISTS ...).
DROP INDEX CONCURRENTLY IF EXISTS public.idx_edges_public_ingest_records_by_ingester;
