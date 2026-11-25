-- no-transaction
--
-- 308's `idx_edges_public_ingest_records_by_ingester ((properties ->>
-- 'ingested_by'), created_at)` is unusable by the disclosure core: under edges'
-- row security in the definer frame the bare `->>` is no index condition (312,
-- section 1). 313's index on the LEAKPROOF accessor replaces it.
--
-- Exactly one statement (see 289).
-- Undo: re-run 308 (CREATE INDEX CONCURRENTLY IF NOT EXISTS ...).
DROP INDEX CONCURRENTLY IF EXISTS public.idx_edges_public_ingest_records_by_ingester;
