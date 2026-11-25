-- no-transaction
--
-- 307's `idx_mass_functions_public_by_source (source_agent_id, created_at)
-- WHERE visibility = 'public'` served 309's BBA probe over every slot kind.
-- 316 counts only assessment slots and 317 indexes that probe, so no reader
-- uses 307's index; it is write cost on every public BBA.
--
-- Exactly one statement (see 289).
-- Undo: re-run 307 (CREATE INDEX CONCURRENTLY IF NOT EXISTS ...).
DROP INDEX CONCURRENTLY IF EXISTS public.idx_mass_functions_public_by_source;
