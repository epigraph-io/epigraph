-- no-transaction
--
-- 330's `idx_mass_functions_public_by_source (source_agent_id, created_at)
-- WHERE visibility = 'public'` served 332's BBA probe over every slot kind.
-- 339 counts only assessment slots and 340 indexes that probe, so no reader
-- uses 330's index; it is write cost on every public BBA.
--
-- Exactly one statement (see 312).
-- Undo: re-run 330 (CREATE INDEX CONCURRENTLY IF NOT EXISTS ...).
DROP INDEX CONCURRENTLY IF EXISTS public.idx_mass_functions_public_by_source;
