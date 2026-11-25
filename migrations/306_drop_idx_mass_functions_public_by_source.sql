-- no-transaction
--
-- 295's `idx_mass_functions_public_by_source (source_agent_id, created_at)
-- WHERE visibility = 'public'` served 297's BBA probe over every slot kind.
-- 304 counts only assessment slots and 305 indexes that probe, so no reader
-- uses 295's index; it is write cost on every public BBA.
--
-- Exactly one statement (see 277).
-- Undo: re-run 295 (CREATE INDEX CONCURRENTLY IF NOT EXISTS ...).
DROP INDEX CONCURRENTLY IF EXISTS public.idx_mass_functions_public_by_source;
