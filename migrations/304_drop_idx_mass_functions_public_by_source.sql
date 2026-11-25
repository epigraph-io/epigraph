-- no-transaction
--
-- 293's `idx_mass_functions_public_by_source (source_agent_id, created_at)
-- WHERE visibility = 'public'` served 295's BBA probe over every slot kind.
-- 302 counts only assessment slots and 303 indexes that probe, so no reader
-- uses 293's index; it is write cost on every public BBA.
--
-- Exactly one statement (see 275).
-- Undo: re-run 293 (CREATE INDEX CONCURRENTLY IF NOT EXISTS ...).
DROP INDEX CONCURRENTLY IF EXISTS public.idx_mass_functions_public_by_source;
