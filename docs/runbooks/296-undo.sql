-- Undo migration 296 (role_projection_edges_maintenance_only): drop the three guard triggers on
-- edges and the guard function. Run on a maintenance connection, AFTER rolling back every binary
-- built with 296 (none calls the guard; the triggers do). Afterwards a writer of a projection
-- edge's owning team can again update (e.g. widen to public) or delete it, and any edge writer
-- can write the projection marker. Idempotent.
DROP TRIGGER IF EXISTS edges_role_projection_guard_insert ON public.edges;
DROP TRIGGER IF EXISTS edges_role_projection_guard_update ON public.edges;
DROP TRIGGER IF EXISTS edges_role_projection_guard_delete ON public.edges;
DROP FUNCTION IF EXISTS public.epigraph_role_projection_edges_guard();
