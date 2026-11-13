-- ===================================================================
-- 210-undo.sql: take migration 210 (per-team Atlas map storage and its
-- staleness triggers, Atlas W2) back out, in ONE transaction, on the
-- migration (superuser) DSN.
--
-- READ FIRST. Roll every binary that reads or writes the atlas_map_* tables
-- (`AtlasMapRepository`, the Atlas nightly once it builds team maps) back
-- BEFORE this runs; a unit left serving them answers with an error (42P01).
-- A binary built after 210 also lists the three tables in
-- `epigraph_api::state::FORCE_PROTECTED_SET`; the boot check skips a listed
-- table that does not exist, so the order is binaries first, then this.
--
-- WHAT IT DOES: drops the three staleness triggers (on claims, edges and
-- evidence) and their three definer functions, the three tables with their
-- policies and tier-A triggers, and the visibility guard function.
--
-- WHAT IT LEAVES:
--   * every claim, edge and evidence row as it stands (210 never changes
--     tenancy; it only counts it);
--   * 197's atlas_layout_* tables, its epoch and its two narrowing triggers;
--   * 210's `_sqlx_migrations` row. Re-introducing the maps is a NEW
--     migration, never a re-run of 210;
--   * the three names in docs/runbooks/079-undo.sql's protected array, which
--     skips a table that does not exist. Remove them there in the same change
--     that drops 210 from the tree.
--
-- WHAT IT LOSES: every stored map run and level document (the nightly
-- rebuilds them) and the epoch counters (a rebuilt run records fresh ones).
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS claims_atlas_map_stale ON public.claims;
DROP TRIGGER IF EXISTS edges_atlas_map_stale ON public.edges;
DROP TRIGGER IF EXISTS evidence_atlas_map_stale ON public.evidence;
DROP FUNCTION IF EXISTS public.epigraph_atlas_map_stale();
DROP FUNCTION IF EXISTS public.epigraph_atlas_map_stale_row();
DROP FUNCTION IF EXISTS public.epigraph_atlas_map_bump(uuid[], uuid[]);
DROP TABLE IF EXISTS public.atlas_map_levels;
DROP TABLE IF EXISTS public.atlas_map_runs;
DROP TABLE IF EXISTS public.atlas_map_epochs;
DROP FUNCTION IF EXISTS public.epigraph_atlas_map_visibility_guard();

COMMIT;
