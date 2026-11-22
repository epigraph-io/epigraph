-- ===================================================================
-- 260-undo.sql: take migration 260 (the recorded edge declaration,
-- backlog 969f01f6) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- Roll every binary built with 260 back FIRST: its privatization re-meet
-- reads `edges.declared_owner_group_id`, and fails on a database without it.
--
-- WHAT IT DOES:
--   * re-creates `edges_owner_immutable` with 120's column list and WHEN
--     (owner_group_id, co_owner_group_id, writer_group_id);
--   * drops the trigger `edges_tenancy_declared` and its function
--     `epigraph_edges_record_declaration()`;
--   * drops `edges.declared_owner_group_id` and
--     `edges.declared_co_owner_group_id`.
--
-- WHAT IT LEAVES:
--   * every edge's live tuple (owner, visibility, co-owner) as it is. A
--     declared edge a 260 binary narrowed to the intersection with its meet
--     stays narrowed (fail-closed); a pre-260 re-meet would treat it as
--     derived again.
--   * 260's `_sqlx_migrations` row. Re-introducing the record is a NEW
--     migration, never a re-run of 260.
--
-- The recorded declarations are lost with the columns. Export them first if
-- they may be wanted again:
--   SELECT id, declared_owner_group_id, declared_co_owner_group_id
--     FROM public.edges WHERE declared_owner_group_id IS NOT NULL;
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS edges_owner_immutable ON public.edges;
CREATE TRIGGER edges_owner_immutable
    BEFORE UPDATE OF owner_group_id, co_owner_group_id, writer_group_id
    ON public.edges
    FOR EACH ROW
    WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id
          OR OLD.co_owner_group_id IS DISTINCT FROM NEW.co_owner_group_id
          OR OLD.writer_group_id IS DISTINCT FROM NEW.writer_group_id)
    EXECUTE FUNCTION public.epigraph_owner_immutable_guard();

DROP TRIGGER IF EXISTS edges_tenancy_declared ON public.edges;
DROP FUNCTION IF EXISTS public.epigraph_edges_record_declaration();

ALTER TABLE public.edges
    DROP COLUMN IF EXISTS declared_co_owner_group_id,
    DROP COLUMN IF EXISTS declared_owner_group_id;

COMMIT;
