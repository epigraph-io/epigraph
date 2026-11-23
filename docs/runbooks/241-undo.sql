-- ===================================================================
-- 241-undo.sql: take migration 241 (the reserved
-- `--allow-unauthenticated-http` reader agent and its membership refusal)
-- back out, in ONE transaction, on the migration (superuser) DSN.
--
-- WHAT IT DOES: drops 241's two triggers and their two functions:
--   * `agents_reserve_unauthenticated_reader_key` /
--     `epigraph_agents_reserve_unauthenticated_reader_key()`;
--   * `group_memberships_refuse_unauthenticated_reader` /
--     `epigraph_group_memberships_refuse_unauthenticated_reader()`.
-- After it, a `groups:admin` holder can again add the reader agent to a group
-- (which closes every read-only unauthenticated listener), and nothing stops
-- a second agent row from taking the key if the reader's row is ever deleted.
--
-- WHAT IT LEAVES:
--   * the reader's `agents` row. A 241 binary only looks it up and refuses to
--     serve without it, so it must stay while any 241 binary runs. A pre-241
--     binary adopts it as it is.
--   * 241's `_sqlx_migrations` row. Re-introducing the refusal is a NEW
--     migration, never a re-run of 241.
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS group_memberships_refuse_unauthenticated_reader
    ON public.group_memberships;
DROP FUNCTION IF EXISTS public.epigraph_group_memberships_refuse_unauthenticated_reader();

DROP TRIGGER IF EXISTS agents_reserve_unauthenticated_reader_key ON public.agents;
DROP FUNCTION IF EXISTS public.epigraph_agents_reserve_unauthenticated_reader_key();

COMMIT;
