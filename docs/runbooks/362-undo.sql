-- ===================================================================
-- 362-undo.sql: take migration 362 (the write-scope re-provision verb and its
-- reverse) back out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: dropping the functions does NOT take back scopes a run
-- granted. If `epigraph-operator reprovision-write-scopes --apply` ran, and
-- the grant itself is to be undone, reverse every applied manifest FIRST,
-- newest first, while the reverse definer still exists:
--   epigraph-operator reprovision-write-scopes --reverse --manifest <file> \
--       --reason TEXT            (dry run: read the RESTORED / HELD lines)
--   epigraph-operator reprovision-write-scopes --reverse --manifest <file> \
--       --reason TEXT --apply    (exit 3: a client or chain was HELD)
-- Undo the MCP scope remap (backlog c2dbcf27) BEFORE reversing a run: with
-- the remap deployed, a reversed client can no longer write edges or
-- evidence.
--
-- No binary but `epigraph-operator reprovision-write-scopes` calls either
-- function, so nothing else needs rolling back first. `security_events` keeps
-- every `oauth.write_scopes_reprovisioned` / `..._reversed` row (it is
-- immutable, 082).
--
-- WHAT IT DOES: drops both functions.
--
-- WHAT IT LEAVES: 362's `_sqlx_migrations` row; delete it as well if 362 is
-- to be re-applied by `epigraph-migrate`:
--   DELETE FROM _sqlx_migrations WHERE version = 362;
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP FUNCTION IF EXISTS public.epigraph_reprovision_write_scopes(text[], text, jsonb);
DROP FUNCTION IF EXISTS public.epigraph_reprovision_write_scopes_reverse(
    uuid, text[], text[], text[], text[], jsonb, text, jsonb);

COMMIT;
