-- ===================================================================
-- 273-undo.sql: take migration 273 (`epigraph_group_live_roster`) back out,
-- in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: roll the API and MCP binaries back to a build WITHOUT 273
-- before running this. A binary built with 273 calls the function from
-- `GET /api/v1/groups/:id` (the member list and count), `GET /api/v1/agents`,
-- `GET /api/v1/agents/:id` and `GET /api/v1/agents/search`, and MCP
-- `find_agent` and `get_agent`, and answers each of them 42883 once it is
-- gone. That list is a build of main before migrations 286-321; a build that
-- also carries them (the human-identity disclosure core) decides the agent
-- routes and tools through 286/320 and calls 273 only from
-- `GET /api/v1/groups/:id`.
--
-- WHAT IT DOES: drops the function. 273 changes nothing else (no table, no
-- other body, no grant on anything else).
--
-- WHAT IT LEAVES: 273's `_sqlx_migrations` row. Delete it as well if 273 is
-- to be re-applied by `epigraph-migrate`:
--   DELETE FROM _sqlx_migrations WHERE version = 273;
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';
DROP FUNCTION IF EXISTS public.epigraph_group_live_roster(uuid);
COMMIT;
