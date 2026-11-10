-- ===================================================================
-- 206-undo.sql: take migration 206 (claim visibility controls: the two
-- membership reads, the default-team write, publicize and share-with-team)
-- back out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: ROLL THE BINARIES BACK BEFORE THIS RUNS. Every API unit and
-- every MCP server built with the visibility controls calls these functions:
-- `epigraph_writable_teams` and `epigraph_default_group` on EVERY claim write
-- that names no visibility (`ClaimRepository::resolve_write_decl`), and the
-- other three behind `publicize_claims`, `share_claims_with_team`,
-- `set_default_group` and their REST routes. A unit left serving after this
-- undo answers every one of those writes with an error (42883), default
-- writes included. A pre-206 binary calls none of them. The same binary's
-- `epigraph-tenancy-backfill verify` also reports the five as missing while
-- 206's `_sqlx_migrations` row stands; the pre-206 binary's does not list
-- them.
--
-- WHAT IT DOES: drops the five functions 206 created. Their owner, grants
-- and EXECUTE revocations go with them. 206 re-states no earlier body and
-- creates no table, column, trigger, policy or index, so nothing is restored.
--
-- WHAT IT LEAVES:
--   * every claim as it stands: a claim publicized under 206 stays public (a
--     narrowing is privatization's job, not an undo's), a claim shared with
--     a team stays owned by the team, and a team or private claim written by
--     a 206 binary keeps the tenancy it was written with;
--   * `agents.default_group_id` values set through `set_default_group` (the
--     column is 062's; nothing reads it after the undo);
--   * the `security_events` rows 206 wrote (`agent.default_group_set`,
--     `claim.publicized`, `claim.shared_with_team`);
--   * 206's `_sqlx_migrations` row.
-- Re-introducing the functions is a NEW migration, never a re-run of 206.
-- Idempotent: a second run changes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP FUNCTION IF EXISTS public.epigraph_share_claims_with_team(uuid[], uuid, text);
DROP FUNCTION IF EXISTS public.epigraph_publicize_claims(uuid[], text);
DROP FUNCTION IF EXISTS public.epigraph_set_default_group(uuid);
DROP FUNCTION IF EXISTS public.epigraph_default_group(uuid);
DROP FUNCTION IF EXISTS public.epigraph_writable_teams(uuid);

COMMIT;
