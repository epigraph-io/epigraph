-- Undo migration 268 (agent_prompt_history_meta): drop the content-free,
-- paged prompt-history definer.
--
-- READ FIRST: roll the binaries back BEFORE this runs. A 268 binary lists
-- GET /api/v1/agents/:id/prompt-history through this function; a unit left
-- serving after the undo answers every listing with a 500 (42883). A binary
-- from before 268 lists through 161's `epigraph_agent_prompt_history`, which
-- this leaves untouched.
--
-- Run on the migration (superuser) or maintenance DSN. Idempotent. Nothing
-- else to restore: 268 wrote no rows and changed no other object. 268's
-- `_sqlx_migrations` row stays; re-introducing the function is a NEW
-- migration, never a re-run of 268.
DROP FUNCTION IF EXISTS public.epigraph_agent_prompt_history_meta(
    uuid, integer, uuid, timestamptz, uuid, integer);
