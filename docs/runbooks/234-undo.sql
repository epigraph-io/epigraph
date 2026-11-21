-- Undo migration 234 (operated_agent_reads_human_teams): drop the read definer.
-- Run on a maintenance connection. Idempotent. Afterwards an operated agent's read set is its own
-- memberships again: binaries that know 234 treat the missing function (SQLSTATE 42883) as "no team".
DROP FUNCTION IF EXISTS public.epigraph_readable_teams(uuid);
