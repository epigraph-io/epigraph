-- Undo migration 264 (role_successor_restore): drop the restore verb.
-- Run on a maintenance connection, AFTER rolling back any epigraph-operator that carries
-- `restore-role-successor` (that command calls the function; without it the command fails 42883
-- and writes nothing). Idempotent. Rows the verb wrote stay as written (`role_agents` is
-- append-only); detach one with `epigraph_detach_agent_from_role` if it is to go. Afterwards a
-- successor cut off by its root's detach is restored by hand again: detach its stale copy, then
-- attach it by name (docs/tenancy.md).
DROP FUNCTION IF EXISTS public.epigraph_restore_role_successor(text, uuid, uuid, timestamptz, text);
