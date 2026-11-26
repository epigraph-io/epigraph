-- Undo migration 322 (unnamed_agent_placeholder_name): drop the placeholder-name function.
-- Run on a maintenance connection, AFTER rolling back every binary built against 322: each
-- surface that names an agent calls it (in the ELSE of the disclosure decision) and fails
-- (SQLSTATE 42883) without it. No rows change. Idempotent.
DROP FUNCTION IF EXISTS public.epigraph_unnamed_agent_name(uuid);
